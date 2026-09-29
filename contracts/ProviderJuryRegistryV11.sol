// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";
import {DrandQuicknet} from "./DrandQuicknet.sol";

interface IMycoSettlementCaseV11 {
    function caseParties(bytes32 key) external view returns (
        address owner, address consumerKey, address provider, address providerSigner,
        address relay, address relaySigner, bool disputed
    );
}

/// @notice V11 Provider-AI jury registry: permissionless registration,
/// reputation derived only from settlement outcomes, drand-seeded selection.
/// @dev No party can write reputation.  The settlement reports every clean
/// release and every confirmed fraud; volume counts toward eligibility only up
/// to a per-counterparty cap, so trading with oneself cannot buy eligibility.
/// A confirmed fraud starts a new reputation epoch and a cooldown.  A jury is
/// drawn from an eligible, party-independent candidate snapshot using a drand
/// quicknet round that is still in the future when the case is opened.
contract ProviderJuryRegistryV11 is MycoUUPSUpgradeable {
    uint256 public constant MAX_PROVIDERS = 128;
    uint16 public constant MAX_JURY_SIZE = 7;

    enum AssignmentStatus { None, Pending, Ready, Failed }

    struct Provider {
        address owner; address voteSigner;
        bytes32 operatorIdHash; bytes32 peerIdHash; bytes32 capabilityHash;
        uint64 registeredAt; bool active;
    }
    struct Stats { uint64 epoch; uint64 counterparties; uint64 lastFraudAt; uint256 countedVolume; }
    struct Eligibility {
        uint256 minCountedVolume; uint64 minCounterparties; uint64 minAge;
        uint64 fraudCooldown; uint256 perCounterpartyCap;
    }
    struct Assignment {
        uint64 round; AssignmentStatus status; bytes32 seed; bytes32 hash;
        address[] candidateOwners; address[] candidateSigners;
        address[] jurorOwners; address[] jurorSigners;
    }

    // ---- storage (append-only across upgrades) ----
    address public settlement;
    uint16 public jurySize;
    uint16 public threshold;
    uint64 public selectionDelay;
    Eligibility public eligibility;
    Provider[] private providers;
    mapping(address => uint256) private providerIndex; // 1-based
    mapping(bytes32 => address) public operatorOwner;
    mapping(address => Stats) public stats;
    mapping(address => mapping(uint64 => mapping(address => uint256))) public counterpartyVolume;
    mapping(bytes32 => Assignment) private assignments;
    mapping(bytes32 => mapping(address => bool)) private jurors;
    uint256[40] private __gap;

    event SettlementBound(address indexed settlement);
    event EligibilityUpdated(Eligibility eligibility);
    event ProviderRegistered(address indexed owner, address indexed voteSigner, bytes32 indexed operatorIdHash);
    event ProviderDeactivated(address indexed owner);
    event ReleaseRecorded(address indexed provider, address indexed consumer, uint256 fee, uint256 counted);
    event FraudRecorded(address indexed provider, uint64 epoch);
    event JuryRequested(bytes32 indexed caseId, uint64 round, bytes32 candidatesHash, uint256 candidates);
    event JuryUnavailable(bytes32 indexed caseId, uint256 candidates);
    event JuryAssigned(bytes32 indexed caseId, bytes32 assignmentHash, uint64 round, address[] voteSigners);

    modifier onlySettlement() {
        require(msg.sender == settlement && settlement != address(0)); // not the settlement
        _;
    }

    constructor() {}

    function initialize(
        address admin_, uint16 jurySize_, uint16 threshold_, uint64 selectionDelay_, Eligibility calldata eligibility_
    ) external reinitializer(1) {
        require(jurySize_ >= 2 && jurySize_ <= MAX_JURY_SIZE); // bad jury size
        require(threshold_ > jurySize_ / 2 && threshold_ <= jurySize_); // not a majority threshold
        require(selectionDelay_ >= DrandQuicknet.PERIOD && selectionDelay_ <= 1 hours); // bad selection delay
        _initializeAdmin(admin_);
        jurySize = jurySize_;
        threshold = threshold_;
        selectionDelay = selectionDelay_;
        _setEligibility(eligibility_);
    }

    // ---------------- admin ----------------

    function bindSettlement(address settlement_) external onlyProxy onlyAdmin {
        require(settlement_ != address(0) && settlement_.code.length > 0); // bad settlement
        settlement = settlement_;
        emit SettlementBound(settlement_);
    }

    function setEligibility(Eligibility calldata eligibility_) external onlyProxy onlyAdmin {
        _setEligibility(eligibility_);
    }

    // ---------------- Providers ----------------

    function register(address voteSigner, bytes32 operatorIdHash, bytes32 peerIdHash, bytes32 capabilityHash)
        external onlyProxy
    {
        require(voteSigner != address(0) && voteSigner != msg.sender && voteSigner.code.length == 0); // bad vote signer
        require(operatorIdHash != bytes32(0) && peerIdHash != bytes32(0)); // empty identity
        address current = operatorOwner[operatorIdHash];
        require(current == address(0) || current == msg.sender); // operator id taken
        uint256 index = providerIndex[msg.sender];
        if (index == 0) {
            require(providers.length < MAX_PROVIDERS); // registry full
            providers.push(Provider(msg.sender, voteSigner, operatorIdHash, peerIdHash, capabilityHash,
                uint64(block.timestamp), true));
            providerIndex[msg.sender] = providers.length;
        } else {
            Provider storage provider = providers[index - 1];
            if (provider.operatorIdHash != operatorIdHash) delete operatorOwner[provider.operatorIdHash];
            provider.voteSigner = voteSigner;
            provider.operatorIdHash = operatorIdHash;
            provider.peerIdHash = peerIdHash;
            provider.capabilityHash = capabilityHash;
            provider.active = true;
        }
        operatorOwner[operatorIdHash] = msg.sender;
        emit ProviderRegistered(msg.sender, voteSigner, operatorIdHash);
    }

    function deactivate() external onlyProxy {
        uint256 index = providerIndex[msg.sender];
        require(index != 0 && providers[index - 1].active); // not an active Provider
        providers[index - 1].active = false;
        emit ProviderDeactivated(msg.sender);
    }

    // ---------------- settlement hooks ----------------

    function recordRelease(address provider, address consumer, uint256 fee) external onlyProxy onlySettlement {
        Stats storage s = stats[provider];
        uint256 previous = counterpartyVolume[provider][s.epoch][consumer];
        if (previous == 0 && fee > 0) ++s.counterparties;
        uint256 cap = eligibility.perCounterpartyCap;
        uint256 room = previous < cap ? cap - previous : 0;
        uint256 counted = fee < room ? fee : room;
        counterpartyVolume[provider][s.epoch][consumer] = previous + fee;
        s.countedVolume += counted;
        emit ReleaseRecorded(provider, consumer, fee, counted);
    }

    function recordConfirmedFraud(address provider) external onlyProxy onlySettlement {
        Stats storage s = stats[provider];
        ++s.epoch;
        s.counterparties = 0;
        s.countedVolume = 0;
        s.lastFraudAt = uint64(block.timestamp);
        emit FraudRecorded(provider, s.epoch);
    }

    // ---------------- jury selection ----------------

    function requestJury(bytes32 caseId, address providerOwner) external onlyProxy onlySettlement {
        Assignment storage item = assignments[caseId];
        require(item.status == AssignmentStatus.None); // jury already requested
        (address owner, address consumerKey, , address providerSigner, address relay, address relaySigner, bool disputed) =
            IMycoSettlementCaseV11(settlement).caseParties(caseId);
        require(disputed); // case not disputed
        address[6] memory parties = [owner, consumerKey, providerOwner, providerSigner, relay, relaySigner];
        for (uint256 i; i < providers.length; ++i) {
            Provider storage candidate = providers[i];
            if (!_eligible(candidate) || _isParty(parties, candidate.owner) || _isParty(parties, candidate.voteSigner)) {
                continue;
            }
            item.candidateOwners.push(candidate.owner);
            item.candidateSigners.push(candidate.voteSigner);
        }
        uint256 count = item.candidateOwners.length;
        if (count < jurySize) {
            item.status = AssignmentStatus.Failed;
            emit JuryUnavailable(caseId, count);
            return;
        }
        item.round = DrandQuicknet.roundAt(block.timestamp + selectionDelay);
        item.status = AssignmentStatus.Pending;
        emit JuryRequested(caseId, item.round, keccak256(abi.encode(item.candidateSigners)), count);
    }

    /// @notice Anyone may finalize with the drand quicknet signature (128-byte
    /// uncompressed G1) of the case's round.  The round is unknown when the
    /// candidate snapshot is fixed, so no party can steer the draw.
    function finalizeJury(bytes32 caseId, bytes calldata signature) external onlyProxy {
        Assignment storage item = assignments[caseId];
        require(item.status == AssignmentStatus.Pending); // no pending jury
        require(DrandQuicknet.verify(item.round, signature)); // invalid drand beacon
        bytes32 seed = keccak256(abi.encode(caseId, item.round, keccak256(signature)));
        uint256 count = item.candidateOwners.length;
        uint256[] memory order = new uint256[](count);
        for (uint256 i; i < count; ++i) order[i] = i;
        for (uint256 i; i < jurySize; ++i) {
            uint256 pick = i + uint256(keccak256(abi.encode(seed, i))) % (count - i);
            (order[i], order[pick]) = (order[pick], order[i]);
            address signer = item.candidateSigners[order[i]];
            item.jurorOwners.push(item.candidateOwners[order[i]]);
            item.jurorSigners.push(signer);
            jurors[caseId][signer] = true;
        }
        item.seed = seed;
        item.hash = keccak256(abi.encode(
            address(this), block.chainid, settlement, caseId, item.round, seed, item.jurorOwners, item.jurorSigners
        ));
        item.status = AssignmentStatus.Ready;
        emit JuryAssigned(caseId, item.hash, item.round, item.jurorSigners);
    }

    // ---------------- views ----------------

    function assignmentHash(bytes32 caseId) external view returns (bytes32) {
        Assignment storage item = assignments[caseId];
        return item.status == AssignmentStatus.Ready ? item.hash : bytes32(0);
    }

    function isVoteSigner(bytes32 caseId, address account) external view returns (bool) {
        return jurors[caseId][account];
    }

    function assignmentInfo(bytes32 caseId) external view returns (
        AssignmentStatus status, uint64 round, bytes32 seed, bytes32 hash,
        address[] memory jurorOwners, address[] memory jurorSigners, uint256 candidates
    ) {
        Assignment storage item = assignments[caseId];
        return (item.status, item.round, item.seed, item.hash, item.jurorOwners, item.jurorSigners,
            item.candidateOwners.length);
    }

    function providerCount() external view returns (uint256) { return providers.length; }
    function providerAt(uint256 index) external view returns (Provider memory) { return providers[index]; }

    function providerOf(address owner) external view returns (Provider memory provider, Stats memory providerStats, bool isEligible) {
        uint256 index = providerIndex[owner];
        if (index != 0) {
            provider = providers[index - 1];
            isEligible = _eligible(providers[index - 1]);
        }
        providerStats = stats[owner];
    }

    // ---------------- internals ----------------

    function _eligible(Provider storage provider) internal view returns (bool) {
        Stats storage s = stats[provider.owner];
        Eligibility storage rules = eligibility;
        return provider.active
            && block.timestamp >= uint256(provider.registeredAt) + rules.minAge
            && s.countedVolume >= rules.minCountedVolume
            && s.counterparties >= rules.minCounterparties
            && (s.lastFraudAt == 0 || block.timestamp >= uint256(s.lastFraudAt) + rules.fraudCooldown);
    }

    function _isParty(address[6] memory parties, address account) internal pure returns (bool) {
        for (uint256 i; i < parties.length; ++i) if (parties[i] == account) return true;
        return false;
    }

    function _setEligibility(Eligibility calldata rules) internal {
        require(rules.perCounterpartyCap > 0); // zero counterparty cap
        eligibility = rules;
        emit EligibilityUpdated(rules);
    }
}
