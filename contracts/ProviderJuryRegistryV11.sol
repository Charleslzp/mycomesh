// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";
import {DrandQuicknet} from "./DrandQuicknet.sol";

interface IMycoSettlementCaseV11 {
    function caseParties(bytes32 key) external view returns (
        address owner, address consumerKey, address provider, address providerSigner,
        address relay, address relaySigner, bool disputed
    );
    function providerSignerOwner(address signer) external view returns (address);
}

/// @notice V11 Provider-AI jury registry: permissionless registration,
/// reputation derived only from settlement outcomes, drand-seeded selection.
/// @dev No party can write reputation.  The settlement reports every clean
/// release and every confirmed fraud; volume counts toward eligibility only up
/// to a per-counterparty cap, so trading with oneself cannot buy eligibility.
/// A confirmed fraud starts a new reputation epoch and a cooldown.  A jury is
/// drawn from an eligible, party-independent candidate snapshot using a drand
/// quicknet round that is still in the future when the case is opened.
/// Candidates are drawn in proportion to their counted volume (capped at
/// ``maxJuryWeight``), so capturing a jury means out-trading every honest
/// Provider across many independent counterparties, not registering many keys.
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
    /// @dev Base prices are stablecoin units per 1000 tokens; the multiplier scales all three.
    struct Tier {
        uint128 baseIn; uint128 baseOut; uint128 minFee; uint128 baseCapacity; uint16 targetBps; bool active;
    }
    struct TierState { uint64 epoch; uint64 multiplier; }
    struct SignerPricing {
        uint32 tier; uint64 lastEpoch; uint128 declared; uint128 peak; uint128 counted; uint128 served;
    }
    struct Assignment {
        uint64 round; AssignmentStatus status; bytes32 seed; bytes32 hash;
        address[] candidateOwners; address[] candidateSigners;
        address[] jurorOwners; address[] jurorSigners;
        uint256[] candidateWeights; // appended in v2; empty for cases requested under v1
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
    uint256 public maxJuryWeight; // v2: 0 means uncapped

    // ---- v4: network pricing, adjusted like Bitcoin's difficulty ----
    mapping(uint32 => Tier) public tiers;
    mapping(uint32 => TierState) public tierState;
    mapping(uint32 => mapping(uint64 => uint64)) public multiplierAt; // tier => epoch => price multiplier (1e6 = 1x)
    mapping(uint32 => mapping(uint64 => uint256)) public demandAt;    // settled work, in base-price units
    mapping(uint32 => mapping(uint64 => uint256)) public supplyAt;    // counted capacity, same units
    mapping(address => SignerPricing) public signerPricing;
    uint256[33] private __gap;

    event SettlementBound(address indexed settlement);
    event EligibilityUpdated(Eligibility eligibility);
    event TierUpdated(uint32 indexed tier, Tier config);
    event SignerTierSet(address indexed signer, uint32 indexed tier, uint256 declaredCapacity);
    event PriceAdjusted(uint32 indexed tier, uint64 indexed epoch, uint64 multiplier, uint256 demand, uint256 supply);
    event JuryRulesUpdated(uint16 jurySize, uint16 threshold, uint64 selectionDelay, uint256 maxJuryWeight);
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
        _initializeAdmin(admin_);
        _setJury(jurySize_, threshold_, selectionDelay_, 0);
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

    function setJury(uint16 jurySize_, uint16 threshold_, uint64 selectionDelay_, uint256 maxJuryWeight_)
        external onlyProxy onlyAdmin
    {
        _setJury(jurySize_, threshold_, selectionDelay_, maxJuryWeight_);
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
            item.candidateWeights.push(_weight(candidate.owner));
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
        uint256[] memory weights = new uint256[](count);
        uint256 total;
        for (uint256 i; i < count; ++i) {
            weights[i] = item.candidateWeights.length == count ? item.candidateWeights[i] : 1;
            total += weights[i];
        }
        // Weighted draw without replacement; every candidate weighs at least 1.
        uint256 size = _drawSize(count);
        for (uint256 i; i < size; ++i) {
            uint256 target = uint256(keccak256(abi.encode(seed, i))) % total;
            uint256 pick;
            for (uint256 acc; pick < count; ++pick) {
                acc += weights[pick];
                if (target < acc) break;
            }
            total -= weights[pick];
            weights[pick] = 0;
            address signer = item.candidateSigners[pick];
            item.jurorOwners.push(item.candidateOwners[pick]);
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

    // ---------------- network pricing ----------------
    //
    // One network price per tier, the same for every Provider. Once a day the
    // price multiplier follows utilisation (settled work / online capacity)
    // toward a target, by at most 10% per day, within 0.1x..10x of the base
    // price, like Bitcoin's difficulty follows the block rate. A Provider is
    // online in a day when it settles anything that day (Relay probes ensure
    // it does). Its capacity for the day is its declaration, capped at twice
    // its best day (new Providers: the tier's base capacity), and it binds: it
    // cannot settle more work than that. Declaring less than it can serve only
    // costs a Provider its own income, and a declaration cannot exceed what it
    // has proven, so neither side can steer the price without real work.

    uint64 public constant EPOCH = 1 days;
    uint64 public constant UNIT = 1_000_000;
    uint64 public constant MIN_MULTIPLIER = 100_000;
    uint64 public constant MAX_MULTIPLIER = 10_000_000;
    uint256 public constant MAX_STEP_BPS = 1_000;

    function setTier(uint32 id, Tier calldata config) external onlyProxy onlyAdmin {
        require(id != 0 && config.targetBps > 0 && config.targetBps <= 10_000 && config.baseIn + config.baseOut > 0); // bad tier
        if (!tiers[id].active && tierState[id].multiplier == 0) {
            uint64 epoch = uint64(block.timestamp / EPOCH);
            tierState[id] = TierState(epoch, UNIT);
            multiplierAt[id][epoch] = UNIT;
        }
        tiers[id] = config;
        emit TierUpdated(id, config);
    }

    /// @notice A Provider owner puts one of its signers in a tier and declares its daily capacity.
    function setSignerTier(address signer, uint32 tier, uint128 declaredCapacity) external onlyProxy {
        require(IMycoSettlementCaseV11(settlement).providerSignerOwner(signer) == msg.sender); // not your signer
        require(tiers[tier].active); // unknown tier
        SignerPricing storage item = signerPricing[signer];
        if (item.tier != tier) item.lastEpoch = 0;
        item.tier = tier;
        item.declared = declaredCapacity;
        emit SignerTierSet(signer, tier, declaredCapacity);
    }

    /// @notice Record one settlement's work and return its network price. Only the settlement calls this.
    function priceAndRecord(address signer, uint64 issuedAt, uint256 inputTokens, uint256 outputTokens)
        external onlyProxy onlySettlement returns (uint256)
    {
        SignerPricing storage item = signerPricing[signer];
        uint32 tier = item.tier;
        Tier storage config = tiers[tier];
        require(config.active); // signer has no priced tier
        _roll(tier);
        uint64 epoch = uint64(block.timestamp / EPOCH);
        uint256 work = _work(config, inputTokens, outputTokens);
        demandAt[tier][epoch] += work;
        if (item.lastEpoch != epoch) {
            uint256 proven = uint256(item.peak) * 2;
            uint256 cap = proven > config.baseCapacity ? proven : config.baseCapacity;
            uint256 counted = item.declared < cap ? item.declared : cap;
            item.lastEpoch = epoch;
            item.served = 0;
            item.counted = uint128(counted);
            supplyAt[tier][epoch] += counted;
        }
        uint256 served = uint256(item.served) + work;
        require(served <= item.counted); // daily capacity used up
        item.served = uint128(served);
        if (served > item.peak) item.peak = uint128(served);
        return _price(config, work, multiplierFor(tier, uint64(issuedAt / EPOCH)));
    }

    /// @notice Work a signer may still settle today (base-price units), the check Relays make before dispatch.
    function remainingCapacity(address signer) external view returns (uint256) {
        SignerPricing storage item = signerPricing[signer];
        Tier storage config = tiers[item.tier];
        if (!config.active) return 0;
        if (item.lastEpoch == block.timestamp / EPOCH) return item.counted - item.served;
        uint256 proven = uint256(item.peak) * 2;
        uint256 cap = proven > config.baseCapacity ? proven : config.baseCapacity;
        return item.declared < cap ? item.declared : cap;
    }

    /// @notice What a request would cost now: the same formula settlement enforces.
    function quote(address signer, uint64 issuedAt, uint256 inputTokens, uint256 outputTokens) external view returns (uint256) {
        SignerPricing storage item = signerPricing[signer];
        Tier storage config = tiers[item.tier];
        require(config.active); // signer has no priced tier
        return _price(config, _work(config, inputTokens, outputTokens), multiplierFor(item.tier, uint64(issuedAt / EPOCH)));
    }

    /// @notice The multiplier of any epoch up to now, including one the chain has not rolled into yet.
    function multiplierFor(uint32 tier, uint64 epoch) public view returns (uint64 multiplier) {
        multiplier = multiplierAt[tier][epoch];
        if (multiplier != 0) return multiplier;
        TierState memory state = tierState[tier];
        multiplier = state.multiplier;
        for (uint64 e = state.epoch; e < epoch && e < state.epoch + 400; ++e) {
            multiplier = _step(tier, e, multiplier);
        }
    }

    function _roll(uint32 tier) internal {
        TierState storage state = tierState[tier];
        uint64 current = uint64(block.timestamp / EPOCH);
        uint64 multiplier = state.multiplier;
        // Gaps are bounded: after 60 idle days the multiplier sits at its floor anyway.
        for (uint64 e = state.epoch; e < current; ++e) {
            if (e >= state.epoch + 60) { e = current - 1; }
            multiplier = _step(tier, e, multiplier);
            multiplierAt[tier][e + 1] = multiplier;
            emit PriceAdjusted(tier, e + 1, multiplier, demandAt[tier][e], supplyAt[tier][e]);
        }
        if (state.epoch != current) {
            state.epoch = current;
            state.multiplier = multiplier;
        }
    }

    function _step(uint32 tier, uint64 epoch, uint64 multiplier) internal view returns (uint64) {
        uint256 supply = supplyAt[tier][epoch];
        uint256 utilization = supply == 0 ? 0 : demandAt[tier][epoch] * 10_000 / supply;
        uint256 ratio = utilization * 10_000 / tiers[tier].targetBps;
        if (ratio > 10_000 + MAX_STEP_BPS) ratio = 10_000 + MAX_STEP_BPS;
        if (ratio < 10_000 - MAX_STEP_BPS) ratio = 10_000 - MAX_STEP_BPS;
        uint256 next = uint256(multiplier) * ratio / 10_000;
        if (next < MIN_MULTIPLIER) next = MIN_MULTIPLIER;
        if (next > MAX_MULTIPLIER) next = MAX_MULTIPLIER;
        return uint64(next);
    }

    function _work(Tier storage config, uint256 inputTokens, uint256 outputTokens) internal view returns (uint256) {
        return (inputTokens * config.baseIn + outputTokens * config.baseOut + 999) / 1000;
    }

    function _price(Tier storage config, uint256 work, uint64 multiplier) internal view returns (uint256 price) {
        price = (work * multiplier + UNIT - 1) / UNIT;
        uint256 minimum = (uint256(config.minFee) * multiplier + UNIT - 1) / UNIT;
        if (price < minimum) price = minimum;
        if (price == 0) price = 1;
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

    /// @dev Jury rules may change while a case is pending; its draw keeps the
    /// size the candidate snapshot can support.
    function _drawSize(uint256 candidates) internal view returns (uint256) {
        return candidates < jurySize ? candidates : jurySize;
    }

    function _weight(address owner) internal view returns (uint256 weight) {
        weight = stats[owner].countedVolume;
        if (maxJuryWeight != 0 && weight > maxJuryWeight) weight = maxJuryWeight;
        if (weight == 0) weight = 1;
    }

    function _setJury(uint16 size, uint16 threshold_, uint64 delay, uint256 maxWeight) internal {
        require(size >= 2 && size <= MAX_JURY_SIZE); // bad jury size
        require(threshold_ > size / 2 && threshold_ <= size); // not a majority threshold
        require(delay >= DrandQuicknet.PERIOD && delay <= 1 hours); // bad selection delay
        jurySize = size;
        threshold = threshold_;
        selectionDelay = delay;
        maxJuryWeight = maxWeight;
        emit JuryRulesUpdated(size, threshold_, delay, maxWeight);
    }

    function _setEligibility(Eligibility calldata rules) internal {
        require(rules.perCounterpartyCap > 0); // zero counterparty cap
        eligibility = rules;
        emit EligibilityUpdated(rules);
    }
}
