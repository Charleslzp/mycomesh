// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoJuryCaseV1 {
    struct ChannelConfigView {
        uint256 inputPer1K;
        uint256 outputPer1K;
        uint256 minimumFee;
        uint16 providerBps;
        uint16 relayBps;
        uint16 poolBps;
        uint16 treasuryBps;
        bool active;
    }

    struct OpenChannelView {
        address consumerOwner;
        address consumerKey;
        address providerOwner;
        address providerSigner;
        address relay;
        address relaySigner;
        address pool;
        bytes32 channel;
        uint64 pricingVersion;
        bytes32 pricingHash;
        uint256 capacity;
        uint256 maxFeePerRequest;
        uint64 validFrom;
        uint64 admitUntil;
        uint64 claimUntil;
        uint256 consumerNonce;
        uint256 providerNonce;
        uint64 permitDeadline;
    }

    struct CapacityChannelView {
        OpenChannelView config;
        uint256 settledMaxFee;
        uint256 creditRemaining;
        uint256 stakeRemaining;
        bool closed;
    }

    struct SettlementView {
        address owner;
        address key;
        address provider;
        address providerSigner;
        address relay;
        address relaySigner;
        address pool;
        address treasury;
        bytes32 requestId;
        bytes32 requestHash;
        bytes32 authorizationHash;
        bytes32 responseHash;
        uint256 grossFee;
        uint256 providerAmount;
        uint256 relayAmount;
        uint256 poolAmount;
        uint256 treasuryAmount;
        uint64 settledAt;
        uint64 releaseAt;
        uint8 status;
    }

    struct DisputeView {
        uint64 openedAt;
        uint64 resolveAt;
        uint16 dismissVotes;
        uint256 reportCount;
        uint256 totalBond;
        bytes32 winningReportId;
        uint256 slashAmount;
        uint256 stableBounty;
    }

    function settlementInfo(bytes32 caseId) external view returns (SettlementView memory);
    function disputeInfo(bytes32 caseId) external view returns (DisputeView memory);
    function channelInfo(bytes32 channelId) external view returns (CapacityChannelView memory);
    function channelVersions(bytes32 channel, uint64 version)
        external
        view
        returns (ChannelConfigView memory, address treasury, bytes32 pricingHash);
    function providerSigners(address provider, address signer) external view returns (bool);
    function juryRegistry() external view returns (address);
    function adjudicationThreshold() external view returns (uint16);
}

/// @notice Dynamic, reputation-gated Provider jury selection for MycoMesh disputes.
/// @dev Providers are not pinned in the settlement constructor.  A separately
/// authorized reputation publisher maintains the live roster.  Once a case asks
/// for a jury, roster mutations pause until a future block hash has selected an
/// operator-distinct jury or the request expires.  The future-block construction
/// is suitable for the Sepolia test network; a production deployment should use
/// the same interface with a stronger VRF-backed randomness implementation.
contract ProviderJuryRegistryV1 {
    uint16 public constant MAX_PROVIDERS = 64;
    uint16 public constant MAX_JURY_SIZE = 7;
    bytes32 public constant RANDOMNESS_MODE_HASH = keccak256("future_blockhash_v1");
    uint8 private constant SETTLEMENT_STATUS_DISPUTED = 2;

    enum AssignmentStatus {
        None,
        Pending,
        Ready,
        Failed
    }

    struct Provider {
        address owner;
        address voteSigner;
        bytes32 operatorIdHash;
        bytes32 peerIdHash;
        bytes32 capabilityHash;
        uint64 reputation;
        bool active;
    }

    struct Assignment {
        uint64 selectionBlock;
        uint64 rosterVersion;
        bytes32 seed;
        bytes32 resultHash;
        AssignmentStatus status;
        address[] owners;
        address[] voteSigners;
        bytes32[] operatorIdHashes;
        bytes32[] peerIdHashes;
        bytes32[] capabilityHashes;
        uint64[] reputations;
        uint16[] candidateIndexes;
    }

    bytes32 private constant ASSIGNMENT_TYPEHASH = keccak256(
        "MycoProviderJuryAssignment(address registry,uint256 chainId,address settlement,bytes32 caseId,uint64 rosterVersion,bytes32 seed,uint64 minimumReputation,uint16 jurySize,uint16 threshold,bytes32 ownersHash,bytes32 voteSignersHash,bytes32 operatorsHash,bytes32 peersHash,bytes32 capabilitiesHash,bytes32 reputationsHash)"
    );

    address public governance;
    address public reputationAuthority;
    address public settlement;
    address public immutable bondPenaltyRecipient;
    uint64 public rosterVersion;
    uint64 public immutable minimumReputation;
    uint16 public immutable jurySize;
    uint16 public immutable threshold;
    uint16 public immutable selectionDelayBlocks;
    uint256 public pendingAssignments;

    Provider[] private providers;
    mapping(address => uint256) private providerIndexPlusOne;
    mapping(address => address) public voteSignerOwner;
    // Monotonic Pool publication identity is retained even after an owner is
    // removed from the live roster.  Removing and re-registering a Provider
    // must therefore never make an older authenticated reputation snapshot
    // admissible again.
    mapping(address => uint64) public providerSourceSequence;
    mapping(address => bytes32) public providerSourceDigest;
    // Random selection is over independent Provider operators, not over an
    // operator's ability to register many aliases.  Keep operator and peer
    // identities unique across the live candidate records so one person
    // cannot increase selection probability with Sybil entries.
    mapping(bytes32 => address) public operatorIdOwner;
    mapping(bytes32 => address) public peerIdOwner;
    mapping(bytes32 => Assignment) private assignments;
    mapping(bytes32 => mapping(address => bool)) private assignedVoteSigners;
    mapping(bytes32 => mapping(address => bool)) private assignedParties;
    mapping(bytes32 => mapping(address => bool)) private assignmentCandidateParties;

    event SettlementBound(address indexed settlement);
    event ReputationAuthorityChanged(address indexed authority);
    event ProviderUpdated(
        address indexed owner,
        address indexed voteSigner,
        bytes32 indexed operatorIdHash,
        uint64 reputation,
        bool active,
        uint64 sourceSequence,
        bytes32 sourceDigest,
        uint64 rosterVersion
    );
    event ProviderRemoved(
        address indexed owner, address indexed voteSigner, bytes32 indexed operatorIdHash, uint64 rosterVersion
    );
    event JuryRequested(
        bytes32 indexed caseId, uint64 indexed rosterVersion, uint64 selectionBlock, bytes32 rosterCommitment
    );
    event JuryAssigned(
        bytes32 indexed caseId,
        bytes32 indexed assignmentHash,
        bytes32 seed,
        address[] owners,
        address[] voteSigners,
        bytes32[] operatorIdHashes
    );
    event JuryAssignmentFailed(bytes32 indexed caseId, bytes32 seed);
    event JuryUnavailable(bytes32 indexed caseId, uint64 indexed rosterVersion, uint256 independentCandidateCount);

    modifier onlyGovernance() {
        require(msg.sender == governance); // not governance
        _;
    }

    modifier onlyReputationAuthority() {
        require(msg.sender == reputationAuthority); // not reputation authority
        _;
    }

    modifier onlySettlement() {
        require(msg.sender == settlement && settlement != address(0)); // not settlement
        _;
    }

    constructor(
        address governance_,
        address reputationAuthority_,
        address bondPenaltyRecipient_,
        uint64 minimumReputation_,
        uint16 jurySize_,
        uint16 threshold_,
        uint16 selectionDelayBlocks_
    ) {
        require(
            governance_ != address(0) && reputationAuthority_ != address(0) && bondPenaltyRecipient_ != address(0)
                && bondPenaltyRecipient_ != address(this) && governance_ != address(this)
                && reputationAuthority_ != address(this) && governance_ != reputationAuthority_
                && bondPenaltyRecipient_ != governance_ && bondPenaltyRecipient_ != reputationAuthority_
        ); // bad authority
        require(minimumReputation_ > 0); // zero reputation threshold
        require(
            jurySize_ >= 3 && jurySize_ <= MAX_JURY_SIZE && threshold_ >= 2 && threshold_ <= jurySize_
                && threshold_ > jurySize_ / 2
        ); // bad jury policy
        require(selectionDelayBlocks_ > 0 && selectionDelayBlocks_ <= 64); // bad selection delay
        governance = governance_;
        reputationAuthority = reputationAuthority_;
        bondPenaltyRecipient = bondPenaltyRecipient_;
        minimumReputation = minimumReputation_;
        jurySize = jurySize_;
        threshold = threshold_;
        selectionDelayBlocks = selectionDelayBlocks_;
    }

    function bindSettlement(address settlement_) external onlyGovernance {
        require(settlement == address(0) && settlement_ != address(0) && settlement_.code.length > 0); // bad settlement
        require(
            settlement_ != address(this) && settlement_ != governance && settlement_ != reputationAuthority
                && settlement_ != bondPenaltyRecipient
        ); // settlement role conflict
        require(providerIndexPlusOne[settlement_] == 0 && voteSignerOwner[settlement_] == address(0)); // provider identity conflict
        require(
            IMycoJuryCaseV1(settlement_).juryRegistry() == address(this)
                && IMycoJuryCaseV1(settlement_).adjudicationThreshold() == threshold
        ); // settlement does not bind this registry policy
        settlement = settlement_;
        emit SettlementBound(settlement_);
    }

    function setReputationAuthority(address authority) external onlyGovernance {
        require(pendingAssignments == 0 && authority != address(0) && authority != address(this)); // unsafe authority change
        require(authority != governance && authority != settlement && authority != bondPenaltyRecipient); // authority role conflict
        require(providerIndexPlusOne[authority] == 0 && voteSignerOwner[authority] == address(0)); // provider identity conflict
        reputationAuthority = authority;
        emit ReputationAuthorityChanged(authority);
    }

    function transferGovernance(address nextGovernance) external onlyGovernance {
        require(pendingAssignments == 0 && nextGovernance != address(0) && nextGovernance != address(this));
        require(
            nextGovernance != reputationAuthority && nextGovernance != settlement
                && nextGovernance != bondPenaltyRecipient
        ); // governance role conflict
        require(providerIndexPlusOne[nextGovernance] == 0 && voteSignerOwner[nextGovernance] == address(0)); // provider identity conflict
        governance = nextGovernance;
    }

    function setProvider(Provider calldata value, uint64 sourceSequence, bytes32 sourceDigest)
        external
        onlyReputationAuthority
    {
        require(pendingAssignments == 0); // roster frozen for pending selection
        require(sourceSequence > providerSourceSequence[value.owner] && sourceDigest != bytes32(0)); // stale or uncommitted reputation source
        require(
            value.owner != address(0) && value.voteSigner != address(0) && value.owner != address(this)
                && value.voteSigner != address(this) && value.owner != value.voteSigner
                && value.operatorIdHash != bytes32(0) && value.peerIdHash != bytes32(0)
                && value.capabilityHash != bytes32(0)
        ); // malformed provider
        require(
            value.owner != governance && value.owner != reputationAuthority && value.voteSigner != governance
                && value.voteSigner != reputationAuthority
        ); // authority conflict
        require(value.owner != bondPenaltyRecipient && value.voteSigner != bondPenaltyRecipient); // penalty conflict
        if (settlement != address(0)) {
            require(value.owner != settlement && value.voteSigner != settlement); // settlement conflict
            require(IMycoJuryCaseV1(settlement).providerSigners(value.owner, value.voteSigner)); // owner did not authorize signer
        }
        uint256 indexPlusOne = providerIndexPlusOne[value.owner];
        address signerOwner = voteSignerOwner[value.voteSigner];
        require(signerOwner == address(0) || signerOwner == value.owner); // duplicate vote signer
        address operatorOwner = operatorIdOwner[value.operatorIdHash];
        require(operatorOwner == address(0) || operatorOwner == value.owner); // duplicate operator
        address peerOwner = peerIdOwner[value.peerIdHash];
        require(peerOwner == address(0) || peerOwner == value.owner); // duplicate peer
        address ownerAsSigner = voteSignerOwner[value.owner];
        require(ownerAsSigner == address(0) || ownerAsSigner == value.owner); // owner aliases another signer
        uint256 signerAsOwner = providerIndexPlusOne[value.voteSigner];
        require(signerAsOwner == 0 || providers[signerAsOwner - 1].owner == value.owner); // signer aliases another owner
        if (indexPlusOne == 0) {
            require(providers.length < MAX_PROVIDERS); // roster full
            providers.push(value);
            providerIndexPlusOne[value.owner] = providers.length;
        } else {
            Provider storage previous = providers[indexPlusOne - 1];
            if (previous.voteSigner != value.voteSigner) {
                delete voteSignerOwner[previous.voteSigner];
            }
            if (previous.operatorIdHash != value.operatorIdHash) {
                delete operatorIdOwner[previous.operatorIdHash];
            }
            if (previous.peerIdHash != value.peerIdHash) {
                delete peerIdOwner[previous.peerIdHash];
            }
            previous.owner = value.owner;
            previous.voteSigner = value.voteSigner;
            previous.operatorIdHash = value.operatorIdHash;
            previous.peerIdHash = value.peerIdHash;
            previous.capabilityHash = value.capabilityHash;
            previous.reputation = value.reputation;
            previous.active = value.active;
        }
        voteSignerOwner[value.voteSigner] = value.owner;
        operatorIdOwner[value.operatorIdHash] = value.owner;
        peerIdOwner[value.peerIdHash] = value.owner;
        providerSourceSequence[value.owner] = sourceSequence;
        providerSourceDigest[value.owner] = sourceDigest;
        ++rosterVersion;
        emit ProviderUpdated(
            value.owner,
            value.voteSigner,
            value.operatorIdHash,
            value.reputation,
            value.active,
            sourceSequence,
            sourceDigest,
            rosterVersion
        );
    }

    /// @notice Release a stale Provider slot and all of its live identity aliases.
    /// @dev Ready assignments retain their own immutable snapshot, while pending
    /// selections freeze every roster mutation through `pendingAssignments`.
    function removeProvider(address owner) external onlyReputationAuthority {
        require(pendingAssignments == 0); // roster frozen for pending selection
        uint256 indexPlusOne = providerIndexPlusOne[owner];
        require(indexPlusOne != 0); // unknown provider
        uint256 index = indexPlusOne - 1;
        Provider memory removed = providers[index];
        uint256 last = providers.length - 1;
        if (index != last) {
            Provider memory moved = providers[last];
            providers[index] = moved;
            providerIndexPlusOne[moved.owner] = index + 1;
        }
        providers.pop();
        delete providerIndexPlusOne[removed.owner];
        delete voteSignerOwner[removed.voteSigner];
        delete operatorIdOwner[removed.operatorIdHash];
        delete peerIdOwner[removed.peerIdHash];
        ++rosterVersion;
        emit ProviderRemoved(removed.owner, removed.voteSigner, removed.operatorIdHash, rosterVersion);
    }

    function providerCount() external view returns (uint256) {
        return providers.length;
    }

    function providerAt(uint256 index) external view returns (Provider memory) {
        return providers[index];
    }

    function providerForOwner(address owner) external view returns (Provider memory) {
        uint256 indexPlusOne = providerIndexPlusOne[owner];
        require(indexPlusOne != 0); // unknown provider
        return providers[indexPlusOne - 1];
    }

    function canFormJury() public view returns (bool) {
        return
            _canFormJuryFor(
                address(0), address(0), address(0), address(0), address(0), address(0), address(0), address(0)
            );
    }

    /// @notice Check that a channel still has a full jury after role exclusion.
    /// @dev Channel creation uses this before locking funds. The later case
    /// snapshot repeats the same role exclusions against settled case state.
    function canFormJuryFor(bytes32 channelId) external view returns (bool) {
        IMycoJuryCaseV1.CapacityChannelView memory slot = IMycoJuryCaseV1(settlement).channelInfo(channelId);
        if (slot.config.capacity == 0 || slot.closed) return false;
        (, address versionTreasury,) =
            IMycoJuryCaseV1(settlement).channelVersions(slot.config.channel, slot.config.pricingVersion);
        return _canFormJuryFor(
            slot.config.consumerOwner,
            slot.config.consumerKey,
            slot.config.providerOwner,
            slot.config.providerSigner,
            slot.config.relay,
            slot.config.relaySigner,
            slot.config.pool,
            versionTreasury
        );
    }

    function _canFormJuryFor(
        address consumerOwner,
        address consumerKey,
        address providerOwner,
        address providerSigner,
        address relay,
        address relaySigner,
        address pool,
        address treasury
    ) private view returns (bool) {
        bytes32[] memory operators = new bytes32[](jurySize);
        uint256 count;
        for (uint256 i; i < providers.length && count < jurySize; ++i) {
            Provider storage candidate = providers[i];
            if (
                !_eligible(candidate) || _containsOperator(operators, count, candidate.operatorIdHash)
                    || !_independentOfRoles(
                        candidate.owner,
                        consumerOwner,
                        consumerKey,
                        providerOwner,
                        providerSigner,
                        relay,
                        relaySigner,
                        pool,
                        treasury
                    )
                    || !_independentOfRoles(
                        candidate.voteSigner,
                        consumerOwner,
                        consumerKey,
                        providerOwner,
                        providerSigner,
                        relay,
                        relaySigner,
                        pool,
                        treasury
                    )
            ) continue;
            operators[count++] = candidate.operatorIdHash;
        }
        return count == jurySize;
    }

    function requestJury(bytes32 caseId) external onlySettlement {
        require(caseId != bytes32(0) && assignments[caseId].status == AssignmentStatus.None); // duplicate case
        _requestJury(caseId);
    }

    /// @notice Retry an unavailable/expired case after the mutable roster recovers.
    /// @dev Initial unavailability must never revert Settlement.openDispute and
    /// erase the user's dispute. Anyone may retry while the case remains open.
    function retryJury(bytes32 caseId) external returns (bool pending) {
        Assignment storage item = assignments[caseId];
        require(item.status == AssignmentStatus.Failed); // assignment is not retryable
        return _requestJury(caseId);
    }

    function _requestJury(bytes32 caseId) private returns (bool pending) {
        Assignment storage item = assignments[caseId];
        delete item.candidateIndexes;
        item.seed = bytes32(0);
        item.resultHash = bytes32(0);
        item.selectionBlock = 0;
        item.rosterVersion = rosterVersion;
        IMycoJuryCaseV1.SettlementView memory record = IMycoJuryCaseV1(settlement).settlementInfo(caseId);
        require(record.status == 2); // case not disputed
        require(block.timestamp < IMycoJuryCaseV1(settlement).disputeInfo(caseId).resolveAt); // adjudication expired
        bytes32[] memory operators = new bytes32[](providers.length);
        uint256 count;
        for (uint256 i; i < providers.length; ++i) {
            Provider storage candidate = providers[i];
            if (
                !_eligible(candidate) || _containsOperator(operators, count, candidate.operatorIdHash)
                    || !_independent(record, candidate.owner) || !_independent(record, candidate.voteSigner)
            ) continue;
            operators[count++] = candidate.operatorIdHash;
            item.candidateIndexes.push(uint16(i));
            // Preserve an immutable, case-scoped view of all candidates while
            // the future-block draw is pending. V10 reporting is owner-only, and
            // the settlement owner was already excluded by _independent.
            assignmentCandidateParties[caseId][candidate.owner] = true;
            assignmentCandidateParties[caseId][candidate.voteSigner] = true;
        }
        if (count < jurySize) {
            item.status = AssignmentStatus.Failed;
            emit JuryUnavailable(caseId, item.rosterVersion, count);
            return false;
        }
        item.selectionBlock = uint64(block.number + selectionDelayBlocks);
        item.status = AssignmentStatus.Pending;
        ++pendingAssignments;
        emit JuryRequested(
            caseId,
            item.rosterVersion,
            item.selectionBlock,
            keccak256(abi.encode(item.rosterVersion, item.candidateIndexes))
        );
        return true;
    }

    function finalizeJury(bytes32 caseId) external returns (bool ready) {
        Assignment storage item = assignments[caseId];
        require(item.status == AssignmentStatus.Pending && block.number > item.selectionBlock); // selection not ready
        IMycoJuryCaseV1.SettlementView memory record = IMycoJuryCaseV1(settlement).settlementInfo(caseId);
        require(
            record.status == SETTLEMENT_STATUS_DISPUTED
                && block.timestamp < IMycoJuryCaseV1(settlement).disputeInfo(caseId).resolveAt
        ); // case closed or adjudication expired
        require(block.number <= uint256(item.selectionBlock) + 256 && item.rosterVersion == rosterVersion); // stale selection
        bytes32 selectedBlockHash = blockhash(item.selectionBlock);
        require(selectedBlockHash != bytes32(0)); // missing entropy
        bytes32 seed = keccak256(
            abi.encode(address(this), block.chainid, settlement, caseId, item.rosterVersion, selectedBlockHash)
        );
        address[] memory owners = new address[](jurySize);
        address[] memory signers = new address[](jurySize);
        bytes32[] memory operators = new bytes32[](jurySize);
        bytes32[] memory peers = new bytes32[](jurySize);
        bytes32[] memory capabilities = new bytes32[](jurySize);
        uint64[] memory reputations = new uint64[](jurySize);
        uint256 eligibleCount = item.candidateIndexes.length;
        uint256[] memory eligible = new uint256[](eligibleCount);
        for (uint256 i; i < eligibleCount; ++i) {
            eligible[i] = item.candidateIndexes[i];
        }
        for (uint256 i; i < eligibleCount; ++i) {
            uint256 other = i + (uint256(keccak256(abi.encode(seed, i))) % (eligibleCount - i));
            (eligible[i], eligible[other]) = (eligible[other], eligible[i]);
        }
        uint256 count;
        for (uint256 i; i < eligibleCount && count < jurySize; ++i) {
            Provider storage candidate = providers[eligible[i]];
            if (_containsOperator(operators, count, candidate.operatorIdHash)) continue;
            owners[count] = candidate.owner;
            signers[count] = candidate.voteSigner;
            operators[count] = candidate.operatorIdHash;
            peers[count] = candidate.peerIdHash;
            capabilities[count] = candidate.capabilityHash;
            reputations[count] = candidate.reputation;
            ++count;
        }
        item.seed = seed;
        --pendingAssignments;
        if (count != jurySize) {
            item.status = AssignmentStatus.Failed;
            emit JuryAssignmentFailed(caseId, seed);
            return false;
        }
        bytes32 resultHash = keccak256(
            abi.encode(
                ASSIGNMENT_TYPEHASH,
                address(this),
                block.chainid,
                settlement,
                caseId,
                item.rosterVersion,
                seed,
                minimumReputation,
                jurySize,
                threshold,
                keccak256(abi.encode(owners)),
                keccak256(abi.encode(signers)),
                keccak256(abi.encode(operators)),
                keccak256(abi.encode(peers)),
                keccak256(abi.encode(capabilities)),
                keccak256(abi.encode(reputations))
            )
        );
        item.resultHash = resultHash;
        item.status = AssignmentStatus.Ready;
        for (uint256 i; i < count; ++i) {
            item.owners.push(owners[i]);
            item.voteSigners.push(signers[i]);
            item.operatorIdHashes.push(operators[i]);
            item.peerIdHashes.push(peers[i]);
            item.capabilityHashes.push(capabilities[i]);
            item.reputations.push(reputations[i]);
            assignedParties[caseId][owners[i]] = true;
            assignedParties[caseId][signers[i]] = true;
            assignedVoteSigners[caseId][signers[i]] = true;
        }
        emit JuryAssigned(caseId, resultHash, seed, owners, signers, operators);
        return true;
    }

    function expireJury(bytes32 caseId) external {
        Assignment storage item = assignments[caseId];
        require(item.status == AssignmentStatus.Pending); // assignment is not pending
        IMycoJuryCaseV1.SettlementView memory record = IMycoJuryCaseV1(settlement).settlementInfo(caseId);
        bool caseClosed = record.status != SETTLEMENT_STATUS_DISPUTED
            || block.timestamp >= IMycoJuryCaseV1(settlement).disputeInfo(caseId).resolveAt;
        require(caseClosed || block.number > uint256(item.selectionBlock) + 256); // assignment not expired
        item.status = AssignmentStatus.Failed;
        --pendingAssignments;
        emit JuryAssignmentFailed(caseId, bytes32(0));
    }

    function assignmentHash(bytes32 caseId) external view returns (bytes32) {
        Assignment storage item = assignments[caseId];
        return item.status == AssignmentStatus.Ready ? item.resultHash : bytes32(0);
    }

    function isVoteSigner(bytes32 caseId, address account) external view returns (bool) {
        return assignedVoteSigners[caseId][account];
    }

    function isJuryParty(bytes32 caseId, address account) external view returns (bool) {
        // Expose both live Provider identities and the immutable case snapshot
        // for runtime/audit consumers. This is no longer a reporting gate:
        // MycoSettlementV10 permits only the settled consumer owner to report.
        return providerIndexPlusOne[account] != 0 || voteSignerOwner[account] != address(0)
            || assignedParties[caseId][account] || assignmentCandidateParties[caseId][account];
    }

    function assignmentInfo(bytes32 caseId)
        external
        view
        returns (
            AssignmentStatus status,
            uint64 selectionBlock,
            uint64 version,
            bytes32 seed,
            bytes32 resultHash,
            address[] memory owners,
            address[] memory voteSigners,
            bytes32[] memory operatorIdHashes
        )
    {
        Assignment storage item = assignments[caseId];
        return (
            item.status,
            item.selectionBlock,
            item.rosterVersion,
            item.seed,
            item.resultHash,
            item.owners,
            item.voteSigners,
            item.operatorIdHashes
        );
    }

    function assignmentProviderEvidence(bytes32 caseId)
        external
        view
        returns (bytes32[] memory peerIdHashes, bytes32[] memory capabilityHashes, uint64[] memory reputations)
    {
        Assignment storage item = assignments[caseId];
        return (item.peerIdHashes, item.capabilityHashes, item.reputations);
    }

    /// @notice Return the immutable assignment snapshot for one selected signer.
    /// @dev The live roster may change after selection, so jurors must validate
    /// tasks against this snapshot rather than providerForOwner.
    function assignmentProviderForSigner(bytes32 caseId, address voteSigner)
        external
        view
        returns (
            bool found,
            address owner,
            bytes32 operatorIdHash,
            bytes32 peerIdHash,
            bytes32 capabilityHash,
            uint64 reputation
        )
    {
        Assignment storage item = assignments[caseId];
        if (item.status != AssignmentStatus.Ready) {
            return (false, address(0), bytes32(0), bytes32(0), bytes32(0), 0);
        }
        for (uint256 i; i < item.voteSigners.length; ++i) {
            if (item.voteSigners[i] == voteSigner) {
                return (
                    true,
                    item.owners[i],
                    item.operatorIdHashes[i],
                    item.peerIdHashes[i],
                    item.capabilityHashes[i],
                    item.reputations[i]
                );
            }
        }
        return (false, address(0), bytes32(0), bytes32(0), bytes32(0), 0);
    }

    function _eligible(Provider storage candidate) private view returns (bool) {
        return candidate.active && candidate.reputation >= minimumReputation && candidate.owner != governance
            && candidate.owner != reputationAuthority && candidate.owner != settlement
            && candidate.voteSigner != governance && candidate.voteSigner != reputationAuthority
            && candidate.voteSigner != settlement && candidate.owner != bondPenaltyRecipient
            && candidate.voteSigner != bondPenaltyRecipient
            && IMycoJuryCaseV1(settlement).providerSigners(candidate.owner, candidate.voteSigner);
    }

    function _independent(IMycoJuryCaseV1.SettlementView memory record, address account) private pure returns (bool) {
        return account != address(0) && account != record.owner && account != record.key && account != record.provider
            && account != record.providerSigner && account != record.relay && account != record.relaySigner
            && account != record.pool && account != record.treasury;
    }

    function _independentOfRoles(
        address account,
        address consumerOwner,
        address consumerKey,
        address providerOwner,
        address providerSigner,
        address relay,
        address relaySigner,
        address pool,
        address treasury
    ) private pure returns (bool) {
        return account != consumerOwner && account != consumerKey && account != providerOwner
            && account != providerSigner && account != relay && account != relaySigner && account != pool
            && account != treasury;
    }

    function _containsOperator(bytes32[] memory values, uint256 length, bytes32 value) private pure returns (bool) {
        for (uint256 i; i < length; ++i) {
            if (values[i] == value) return true;
        }
        return false;
    }
}
