// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";

interface IMycoERC20V11 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice The jury registry is the only source of juror selection.  Reputation
/// hooks are notifications: a failing registry can never block a payout.
interface IProviderJuryRegistryV11 {
    function threshold() external view returns (uint16);
    function requestJury(bytes32 caseId, address providerOwner) external;
    function assignmentHash(bytes32 caseId) external view returns (bytes32);
    function isVoteSigner(bytes32 caseId, address account) external view returns (bool);
    function recordRelease(address providerOwner, address consumerOwner, uint256 fee) external;
    function recordConfirmedFraud(address providerOwner) external;
}

/// @notice V11: Consumer-custodied deposits, no Provider stake, free Relay probes.
/// @dev Economics, per settlement:
/// * the Consumer's deposit pays each request; the fee stays escrowed for the
///   dispute window, so a confirmed fraud is refunded from that escrow;
/// * Providers post no stake.  A share of released earnings is held back for
///   a bounded period and is the source of penalties and reporter bounties;
/// * each Provider's unreleased exposure is capped by an allowance that grows
///   only with cleanly released volume, and resets on confirmed fraud;
/// * a Relay can void probes it sent from a pre-committed, hidden key set, so
///   probes look like paid traffic but the Provider bears their cost.
/// Upgradeable by a single admin with no delay (early-network choice).
contract MycoSettlementV11 is MycoUUPSUpgradeable {
    uint16 public constant BPS = 10_000;
    uint256 public constant MAX_BATCH_SIZE = 32;
    uint256 public constant MAX_AUTHORIZATION_TTL = 3 hours;
    uint256 public constant PROTOCOL_VERSION = 11;
    uint256 public constant HOLDBACK_BUCKETS = 8;
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant PAYMENT_AUTHORIZATION_TYPEHASH = keccak256(
        "PaymentAuthorization(bytes32 requestId,bytes32 requestHash,address key,address providerSigner,address relaySigner,uint256 maxFee,uint64 issuedAt,uint64 executeBy,uint64 deadline)"
    );
    bytes32 public constant USAGE_RECEIPT_TYPEHASH = keccak256(
        "UsageReceipt(bytes32 authorizationHash,bytes32 dispatchHash,bytes32 responseHash,uint256 inputTokens,uint256 outputTokens,uint256 actualFee)"
    );
    bytes32 public constant DISPATCH_TYPEHASH = keccak256("RelayDispatch(bytes32 authorizationHash)");
    bytes32 private constant DISPUTE_VOTE_TYPEHASH = keccak256(
        "DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)"
    );

    struct Params {
        uint64 disputeWindow;
        uint64 arbitrationTimeout;
        uint64 consumerWithdrawalDelay;
        uint256 reporterBond;
        uint16 relayBps;
        uint16 holdbackBps;
        uint64 holdbackPeriod;
        uint256 baseExposureCap;
        uint16 exposureGrowthBps;
        uint256 maxExposureCap;
        uint16 slashBps;
        uint256 slashCap;
        uint16 reporterBountyBps;
        uint16 probeVoidsPerDay;
        address penaltyRecipient;
    }

    struct KeyGrant { address owner; uint256 maxPerRequest; uint64 validUntil; bool active; }
    struct Withdrawal { uint256 amount; uint64 availableAt; }

    struct PaymentAuthorization {
        bytes32 requestId; bytes32 requestHash; address key; address providerSigner; address relaySigner;
        uint256 maxFee; uint64 issuedAt; uint64 executeBy; uint64 deadline;
    }
    struct UsageReceipt {
        bytes32 authorizationHash; bytes32 dispatchHash; bytes32 responseHash;
        uint256 inputTokens; uint256 outputTokens; uint256 actualFee;
    }
    struct SignedReceipt {
        PaymentAuthorization authorization; UsageReceipt receipt;
        bytes keySignature; bytes providerSignature; bytes relaySignature;
    }

    enum Status { None, Pending, Disputed, Released, Confirmed, Dismissed, TimedOut, JuryUnavailable, Voided }

    struct Settlement {
        address owner; address key;
        address provider; address providerSigner;
        address relay; address relaySigner;
        bytes32 requestId; bytes32 requestHash; bytes32 authorizationHash; bytes32 responseHash;
        uint256 fee;
        uint64 issuedAt; uint64 settledAt; uint64 releaseAt;
        Status status;
    }

    struct Dispute {
        uint64 openedAt; uint64 resolveAt; uint16 dismissVotes;
        uint256 totalBond; bytes32 winningReportId; uint256 penalty; uint256 bounty;
    }
    struct Report { address reporter; bytes32 evidenceHash; bool bondClaimed; }

    struct DisputeVotePermit {
        bytes32 assignmentHash; bool confirmed; bytes32 reportId; bytes32 decisionHash;
        uint256 nonce; uint64 deadline; bytes signature;
    }

    struct HoldbackBucket { uint64 day; uint256 amount; }
    struct ProbeRoot { bytes32 root; uint64 committedAt; }

    // ---- storage (append-only across upgrades) ----
    IMycoERC20V11 public stablecoin;
    IProviderJuryRegistryV11 public juryRegistry;
    Params public params;
    bool private entered;

    mapping(address => uint256) public availableBalance;
    mapping(address => uint256) public claimableBalance;
    mapping(address => KeyGrant) public keyGrants;
    mapping(address => Withdrawal) public withdrawals;
    mapping(address => address) public providerSignerOwner;
    mapping(address => address) public relaySignerOwner;

    mapping(bytes32 => bool) public settled;
    mapping(bytes32 => Settlement) private settlements;
    mapping(bytes32 => Dispute) private disputes;
    mapping(bytes32 => mapping(bytes32 => Report)) public reports;
    mapping(bytes32 => mapping(address => uint8)) public disputeVotes;
    mapping(bytes32 => mapping(address => uint256)) public adjudicatorNonce;
    mapping(bytes32 => mapping(bytes32 => uint16)) public confirmationVotes;

    mapping(address => uint256) public pendingExposure;
    mapping(address => uint256) public cleanVolume;
    mapping(address => HoldbackBucket[HOLDBACK_BUCKETS]) private holdbackBuckets;
    mapping(address => uint256) public holdbackBalance;

    mapping(address => ProbeRoot[]) private probeRoots;
    mapping(address => mapping(address => mapping(uint64 => uint16))) public probeVoidsByDay;

    uint256 public totalAvailable;
    uint256 public totalClaimable;
    uint256 public totalPendingFees;
    uint256 public totalHoldback;
    uint256 public totalReporterBonds;

    uint256[40] private __gap;

    event ParamsUpdated(Params params);
    event Deposited(address indexed account, uint256 amount);
    event WithdrawalRequested(address indexed account, uint256 amount, uint256 availableAt);
    event WithdrawalCancelled(address indexed account);
    event Withdrawn(address indexed account, uint256 amount);
    event KeyRegistered(address indexed owner, address indexed key, uint256 maxPerRequest, uint256 validUntil);
    event KeyRevoked(address indexed owner, address indexed key);
    event ProviderSignerAuthorized(address indexed provider, address indexed signer);
    event ProviderSignerRevoked(address indexed provider, address indexed signer);
    event RelaySignerAuthorized(address indexed relay, address indexed signer);
    event RelaySignerRevoked(address indexed relay, address indexed signer);
    event ReceiptEscrowed(
        bytes32 indexed settlementKey, bytes32 indexed requestId, address indexed owner,
        address provider, uint256 grossFee, uint256 releaseAt
    );
    event SettlementReleased(bytes32 indexed settlementKey, Status status);
    event HoldbackAdded(address indexed provider, uint256 amount, uint64 day);
    event HoldbackMatured(address indexed provider, uint256 amount);
    event ProbeKeysCommitted(address indexed relay, uint256 indexed index, bytes32 root);
    event ProbeVoided(bytes32 indexed settlementKey, address indexed relay, address indexed provider);
    event DisputeOpened(bytes32 indexed settlementKey, uint256 resolveAt);
    event EvidenceSubmitted(
        bytes32 indexed settlementKey, bytes32 indexed reportId, address indexed reporter, bytes32 evidenceHash, uint256 bond
    );
    event DisputeBondReturned(bytes32 indexed settlementKey, bytes32 indexed reportId, address indexed reporter);
    event DisputeVote(
        bytes32 indexed settlementKey, address indexed adjudicator, bool confirmed, bytes32 reportId, bytes32 decisionHash
    );
    event DisputeResolved(bytes32 indexed settlementKey, Status status, uint256 penalty, uint256 bounty);
    event PayoutClaimed(address indexed account, uint256 amount);
    event RegistryHookFailed(address indexed provider, bytes4 selector);

    modifier nonReentrant() {
        require(!entered); // reentrant
        entered = true;
        _;
        entered = false;
    }

    constructor() {}

    function initialize(address stablecoin_, address juryRegistry_, address admin_, Params calldata params_)
        external
        reinitializer(1)
    {
        require(stablecoin_ != address(0) && stablecoin_.code.length > 0); // bad stablecoin
        require(juryRegistry_ != address(0) && juryRegistry_.code.length > 0); // bad jury registry
        require(IProviderJuryRegistryV11(juryRegistry_).threshold() >= 2); // bad jury threshold
        _initializeAdmin(admin_);
        stablecoin = IMycoERC20V11(stablecoin_);
        juryRegistry = IProviderJuryRegistryV11(juryRegistry_);
        _setParams(params_);
    }

    // ---------------- admin ----------------

    function setParams(Params calldata params_) external onlyProxy onlyAdmin {
        _setParams(params_);
    }

    function setJuryRegistry(address juryRegistry_) external onlyProxy onlyAdmin {
        require(juryRegistry_ != address(0) && juryRegistry_.code.length > 0); // bad jury registry
        require(IProviderJuryRegistryV11(juryRegistry_).threshold() >= 2); // bad jury threshold
        juryRegistry = IProviderJuryRegistryV11(juryRegistry_);
    }

    // ---------------- views ----------------

    function settlementInfo(bytes32 key) external view returns (Settlement memory) { return settlements[key]; }

    /// @notice The parties a jury must exclude, and whether the case is open.
    function caseParties(bytes32 key) external view returns (
        address owner, address consumerKey, address provider, address providerSigner,
        address relay, address relaySigner, bool disputed
    ) {
        Settlement storage record = settlements[key];
        return (record.owner, record.key, record.provider, record.providerSigner,
            record.relay, record.relaySigner, record.status == Status.Disputed);
    }
    function disputeInfo(bytes32 key) external view returns (Dispute memory) { return disputes[key]; }
    function probeRoot(address relay, uint256 index) external view returns (ProbeRoot memory) { return probeRoots[relay][index]; }
    function probeRootCount(address relay) external view returns (uint256) { return probeRoots[relay].length; }
    function holdbackBucket(address provider, uint256 index) external view returns (HoldbackBucket memory) {
        return holdbackBuckets[provider][index];
    }

    /// @notice With supported ERC-20s, the contract balance must cover this sum.
    function stableLiabilities() external view returns (uint256) {
        return totalAvailable + totalClaimable + totalPendingFees + totalHoldback + totalReporterBonds;
    }

    /// @notice Unreleased fees a Provider may carry; grows only with clean volume.
    function exposureCap(address provider) public view returns (uint256 cap) {
        cap = params.baseExposureCap + _portion(cleanVolume[provider], params.exposureGrowthBps);
        if (cap > params.maxExposureCap) cap = params.maxExposureCap;
    }

    function settlementKeyFor(address key, bytes32 requestId) public pure returns (bytes32) {
        return keccak256(abi.encode(key, requestId));
    }
    function authorizationStructHash(PaymentAuthorization calldata a) public pure returns (bytes32) {
        return keccak256(abi.encode(PAYMENT_AUTHORIZATION_TYPEHASH, a));
    }
    function authorizationDigest(PaymentAuthorization calldata a) public view returns (bytes32) {
        return _typedDataHash(authorizationStructHash(a));
    }
    function dispatchStructHash(bytes32 authorizationHash) public pure returns (bytes32) {
        return keccak256(abi.encode(DISPATCH_TYPEHASH, authorizationHash));
    }
    function dispatchDigest(bytes32 authorizationHash) external view returns (bytes32) {
        return _typedDataHash(dispatchStructHash(authorizationHash));
    }
    function receiptStructHash(UsageReceipt calldata r) public pure returns (bytes32) {
        return keccak256(abi.encode(USAGE_RECEIPT_TYPEHASH, r));
    }
    function receiptDigest(UsageReceipt calldata r) public view returns (bytes32) {
        return _typedDataHash(receiptStructHash(r));
    }
    function reportIdFor(bytes32 key, address reporter, bytes32 evidenceHash) public pure returns (bytes32) {
        return keccak256(abi.encode(key, reporter, evidenceHash));
    }
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes("MycoMesh Settlement")), keccak256(bytes("11")), block.chainid, address(this)
        ));
    }

    // ---------------- Consumer funds ----------------

    function deposit(uint256 amount) external onlyProxy nonReentrant {
        require(amount > 0); // zero amount
        _takeExact(msg.sender, amount);
        availableBalance[msg.sender] += amount;
        totalAvailable += amount;
        emit Deposited(msg.sender, amount);
    }

    function registerKey(address key, uint256 maxPerRequest, uint64 validUntil) external onlyProxy nonReentrant {
        require(key != address(0) && key.code.length == 0 && key != msg.sender && key != address(this)); // bad key
        require(maxPerRequest > 0); // zero key limit
        require(validUntil == 0 || validUntil > block.timestamp); // key expired
        require(keyGrants[key].owner == address(0) || keyGrants[key].owner == msg.sender); // key owned
        keyGrants[key] = KeyGrant(msg.sender, maxPerRequest, validUntil, true);
        emit KeyRegistered(msg.sender, key, maxPerRequest, validUntil);
    }

    function revokeKey(address key) external onlyProxy nonReentrant {
        KeyGrant storage grant = keyGrants[key];
        require(grant.owner == msg.sender && grant.active); // not an active own key
        grant.active = false;
        emit KeyRevoked(msg.sender, key);
    }

    function requestWithdrawal(uint256 amount) external onlyProxy nonReentrant {
        require(amount > 0 && amount <= availableBalance[msg.sender]); // bad withdrawal
        uint64 availableAt = _future(params.consumerWithdrawalDelay);
        withdrawals[msg.sender] = Withdrawal(amount, availableAt);
        emit WithdrawalRequested(msg.sender, amount, availableAt);
    }

    function cancelWithdrawal() external onlyProxy nonReentrant {
        require(withdrawals[msg.sender].amount > 0); // no withdrawal
        delete withdrawals[msg.sender];
        emit WithdrawalCancelled(msg.sender);
    }

    function withdraw() external onlyProxy nonReentrant {
        Withdrawal memory request = withdrawals[msg.sender];
        require(request.amount > 0 && block.timestamp >= request.availableAt); // withdrawal pending
        require(availableBalance[msg.sender] >= request.amount); // balance changed
        delete withdrawals[msg.sender];
        availableBalance[msg.sender] -= request.amount;
        totalAvailable -= request.amount;
        _sendExact(msg.sender, request.amount);
        emit Withdrawn(msg.sender, request.amount);
    }

    function claim() external onlyProxy nonReentrant returns (uint256 amount) {
        amount = claimableBalance[msg.sender];
        require(amount > 0); // no claimable balance
        claimableBalance[msg.sender] = 0;
        totalClaimable -= amount;
        _sendExact(msg.sender, amount);
        emit PayoutClaimed(msg.sender, amount);
    }

    // ---------------- Provider and Relay signers ----------------

    function authorizeProviderSigner(address signer) external onlyProxy nonReentrant {
        _requireSigner(signer);
        require(providerSignerOwner[signer] == address(0) && relaySignerOwner[signer] == address(0)); // signer bound
        providerSignerOwner[signer] = msg.sender;
        emit ProviderSignerAuthorized(msg.sender, signer);
    }

    function revokeProviderSigner(address signer) external onlyProxy nonReentrant {
        require(providerSignerOwner[signer] == msg.sender); // not own signer
        providerSignerOwner[signer] = address(0);
        emit ProviderSignerRevoked(msg.sender, signer);
    }

    function authorizeRelaySigner(address signer) external onlyProxy nonReentrant {
        _requireSigner(signer);
        require(relaySignerOwner[signer] == address(0) && providerSignerOwner[signer] == address(0)); // signer bound
        relaySignerOwner[signer] = msg.sender;
        emit RelaySignerAuthorized(msg.sender, signer);
    }

    function revokeRelaySigner(address signer) external onlyProxy nonReentrant {
        require(relaySignerOwner[signer] == msg.sender); // not own signer
        relaySignerOwner[signer] = address(0);
        emit RelaySignerRevoked(msg.sender, signer);
    }

    // ---------------- settlement ----------------

    function settleReceipt(SignedReceipt calldata input) external onlyProxy nonReentrant {
        _settle(input);
    }

    function settleBatch(SignedReceipt[] calldata inputs) external onlyProxy nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE); // bad batch length
        for (uint256 i; i < inputs.length; ++i) _settle(inputs[i]);
    }

    function release(bytes32 key) external onlyProxy nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(block.timestamp >= record.releaseAt); // release pending
        _release(key, record, Status.Released);
    }

    /// @notice Move a Provider's matured holdback to its claimable balance.
    function releaseHoldback(address provider) external onlyProxy nonReentrant {
        _matureHoldback(provider);
    }

    // ---------------- probes ----------------

    /// @notice Commit a Merkle root of probe keys before using them.
    /// @dev Leaves are keccak256(abi.encode(key)); pairs are hashed sorted.
    function commitProbeKeys(bytes32 root) external onlyProxy nonReentrant returns (uint256 index) {
        require(root != bytes32(0)); // empty root
        index = probeRoots[msg.sender].length;
        probeRoots[msg.sender].push(ProbeRoot(root, uint64(block.timestamp)));
        emit ProbeKeysCommitted(msg.sender, index, root);
    }

    /// @notice Void a probe the caller's Relay dispatched: the probe key is
    /// refunded and the Provider is not paid, so the Provider bears the cost.
    function voidProbe(bytes32 key, uint256 rootIndex, bytes32[] calldata proof) external onlyProxy nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending && block.timestamp < record.releaseAt); // not voidable
        require(record.relay == msg.sender); // not the dispatching Relay
        ProbeRoot memory committed = probeRoots[msg.sender][rootIndex];
        require(committed.committedAt < record.issuedAt); // probe key committed too late
        require(_verifyProof(proof, committed.root, keccak256(abi.encode(record.key)))); // not a committed probe key
        uint64 day = uint64(block.timestamp / 1 days);
        uint16 used = probeVoidsByDay[msg.sender][record.provider][day];
        require(used < params.probeVoidsPerDay); // daily probe allowance exhausted
        probeVoidsByDay[msg.sender][record.provider][day] = used + 1;
        record.status = Status.Voided;
        _refund(record);
        emit ProbeVoided(key, msg.sender, record.provider);
    }

    // ---------------- disputes ----------------

    function openDispute(bytes32 key, bytes32 evidenceHash) external onlyProxy nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(msg.sender == record.owner); // only settlement owner
        require(block.timestamp < record.releaseAt); // dispute window closed
        require(evidenceHash != bytes32(0)); // empty evidence
        require(record.releaseAt <= type(uint64).max - params.arbitrationTimeout); // timestamp overflow
        Dispute storage dispute = disputes[key];
        record.status = Status.Disputed;
        dispute.openedAt = uint64(block.timestamp);
        dispute.resolveAt = record.releaseAt + params.arbitrationTimeout;
        bytes32 reportId = reportIdFor(key, msg.sender, evidenceHash);
        reports[key][reportId] = Report(msg.sender, evidenceHash, false);
        dispute.totalBond = params.reporterBond;
        totalReporterBonds += params.reporterBond;
        if (params.reporterBond > 0) _takeExact(msg.sender, params.reporterBond);
        emit EvidenceSubmitted(key, reportId, msg.sender, evidenceHash, params.reporterBond);
        juryRegistry.requestJury(key, record.provider);
        emit DisputeOpened(key, dispute.resolveAt);
    }

    /// @notice Submit one consistent quorum of selected Provider-AI votes.
    function voteDisputeBySig(bytes32 key, DisputeVotePermit[] calldata permits) external onlyProxy nonReentrant {
        uint16 threshold = juryRegistry.threshold();
        require(permits.length == threshold); // bad vote batch
        bytes32 assignment = juryRegistry.assignmentHash(key);
        require(assignment != bytes32(0) && permits[0].assignmentHash == assignment); // wrong jury assignment
        Settlement storage record = settlements[key];
        Dispute storage dispute = disputes[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp < dispute.resolveAt); // adjudication expired
        bool confirmed = permits[0].confirmed;
        bytes32 reportId = permits[0].reportId;
        bytes32 decisionHash = permits[0].decisionHash;
        require(decisionHash != bytes32(0)); // empty decision
        if (confirmed) require(reports[key][reportId].reporter != address(0)); // unknown report
        else require(reportId == bytes32(0)); // unexpected report
        for (uint256 i; i < permits.length; ++i) {
            DisputeVotePermit calldata permit = permits[i];
            require(permit.assignmentHash == assignment && permit.confirmed == confirmed
                && permit.reportId == reportId && permit.decisionHash == decisionHash); // inconsistent verdict
            _recordVote(key, record, permit);
        }
        if (confirmed) confirmationVotes[key][reportId] += threshold;
        else dispute.dismissVotes += threshold;
        if (confirmed) {
            dispute.winningReportId = reportId;
            _confirm(key, record, dispute);
        } else {
            _dismiss(key, record, dispute);
        }
    }

    function _recordVote(bytes32 key, Settlement storage record, DisputeVotePermit calldata permit) internal {
        require(permit.deadline >= block.timestamp); // vote authorization expired
        address judge = _recover(_typedDataHash(keccak256(abi.encode(DISPUTE_VOTE_TYPEHASH, key,
            permit.assignmentHash, permit.confirmed, permit.reportId, permit.decisionHash,
            permit.nonce, permit.deadline))), permit.signature);
        require(judge != address(0) && permit.nonce == adjudicatorNonce[key][judge]++); // bad or replayed vote
        require(juryRegistry.isVoteSigner(key, judge) && _independent(record, judge)); // not a selected independent juror
        require(disputeVotes[key][judge] == 0); // already voted
        disputeVotes[key][judge] = permit.confirmed ? 1 : 2;
        emit DisputeVote(key, judge, permit.confirmed, permit.reportId, permit.decisionHash);
    }

    function claimDisputeBond(bytes32 key, bytes32 reportId) external onlyProxy nonReentrant {
        Status status = settlements[key].status;
        require(status == Status.Confirmed || status == Status.TimedOut || status == Status.JuryUnavailable); // bond not refundable
        Report storage report = reports[key][reportId];
        require(report.reporter != address(0) && !report.bondClaimed); // no refundable bond
        report.bondClaimed = true;
        uint256 bond = disputes[key].totalBond;
        totalReporterBonds -= bond;
        _credit(report.reporter, bond);
        emit DisputeBondReturned(key, reportId, report.reporter);
    }

    /// @notice Silence is not a verdict: an assigned but silent jury releases,
    /// a case that never got a jury refunds.  No penalty either way.
    function resolveTimedOutDispute(bytes32 key) external onlyProxy nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp >= disputes[key].resolveAt); // adjudication pending
        Status status = Status.TimedOut;
        if (juryRegistry.assignmentHash(key) == bytes32(0)) {
            status = Status.JuryUnavailable;
            record.status = status;
            _refund(record);
        } else {
            _release(key, record, status);
        }
        emit DisputeResolved(key, status, 0, 0);
    }

    // ---------------- internals ----------------

    function _settle(SignedReceipt calldata input) internal {
        PaymentAuthorization calldata a = input.authorization;
        UsageReceipt calldata r = input.receipt;
        require(a.requestId != bytes32(0) && a.requestHash != bytes32(0)); // bad request
        KeyGrant memory grant = keyGrants[a.key];
        require(grant.owner != address(0) && grant.active && a.maxFee <= grant.maxPerRequest
            && (grant.validUntil == 0 || grant.validUntil >= a.deadline)); // key grant
        require(a.issuedAt <= block.timestamp && a.executeBy >= a.issuedAt && a.deadline > a.executeBy
            && a.deadline >= block.timestamp && a.deadline - a.issuedAt <= MAX_AUTHORIZATION_TTL); // authorization window
        address provider = providerSignerOwner[a.providerSigner];
        address relay = relaySignerOwner[a.relaySigner];
        require(provider != address(0) && relay != address(0)); // unbound signer
        bytes32 authHash = authorizationStructHash(a);
        bytes32 dispatchHash = dispatchStructHash(authHash);
        require(r.authorizationHash == authHash && r.dispatchHash == dispatchHash && r.responseHash != bytes32(0)); // receipt binding
        require(_recover(_typedDataHash(authHash), input.keySignature) == a.key); // bad key signature
        require(_recover(_typedDataHash(dispatchHash), input.relaySignature) == a.relaySigner); // bad dispatch signature
        require(_recover(receiptDigest(r), input.providerSignature) == a.providerSigner); // bad provider signature
        uint256 fee = r.actualFee;
        require(fee > 0 && fee <= a.maxFee); // fee exceeds authorization
        bytes32 key = settlementKeyFor(a.key, a.requestId);
        require(!settled[key]); // request settled
        require(pendingExposure[provider] + fee <= exposureCap(provider)); // provider exposure cap
        require(availableBalance[grant.owner] >= fee); // insufficient consumer deposit
        availableBalance[grant.owner] -= fee;
        totalAvailable -= fee;
        totalPendingFees += fee;
        pendingExposure[provider] += fee;
        settled[key] = true;
        Settlement storage record = settlements[key];
        record.owner = grant.owner; record.key = a.key;
        record.provider = provider; record.providerSigner = a.providerSigner;
        record.relay = relay; record.relaySigner = a.relaySigner;
        record.requestId = a.requestId; record.requestHash = a.requestHash;
        record.authorizationHash = authHash; record.responseHash = r.responseHash;
        record.fee = fee;
        record.issuedAt = a.issuedAt; record.settledAt = uint64(block.timestamp);
        record.releaseAt = _future(params.disputeWindow);
        record.status = Status.Pending;
        emit ReceiptEscrowed(key, a.requestId, grant.owner, provider, fee, record.releaseAt);
    }

    function _release(bytes32 key, Settlement storage record, Status status) internal {
        record.status = status;
        uint256 fee = record.fee;
        totalPendingFees -= fee;
        pendingExposure[record.provider] -= fee;
        uint256 relayAmount = _portion(fee, params.relayBps);
        uint256 providerGross = fee - relayAmount;
        uint256 held = _portion(providerGross, params.holdbackBps);
        _credit(record.relay, relayAmount);
        _credit(record.provider, providerGross - held);
        if (held > 0) _addHoldback(record.provider, held);
        cleanVolume[record.provider] += fee;
        _notifyRelease(record.provider, record.owner, fee);
        emit SettlementReleased(key, status);
    }

    function _refund(Settlement storage record) internal {
        uint256 fee = record.fee;
        totalPendingFees -= fee;
        pendingExposure[record.provider] -= fee;
        availableBalance[record.owner] += fee;
        totalAvailable += fee;
    }

    function _confirm(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        record.status = Status.Confirmed;
        _refund(record);
        uint256 penalty = _portion(record.fee, params.slashBps);
        if (penalty > params.slashCap) penalty = params.slashCap;
        penalty = _takeHoldback(record.provider, penalty);
        uint256 bounty = _portion(penalty, params.reporterBountyBps);
        dispute.penalty = penalty;
        dispute.bounty = bounty;
        _credit(reports[key][dispute.winningReportId].reporter, bounty);
        _credit(params.penaltyRecipient, penalty - bounty);
        // Earned trust restarts from the base allowance.
        cleanVolume[record.provider] = 0;
        _notifyFraud(record.provider);
        emit DisputeResolved(key, Status.Confirmed, penalty, bounty);
    }

    function _dismiss(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        _release(key, record, Status.Dismissed);
        totalReporterBonds -= dispute.totalBond;
        _credit(params.penaltyRecipient, dispute.totalBond);
        emit DisputeResolved(key, Status.Dismissed, 0, 0);
    }

    function _addHoldback(address provider, uint256 amount) internal {
        uint64 day = uint64(block.timestamp / 1 days);
        HoldbackBucket storage bucket = holdbackBuckets[provider][day % HOLDBACK_BUCKETS];
        if (bucket.day != day) {
            // A reused slot is at least HOLDBACK_BUCKETS days old, beyond the
            // maximum holdback period, so its balance has matured.
            if (bucket.amount > 0) _payHoldback(provider, bucket.amount);
            bucket.day = day;
            bucket.amount = 0;
        }
        bucket.amount += amount;
        holdbackBalance[provider] += amount;
        totalHoldback += amount;
        emit HoldbackAdded(provider, amount, day);
    }

    function _matureHoldback(address provider) internal {
        uint256 matured;
        for (uint256 i; i < HOLDBACK_BUCKETS; ++i) {
            HoldbackBucket storage bucket = holdbackBuckets[provider][i];
            if (bucket.amount > 0 && uint256(bucket.day) * 1 days + params.holdbackPeriod <= block.timestamp) {
                matured += bucket.amount;
                bucket.amount = 0;
            }
        }
        if (matured > 0) _payHoldback(provider, matured);
    }

    function _payHoldback(address provider, uint256 amount) internal {
        holdbackBalance[provider] -= amount;
        totalHoldback -= amount;
        _credit(provider, amount);
        emit HoldbackMatured(provider, amount);
    }

    /// @dev Unclaimed holdback, matured or not, is at risk until paid out.
    function _takeHoldback(address provider, uint256 amount) internal returns (uint256 taken) {
        for (uint256 i; i < HOLDBACK_BUCKETS && taken < amount; ++i) {
            HoldbackBucket storage bucket = holdbackBuckets[provider][i];
            uint256 part = bucket.amount < amount - taken ? bucket.amount : amount - taken;
            bucket.amount -= part;
            taken += part;
        }
        holdbackBalance[provider] -= taken;
        totalHoldback -= taken;
    }

    function _notifyRelease(address provider, address consumer, uint256 fee) internal {
        try juryRegistry.recordRelease(provider, consumer, fee) {} catch {
            emit RegistryHookFailed(provider, IProviderJuryRegistryV11.recordRelease.selector);
        }
    }

    function _notifyFraud(address provider) internal {
        try juryRegistry.recordConfirmedFraud(provider) {} catch {
            emit RegistryHookFailed(provider, IProviderJuryRegistryV11.recordConfirmedFraud.selector);
        }
    }

    function _independent(Settlement storage record, address judge) internal view returns (bool) {
        return judge != record.owner && judge != record.key && judge != record.provider
            && judge != record.providerSigner && judge != record.relay && judge != record.relaySigner
            && providerSignerOwner[judge] != record.provider && judge != params.penaltyRecipient;
    }

    function _setParams(Params calldata p) internal {
        require(p.disputeWindow > 0 && p.disputeWindow <= 30 days); // bad dispute window
        require(p.arbitrationTimeout > 0 && p.arbitrationTimeout <= 30 days); // bad arbitration timeout
        require(p.consumerWithdrawalDelay > 0 && p.consumerWithdrawalDelay <= 30 days); // bad withdrawal delay
        require(p.relayBps < BPS && p.holdbackBps <= BPS && p.exposureGrowthBps <= BPS); // bad bps
        require(p.holdbackPeriod > 0 && p.holdbackPeriod < HOLDBACK_BUCKETS * 1 days); // bad holdback period
        require(p.baseExposureCap > 0 && p.maxExposureCap >= p.baseExposureCap); // bad exposure caps
        require(p.slashBps <= BPS && p.reporterBountyBps <= BPS); // bad penalty bps
        require(p.penaltyRecipient != address(0) && p.penaltyRecipient != address(this)); // bad penalty recipient
        params = p;
        emit ParamsUpdated(p);
    }

    function _requireSigner(address signer) internal view {
        require(signer != address(0) && signer.code.length == 0 && signer != msg.sender && signer != address(this)); // bad signer
    }

    function _verifyProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 hash = leaf;
        for (uint256 i; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            hash = hash < sibling ? keccak256(abi.encode(hash, sibling)) : keccak256(abi.encode(sibling, hash));
        }
        return hash == root;
    }

    function _portion(uint256 amount, uint16 bps) internal pure returns (uint256) {
        return amount / BPS * bps + amount % BPS * bps / BPS;
    }

    function _credit(address account, uint256 amount) internal {
        if (amount == 0) return;
        require(account != address(0) && account != address(this)); // bad credit
        claimableBalance[account] += amount;
        totalClaimable += amount;
    }

    function _future(uint64 delay) internal view returns (uint64) {
        require(block.timestamp <= type(uint64).max - delay); // timestamp overflow
        return uint64(block.timestamp + delay);
    }

    function _typedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER) return address(0);
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }

    function _takeExact(address from, uint256 amount) internal {
        uint256 beforeHere = stablecoin.balanceOf(address(this));
        uint256 beforeThere = stablecoin.balanceOf(from);
        require(from != address(this) && beforeThere >= amount); // bad token payer
        _callToken(abi.encodeWithSelector(IMycoERC20V11.transferFrom.selector, from, address(this), amount));
        require(stablecoin.balanceOf(address(this)) == beforeHere + amount
            && stablecoin.balanceOf(from) == beforeThere - amount); // unsupported token
    }

    function _sendExact(address to, uint256 amount) internal {
        uint256 beforeHere = stablecoin.balanceOf(address(this));
        uint256 beforeThere = stablecoin.balanceOf(to);
        require(to != address(0) && to != address(this) && beforeHere >= amount); // bad token recipient
        _callToken(abi.encodeWithSelector(IMycoERC20V11.transfer.selector, to, amount));
        require(stablecoin.balanceOf(address(this)) == beforeHere - amount
            && stablecoin.balanceOf(to) == beforeThere + amount); // unsupported token
    }

    function _callToken(bytes memory input) private {
        (bool ok, bytes memory data) = address(stablecoin).call(input);
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool))))); // token transfer failed
    }
}
