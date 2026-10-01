// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";
import {MycoReleaseV11} from "./MycoReleaseV11.sol";

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
    function recordReleases(MycoReleaseV11[] calldata items, address caller) external;
    function recordConfirmedFraud(address providerOwner) external;
    function requestTierJury(bytes32 caseId, address providerOwner, address providerSigner) external;
    function recordCapabilityConviction(address providerOwner, address hunter) external;
    function priceAndRecord(address signer, uint64 issuedAt, uint256 inputTokens, uint256 outputTokens) external returns (uint256);
}

/// @notice Storage, types and shared rules of the V11 settlement. The settlement is two implementations
/// behind one proxy: ``MycoSettlementV11`` (funds, settlement, release, probes) and
/// ``MycoSettlementDisputesV11`` (disputes), which it reaches by delegatecall for any selector it does not
/// define. Both inherit this contract, so they share one storage layout; the proxy's ABI is the union.
abstract contract MycoSettlementBaseV11 is MycoUUPSUpgradeable {
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
    /// @notice Protocol revenue on every released fee, credited to settings.penaltyRecipient (the treasury).
    uint16 public constant TREASURY_BPS = 1_000;
    uint256 internal constant HOOK_GAS = 600_000;
    uint256 internal constant HOOK_GAS_PER_ITEM = 200_000;
    bytes32 public constant DISPATCH_TYPEHASH = keccak256("RelayDispatch(bytes32 authorizationHash)");
    bytes32 internal constant DISPUTE_VOTE_TYPEHASH = keccak256(
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
    /// @dev Multi-tenant accounts: an owner (say, a custodial service) gives each tenant its own
    /// payment key with a total budget; zero means unlimited. Only budgeted keys pay for tracking.
    struct KeyBudget { uint128 limit; uint128 spent; }
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

    /// @dev v7, open probing: who voided a probe (the hunter named in its commitment) and on which day.
    struct ProbeVoid { address hunter; uint64 day; bool inCase; }

    enum CaseStatus { None, Open, Confirmed, Dismissed, TimedOut }
    /// @dev v7: a hunter's statistical accusation that a Provider serves a weaker model than its tier,
    /// backed by every probe the hunter voided on it over a range of days.
    struct CapabilityCase {
        address hunter; address provider; address providerSigner;
        uint64 fromDay; uint64 toDay; uint64 resolveAt; uint16 probes; CaseStatus status;
        bytes32 evidenceHash; bytes32 keysHash; uint256 bond; uint256 penalty; uint256 bounty;
    }

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
    Params internal settings;
    bool internal entered;

    mapping(address => uint256) public availableBalance;
    mapping(address => uint256) public claimableBalance;
    mapping(address => KeyGrant) public keyGrants;
    mapping(address => Withdrawal) public withdrawals;
    mapping(address => address) public providerSignerOwner;
    mapping(address => address) public relaySignerOwner;

    mapping(bytes32 => bool) public settled;
    mapping(bytes32 => Settlement) internal settlements;
    mapping(bytes32 => Dispute) internal disputes;
    mapping(bytes32 => mapping(bytes32 => Report)) public reports;
    mapping(bytes32 => mapping(address => uint8)) public disputeVotes;
    mapping(bytes32 => mapping(address => uint256)) public adjudicatorNonce;
    mapping(bytes32 => mapping(bytes32 => uint16)) public confirmationVotes;

    mapping(address => uint256) public pendingExposure;
    mapping(address => uint256) public cleanVolume;
    mapping(address => HoldbackBucket[HOLDBACK_BUCKETS]) internal holdbackBuckets;
    mapping(address => uint256) public holdbackBalance;

    mapping(address => ProbeRoot[]) internal probeRoots; // retired in v7 (Relay-only probes)
    mapping(address => mapping(address => mapping(uint64 => uint16))) internal probeVoidsByDay; // retired in v7

    uint256 public totalAvailable;
    uint256 public totalClaimable;
    uint256 public totalPendingFees;
    uint256 public totalHoldback;
    uint256 public totalReporterBonds;

    mapping(address => KeyBudget) public keyBudgets; // v3

    // v7: open probing. A commitment keccak256(abi.encode(hunter, merkleRoot, salt)) hides who probes until
    // the probe is voided; every Provider gives probeVoidsPerDay free probes a day to all hunters together.
    mapping(bytes32 => uint64) public probeCommitments;
    mapping(address => mapping(uint64 => uint16)) public providerProbeVoids;
    mapping(address => mapping(address => mapping(uint64 => uint16))) public hunterProbeVoids;
    mapping(bytes32 => ProbeVoid) public probeVoids;
    mapping(bytes32 => CapabilityCase) internal capabilityCases;
    uint256 public probeMaxFee;

    // v8: on-chain inference. Reservations stay counted in totalAvailable until the fee is escrowed.
    address public oracle;
    mapping(address => uint256) public oracleReserved;
    mapping(bytes32 => address) public oracleDisputer; // may dispute an on-chain request beside its owner

    uint256[30] internal __gap;

    event ParamsUpdated(Params params);
    event Deposited(address indexed account, uint256 amount);
    event WithdrawalRequested(address indexed account, uint256 amount, uint256 availableAt);
    event WithdrawalCancelled(address indexed account);
    event Withdrawn(address indexed account, uint256 amount);
    event KeyRegistered(address indexed owner, address indexed key, uint256 maxPerRequest, uint256 validUntil);
    event KeyRevoked(address indexed owner, address indexed key);
    event KeyBudgetSet(address indexed owner, address indexed key, uint256 limit);
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
    event ProbeVoided(bytes32 indexed settlementKey, address indexed hunter, address indexed provider);
    event ProbesCommitted(bytes32 indexed commitment);
    event CapabilityCaseOpened(bytes32 indexed caseId, address indexed hunter, address indexed provider, uint256 probes,
        bytes32 evidenceHash, uint256 resolveAt);
    event CapabilityCaseResolved(bytes32 indexed caseId, CaseStatus status, uint256 penalty, uint256 bounty);
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

    // The implementation itself holds no funds or configuration (it can never
    // be initialized), so business functions need no proxy-only guard; the
    // upgrade entry points in MycoUUPSUpgradeable keep theirs.
    modifier nonReentrant() {
        _enter();
        _;
        entered = false;
    }

    function _enter() internal {
        require(!entered); // reentrant
        entered = true;
    }

    /// @dev All-static struct: encoded exactly like the 15 values an automatic getter returns.
    function params() external view returns (Params memory) { return settings; }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes("MycoMesh Settlement")), keccak256(bytes("11")), block.chainid, address(this)
        ));
    }

    /// @notice Unreleased fees a Provider may carry; grows only with clean volume.
    function exposureCap(address provider) public view returns (uint256 cap) {
        cap = settings.baseExposureCap + _portion(cleanVolume[provider], settings.exposureGrowthBps);
        if (cap > settings.maxExposureCap) cap = settings.maxExposureCap;
    }

    function _release(bytes32 key, Settlement storage record, Status status) internal {
        MycoReleaseV11[] memory items = new MycoReleaseV11[](1);
        _payReleases(items, _markReleased(key, record, status, items, 0));
    }

    /// @dev Marks one receipt released and folds its fee into the per-(Provider, Consumer, Relay) totals.
    /// @return the number of distinct totals in ``items``
    function _markReleased(bytes32 key, Settlement storage record, Status status, MycoReleaseV11[] memory items,
        uint256 n) internal returns (uint256)
    {
        record.status = status;
        emit SettlementReleased(key, status);
        (address provider, address consumer, address relay, uint256 fee) = (record.provider, record.owner, record.relay, record.fee);
        for (uint256 i; i < n; ++i) {
            MycoReleaseV11 memory item = items[i];
            if (item.provider == provider && item.consumer == consumer && item.relay == relay) {
                item.fee += fee;
                ++item.count;
                return n;
            }
        }
        items[n] = MycoReleaseV11(provider, consumer, relay, fee, 1);
        return n + 1;
    }

    /// @dev Pays out released fees: Relay and treasury shares, the Provider's share less its holdback;
    /// then reports the totals to the registry (reputation, MYCO emission) in one call.
    function _payReleases(MycoReleaseV11[] memory items, uint256 n) internal {
        assembly ("memory-safe") {
            mstore(items, n)
        }
        uint256 total;
        uint256 treasury;
        for (uint256 i; i < n; ++i) {
            MycoReleaseV11 memory item = items[i];
            uint256 fee = item.fee;
            total += fee;
            pendingExposure[item.provider] -= fee;
            uint256 relayAmount = _portion(fee, settings.relayBps);
            uint256 cut = _portion(fee, TREASURY_BPS);
            treasury += cut;
            uint256 providerGross = fee - relayAmount - cut;
            uint256 held = _portion(providerGross, settings.holdbackBps);
            _credit(item.relay, relayAmount);
            _credit(item.provider, providerGross - held);
            if (held > 0) _addHoldback(item.provider, held);
            cleanVolume[item.provider] += fee;
        }
        totalPendingFees -= total;
        _credit(settings.penaltyRecipient, treasury);
        _notifyReleases(items);
    }

    function _refund(Settlement storage record) internal {
        uint256 fee = record.fee;
        KeyBudget storage budget = keyBudgets[record.key];
        if (budget.spent >= fee) budget.spent -= uint128(fee);
        totalPendingFees -= fee;
        pendingExposure[record.provider] -= fee;
        availableBalance[record.owner] += fee;
        totalAvailable += fee;
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
            if (bucket.amount > 0 && uint256(bucket.day) * 1 days + settings.holdbackPeriod <= block.timestamp) {
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

    function _notifyReleases(MycoReleaseV11[] memory items) internal {
        // msg.sender did the release: a keeper's work, rewarded by the emission schedule.
        require(gasleft() > HOOK_GAS + items.length * HOOK_GAS_PER_ITEM); // gas too low for the registry hooks
        try juryRegistry.recordReleases(items, msg.sender) {} catch {
            emit RegistryHookFailed(items[0].provider, IProviderJuryRegistryV11.recordReleases.selector);
        }
    }

    function _notifyFraud(address provider) internal {
        _hookGas();
        try juryRegistry.recordConfirmedFraud(provider) {} catch {
            emit RegistryHookFailed(provider, IProviderJuryRegistryV11.recordConfirmedFraud.selector);
        }
    }

    /// @dev A hook that runs out of gas is caught like any failure, so a caller (or eth_estimateGas) that
    /// sends just enough for the payout would silently skip reputation and rewards. Require room for them.
    function _hookGas() internal view {
        require(gasleft() > HOOK_GAS); // gas too low for the registry hooks
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
        settings = p;
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

    function _callToken(bytes memory input) internal {
        (bool ok, bytes memory data) = address(stablecoin).call(input);
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool))))); // token transfer failed
    }
}
