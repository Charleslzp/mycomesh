// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMycoERC20V11, IProviderJuryRegistryV11, MycoSettlementBaseV11} from "./MycoSettlementBaseV11.sol";
import {MycoReleaseV11} from "./MycoReleaseV11.sol";

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
/// Disputes live in ``MycoSettlementDisputesV11`` (see the fallback).
/// Upgradeable by a single admin with no delay (early-network choice).
contract MycoSettlementV11 is MycoSettlementBaseV11 {
    uint256 public constant MAX_RELEASE_BATCH = 64;

    /// @notice The dispute implementation this version delegates to.
    address public immutable disputeModule;

    constructor(address disputeModule_) {
        require(disputeModule_.code.length > 0); // dispute module has no code
        disputeModule = disputeModule_;
    }

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

    function setParams(Params calldata params_) external onlyAdmin {
        _setParams(params_);
    }

    // ---------------- views ----------------

    function _settlementKey(address key, bytes32 requestId) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, requestId));
    }
    function authorizationStructHash(PaymentAuthorization calldata a) public pure returns (bytes32) {
        return keccak256(abi.encode(PAYMENT_AUTHORIZATION_TYPEHASH, a));
    }
    function dispatchStructHash(bytes32 authorizationHash) public pure returns (bytes32) {
        return keccak256(abi.encode(DISPATCH_TYPEHASH, authorizationHash));
    }
    function receiptStructHash(UsageReceipt calldata r) public pure returns (bytes32) {
        return keccak256(abi.encode(USAGE_RECEIPT_TYPEHASH, r));
    }

    // ---------------- Consumer funds ----------------

    function deposit(uint256 amount) external nonReentrant {
        require(amount > 0); // zero amount
        _takeExact(msg.sender, amount);
        availableBalance[msg.sender] += amount;
        totalAvailable += amount;
        emit Deposited(msg.sender, amount);
    }

    function registerKey(address key, uint256 maxPerRequest, uint64 validUntil) external nonReentrant {
        require(key != address(0) && key.code.length == 0 && key != msg.sender && key != address(this)); // bad key
        require(maxPerRequest > 0); // zero key limit
        require(validUntil == 0 || validUntil > block.timestamp); // key expired
        require(keyGrants[key].owner == address(0) || keyGrants[key].owner == msg.sender); // key owned
        keyGrants[key] = KeyGrant(msg.sender, maxPerRequest, validUntil, true);
        emit KeyRegistered(msg.sender, key, maxPerRequest, validUntil);
    }

    /// @notice Cap what one key may ever spend; raising the limit tops the tenant up.
    function setKeyBudget(address key, uint128 limit) external nonReentrant {
        require(keyGrants[key].owner == msg.sender); // not own key
        keyBudgets[key].limit = limit;
        emit KeyBudgetSet(msg.sender, key, limit);
    }

    function revokeKey(address key) external nonReentrant {
        KeyGrant storage grant = keyGrants[key];
        require(grant.owner == msg.sender && grant.active); // not an active own key
        grant.active = false;
        emit KeyRevoked(msg.sender, key);
    }

    function requestWithdrawal(uint256 amount) external nonReentrant {
        require(amount > 0 && amount <= availableBalance[msg.sender]); // bad withdrawal
        uint64 availableAt = _future(settings.consumerWithdrawalDelay);
        withdrawals[msg.sender] = Withdrawal(amount, availableAt);
        emit WithdrawalRequested(msg.sender, amount, availableAt);
    }

    function cancelWithdrawal() external nonReentrant {
        require(withdrawals[msg.sender].amount > 0); // no withdrawal
        delete withdrawals[msg.sender];
        emit WithdrawalCancelled(msg.sender);
    }

    function withdraw() external nonReentrant {
        Withdrawal memory request = withdrawals[msg.sender];
        require(request.amount > 0 && block.timestamp >= request.availableAt); // withdrawal pending
        require(availableBalance[msg.sender] >= request.amount); // balance changed
        delete withdrawals[msg.sender];
        availableBalance[msg.sender] -= request.amount;
        totalAvailable -= request.amount;
        _sendExact(msg.sender, request.amount);
        emit Withdrawn(msg.sender, request.amount);
    }

    function claim() external nonReentrant returns (uint256 amount) {
        amount = claimableBalance[msg.sender];
        require(amount > 0); // no claimable balance
        claimableBalance[msg.sender] = 0;
        totalClaimable -= amount;
        _sendExact(msg.sender, amount);
        emit PayoutClaimed(msg.sender, amount);
    }

    // ---------------- Provider and Relay signers ----------------

    function authorizeProviderSigner(address signer) external nonReentrant {
        _requireSigner(signer);
        require(providerSignerOwner[signer] == address(0) && relaySignerOwner[signer] == address(0)); // signer bound
        providerSignerOwner[signer] = msg.sender;
        emit ProviderSignerAuthorized(msg.sender, signer);
    }

    function revokeProviderSigner(address signer) external nonReentrant {
        require(providerSignerOwner[signer] == msg.sender); // not own signer
        providerSignerOwner[signer] = address(0);
        emit ProviderSignerRevoked(msg.sender, signer);
    }

    function authorizeRelaySigner(address signer) external nonReentrant {
        _requireSigner(signer);
        require(relaySignerOwner[signer] == address(0) && providerSignerOwner[signer] == address(0)); // signer bound
        relaySignerOwner[signer] = msg.sender;
        emit RelaySignerAuthorized(msg.sender, signer);
    }

    function revokeRelaySigner(address signer) external nonReentrant {
        require(relaySignerOwner[signer] == msg.sender); // not own signer
        relaySignerOwner[signer] = address(0);
        emit RelaySignerRevoked(msg.sender, signer);
    }

    // ---------------- settlement ----------------

    function settleBatch(SignedReceipt[] calldata inputs) external nonReentrant {
        require(inputs.length > 0 && inputs.length <= MAX_BATCH_SIZE); // bad batch length
        for (uint256 i; i < inputs.length; ++i) _settle(inputs[i]);
    }

    function release(bytes32 key) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(block.timestamp >= record.releaseAt); // release pending
        _release(key, record, Status.Released);
    }

    /// @notice Release every due receipt among ``keys`` in one transaction; the rest are skipped. Credits and
    /// the registry and emission hooks are aggregated per (Provider, Consumer, Relay), so a keeper pays for
    /// one hook call per batch rather than per receipt.
    function releaseBatch(bytes32[] calldata keys) external nonReentrant returns (uint256 released) {
        require(keys.length > 0 && keys.length <= MAX_RELEASE_BATCH); // bad batch length
        MycoReleaseV11[] memory items = new MycoReleaseV11[](keys.length);
        uint256 n;
        for (uint256 i; i < keys.length; ++i) {
            Settlement storage record = settlements[keys[i]];
            if (record.status != Status.Pending || block.timestamp < record.releaseAt) continue;
            n = _markReleased(keys[i], record, Status.Released, items, n);
            ++released;
        }
        require(released > 0); // nothing to release
        _payReleases(items, n);
    }

    /// @notice Move a Provider's matured holdback to its claimable balance.
    function releaseHoldback(address provider) external nonReentrant {
        _matureHoldback(provider);
    }

    // ---------------- probes (open to anyone) ----------------

    /// @notice Commit a batch of probe keys before using them. The commitment is
    /// keccak256(abi.encode(hunter, root, salt)) over a Merkle root of keccak256(abi.encode(key)) leaves
    /// (pairs hashed sorted), so it reveals nothing about who probes, whom or when; anyone may post it.
    function commitProbes(bytes32 commitment) external {
        require(commitment != bytes32(0) && probeCommitments[commitment] == 0); // empty or already committed
        probeCommitments[commitment] = uint64(block.timestamp);
        emit ProbesCommitted(commitment);
    }

    /// @notice The request's owner voids one of its probes inside the dispute window: the key is refunded
    /// and the Provider is not paid. A Provider gives at most probeVoidsPerDay such free probes a day, to all
    /// hunters together and first come first served, each no larger than probeMaxFee.
    function voidProbe(bytes32 key, address hunter, bytes32 root, bytes32 salt, bytes32[] calldata proof)
        external nonReentrant
    {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending && block.timestamp < record.releaseAt); // not voidable
        require(record.owner == msg.sender && hunter != address(0)); // not the request's owner
        require(record.fee <= probeMaxFee); // larger than a free probe
        uint64 committedAt = probeCommitments[keccak256(abi.encode(hunter, root, salt))];
        require(committedAt != 0 && committedAt < record.issuedAt); // probe key not committed in advance
        require(_verifyProof(proof, root, keccak256(abi.encode(record.key)))); // not a committed probe key
        uint64 day = uint64(block.timestamp / 1 days);
        require(providerProbeVoids[record.provider][day] < settings.probeVoidsPerDay); // allowance used today
        ++providerProbeVoids[record.provider][day];
        ++hunterProbeVoids[hunter][record.provider][day];
        probeVoids[key] = ProbeVoid(hunter, day, false);
        record.status = Status.Voided;
        _refund(record);
        emit ProbeVoided(key, hunter, record.provider);
    }

    function setProbeMaxFee(uint256 value) external onlyAdmin {
        probeMaxFee = value;
    }

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
        require(_recover(_typedDataHash(receiptStructHash(r)), input.providerSignature) == a.providerSigner); // bad provider signature
        uint256 fee = r.actualFee;
        require(fee > 0 && fee <= a.maxFee); // fee exceeds authorization
        // One network price for everyone (see the registry): the fee is exactly the quote, capped by the Consumer.
        uint256 price = juryRegistry.priceAndRecord(a.providerSigner, a.issuedAt, r.inputTokens, r.outputTokens);
        require(fee == (price < a.maxFee ? price : a.maxFee)); // not the network price
        KeyBudget storage budget = keyBudgets[a.key];
        if (budget.limit != 0) {
            require(budget.spent + fee <= budget.limit); // key budget spent
            budget.spent += uint128(fee);
        }
        bytes32 key = _settlementKey(a.key, a.requestId);
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
        record.releaseAt = _future(settings.disputeWindow);
        record.status = Status.Pending;
        emit ReceiptEscrowed(key, a.requestId, grant.owner, provider, fee, record.releaseAt);
    }

    /// @notice Everything else (disputes and their views) runs in the dispute module on this storage.
    fallback() external {
        address module = disputeModule;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), module, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
