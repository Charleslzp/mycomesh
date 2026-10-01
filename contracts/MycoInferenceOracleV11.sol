// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";
import {MycoSettlementBaseV11 as Base} from "./MycoSettlementBaseV11.sol";

/// @notice What a contract implements to receive an answer.
interface IMycoInferenceReceiverV11 {
    function onInference(bytes32 requestId, bytes calldata response, bytes32 settlementKey) external;
}

interface IMycoOracleSettlementV11 {
    function reserveForOracle(address owner, uint256 amount) external;
    function releaseOracleReserve(address owner, uint256 amount) external;
    function settleOracle(address owner, address disputer, Base.SignedReceipt calldata input) external returns (bytes32);
    function settlementInfo(bytes32 key) external view returns (Base.Settlement memory);
}

interface IMycoTierRegistryV11 {
    function signerPricing(address signer) external view returns (
        uint32 tier, uint64 lastEpoch, uint128 declared, uint128 peak, uint128 counted, uint128 served
    );
}

/// @notice On-chain inference: a contract asks a model a question and gets the answer in a callback.
/// @dev One Provider answers each request, as any off-chain request is answered: the network's trust
/// layer stands behind it, not redundancy. The requesting contract pays from its deposit in the
/// settlement (reserved here at request time, so the Provider is sure to be paid); the answer's
/// receipt is signed by the Provider and dispatched by a Relay, priced at the network price of the
/// requested tier, and escrowed for the usual dispute window, during which the requester (or the
/// ``disputer`` it names) can take it to a Provider-AI jury.
///
/// A requester chooses when its callback runs:
/// * ``Immediate``: with the answer, minutes after the request; the contract bears the risk that the
///   answer is later judged fraudulent (the fee is then refunded and the Provider penalised);
/// * ``AfterDisputeWindow``: only once the escrow is released undisputed or a dispute was dismissed.
///
/// Requests and answers are public, so this suits public questions (classification, moderation,
/// scoring, arbitration, agent decisions), not secrets.
contract MycoInferenceOracleV11 is MycoUUPSUpgradeable {
    bytes32 public constant REQUEST_SCHEMA = keccak256("mycomesh.v11.onchain-request.v1");
    uint64 public constant REQUEST_TTL = 1 hours;
    uint32 public constant MAX_CALLBACK_GAS = 2_000_000;
    uint256 public constant MAX_PROMPT_BYTES = 32_768;
    uint8 private constant RELEASED = 3;
    uint8 private constant DISMISSED = 5;
    uint8 private constant TIMED_OUT = 6;

    enum Finality { Immediate, AfterDisputeWindow }
    enum State { None, Open, Answered, Delivered, Expired }

    /// @dev What a contract asks for.
    struct Ask {
        uint32 tier; string model; bytes prompt; uint32 maxOutputTokens; uint256 maxFee;
        address callback; uint32 callbackGas; Finality finality; address disputer;
    }

    struct Request {
        address owner; address callback; address disputer;
        uint32 tier; uint32 maxOutputTokens; uint32 callbackGas; Finality finality; State state; uint64 deadline;
        uint256 maxFee; bytes32 requestHash; bytes32 settlementKey; bytes32 responseHash;
    }

    IMycoOracleSettlementV11 public settlement;
    IMycoTierRegistryV11 public registry;
    mapping(bytes32 => Request) internal requests;
    mapping(address => uint256) public nonces;
    bool private entered;
    uint256[40] private __gap;

    event InferenceRequested(bytes32 indexed requestId, address indexed owner, uint32 indexed tier, Ask ask,
        bytes32 requestHash, uint64 deadline);
    event InferenceAnswered(bytes32 indexed requestId, bytes32 indexed settlementKey, uint256 fee, bytes response);
    event InferenceDelivered(bytes32 indexed requestId, bool callbackSucceeded);
    event InferenceExpired(bytes32 indexed requestId);

    modifier nonReentrant() {
        require(!entered); // reentrant
        entered = true;
        _;
        entered = false;
    }

    constructor() {}

    function initialize(address admin_, address settlement_, address registry_) external reinitializer(1) {
        _initializeAdmin(admin_);
        settlement = IMycoOracleSettlementV11(settlement_);
        registry = IMycoTierRegistryV11(registry_);
    }

    function requestInfo(bytes32 requestId) external view returns (Request memory) { return requests[requestId]; }

    /// @notice The hash a Provider signs as the request's: sha256 over everything that defines the question.
    function requestHashOf(bytes32 requestId, string calldata model, bytes calldata prompt, uint32 maxOutputTokens)
        public view returns (bytes32)
    {
        return sha256(abi.encode(REQUEST_SCHEMA, block.chainid, address(this), requestId, model, prompt, maxOutputTokens));
    }

    /// @notice Ask a model in ``ask.tier`` a question; the caller must hold ``ask.maxFee`` in its settlement
    /// deposit. ``ask.callback`` receives onInference (address(0): none, read InferenceAnswered instead);
    /// ``ask.disputer`` may dispute the answer besides the caller (e.g. an operator's wallet).
    function request(Ask calldata ask) external onlyProxy nonReentrant returns (bytes32 requestId) {
        require(bytes(ask.model).length > 0 && bytes(ask.model).length <= 160 && ask.prompt.length > 0
            && ask.prompt.length <= MAX_PROMPT_BYTES); // bad model or prompt
        require(ask.maxOutputTokens > 0 && ask.maxFee > 0 && ask.callbackGas <= MAX_CALLBACK_GAS); // bad limits
        requestId = keccak256(abi.encode(block.chainid, address(this), msg.sender, nonces[msg.sender]++));
        settlement.reserveForOracle(msg.sender, ask.maxFee);
        Request storage item = requests[requestId];
        (item.owner, item.callback, item.disputer) = (msg.sender, ask.callback, ask.disputer);
        (item.tier, item.maxOutputTokens, item.callbackGas) = (ask.tier, ask.maxOutputTokens, ask.callbackGas);
        item.finality = ask.finality;
        item.state = State.Open;
        item.deadline = uint64(block.timestamp) + REQUEST_TTL;
        item.maxFee = ask.maxFee;
        item.requestHash = requestHashOf(requestId, ask.model, ask.prompt, ask.maxOutputTokens);
        emit InferenceRequested(requestId, msg.sender, ask.tier, ask, item.requestHash, item.deadline);
    }

    /// @notice Anyone (normally the dispatching Relay) submits the Provider's answer and its signed receipt.
    /// The authorization names this oracle as its key; the settlement checks the signatures and the price.
    function fulfill(bytes32 requestId, Base.SignedReceipt calldata input, bytes calldata response)
        external onlyProxy nonReentrant
    {
        Request storage item = requests[requestId];
        require(item.state == State.Open && block.timestamp <= item.deadline); // not open
        Base.PaymentAuthorization calldata a = input.authorization;
        require(a.requestId == requestId && a.requestHash == item.requestHash && a.maxFee == item.maxFee); // other request
        require(sha256(response) == input.receipt.responseHash); // not the signed answer
        (uint32 tier, , , , , ) = registry.signerPricing(a.providerSigner);
        require(tier == item.tier); // the Provider serves another tier
        item.state = State.Answered;
        bytes32 key = settlement.settleOracle(item.owner, item.disputer, input);
        uint256 fee = input.receipt.actualFee;
        if (fee < item.maxFee) settlement.releaseOracleReserve(item.owner, item.maxFee - fee);
        (item.settlementKey, item.responseHash) = (key, input.receipt.responseHash);
        emit InferenceAnswered(requestId, key, fee, response);
        if (item.finality == Finality.Immediate) _deliver(requestId, item, response);
    }

    /// @notice For AfterDisputeWindow requests: anyone hands over the answer once its escrow is final and
    /// was not judged fraudulent (released, dispute dismissed, or a silent jury timed out).
    function deliver(bytes32 requestId, bytes calldata response) external onlyProxy nonReentrant {
        Request storage item = requests[requestId];
        require(item.state == State.Answered && sha256(response) == item.responseHash); // not deliverable
        uint8 status = uint8(settlement.settlementInfo(item.settlementKey).status);
        require(status == RELEASED || status == DISMISSED || status == TIMED_OUT); // not final, or fraud
        _deliver(requestId, item, response);
    }

    /// @notice An unanswered request returns its reservation after its deadline.
    function expire(bytes32 requestId) external onlyProxy nonReentrant {
        Request storage item = requests[requestId];
        require(item.state == State.Open && block.timestamp > item.deadline); // not expired
        item.state = State.Expired;
        settlement.releaseOracleReserve(item.owner, item.maxFee);
        emit InferenceExpired(requestId);
    }

    function _deliver(bytes32 requestId, Request storage item, bytes calldata response) internal {
        item.state = State.Delivered;
        bool ok = true;
        if (item.callback != address(0)) {
            // A callback starved of gas would fail silently and lose the answer: require the gas it asked for.
            require(gasleft() > uint256(item.callbackGas) * 64 / 63 + 20_000); // gas too low for the callback
            (ok, ) = item.callback.call{gas: item.callbackGas}(
                abi.encodeCall(IMycoInferenceReceiverV11.onInference, (requestId, response, item.settlementKey)));
        }
        emit InferenceDelivered(requestId, ok);
    }
}
