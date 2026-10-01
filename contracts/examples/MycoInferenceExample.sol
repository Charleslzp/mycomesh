// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMycoInferenceReceiverV11, MycoInferenceOracleV11} from "../MycoInferenceOracleV11.sol";

interface IExampleToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IExampleSettlement {
    function deposit(uint256 amount) external;
}

/// @notice A minimal contract that asks MycoMesh models questions and keeps the answers.
/// It pays from its own deposit in the settlement, like any Consumer.
contract MycoInferenceExample is IMycoInferenceReceiverV11 {
    MycoInferenceOracleV11 public immutable oracle;
    IExampleSettlement public immutable settlement;
    IExampleToken public immutable stablecoin;
    mapping(bytes32 => bytes) public answers;

    event Answered(bytes32 indexed requestId, string answer);

    constructor(MycoInferenceOracleV11 oracle_, IExampleSettlement settlement_, IExampleToken stablecoin_) {
        (oracle, settlement, stablecoin) = (oracle_, settlement_, stablecoin_);
    }

    /// @notice Move stablecoin from the caller into this contract's settlement deposit.
    function fund(uint256 amount) external {
        require(stablecoin.transferFrom(msg.sender, address(this), amount) && stablecoin.approve(address(settlement), amount));
        settlement.deposit(amount);
    }

    function ask(uint32 tier, string calldata model, string calldata question, uint256 maxFee,
        MycoInferenceOracleV11.Finality finality) external returns (bytes32)
    {
        // The caller may dispute a wrong answer on this contract's behalf.
        return oracle.request(MycoInferenceOracleV11.Ask({
            tier: tier, model: model, prompt: bytes(question), maxOutputTokens: 512, maxFee: maxFee,
            callback: address(this), callbackGas: 200_000, finality: finality, disputer: msg.sender
        }));
    }

    function onInference(bytes32 requestId, bytes calldata response, bytes32) external {
        require(msg.sender == address(oracle)); // only the oracle answers
        answers[requestId] = response;
        emit Answered(requestId, string(response));
    }
}
