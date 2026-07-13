// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV3} from "./MycoSettlementV3.sol";
import {MycoTokenV2} from "./MycoTokenV2.sol";
import {TestUSDC} from "./TestUSDC.sol";

/// @notice Atomically deploys the test-only stablecoin and the immutable V3 settlement/token pair.
/// @dev TestUSDC has unrestricted minting. Do not use this deployer for production stablecoins.
contract MycoV3TestnetDeployer {
    bytes32 public constant CODEX_STANDARD_V1 = keccak256("codex-standard-v1");

    TestUSDC public immutable testUSDC;
    MycoSettlementV3 public immutable settlement;
    MycoTokenV2 public immutable token;

    event MycoV3TestnetDeployed(
        address indexed testUSDC,
        address indexed settlement,
        address indexed token,
        address treasury,
        address governance,
        uint16 maxConsumerRebateBps,
        uint256 maxSupply
    );

    constructor(address treasury, address governance, uint16 maxConsumerRebateBps, uint256 maxSupply) {
        require(treasury != address(0), "zero treasury");
        require(governance != address(0), "zero governance");
        require(maxConsumerRebateBps >= 1_000 && maxConsumerRebateBps <= 10_000, "bad rebate cap");
        require(maxSupply > 0, "zero max supply");

        address predictedStablecoin = computeCreateAddress(address(this), 1);
        address predictedSettlement = computeCreateAddress(address(this), 2);
        address predictedToken = computeCreateAddress(address(this), 3);

        TestUSDC deployedStablecoin = new TestUSDC();
        require(address(deployedStablecoin) == predictedStablecoin, "stablecoin address mismatch");

        MycoSettlementV3.ChannelConfig memory initialConfig = MycoSettlementV3.ChannelConfig({
            inputPer1K: 1_000,
            outputPer1K: 4_000,
            minimumFee: 2_000,
            providerBps: 8_500,
            relayBps: 300,
            poolBps: 200,
            treasuryBps: 1_000,
            providerRewardBps: 9_000,
            consumerRewardBps: 1_000,
            rewardPerTreasuryUnit: 1e12,
            active: true
        });
        MycoSettlementV3 deployedSettlement = new MycoSettlementV3(
            predictedStablecoin,
            predictedToken,
            treasury,
            governance,
            maxConsumerRebateBps,
            CODEX_STANDARD_V1,
            initialConfig
        );
        require(address(deployedSettlement) == predictedSettlement, "settlement address mismatch");

        MycoTokenV2 deployedToken = new MycoTokenV2(predictedSettlement, maxSupply);
        require(address(deployedToken) == predictedToken, "token address mismatch");

        require(address(deployedSettlement.stablecoin()) == predictedStablecoin, "stablecoin invariant");
        require(address(deployedSettlement.rewardToken()) == predictedToken, "reward invariant");
        require(deployedToken.mintAuthority() == predictedSettlement, "authority invariant");

        testUSDC = deployedStablecoin;
        settlement = deployedSettlement;
        token = deployedToken;

        emit MycoV3TestnetDeployed(
            predictedStablecoin,
            predictedSettlement,
            predictedToken,
            treasury,
            governance,
            maxConsumerRebateBps,
            maxSupply
        );
    }

    /// @notice Computes a child CREATE address for the single-byte RLP nonce range.
    function computeCreateAddress(address creator, uint8 nonce) public pure returns (address) {
        require(nonce > 0 && nonce <= 0x7f, "unsupported nonce");
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", creator, nonce)))));
    }
}
