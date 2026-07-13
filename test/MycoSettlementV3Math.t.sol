// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV3} from "../contracts/MycoSettlementV3.sol";

contract MathStablecoinV3 {
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }
}

contract MycoSettlementV3MathHarness is MycoSettlementV3 {
    constructor(ChannelConfig memory initialConfig)
        MycoSettlementV3(
            address(new MathStablecoinV3()), address(2), address(3), address(4), 0, bytes32(uint256(1)), initialConfig
        )
    {}

    function bpsAmount(uint256 amount, uint16 bps) external pure returns (uint256) {
        return _bpsAmount(amount, bps);
    }
}

contract MycoSettlementV3MathTest {
    function testSplitMathSupportsUint256MaximumWithoutIntermediateOverflow() public {
        MycoSettlementV3.ChannelConfig memory initialConfig = MycoSettlementV3.ChannelConfig({
            inputPer1K: 0,
            outputPer1K: 0,
            minimumFee: 0,
            providerBps: 10_000,
            relayBps: 0,
            poolBps: 0,
            treasuryBps: 0,
            providerRewardBps: 10_000,
            consumerRewardBps: 0,
            rewardPerTreasuryUnit: 0,
            active: true
        });
        MycoSettlementV3MathHarness harness = new MycoSettlementV3MathHarness(initialConfig);

        require(harness.bpsAmount(type(uint256).max, 10_000) == type(uint256).max, "full split");
        require(harness.bpsAmount(type(uint256).max, 5_000) == type(uint256).max / 2, "half split");
        require(harness.bpsAmount(type(uint256).max, 0) == 0, "zero split");
    }
}
