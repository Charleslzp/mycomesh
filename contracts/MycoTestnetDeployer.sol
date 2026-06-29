// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MycoSettlementV2.sol";
import "./MycoToken.sol";
import "./TestUSDC.sol";

contract MycoTestnetDeployer {
    bytes32 public constant CODEX_STANDARD_V1 = keccak256(bytes("codex-standard-v1"));

    TestUSDC public immutable testUSDC;
    MycoToken public immutable token;
    MycoSettlementV2 public immutable settlement;

    constructor(address treasury) {
        require(treasury != address(0), "zero treasury");

        testUSDC = new TestUSDC();
        token = new MycoToken(address(this));
        settlement = new MycoSettlementV2(address(testUSDC), address(token), treasury);

        token.setMinter(address(settlement));
        settlement.setChannel(
            CODEX_STANDARD_V1,
            MycoSettlementV2.ChannelConfig({
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
            })
        );
        settlement.setGovernanceDelay(settlement.MIN_GOVERNANCE_DELAY_SECONDS());

        token.transferOwnership(msg.sender);
        settlement.transferOwnership(msg.sender);
    }

}
