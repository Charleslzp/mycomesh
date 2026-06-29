// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Legacy v1 compatibility deployer. MycoMesh v2 uses MycoTestnetDeployer.
import "./FandaiSettlement.sol";
import "./FandaiToken.sol";
import "./TestUSDC.sol";

contract FandaiTestnetDeployer {
    bytes32 public constant CODEX_STANDARD_V1 = keccak256(bytes("codex-standard-v1"));

    TestUSDC public immutable testUSDC;
    FandaiToken public immutable token;
    FandaiSettlement public immutable settlement;

    constructor(address treasury) {
        require(treasury != address(0), "zero treasury");

        testUSDC = new TestUSDC();
        token = new FandaiToken(address(this));
        settlement = new FandaiSettlement(address(testUSDC), address(token), treasury);

        token.setMinter(address(settlement));
        settlement.setChannel(
            CODEX_STANDARD_V1,
            FandaiSettlement.ChannelConfig({
                inputPer1K: 1_000,
                outputPer1K: 4_000,
                minimumFee: 2_000,
                providerBps: 8_500,
                relayBps: 300,
                poolBps: 200,
                treasuryBps: 1_000,
                rewardPerTreasuryUnit: 1e12,
                active: true
            })
        );

        token.transferOwnership(msg.sender);
        settlement.transferOwnership(msg.sender);
    }
}
