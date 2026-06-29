// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Legacy v1 compatibility tests. MycoMesh v2 coverage lives in MycoSettlementV2.t.sol.
import "../contracts/FandaiSettlement.sol";
import "../contracts/FandaiTestnetDeployer.sol";
import "../contracts/FandaiToken.sol";
import "../contracts/TestUSDC.sol";

contract FandaiSettlementTest {
    bytes32 internal constant CHANNEL = keccak256(bytes("codex-standard-v1"));

    function testSettlementSplitsAndRewards() public {
        address provider = address(0x1001);
        address relay = address(0x1002);
        address pool = address(0x1003);
        address treasury = address(0x1004);

        TestUSDC usdc = new TestUSDC();
        FandaiToken token = new FandaiToken(address(this));
        FandaiSettlement settlement = new FandaiSettlement(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());

        usdc.mint(address(this), 10_000_000);
        usdc.approve(address(settlement), type(uint256).max);
        settlement.settleReceipt(
            keccak256(bytes("receipt-1")),
            CHANNEL,
            address(this),
            provider,
            relay,
            pool,
            1000,
            500
        );

        require(usdc.balanceOf(provider) == 2550, "provider split");
        require(usdc.balanceOf(relay) == 90, "relay split");
        require(usdc.balanceOf(pool) == 60, "pool split");
        require(usdc.balanceOf(treasury) == 300, "treasury split");
        require(token.balanceOf(provider) == 300 * 1e12, "reward amount");
    }

    function testZeroRelayAndPoolGoToTreasuryReward() public {
        address provider = address(0x2001);
        address treasury = address(0x2004);

        TestUSDC usdc = new TestUSDC();
        FandaiToken token = new FandaiToken(address(this));
        FandaiSettlement settlement = new FandaiSettlement(address(usdc), address(token), treasury);
        token.setMinter(address(settlement));
        settlement.setChannel(CHANNEL, _defaultConfig());

        usdc.mint(address(this), 10_000_000);
        usdc.approve(address(settlement), type(uint256).max);
        settlement.settleReceipt(
            keccak256(bytes("receipt-2")),
            CHANNEL,
            address(this),
            provider,
            address(0),
            address(0),
            1000,
            500
        );

        require(usdc.balanceOf(provider) == 2550, "provider split");
        require(usdc.balanceOf(treasury) == 450, "treasury with missing relay pool");
        require(token.balanceOf(provider) == 450 * 1e12, "reward with missing relay pool");
    }

    function testTestnetDeployerWiresOwnershipAndChannel() public {
        FandaiTestnetDeployer deployer = new FandaiTestnetDeployer(address(0x3004));

        FandaiToken token = deployer.token();
        FandaiSettlement settlement = deployer.settlement();

        require(token.owner() == address(this), "token owner");
        require(settlement.owner() == address(this), "settlement owner");
        require(token.minter() == address(settlement), "settlement minter");
        require(settlement.quote(CHANNEL, 1000, 500) == 3000, "default quote");
    }

    function _defaultConfig() internal pure returns (FandaiSettlement.ChannelConfig memory) {
        return
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
            });
    }
}
