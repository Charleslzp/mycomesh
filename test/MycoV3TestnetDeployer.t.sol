// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV3} from "../contracts/MycoSettlementV3.sol";
import {MycoTokenV2} from "../contracts/MycoTokenV2.sol";
import {MycoV3TestnetDeployer} from "../contracts/MycoV3TestnetDeployer.sol";
import {TestUSDC} from "../contracts/TestUSDC.sol";

interface VmV3Deployer {
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
}

contract MycoV3TestnetDeployerTest {
    VmV3Deployer private constant vm = VmV3Deployer(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant TREASURY = address(0x7001);
    address private constant GOVERNANCE = address(0x7002);
    uint16 private constant MAX_CONSUMER_REBATE_BPS = 2_000;
    uint256 private constant MAX_SUPPLY = 1_000_000_000 ether;

    function testAtomicDeploymentClosesImmutableAddressCycle() public {
        MycoV3TestnetDeployer deployer =
            new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);

        TestUSDC stablecoin = deployer.testUSDC();
        MycoSettlementV3 settlement = deployer.settlement();
        MycoTokenV2 token = deployer.token();

        require(address(stablecoin) == deployer.computeCreateAddress(address(deployer), 1), "stablecoin CREATE address");
        require(address(settlement) == deployer.computeCreateAddress(address(deployer), 2), "settlement CREATE address");
        require(address(token) == deployer.computeCreateAddress(address(deployer), 3), "token CREATE address");

        require(address(settlement.stablecoin()) == address(stablecoin), "stablecoin wiring");
        require(address(settlement.rewardToken()) == address(token), "reward wiring");
        require(token.mintAuthority() == address(settlement), "mint authority wiring");
        require(settlement.treasury() == TREASURY, "treasury wiring");
        require(settlement.governance() == GOVERNANCE, "governance wiring");
        require(settlement.maxConsumerRebateBps() == MAX_CONSUMER_REBATE_BPS, "rebate cap wiring");
        require(token.maxSupply() == MAX_SUPPLY, "supply cap wiring");
    }

    function testOnlyDeployedSettlementCanMintRewardToken() public {
        MycoV3TestnetDeployer deployer =
            new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);
        MycoSettlementV3 settlement = deployer.settlement();
        MycoTokenV2 token = deployer.token();
        address holder = address(0x7003);

        vm.expectRevert(bytes("not mint authority"));
        token.mint(holder, 1);

        vm.prank(address(settlement));
        token.mint(holder, 1);
        require(token.balanceOf(holder) == 1, "settlement mint failed");
    }

    function testInitialChannelAcceptsReservationImmediately() public {
        MycoV3TestnetDeployer deployer =
            new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);
        TestUSDC stablecoin = deployer.testUSDC();
        MycoSettlementV3 settlement = deployer.settlement();
        bytes32 channel = deployer.CODEX_STANDARD_V1();

        require(settlement.latestChannelVersion(channel) == 1, "initial version missing");
        require(settlement.quote(channel, 1, 1_000, 500) == 3_000, "initial pricing missing");

        stablecoin.mint(address(this), 5_000);
        stablecoin.approve(address(settlement), 5_000);
        settlement.deposit(5_000);
        bytes32 salt = keccak256("immediately-usable");
        bytes32 requestHash = keccak256("immediately-usable-request");
        bytes32 reservationId = settlement.createReservation(
            salt, address(0x7004), channel, requestHash, 1, 5_000, uint64(block.timestamp + 1 days), false
        );

        (address consumer,,,,,,, bool closed,) = settlement.reservations(reservationId);
        require(consumer == address(this) && !closed, "initial reservation failed");
    }

    function testCreateAddressHelperRejectsUnsupportedRlpNonces() public {
        MycoV3TestnetDeployer deployer =
            new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);

        vm.expectRevert(bytes("unsupported nonce"));
        deployer.computeCreateAddress(address(deployer), 0);
        vm.expectRevert(bytes("unsupported nonce"));
        deployer.computeCreateAddress(address(deployer), 128);
    }

    function testDeploymentParametersAreRejectedBeforeChildCreation() public {
        vm.expectRevert(bytes("zero treasury"));
        new MycoV3TestnetDeployer(address(0), GOVERNANCE, MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);

        vm.expectRevert(bytes("zero governance"));
        new MycoV3TestnetDeployer(TREASURY, address(0), MAX_CONSUMER_REBATE_BPS, MAX_SUPPLY);

        vm.expectRevert(bytes("bad rebate cap"));
        new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, 999, MAX_SUPPLY);

        vm.expectRevert(bytes("zero max supply"));
        new MycoV3TestnetDeployer(TREASURY, GOVERNANCE, MAX_CONSUMER_REBATE_BPS, 0);
    }
}
