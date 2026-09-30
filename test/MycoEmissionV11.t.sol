// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoEmissionV11 as Emission} from "../contracts/MycoEmissionV11.sol";
import {MycoToken} from "../contracts/MycoToken.sol";
import {MycoERC1967Proxy} from "../contracts/MycoUpgradeable.sol";
import {MockExactToken as USDC, Vm} from "./TestSupport.sol";

/// The test contract plays the registry, forwarding settlement events.
contract MycoEmissionV11Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant ADMIN = address(0xAD);
    address constant ALICE = address(0xA1);   // consumer
    address constant BOB = address(0xB0B);    // consumer
    address constant PROV = address(0xB0);    // provider
    address constant RELAY = address(0xA0);
    address constant KEEPER = address(0xEE);
    uint64 constant GENESIS = 1_000_000;
    uint256 constant MIN_SPEND = 1_000_000;

    Emission e; MycoToken token; USDC usdc;

    function setUp() public {
        vm.warp(GENESIS);
        usdc = new USDC();
        Emission implementation = new Emission();
        e = Emission(address(new MycoERC1967Proxy(address(implementation), abi.encodeCall(
            Emission.initialize, (ADMIN, address(this), address(usdc), GENESIS, MIN_SPEND, 10_000)))));
        token = new MycoToken(address(e));
        vm.prank(ADMIN); e.setToken(address(token));
    }

    function _block(uint256 b) internal { vm.warp(GENESIS + b * 1 hours + 60); }

    function _claim(address who, uint64 b, uint8 role) internal returns (uint256) {
        uint64[] memory blocks = new uint64[](1);
        blocks[0] = b;
        vm.prank(who);
        return e.claim(blocks, role);
    }

    function test_schedule_halves_with_doubling_eras_and_converges_to_one_billion() public view {
        uint256 week = 7 days;
        uint256 era0 = e.scheduled(0, week);
        require(era0 == e.FIRST_RATE() * week, "era 0");
        require(era0 / 1e18 == 103_835_902, "about 10.4% of supply in week one");
        // Equal eras, up to the wei lost when the per-second rate is halved.
        require(era0 - e.scheduled(week, 3 * week) < 4 weeks, "era 1: half the rate for twice as long");
        require(era0 - e.scheduled(3 * week, 7 * week) < 8 weeks, "era 2");
        uint256 lifetime = e.scheduled(0, 300 * 365 days);
        require(lifetime <= 1e27 && lifetime > 1e27 - 1e21, "converges to 1,000,000,000 MYCO");
        // After 128-week eras the length stays four years: era 8 mints 0.815 of era 0.
        uint256 start8 = 255 * week;
        require(e.scheduled(start8, start8 + 1461 days) == (e.FIRST_RATE() >> 8) * 1461 days, "four-year eras");
    }

    function test_block_rewards_split_80_10_7_3_by_released_fees() public {
        _block(0);
        e.recordRelease(ALICE, PROV, RELAY, RELAY, 3_000_000);
        e.recordRelease(BOB, PROV, RELAY, KEEPER, 1_000_000);
        _block(1);
        e.poke();
        uint256 pool = e.poolAt(0);
        require(pool == e.scheduled(0, 1 hours), "a busy block pays its full schedule");
        require(_claim(ALICE, 0, 0) == pool * 8_000 / 10_000 * 3 / 4, "Alice: 80% x 3/4");
        require(_claim(BOB, 0, 0) == pool * 8_000 / 10_000 / 4, "Bob: 80% x 1/4");
        require(_claim(RELAY, 0, 2) == pool * 700 / 10_000, "Relay: 7%");
        require(_claim(KEEPER, 0, 3) == pool * 300 / 10_000 / 4, "keeper: 3% x its share of calls");
        require(_claim(ALICE, 0, 0) == 0, "claimed once");
        require(token.balanceOf(ALICE) > 0 && token.totalMinted() <= e.scheduled(0, 2 hours), "never above schedule");
    }

    function test_providers_wait_48_hours_and_are_paid_by_success_rate() public {
        _block(0);
        e.recordRelease(ALICE, PROV, RELAY, RELAY, 2_000_000);
        _block(1);
        e.recordRelease(ALICE, PROV, RELAY, RELAY, 2_000_000);
        e.recordFraud(PROV); // one confirmed fraud against two releases: two thirds
        require(_claim(PROV, 0, 1) == 0, "not before 48 hours");
        vm.warp(GENESIS + 1 hours + 48 hours);
        uint256 full = e.poolAt(0) * 1_000 / 10_000;
        uint256 carryBefore = e.carry();
        require(_claim(PROV, 0, 1) == full * 2 / 3, "success rate applied");
        require(e.carry() >= carryBefore + full - full * 2 / 3, "shortfall stays in the schedule");
    }

    function test_quiet_blocks_pay_a_fraction_and_roll_the_rest_forward() public {
        _block(0);
        e.recordRelease(ALICE, PROV, RELAY, RELAY, MIN_SPEND / 4); // a quarter of the minimum
        _block(1);
        e.recordRelease(BOB, PROV, RELAY, RELAY, MIN_SPEND);
        uint256 scheduled0 = e.scheduled(0, 1 hours);
        require(e.poolAt(0) == scheduled0 / 4, "quarter paid");
        require(e.carry() == scheduled0 - scheduled0 / 4, "rest carried");
        _block(5); // blocks 2-4 idle
        e.poke();
        require(e.poolAt(1) == e.scheduled(1 hours, 2 hours) + scheduled0 - scheduled0 / 4, "carry paid by a busy block");
        require(e.carry() == e.scheduled(2 hours, 5 hours), "idle blocks roll forward");
    }

    function test_keepers_earn_funded_stablecoin_bounties() public {
        usdc.mint(address(this), 1_000_000);
        usdc.approve(address(e), type(uint256).max);
        e.fundBounties(25_000);
        _block(0);
        e.recordRelease(ALICE, PROV, RELAY, KEEPER, 1_000_000); // keeper released: bounty
        e.recordRelease(ALICE, PROV, RELAY, RELAY, 1_000_000);  // the Relay's own release: already paid
        e.recordKeeperCall(KEEPER);                             // a jury draw
        require(e.bountyOwed(KEEPER) == 20_000 && e.bountyOwed(RELAY) == 0, "bounties");
        vm.prank(KEEPER);
        e.claimBounty();
        require(usdc.balanceOf(KEEPER) == 20_000, "paid in stablecoin");
        e.recordKeeperCall(KEEPER); // reserve 5_000 < 10_000: nothing owed, nothing fails
        require(e.bountyOwed(KEEPER) == 0, "unfunded bounties are skipped");
    }

    function test_only_the_registry_records_and_only_emission_mints() public {
        vm.prank(ALICE);
        vm.expectRevert();
        e.recordRelease(ALICE, PROV, RELAY, RELAY, 1);
        vm.expectRevert();
        token.mint(ALICE, 1);
        vm.prank(ADMIN);
        vm.expectRevert();
        e.setToken(address(1)); // set once
    }
}
