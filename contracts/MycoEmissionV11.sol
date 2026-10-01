// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoUUPSUpgradeable} from "./MycoUpgradeable.sol";
import {MycoReleaseV11} from "./MycoReleaseV11.sol";

interface IMycoMintableV11 {
    function mint(address to, uint256 amount) external;
}

interface IMycoStablecoinV11 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice MYCO emission, Bitcoin-style: a fixed schedule of halvings, paid for
/// work the chain can see, one hourly block at a time.
/// @dev Schedule: the first era lasts one week and every era halves the rate;
/// era lengths double (1, 2, 4 ... weeks) until they reach four years, then stay
/// there. Every era up to 128 weeks mints the same amount; the total converges
/// to 1,000,000,000 MYCO and is never exceeded.
///
/// Each block's tokens go 80% to Consumers (by fees they paid that were
/// released), 10% to Providers (by fees they earned, times their success rate,
/// claimable 48 hours after the block), 7% to Relays (fees they dispatched) and
/// 3% to Bridges (keeper calls). A block whose released fees fall short of
/// minSpendPerBlock pays out only that fraction; the rest rolls into later
/// blocks, so quiet hours cannot be farmed cheaply and nothing is lost.
contract MycoEmissionV11 is MycoUUPSUpgradeable {
    uint256 public constant BLOCK = 1 hours;
    uint256 public constant FIRST_ERA = 7 days;
    uint256 public constant MAX_ERA = 1461 days;
    /// @dev 1e27 wei over 8 equal eras of 604,800 s-equivalents plus the 4-year tail (5,824,575 s at the first rate).
    uint256 public constant FIRST_RATE = 171686346214101458046; // floor(1e27 / 5_824_575): MYCO wei per second in era 0
    uint256 public constant PROVIDER_DELAY = 48 hours;
    uint8 public constant CONSUMER = 0;
    uint8 public constant PROVIDER = 1;
    uint8 public constant RELAY = 2;
    uint8 public constant BRIDGE = 3;
    uint256 public constant KEEPER_WEIGHT = 1_000_000; // a jury draw counts like a 1-unit-USDC release

    struct ProviderRecord { uint128 releases; uint128 frauds; }

    // ---- storage (append-only across upgrades) ----
    IMycoMintableV11 public token;
    IMycoStablecoinV11 public stablecoin;
    address public registry;
    uint64 public genesis;
    uint64 public accounted; // blocks before this have their schedule assigned (to a pool or the carry)
    uint64 public openBlock;
    bool public hasOpen;
    uint256 public carry;
    uint256 public minSpendPerBlock;
    uint256 public bountyPerCall;
    uint256 public bountyReserve;
    mapping(uint64 => uint256) public spendAt;
    mapping(uint64 => uint256) public poolAt;
    mapping(uint64 => mapping(uint8 => uint256)) public totalPoints;
    mapping(uint64 => mapping(uint8 => mapping(address => uint256))) public points;
    mapping(address => ProviderRecord) public providerRecord;
    mapping(address => uint256) public bountyOwed;
    mapping(address => uint256) public mycoBountyOwed; // v7: MYCO for hunters whose capability case convicted
    uint256[29] private __gap;

    event Points(uint64 indexed block_, uint8 indexed role, address indexed account, uint256 amount);
    event BlockFinalized(uint64 indexed block_, uint256 spend, uint256 pool, uint256 carry);
    event Claimed(address indexed account, uint8 indexed role, uint256 amount);
    event BountyEarned(address indexed keeper, uint256 amount);
    event HunterRewarded(address indexed hunter, address indexed provider, uint256 amount);

    modifier onlyRegistry() {
        require(msg.sender == registry); // not the registry
        _;
    }

    constructor() {}

    function initialize(address admin_, address registry_, address stablecoin_, uint64 genesis_, uint256 minSpend,
        uint256 bounty) external reinitializer(1)
    {
        _initializeAdmin(admin_);
        registry = registry_;
        stablecoin = IMycoStablecoinV11(stablecoin_);
        genesis = genesis_;
        minSpendPerBlock = minSpend;
        bountyPerCall = bounty;
    }

    // ---------------- admin ----------------

    function setToken(address token_) external onlyProxy onlyAdmin {
        require(address(token) == address(0) && token_ != address(0)); // token is set once
        token = IMycoMintableV11(token_);
    }

    function setMinSpendPerBlock(uint256 value) external onlyProxy onlyAdmin { minSpendPerBlock = value; }
    function setBountyPerCall(uint256 value) external onlyProxy onlyAdmin { bountyPerCall = value; }

    /// @notice The treasury (or anyone) funds keeper bounties in the stablecoin.
    function fundBounties(uint256 amount) external onlyProxy {
        require(stablecoin.transferFrom(msg.sender, address(this), amount)); // funding failed
        bountyReserve += amount;
    }

    // ---------------- schedule ----------------

    function currentBlock() public view returns (uint64) {
        return uint64((block.timestamp - genesis) / BLOCK);
    }

    /// @notice MYCO (wei) the schedule releases in [genesis + from, genesis + to), in seconds since genesis.
    function scheduled(uint256 from, uint256 to) public pure returns (uint256 total) {
        uint256 start;
        for (uint256 era; era < 96 && start < to; ++era) {
            uint256 length = era < 20 && (FIRST_ERA << era) < MAX_ERA ? FIRST_ERA << era : MAX_ERA;
            uint256 end = start + length;
            uint256 a = from > start ? from : start;
            uint256 b = to < end ? to : end;
            if (b > a) total += (b - a) * (FIRST_RATE >> era);
            start = end;
        }
    }

    function _blocks(uint64 from, uint64 to) internal pure returns (uint256) {
        return scheduled(uint256(from) * BLOCK, uint256(to) * BLOCK);
    }

    // ---------------- recording (the registry forwards settlement events) ----------------

    function recordRelease(address consumer, address provider, address relay, address caller, uint256 fee)
        external onlyProxy onlyRegistry
    {
        uint64 b = _advance();
        spendAt[b] += fee;
        _add(b, CONSUMER, consumer, fee);
        _add(b, PROVIDER, provider, fee);
        _add(b, RELAY, relay, fee);
        _add(b, BRIDGE, caller, fee);
        ++providerRecord[provider].releases;
        if (caller != relay) _bounty(caller); // a Relay releasing its own receipts is already paid
    }

    /// @notice A release batch, aggregated per (Provider, Consumer, Relay): one call however many receipts.
    function recordReleases(MycoReleaseV11[] calldata items, address caller) external onlyProxy onlyRegistry {
        uint64 b = _advance();
        uint256 total;
        bool ownReceipts;
        for (uint256 i; i < items.length; ++i) {
            MycoReleaseV11 calldata item = items[i];
            total += item.fee;
            _point(b, CONSUMER, item.consumer, item.fee);
            _point(b, PROVIDER, item.provider, item.fee);
            _point(b, RELAY, item.relay, item.fee);
            providerRecord[item.provider].releases += uint128(item.count);
            if (item.relay == caller) ownReceipts = true;
        }
        spendAt[b] += total;
        totalPoints[b][CONSUMER] += total;
        totalPoints[b][PROVIDER] += total;
        totalPoints[b][RELAY] += total;
        _add(b, BRIDGE, caller, total);
        if (!ownReceipts) _bounty(caller); // a Relay releasing its own receipts is already paid
    }

    function recordFraud(address provider) external onlyProxy onlyRegistry {
        ++providerRecord[provider].frauds;
    }

    /// @notice A capability case convicted ``provider``: it counts as a fraud against its success rate, and
    /// the hunter earns one block's scheduled emission, taken from the undistributed carry (quiet hours and
    /// the shares Providers forfeited), so the schedule's total never grows.
    function recordConviction(address provider, address hunter) external onlyProxy onlyRegistry {
        ++providerRecord[provider].frauds;
        uint64 b = _advance();
        uint256 bounty = _blocks(b, b + 1);
        if (bounty > carry) bounty = carry;
        carry -= bounty;
        mycoBountyOwed[hunter] += bounty;
        emit HunterRewarded(hunter, provider, bounty);
    }

    function claimMycoBounty() external onlyProxy returns (uint256 amount) {
        amount = mycoBountyOwed[msg.sender];
        require(amount > 0); // nothing owed
        mycoBountyOwed[msg.sender] = 0;
        token.mint(msg.sender, amount);
    }

    function recordKeeperCall(address caller) external onlyProxy onlyRegistry {
        _add(_advance(), BRIDGE, caller, KEEPER_WEIGHT);
        _bounty(caller);
    }

    /// @notice Finalize the last active block so its rewards become claimable; anyone may call.
    function poke() external onlyProxy {
        _advance();
    }

    /// @dev Points without the block total, for callers that add the total once.
    function _point(uint64 b, uint8 role, address account, uint256 amount) internal {
        points[b][role][account] += amount;
        emit Points(b, role, account, amount);
    }

    function _add(uint64 b, uint8 role, address account, uint256 amount) internal {
        points[b][role][account] += amount;
        totalPoints[b][role] += amount;
        emit Points(b, role, account, amount);
    }

    function _bounty(address keeper) internal {
        uint256 bounty = bountyPerCall;
        if (bounty == 0 || bountyReserve < bounty) return;
        bountyReserve -= bounty;
        bountyOwed[keeper] += bounty;
        emit BountyEarned(keeper, bounty);
    }

    /// @dev Finalizes the previous active block and opens the current one.
    function _advance() internal returns (uint64 b) {
        b = currentBlock();
        if (hasOpen && openBlock < b) {
            uint64 last = openBlock;
            uint256 pool = _blocks(last, last + 1) + carry;
            uint256 spend = spendAt[last];
            uint256 minimum = minSpendPerBlock;
            uint256 paid = minimum == 0 || spend >= minimum ? pool : pool * spend / minimum;
            carry = pool - paid;
            poolAt[last] = paid;
            accounted = last + 1;
            hasOpen = false;
            emit BlockFinalized(last, spend, paid, carry);
        }
        if (!hasOpen) {
            if (b > accounted) carry += _blocks(accounted, b); // idle blocks roll forward
            accounted = b;
            openBlock = b;
            hasOpen = true;
        }
    }

    // ---------------- claims ----------------

    function share(uint8 role) public pure returns (uint256) {
        return role == CONSUMER ? 8_000 : role == PROVIDER ? 1_000 : role == RELAY ? 700 : 300;
    }

    /// @notice MYCO an account could claim for one block and role now (0 if not yet final or already claimed).
    function claimable(uint64 b, uint8 role, address account) public view returns (uint256 amount) {
        (amount, ) = _entitlement(b, role, account);
    }

    /// @return amount what the account receives; forfeited the Provider success-rate shortfall
    function _entitlement(uint64 b, uint8 role, address account) internal view returns (uint256 amount, uint256 forfeited) {
        uint256 held = points[b][role][account];
        if (held == 0 || b >= accounted || role > BRIDGE) return (0, 0);
        if (role == PROVIDER && block.timestamp < genesis + (uint256(b) + 1) * BLOCK + PROVIDER_DELAY) return (0, 0);
        uint256 full = poolAt[b] * share(role) / 10_000 * held / totalPoints[b][role];
        amount = full;
        if (role == PROVIDER) {
            ProviderRecord memory record = providerRecord[account];
            amount = full * record.releases / (uint256(record.releases) + record.frauds);
            forfeited = full - amount;
        }
    }

    function claim(uint64[] calldata blocks, uint8 role) external onlyProxy returns (uint256 total) {
        _advance();
        for (uint256 i; i < blocks.length; ++i) {
            uint64 b = blocks[i];
            (uint256 amount, uint256 forfeited) = _entitlement(b, role, msg.sender);
            if (amount == 0 && forfeited == 0) continue;
            points[b][role][msg.sender] = 0;
            carry += forfeited; // the success-rate shortfall stays in the schedule
            total += amount;
        }
        if (total > 0) token.mint(msg.sender, total);
        emit Claimed(msg.sender, role, total);
    }

    function claimBounty() external onlyProxy returns (uint256 amount) {
        amount = bountyOwed[msg.sender];
        require(amount > 0); // nothing owed
        bountyOwed[msg.sender] = 0;
        require(stablecoin.transfer(msg.sender, amount)); // transfer failed
    }
}
