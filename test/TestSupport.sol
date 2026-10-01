// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Shared helpers for the V11 forge suites: the cheatcode interface and an exact-transfer token.

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert() external;
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function getBlockTimestamp() external view returns (uint256);
    function roll(uint256 blockNumber) external;
    function setBlockhash(uint256 blockNumber, bytes32 blockHash) external;
    function chainId(uint256 chainId) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function snapshotState() external returns (uint256);
    function revertToState(uint256 snapshotId) external returns (bool);
}

/// @dev Adversarial test token, local only. Never deployed by this test suite.
contract MockExactToken {
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public feeOnTransfer;
    bool public extraSenderDebit;
    bool public blocked;
    bool public returnFalse;
    address public hookTarget;
    bytes public hookData;
    bool public hookSucceeded;

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        require(!blocked, "token blocked");
        return balances[account];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function setModes(bool fee, bool debit, bool blocked_, bool false_) external {
        feeOnTransfer = fee;
        extraSenderDebit = debit;
        blocked = blocked_;
        returnFalse = false_;
    }

    function setHook(address target, bytes calldata data) external {
        hookTarget = target;
        hookData = data;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return !returnFalse;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        if (allowance[from][msg.sender] != type(uint256).max) allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return !returnFalse;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(!blocked, "token blocked");
        uint256 debit = amount + (extraSenderDebit && amount > 0 ? 1 : 0);
        uint256 credit = amount - (feeOnTransfer && amount > 0 ? 1 : 0);
        require(balances[from] >= debit, "balance");
        balances[from] -= debit;
        balances[to] += credit;
        if (hookTarget != address(0)) (hookSucceeded,) = hookTarget.call(hookData);
    }
}
