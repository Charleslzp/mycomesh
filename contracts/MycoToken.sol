// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice MYCO: 1,000,000,000 maximum supply, no premine. Only the emission
/// contract mints, block by block, on a halving schedule.
contract MycoToken {
    string public constant name = "MycoMesh";
    string public constant symbol = "MYCO";
    uint8 public constant decimals = 18;
    uint256 public constant MAX_SUPPLY = 1_000_000_000e18;

    address public immutable minter;
    uint256 public totalSupply;
    uint256 public totalMinted; // burns never make room for more minting
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(address minter_) {
        require(minter_ != address(0)); // no minter
        minter = minter_;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter && to != address(0)); // only the emission schedule mints
        require(totalMinted + amount <= MAX_SUPPLY); // supply cap
        totalMinted += amount;
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount); // allowance
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    /// @notice Anyone may burn their own tokens, e.g. a treasury retiring bought-back supply.
    function burn(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0)); // burn with burn()
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
