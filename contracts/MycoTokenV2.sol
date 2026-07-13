// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Capped MYCO reward token with an immutable mint authority.
/// @dev Deploy with the V3 settlement address as mintAuthority (normally via CREATE2 or a deployment factory).
contract MycoTokenV2 {
    string public constant name = "MycoMesh Token";
    string public constant symbol = "MYCO";
    uint8 public constant decimals = 18;

    address public immutable mintAuthority;
    uint256 public immutable maxSupply;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    modifier onlyMintAuthority() {
        require(msg.sender == mintAuthority, "not mint authority");
        _;
    }

    constructor(address mintAuthority_, uint256 maxSupply_) {
        require(mintAuthority_ != address(0), "zero mint authority");
        require(mintAuthority_.code.length > 0, "authority not contract");
        require(maxSupply_ > 0, "zero max supply");
        mintAuthority = mintAuthority_;
        maxSupply = maxSupply_;
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
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function mint(address to, uint256 amount) external onlyMintAuthority {
        require(to != address(0), "zero to");
        require(totalSupply + amount <= maxSupply, "max supply");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @notice Holders, including the treasury, can only burn their own balance.
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero to");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
