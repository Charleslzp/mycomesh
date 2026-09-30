// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoProxiable {
    function proxiableUUID() external view returns (bytes32);
}

/// @dev keccak256("eip1967.proxy.implementation") - 1, per ERC-1967.
bytes32 constant MYCO_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
/// @dev keccak256("myco.upgrade.sunset") - 1: outside the sequential layout, so no version can collide with it.
bytes32 constant MYCO_SUNSET_SLOT = 0x80ac8f62773d70b9b08201823b2bc5c1cca6a0eb4bb2846b8da7b95abe6dbe68;

/// @notice Minimal ERC-1967 proxy. All logic and the upgrade entry point live
/// in the UUPS implementation; the proxy only forwards calls.
contract MycoERC1967Proxy {
    event Upgraded(address indexed implementation);

    constructor(address implementation, bytes memory initData) {
        require(implementation.code.length > 0); // implementation has no code
        require(IMycoProxiable(implementation).proxiableUUID() == MYCO_IMPLEMENTATION_SLOT); // not UUPS
        assembly {
            sstore(MYCO_IMPLEMENTATION_SLOT, implementation)
        }
        emit Upgraded(implementation);
        if (initData.length > 0) {
            (bool ok, bytes memory result) = implementation.delegatecall(initData);
            if (!ok) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }

    fallback() external payable {
        assembly {
            let implementation := sload(MYCO_IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// @notice UUPS base with one admin key and no upgrade delay.
/// @dev Deliberately simple for the early network: the admin can upgrade the
/// implementation (and therefore change any rule, including custody) at once.
/// The exit is one-way: ``renounceUpgrades`` freezes the code forever, and
/// ``renounceAdmin`` then removes the last privileged key. ``setUpgradeSunset``
/// publishes the date upgrades end; it can only ever move earlier.
/// Storage declared here must never be reordered by later versions.
abstract contract MycoUUPSUpgradeable is IMycoProxiable {
    address private immutable self = address(this);

    address public admin;
    uint64 private initializedVersion;
    bool public upgradesRenounced; // packs into slot 0 after admin and initializedVersion

    event Upgraded(address indexed implementation);
    event AdminTransferred(address indexed previousAdmin, address indexed nextAdmin);
    event UpgradesRenounced();
    event UpgradeSunsetSet(uint64 sunset);

    modifier onlyAdmin() {
        require(msg.sender == admin); // not admin
        _;
    }

    modifier onlyProxy() {
        require(address(this) != self && _implementation() == self); // not through the active proxy
        _;
    }

    /// @dev The implementation contract itself can never be initialized.
    modifier reinitializer(uint64 version) {
        require(address(this) != self); // implementation is not initializable
        require(version > initializedVersion); // already initialized
        initializedVersion = version;
        _;
    }

    function proxiableUUID() external view returns (bytes32) {
        require(address(this) == self); // must not be called through a proxy
        return MYCO_IMPLEMENTATION_SLOT;
    }

    function implementation() external view returns (address) {
        return _implementation();
    }

    function initializedVersionOf() external view returns (uint64) {
        return initializedVersion;
    }

    function upgradeToAndCall(address nextImplementation, bytes calldata data) external onlyProxy onlyAdmin {
        uint64 sunset = upgradeSunset();
        require(!upgradesRenounced && (sunset == 0 || block.timestamp < sunset)); // code is frozen
        require(nextImplementation.code.length > 0); // implementation has no code
        require(IMycoProxiable(nextImplementation).proxiableUUID() == MYCO_IMPLEMENTATION_SLOT); // not UUPS
        assembly ("memory-safe") {
            sstore(MYCO_IMPLEMENTATION_SLOT, nextImplementation)
        }
        emit Upgraded(nextImplementation);
        if (data.length > 0) {
            (bool ok, bytes memory result) = nextImplementation.delegatecall(data);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }

    function transferAdmin(address nextAdmin) external onlyProxy onlyAdmin {
        require(nextAdmin != address(0) && nextAdmin != address(this)); // bad admin
        emit AdminTransferred(admin, nextAdmin);
        admin = nextAdmin;
    }

    /// @notice Commit on-chain to the moment upgrades stop; later calls may only bring it forward.
    function setUpgradeSunset(uint64 sunset) external onlyProxy onlyAdmin {
        uint64 current = upgradeSunset();
        require(sunset > block.timestamp && (current == 0 || sunset < current)); // may only move earlier
        assembly ("memory-safe") {
            sstore(MYCO_SUNSET_SLOT, sunset)
        }
        emit UpgradeSunsetSet(sunset);
    }

    function upgradeSunset() public view returns (uint64 sunset) {
        assembly ("memory-safe") {
            sunset := sload(MYCO_SUNSET_SLOT)
        }
    }

    /// @notice Freeze the implementation forever.
    function renounceUpgrades() external onlyProxy onlyAdmin {
        upgradesRenounced = true;
        emit UpgradesRenounced();
    }

    /// @notice Remove the admin key; only possible once the code is frozen.
    function renounceAdmin() external onlyProxy onlyAdmin {
        require(upgradesRenounced); // freeze upgrades first
        emit AdminTransferred(admin, address(0));
        admin = address(0);
    }

    function _initializeAdmin(address admin_) internal {
        require(admin_ != address(0) && admin_ != address(this)); // bad admin
        admin = admin_;
        emit AdminTransferred(address(0), admin_);
    }

    function _implementation() internal view returns (address current) {
        assembly ("memory-safe") {
            current := sload(MYCO_IMPLEMENTATION_SLOT)
        }
    }
}
