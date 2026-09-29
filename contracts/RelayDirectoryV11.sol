// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoRelaySignersV11 {
    function relaySignerOwner(address signer) external view returns (address);
}

/// @notice Permissionless on-chain directory of V11 Relays.
/// @dev No admin and no upgrades. Any Relay owner may announce the public
/// endpoints of a signer it has bound in the settlement contract; an entry
/// stops counting as soon as that binding is revoked. Consumers and Providers
/// discover Relays here instead of trusting whoever publishes a manifest, and
/// verify each one by the signer its /health reports.
contract RelayDirectoryV11 {
    uint256 public constant MAX_RELAYS = 256;
    uint256 public constant MAX_ENDPOINT_BYTES = 200;

    struct Entry { address owner; address signer; string url; string link; uint64 updatedAt; }

    IMycoRelaySignersV11 public immutable settlement;
    Entry[] private entries;
    mapping(address => uint256) private indexOf; // owner => 1-based index

    event RelayAnnounced(address indexed owner, address indexed signer, string url, string link);
    event RelayWithdrawn(address indexed owner);

    constructor(IMycoRelaySignersV11 settlement_) {
        require(address(settlement_).code.length > 0); // settlement has no code
        settlement = settlement_;
    }

    function announce(address signer, string calldata url, string calldata link) external {
        require(settlement.relaySignerOwner(signer) == msg.sender); // signer not bound to caller
        require(bytes(url).length > 8 && bytes(url).length <= MAX_ENDPOINT_BYTES
            && bytes(link).length <= MAX_ENDPOINT_BYTES); // bad endpoint
        uint256 index = indexOf[msg.sender];
        if (index == 0) {
            require(entries.length < MAX_RELAYS); // directory full
            entries.push();
            index = entries.length;
            indexOf[msg.sender] = index;
        }
        entries[index - 1] = Entry(msg.sender, signer, url, link, uint64(block.timestamp));
        emit RelayAnnounced(msg.sender, signer, url, link);
    }

    function withdraw() external {
        uint256 index = indexOf[msg.sender];
        require(index != 0); // not announced
        uint256 last = entries.length;
        if (index != last) {
            entries[index - 1] = entries[last - 1];
            indexOf[entries[index - 1].owner] = index;
        }
        entries.pop();
        delete indexOf[msg.sender];
        emit RelayWithdrawn(msg.sender);
    }

    function relayCount() external view returns (uint256) {
        return entries.length;
    }

    /// @return entry the announcement; active whether its signer is still bound to the owner
    function relayAt(uint256 index) external view returns (Entry memory entry, bool active) {
        entry = entries[index];
        active = settlement.relaySignerOwner(entry.signer) == entry.owner;
    }
}
