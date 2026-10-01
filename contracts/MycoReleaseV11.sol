// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Released fees aggregated per (Provider, Consumer, Relay): what a release batch reports to
/// the registry and the emission once, instead of once per receipt.
struct MycoReleaseV11 {
    address provider;
    address consumer;
    address relay;
    uint256 fee;
    uint256 count;
}
