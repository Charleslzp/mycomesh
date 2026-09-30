// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMycoSettlementProbesV11 {
    function caseParties(bytes32 key) external view returns (
        address owner, address consumerKey, address provider, address providerSigner,
        address relay, address relaySigner, bool disputed
    );
    function settlementInfo(bytes32 key) external view returns (ProbeSettlement memory);
}

struct ProbeSettlement {
    address owner; address key; address provider; address providerSigner; address relay; address relaySigner;
    bytes32 requestId; bytes32 requestHash; bytes32 authorizationHash; bytes32 responseHash;
    uint256 fee; uint64 issuedAt; uint64 settledAt; uint64 releaseAt; uint8 status;
}

/// @notice Public, self-verifying record of Relay probe verdicts.
/// @dev No admin and no upgrades. Only the Relay that dispatched a probe (a
/// settlement it voided with a committed probe key) may record its verdict,
/// once. The evidence (question parameters, Provider-signed receipt and both
/// plaintexts) is published by that Relay under ``evidenceHash``, so anyone can
/// re-grade it: a Relay cannot frame an honest Provider, because it cannot
/// forge the Provider's signature on a wrong answer.
contract ProbeLedgerV11 {
    uint8 private constant STATUS_VOIDED = 8;
    uint8 public constant PASS = 1;
    uint8 public constant WRONG = 2;

    IMycoSettlementProbesV11 public immutable settlement;
    mapping(bytes32 => uint8) public verdictOf;

    event ProbeRecorded(address indexed provider, address indexed relay, bytes32 indexed settlementKey,
        bytes32 evidenceHash, uint8 verdict);

    constructor(IMycoSettlementProbesV11 settlement_) {
        require(address(settlement_).code.length > 0); // settlement has no code
        settlement = settlement_;
    }

    function record(bytes32 key, bytes32 evidenceHash, uint8 verdict) external {
        require(verdict == PASS || verdict == WRONG); // bad verdict
        require(verdictOf[key] == 0 && evidenceHash != bytes32(0)); // already recorded or empty
        ProbeSettlement memory s = settlement.settlementInfo(key);
        require(s.status == STATUS_VOIDED && s.relay == msg.sender); // not this Relay's voided probe
        verdictOf[key] = verdict;
        emit ProbeRecorded(s.provider, msg.sender, key, evidenceHash, verdict);
    }
}
