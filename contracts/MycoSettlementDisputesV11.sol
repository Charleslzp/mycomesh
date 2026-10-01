// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementBaseV11} from "./MycoSettlementBaseV11.sol";

/// @notice The dispute half of the V11 settlement: evidence, Provider-AI jury votes and timeouts.
/// @dev Reached only by delegatecall from ``MycoSettlementV11`` behind the settlement proxy, so it runs on
/// the settlement's storage. Called directly it sees its own empty storage and can do nothing.
contract MycoSettlementDisputesV11 is MycoSettlementBaseV11 {
    // ---------------- views ----------------

    function settlementInfo(bytes32 key) external view returns (Settlement memory) { return settlements[key]; }

    /// @notice The parties a jury must exclude, and whether the case is open.
    function caseParties(bytes32 key) external view returns (
        address owner, address consumerKey, address provider, address providerSigner,
        address relay, address relaySigner, bool disputed
    ) {
        Settlement storage record = settlements[key];
        return (record.owner, record.key, record.provider, record.providerSigner,
            record.relay, record.relaySigner, record.status == Status.Disputed);
    }
    function disputeInfo(bytes32 key) external view returns (Dispute memory) { return disputes[key]; }
    function probeRootCount(address relay) external view returns (uint256) { return probeRoots[relay].length; }


    function _reportId(bytes32 key, address reporter, bytes32 evidenceHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, reporter, evidenceHash));
    }

    // ---------------- disputes ----------------

    function openDispute(bytes32 key, bytes32 evidenceHash) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(msg.sender == record.owner); // only settlement owner
        require(block.timestamp < record.releaseAt); // dispute window closed
        require(evidenceHash != bytes32(0)); // empty evidence
        require(record.releaseAt <= type(uint64).max - settings.arbitrationTimeout); // timestamp overflow
        Dispute storage dispute = disputes[key];
        record.status = Status.Disputed;
        dispute.openedAt = uint64(block.timestamp);
        dispute.resolveAt = record.releaseAt + settings.arbitrationTimeout;
        bytes32 reportId = _reportId(key, msg.sender, evidenceHash);
        reports[key][reportId] = Report(msg.sender, evidenceHash, false);
        dispute.totalBond = settings.reporterBond;
        totalReporterBonds += settings.reporterBond;
        if (settings.reporterBond > 0) _takeExact(msg.sender, settings.reporterBond);
        emit EvidenceSubmitted(key, reportId, msg.sender, evidenceHash, settings.reporterBond);
        juryRegistry.requestJury(key, record.provider);
        emit DisputeOpened(key, dispute.resolveAt);
    }

    /// @notice Submit one consistent quorum of selected Provider-AI votes.
    function voteDisputeBySig(bytes32 key, DisputeVotePermit[] calldata permits) external nonReentrant {
        uint16 threshold = juryRegistry.threshold();
        require(permits.length == threshold); // bad vote batch
        bytes32 assignment = juryRegistry.assignmentHash(key);
        require(assignment != bytes32(0) && permits[0].assignmentHash == assignment); // wrong jury assignment
        Settlement storage record = settlements[key];
        Dispute storage dispute = disputes[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp < dispute.resolveAt); // adjudication expired
        bool confirmed = permits[0].confirmed;
        bytes32 reportId = permits[0].reportId;
        bytes32 decisionHash = permits[0].decisionHash;
        require(decisionHash != bytes32(0)); // empty decision
        if (confirmed) require(reports[key][reportId].reporter != address(0)); // unknown report
        else require(reportId == bytes32(0)); // unexpected report
        for (uint256 i; i < permits.length; ++i) {
            DisputeVotePermit calldata permit = permits[i];
            require(permit.assignmentHash == assignment && permit.confirmed == confirmed
                && permit.reportId == reportId && permit.decisionHash == decisionHash); // inconsistent verdict
            _recordVote(key, record, permit);
        }
        if (confirmed) confirmationVotes[key][reportId] += threshold;
        else dispute.dismissVotes += threshold;
        if (confirmed) {
            dispute.winningReportId = reportId;
            _confirm(key, record, dispute);
        } else {
            _dismiss(key, record, dispute);
        }
    }

    function _recordVote(bytes32 key, Settlement storage record, DisputeVotePermit calldata permit) internal {
        require(permit.deadline >= block.timestamp); // vote authorization expired
        address judge = _recover(_typedDataHash(keccak256(abi.encode(DISPUTE_VOTE_TYPEHASH, key,
            permit.assignmentHash, permit.confirmed, permit.reportId, permit.decisionHash,
            permit.nonce, permit.deadline))), permit.signature);
        require(judge != address(0) && permit.nonce == adjudicatorNonce[key][judge]++); // bad or replayed vote
        require(juryRegistry.isVoteSigner(key, judge) && _independent(record, judge)); // not a selected independent juror
        require(disputeVotes[key][judge] == 0); // already voted
        disputeVotes[key][judge] = permit.confirmed ? 1 : 2;
        emit DisputeVote(key, judge, permit.confirmed, permit.reportId, permit.decisionHash);
    }

    function claimDisputeBond(bytes32 key, bytes32 reportId) external nonReentrant {
        Status status = settlements[key].status;
        require(status == Status.Confirmed || status == Status.TimedOut || status == Status.JuryUnavailable); // bond not refundable
        Report storage report = reports[key][reportId];
        require(report.reporter != address(0) && !report.bondClaimed); // no refundable bond
        report.bondClaimed = true;
        uint256 bond = disputes[key].totalBond;
        totalReporterBonds -= bond;
        _credit(report.reporter, bond);
        emit DisputeBondReturned(key, reportId, report.reporter);
    }

    /// @notice Silence is not a verdict: an assigned but silent jury releases,
    /// a case that never got a jury refunds.  No penalty either way.
    function resolveTimedOutDispute(bytes32 key) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Disputed); // not disputed
        require(block.timestamp >= disputes[key].resolveAt); // adjudication pending
        Status status = Status.TimedOut;
        if (juryRegistry.assignmentHash(key) == bytes32(0)) {
            status = Status.JuryUnavailable;
            record.status = status;
            _refund(record);
        } else {
            _release(key, record, status);
        }
        emit DisputeResolved(key, status, 0, 0);
    }

    function _confirm(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        record.status = Status.Confirmed;
        _refund(record);
        uint256 penalty = _portion(record.fee, settings.slashBps);
        if (penalty > settings.slashCap) penalty = settings.slashCap;
        penalty = _takeHoldback(record.provider, penalty);
        uint256 bounty = _portion(penalty, settings.reporterBountyBps);
        dispute.penalty = penalty;
        dispute.bounty = bounty;
        _credit(reports[key][dispute.winningReportId].reporter, bounty);
        _credit(settings.penaltyRecipient, penalty - bounty);
        // Earned trust restarts from the base allowance.
        cleanVolume[record.provider] = 0;
        _notifyFraud(record.provider);
        emit DisputeResolved(key, Status.Confirmed, penalty, bounty);
    }

    function _dismiss(bytes32 key, Settlement storage record, Dispute storage dispute) internal {
        _release(key, record, Status.Dismissed);
        totalReporterBonds -= dispute.totalBond;
        _credit(settings.penaltyRecipient, dispute.totalBond);
        emit DisputeResolved(key, Status.Dismissed, 0, 0);
    }

    function _independent(Settlement storage record, address judge) internal view returns (bool) {
        return judge != record.owner && judge != record.key && judge != record.provider
            && judge != record.providerSigner && judge != record.relay && judge != record.relaySigner
            && providerSignerOwner[judge] != record.provider && judge != settings.penaltyRecipient;
    }

}
