// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProviderJuryRegistryV11, MycoSettlementBaseV11} from "./MycoSettlementBaseV11.sol";

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
        CapabilityCase storage item = capabilityCases[key];
        if (item.status != CaseStatus.None) {
            return (item.hunter, address(0), item.provider, item.providerSigner, address(0), address(0),
                item.status == CaseStatus.Open);
        }
        Settlement storage record = settlements[key];
        return (record.owner, record.key, record.provider, record.providerSigner,
            record.relay, record.relaySigner, record.status == Status.Disputed);
    }
    function capabilityCaseInfo(bytes32 caseId) external view returns (CapabilityCase memory) { return capabilityCases[caseId]; }
    function disputeInfo(bytes32 key) external view returns (Dispute memory) { return disputes[key]; }


    function _reportId(bytes32 key, address reporter, bytes32 evidenceHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, reporter, evidenceHash));
    }

    // ---------------- disputes ----------------

    function openDispute(bytes32 key, bytes32 evidenceHash) external nonReentrant {
        Settlement storage record = settlements[key];
        require(record.status == Status.Pending); // not pending
        require(msg.sender == record.owner || msg.sender == oracleDisputer[key]); // only the payer (or its disputer)
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
        require(_independent(record, _countVote(key, permit))); // not an independent juror
    }

    /// @dev Checks a drawn juror's signed vote, once; returns the juror.
    function _countVote(bytes32 key, DisputeVotePermit calldata permit) internal returns (address judge) {
        require(permit.deadline >= block.timestamp); // vote authorization expired
        judge = _recover(_typedDataHash(keccak256(abi.encode(DISPUTE_VOTE_TYPEHASH, key,
            permit.assignmentHash, permit.confirmed, permit.reportId, permit.decisionHash,
            permit.nonce, permit.deadline))), permit.signature);
        require(judge != address(0) && permit.nonce == adjudicatorNonce[key][judge]++); // bad or replayed vote
        require(juryRegistry.isVoteSigner(key, judge)); // not a selected juror
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


    // ---------------- capability cases (open probing) ----------------
    //
    // One wrong answer proves nothing: honest frontier models miss some hard questions too. A hunter that
    // suspects a Provider of serving a weaker model than its tier accuses it with every probe the hunter
    // voided on it over closed days. Drawn jurors serve the same tier: each answers the same questions
    // with its own model as a control group, and votes to convict only when the accused did significantly
    // worse. Since the chain counts each hunter's voids, a hunter cannot leave out the probes it lost, and
    // hard questions cost the control group as much as the accused.

    uint16 public constant MIN_CASE_PROBES = 20;
    uint16 public constant MAX_CASE_PROBES = 120;
    uint64 public constant MAX_CASE_DAYS = 30;

    function capabilityCaseId(address hunter, address provider, uint64 fromDay, uint64 toDay) public pure returns (bytes32) {
        return keccak256(abi.encode("mycomesh.capability-case", hunter, provider, fromDay, toDay));
    }

    /// @param keys every probe the caller voided on ``provider`` in [fromDay, toDay], sorted ascending
    /// @param evidenceHash the published evidence: each probe's task, plaintexts and Provider-signed receipt
    function openCapabilityCase(address provider, uint64 fromDay, uint64 toDay, bytes32[] calldata keys, bytes32 evidenceHash)
        external nonReentrant returns (bytes32 caseId)
    {
        require(fromDay <= toDay && toDay < block.timestamp / 1 days && toDay - fromDay < MAX_CASE_DAYS); // closed days only
        require(keys.length >= MIN_CASE_PROBES && keys.length <= MAX_CASE_PROBES && evidenceHash != bytes32(0)); // case size
        uint256 voided;
        for (uint64 day = fromDay; day <= toDay; ++day) voided += hunterProbeVoids[msg.sender][provider][day];
        require(keys.length == voided); // all of the range's probes, no more
        for (uint256 i; i < keys.length; ++i) {
            require(i == 0 || keys[i] > keys[i - 1]); // sorted and distinct
            ProbeVoid storage probe = probeVoids[keys[i]];
            require(probe.hunter == msg.sender && !probe.inCase && probe.day >= fromDay && probe.day <= toDay
                && settlements[keys[i]].provider == provider); // not this hunter's probe of this Provider in range
            probe.inCase = true;
        }
        caseId = capabilityCaseId(msg.sender, provider, fromDay, toDay);
        CapabilityCase storage item = capabilityCases[caseId];
        item.hunter = msg.sender;
        item.provider = provider;
        item.providerSigner = settlements[keys[0]].providerSigner; // the jury comes from this signer's tier
        (item.fromDay, item.toDay, item.probes) = (fromDay, toDay, uint16(keys.length));
        item.resolveAt = _future(settings.arbitrationTimeout);
        item.status = CaseStatus.Open;
        item.evidenceHash = evidenceHash;
        item.keysHash = keccak256(abi.encode(keys));
        item.bond = settings.reporterBond;
        totalReporterBonds += item.bond;
        if (item.bond > 0) _takeExact(msg.sender, item.bond);
        juryRegistry.requestTierJury(caseId, provider, item.providerSigner);
        emit CapabilityCaseOpened(caseId, msg.sender, provider, keys.length, evidenceHash, item.resolveAt);
    }

    /// @notice A consistent quorum of the drawn jurors' signed votes decides the case.
    function voteCapabilityCase(bytes32 caseId, DisputeVotePermit[] calldata permits) external nonReentrant {
        CapabilityCase storage item = capabilityCases[caseId];
        require(item.status == CaseStatus.Open && block.timestamp < item.resolveAt); // not open
        require(permits.length == juryRegistry.threshold()); // bad vote batch
        bytes32 assignment = juryRegistry.assignmentHash(caseId);
        bool confirmed = permits[0].confirmed;
        bytes32 reportId = confirmed ? _reportId(caseId, item.hunter, item.evidenceHash) : bytes32(0);
        require(assignment != bytes32(0) && permits[0].decisionHash != bytes32(0)); // no jury or empty decision
        for (uint256 i; i < permits.length; ++i) {
            DisputeVotePermit calldata permit = permits[i];
            require(permit.assignmentHash == assignment && permit.confirmed == confirmed && permit.reportId == reportId
                && permit.decisionHash == permits[0].decisionHash); // inconsistent verdict
            address judge = _countVote(caseId, permit);
            require(judge != item.hunter && judge != item.provider && providerSignerOwner[judge] != item.provider
                && judge != settings.penaltyRecipient); // not an independent juror
        }
        totalReporterBonds -= item.bond;
        if (confirmed) {
            // The Provider forfeits its holdback up to the slash cap; the hunter gets its bond back, half the
            // forfeit and a MYCO bounty (minted by the emission); the rest of the forfeit goes to the treasury.
            uint256 penalty = _takeHoldback(item.provider, settings.slashCap);
            uint256 bounty = _portion(penalty, settings.reporterBountyBps);
            (item.status, item.penalty, item.bounty) = (CaseStatus.Confirmed, penalty, bounty);
            _credit(item.hunter, item.bond + bounty);
            _credit(settings.penaltyRecipient, penalty - bounty);
            cleanVolume[item.provider] = 0;
            _hookGas();
            try juryRegistry.recordCapabilityConviction(item.provider, item.hunter) {} catch {
                emit RegistryHookFailed(item.provider, IProviderJuryRegistryV11.recordCapabilityConviction.selector);
            }
        } else {
            item.status = CaseStatus.Dismissed;
            _credit(settings.penaltyRecipient, item.bond);
        }
        emit CapabilityCaseResolved(caseId, item.status, item.penalty, item.bounty);
    }

    /// @notice Silence is not a verdict: without a quorum by the deadline the hunter gets its bond back.
    function resolveTimedOutCapabilityCase(bytes32 caseId) external nonReentrant {
        CapabilityCase storage item = capabilityCases[caseId];
        require(item.status == CaseStatus.Open && block.timestamp >= item.resolveAt); // not timed out
        item.status = CaseStatus.TimedOut;
        totalReporterBonds -= item.bond;
        _credit(item.hunter, item.bond);
        emit CapabilityCaseResolved(caseId, CaseStatus.TimedOut, 0, 0);
    }
}
