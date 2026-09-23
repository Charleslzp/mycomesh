// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IMycoJuryCaseV1, ProviderJuryRegistryV1 as Registry} from "../contracts/ProviderJuryRegistryV1.sol";
import {VmV9} from "./MycoSettlementV9.t.sol";

contract JuryCaseMockV1 {
    IMycoJuryCaseV1.SettlementView private record;
    IMycoJuryCaseV1.DisputeView private dispute;
    mapping(address => mapping(address => bool)) public providerSigners;
    address public juryRegistry;
    uint16 public adjudicationThreshold;

    constructor() {
        record.owner = address(101);
        record.key = address(102);
        record.provider = address(103);
        record.providerSigner = address(104);
        record.relay = address(105);
        record.relaySigner = address(106);
        record.pool = address(107);
        record.treasury = address(108);
        record.status = 2;
        dispute.resolveAt = type(uint64).max;
    }

    function settlementInfo(bytes32) external view returns (IMycoJuryCaseV1.SettlementView memory) {
        return record;
    }

    function disputeInfo(bytes32) external view returns (IMycoJuryCaseV1.DisputeView memory) {
        return dispute;
    }

    function setResolveAt(uint64 value) external {
        dispute.resolveAt = value;
    }

    function setStatus(uint8 value) external {
        record.status = value;
    }

    function configureRegistry(address value, uint16 threshold) external {
        require(juryRegistry == address(0));
        juryRegistry = value;
        adjudicationThreshold = threshold;
    }

    function request(Registry registry, bytes32 caseId) external {
        registry.requestJury(caseId);
    }

    function setConsumerParties(address owner, address key) external {
        record.owner = owner;
        record.key = key;
    }

    function authorize(address owner, address signer) external {
        providerSigners[owner][signer] = true;
    }

    function revoke(address owner, address signer) external {
        providerSigners[owner][signer] = false;
    }
}

contract ProviderJuryRegistryV1Test {
    VmV9 constant vm = VmV9(address(uint160(uint256(keccak256("hevm cheat code")))));
    Registry registry;
    JuryCaseMockV1 settlement;
    address[] owners;
    address[] signers;
    mapping(uint256 => uint64) sourceSequences;
    address constant REPUTATION_AUTHORITY = address(110);

    function setUp() public {
        registry = new Registry(address(this), REPUTATION_AUTHORITY, address(109), 80, 3, 2, 2);
        settlement = new JuryCaseMockV1();
        for (uint256 i; i < 5; ++i) {
            owners.push(address(uint160(1000 + i)));
            signers.push(address(uint160(2000 + i)));
            settlement.authorize(owners[i], signers[i]);
        }
        _set(0, "operator-a", 100, true);
        _set(1, "operator-b", 90, true);
        _set(2, "operator-c", 80, true);
        _set(3, "operator-d", 100, true);
        _set(4, "operator-e", 79, true);
        settlement.configureRegistry(address(registry), registry.threshold());
        registry.bindSettlement(address(settlement));
    }

    function _set(uint256 index, string memory operator, uint64 reputation, bool active) internal {
        uint64 sourceSequence = ++sourceSequences[index];
        vm.prank(REPUTATION_AUTHORITY);
        registry.setProvider(
            Registry.Provider({
                owner: owners[index],
                voteSigner: signers[index],
                operatorIdHash: keccak256(bytes(operator)),
                peerIdHash: keccak256(abi.encode("peer", index)),
                capabilityHash: keccak256(abi.encode("capability", index)),
                reputation: reputation,
                active: active
            }),
            sourceSequence,
            keccak256(abi.encode("source", index, sourceSequence))
        );
    }

    function _ready(bytes32 caseId) internal returns (bool) {
        (, uint64 selectionBlock,,,,,,) = registry.assignmentInfo(caseId);
        vm.roll(uint256(selectionBlock) + 1);
        vm.setBlockhash(selectionBlock, keccak256(abi.encode(caseId, selectionBlock)));
        return registry.finalizeJury(caseId);
    }

    function testFutureBlockSelectsOnlyQualifiedDistinctProviders() public {
        bytes32 caseId = keccak256("case-a");
        settlement.request(registry, caseId);
        vm.expectRevert();
        registry.finalizeJury(caseId);
        vm.expectRevert();
        _set(0, "operator-a", 100, true);
        require(_ready(caseId));
        (
            Registry.AssignmentStatus status,,,,
            bytes32 assignment,
            address[] memory selectedOwners,
            address[] memory selectedSigners,
            bytes32[] memory operators
        ) = registry.assignmentInfo(caseId);
        require(status == Registry.AssignmentStatus.Ready && assignment != bytes32(0));
        require(selectedOwners.length == 3 && selectedSigners.length == 3 && operators.length == 3);
        (bytes32[] memory peers, bytes32[] memory capabilities, uint64[] memory reputations) =
            registry.assignmentProviderEvidence(caseId);
        require(peers.length == 3 && capabilities.length == 3 && reputations.length == 3);
        for (uint256 i; i < 3; ++i) {
            require(selectedOwners[i] != owners[4] && selectedSigners[i] != signers[4]);
            require(peers[i] != bytes32(0) && capabilities[i] != bytes32(0) && reputations[i] >= 80);
            require(registry.isVoteSigner(caseId, selectedSigners[i]));
            require(registry.isJuryParty(caseId, selectedOwners[i]));
            (
                bool found,
                address snapshotOwner,
                bytes32 snapshotOperator,
                bytes32 snapshotPeer,
                bytes32 snapshotCapability,
                uint64 snapshotReputation
            ) = registry.assignmentProviderForSigner(caseId, selectedSigners[i]);
            require(found && snapshotOwner == selectedOwners[i] && snapshotOperator == operators[i]);
            require(snapshotPeer == peers[i] && snapshotCapability == capabilities[i]);
            require(snapshotReputation == reputations[i]);
            for (uint256 j; j < i; ++j) {
                require(operators[i] != operators[j]);
            }
        }
        (bool missing,,,,,) = registry.assignmentProviderForSigner(caseId, address(9999));
        require(!missing);
    }

    function testFinalizeRequiresAnOpenCaseStrictlyBeforeItsDeadline() public {
        bytes32 beforeDeadline = keccak256("case-before-deadline");
        settlement.request(registry, beforeDeadline);
        require(_ready(beforeDeadline));

        bytes32 atDeadline = keccak256("case-at-deadline");
        settlement.request(registry, atDeadline);
        (, uint64 selectionBlock,,,,,,) = registry.assignmentInfo(atDeadline);
        vm.roll(uint256(selectionBlock) + 1);
        vm.setBlockhash(selectionBlock, keccak256(abi.encode(atDeadline, selectionBlock)));
        settlement.setResolveAt(uint64(block.timestamp));
        vm.expectRevert();
        registry.finalizeJury(atDeadline);
        require(registry.assignmentHash(atDeadline) == bytes32(0));
        registry.expireJury(atDeadline);
        (Registry.AssignmentStatus status,,,,,,,) = registry.assignmentInfo(atDeadline);
        require(status == Registry.AssignmentStatus.Failed && registry.pendingAssignments() == 0);
    }

    function testFinalizeRejectsAClosedCaseAndExpireReleasesItsPendingFence() public {
        bytes32 caseId = keccak256("case-closed-before-finalize");
        settlement.request(registry, caseId);
        (, uint64 selectionBlock,,,,,,) = registry.assignmentInfo(caseId);
        vm.roll(uint256(selectionBlock) + 1);
        vm.setBlockhash(selectionBlock, keccak256(abi.encode(caseId, selectionBlock)));
        settlement.setStatus(6);
        vm.expectRevert();
        registry.finalizeJury(caseId);
        registry.expireJury(caseId);
        require(registry.pendingAssignments() == 0);
    }

    function testSettlementPartiesCannotJoinJury() public {
        bytes32 caseId = keccak256("case-b");
        settlement.setConsumerParties(owners[0], signers[1]);
        settlement.request(registry, caseId);
        (Registry.AssignmentStatus status,,,, bytes32 assignment,,,) = registry.assignmentInfo(caseId);
        require(status == Registry.AssignmentStatus.Failed && assignment == bytes32(0));

        // A recovered roster can be retried without reopening (and therefore
        // without rolling back) the original settlement dispute.
        _set(4, "operator-e", 100, true);
        require(registry.retryJury(caseId));
        require(_ready(caseId));
    }

    function testUnavailableJuryCannotRetryAfterAdjudicationDeadline() public {
        bytes32 caseId = keccak256("case-expired-retry");
        settlement.setConsumerParties(owners[0], signers[1]);
        settlement.request(registry, caseId);
        (Registry.AssignmentStatus status,,,,,,,) = registry.assignmentInfo(caseId);
        require(status == Registry.AssignmentStatus.Failed);
        _set(4, "operator-e", 100, true);
        settlement.setResolveAt(uint64(block.timestamp));
        vm.expectRevert();
        registry.retryJury(caseId);
    }

    function testDuplicateOperatorAndPeerAliasesAreRejected() public {
        vm.expectRevert();
        _set(1, "operator-a", 100, true);
        Registry.Provider memory value = registry.providerForOwner(owners[1]);
        value.peerIdHash = registry.providerForOwner(owners[0]).peerIdHash;
        uint64 sourceSequence = registry.providerSourceSequence(value.owner) + 1;
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, sourceSequence, keccak256("duplicate-peer-source"));
        require(registry.canFormJury());
    }

    function testOnlyBoundSettlementCanRequest() public {
        vm.expectRevert();
        registry.requestJury(keccak256("case-d"));
    }

    function testPendingAssignmentUsesImmutableCandidateSnapshot() public {
        bytes32 caseId = keccak256("case-snapshot");
        settlement.request(registry, caseId);
        require(registry.isJuryParty(caseId, owners[0]));
        require(registry.isJuryParty(caseId, signers[1]));
        settlement.revoke(owners[0], signers[0]);
        settlement.revoke(owners[1], signers[1]);
        settlement.revoke(owners[2], signers[2]);
        require(_ready(caseId));
    }

    function testProviderOwnerAndVoteSignerCannotAliasAnotherProvider() public {
        Registry.Provider memory value = registry.providerForOwner(owners[1]);
        value.voteSigner = owners[0];
        uint64 sourceSequence = registry.providerSourceSequence(value.owner) + 1;
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, sourceSequence, keccak256("owner-as-signer-source"));
        value = registry.providerForOwner(owners[1]);
        value.owner = signers[0];
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, 1, keccak256("signer-as-owner-source"));
    }

    function testProviderRemovalReleasesSlotAndAliasesButFreezesWhilePending() public {
        bytes32 caseId = keccak256("case-removal");
        settlement.request(registry, caseId);
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.removeProvider(owners[0]);
        require(_ready(caseId));

        Registry.Provider memory removed = registry.providerForOwner(owners[0]);
        uint256 countBefore = registry.providerCount();
        vm.prank(REPUTATION_AUTHORITY);
        registry.removeProvider(owners[0]);
        require(registry.providerCount() == countBefore - 1);
        vm.expectRevert();
        registry.providerForOwner(owners[0]);

        removed.owner = address(3000);
        removed.voteSigner = address(4000);
        settlement.authorize(removed.owner, removed.voteSigner);
        vm.prank(REPUTATION_AUTHORITY);
        registry.setProvider(removed, 1, keccak256("replacement-source"));
        require(registry.providerCount() == countBefore);
        Registry.Provider memory replacement = registry.providerForOwner(address(3000));
        require(replacement.operatorIdHash == removed.operatorIdHash);
        require(replacement.peerIdHash == removed.peerIdHash);
    }

    function testSourceSequenceAndDigestPersistAcrossRemovalAndReregistration() public {
        address owner = owners[0];
        Registry.Provider memory value = registry.providerForOwner(owner);
        uint64 sequence = registry.providerSourceSequence(owner);
        bytes32 digest = registry.providerSourceDigest(owner);
        require(sequence == 1 && digest != bytes32(0));

        vm.prank(REPUTATION_AUTHORITY);
        registry.removeProvider(owner);
        require(registry.providerSourceSequence(owner) == sequence);
        require(registry.providerSourceDigest(owner) == digest);

        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, sequence, keccak256("replayed-source"));

        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, sequence + 1, bytes32(0));

        bytes32 nextDigest = keccak256("next-source");
        vm.prank(REPUTATION_AUTHORITY);
        registry.setProvider(value, sequence + 1, nextDigest);
        require(registry.providerSourceSequence(owner) == sequence + 1);
        require(registry.providerSourceDigest(owner) == nextDigest);
    }

    function testConstructorRejectsPenaltyRecipientAuthorityConflicts() public {
        vm.expectRevert();
        new Registry(address(this), REPUTATION_AUTHORITY, address(this), 80, 3, 2, 2);

        vm.expectRevert();
        new Registry(address(this), REPUTATION_AUTHORITY, REPUTATION_AUTHORITY, 80, 3, 2, 2);
    }

    function testBindSettlementRejectsReservedRoleConflicts() public {
        JuryCaseMockV1 governanceSettlement = new JuryCaseMockV1();
        Registry governanceRegistry =
            new Registry(address(governanceSettlement), REPUTATION_AUTHORITY, address(109), 80, 3, 2, 2);
        governanceSettlement.configureRegistry(address(governanceRegistry), governanceRegistry.threshold());
        vm.prank(address(governanceSettlement));
        vm.expectRevert();
        governanceRegistry.bindSettlement(address(governanceSettlement));

        JuryCaseMockV1 authoritySettlement = new JuryCaseMockV1();
        Registry authorityRegistry =
            new Registry(address(this), address(authoritySettlement), address(109), 80, 3, 2, 2);
        authoritySettlement.configureRegistry(address(authorityRegistry), authorityRegistry.threshold());
        vm.expectRevert();
        authorityRegistry.bindSettlement(address(authoritySettlement));

        JuryCaseMockV1 penaltySettlement = new JuryCaseMockV1();
        Registry penaltyRegistry =
            new Registry(address(this), REPUTATION_AUTHORITY, address(penaltySettlement), 80, 3, 2, 2);
        penaltySettlement.configureRegistry(address(penaltyRegistry), penaltyRegistry.threshold());
        vm.expectRevert();
        penaltyRegistry.bindSettlement(address(penaltySettlement));
    }

    function testBindSettlementRejectsExistingProviderIdentityAndRebinding() public {
        JuryCaseMockV1 ownerSettlement = new JuryCaseMockV1();
        Registry ownerRegistry = new Registry(address(this), REPUTATION_AUTHORITY, address(109), 80, 3, 2, 2);
        vm.prank(REPUTATION_AUTHORITY);
        ownerRegistry.setProvider(
            Registry.Provider({
                owner: address(ownerSettlement),
                voteSigner: address(5001),
                operatorIdHash: keccak256("bind-owner-operator"),
                peerIdHash: keccak256("bind-owner-peer"),
                capabilityHash: keccak256("bind-owner-capability"),
                reputation: 100,
                active: true
            }),
            1,
            keccak256("bind-owner-source")
        );
        ownerSettlement.configureRegistry(address(ownerRegistry), ownerRegistry.threshold());
        vm.expectRevert();
        ownerRegistry.bindSettlement(address(ownerSettlement));

        JuryCaseMockV1 signerSettlement = new JuryCaseMockV1();
        Registry signerRegistry = new Registry(address(this), REPUTATION_AUTHORITY, address(109), 80, 3, 2, 2);
        vm.prank(REPUTATION_AUTHORITY);
        signerRegistry.setProvider(
            Registry.Provider({
                owner: address(5002),
                voteSigner: address(signerSettlement),
                operatorIdHash: keccak256("bind-signer-operator"),
                peerIdHash: keccak256("bind-signer-peer"),
                capabilityHash: keccak256("bind-signer-capability"),
                reputation: 100,
                active: true
            }),
            1,
            keccak256("bind-signer-source")
        );
        signerSettlement.configureRegistry(address(signerRegistry), signerRegistry.threshold());
        vm.expectRevert();
        signerRegistry.bindSettlement(address(signerSettlement));

        JuryCaseMockV1 replacement = new JuryCaseMockV1();
        replacement.configureRegistry(address(registry), registry.threshold());
        vm.expectRevert();
        registry.bindSettlement(address(replacement));
        require(registry.settlement() == address(settlement));
    }

    function testReputationAuthorityCannotAssumeReservedOrProviderRoles() public {
        vm.expectRevert();
        registry.setReputationAuthority(address(this));
        vm.expectRevert();
        registry.setReputationAuthority(address(settlement));
        vm.expectRevert();
        registry.setReputationAuthority(address(109));
        vm.expectRevert();
        registry.setReputationAuthority(owners[0]);
        vm.expectRevert();
        registry.setReputationAuthority(signers[0]);
    }

    function testGovernanceCannotAssumeReservedOrProviderRoles() public {
        vm.expectRevert();
        registry.transferGovernance(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.transferGovernance(address(settlement));
        vm.expectRevert();
        registry.transferGovernance(address(109));
        vm.expectRevert();
        registry.transferGovernance(owners[0]);
        vm.expectRevert();
        registry.transferGovernance(signers[0]);
    }

    function testAuthorityRotationsRemainAvailableForIndependentAccounts() public {
        address nextAuthority = address(111);
        registry.setReputationAuthority(nextAuthority);
        require(registry.reputationAuthority() == nextAuthority);

        Registry.Provider memory value = registry.providerForOwner(owners[0]);
        value.reputation = 101;
        uint64 nextSequence = registry.providerSourceSequence(value.owner) + 1;
        vm.prank(nextAuthority);
        registry.setProvider(value, nextSequence, keccak256("rotated-authority-source"));

        address nextGovernance = address(112);
        registry.transferGovernance(nextGovernance);
        require(registry.governance() == nextGovernance);
        vm.prank(nextGovernance);
        registry.setReputationAuthority(address(113));
        require(registry.reputationAuthority() == address(113));
    }

    function testProviderVoteSignerCannotBeAnAuthorityButCanRotateIndependently() public {
        Registry.Provider memory value = registry.providerForOwner(owners[0]);
        uint64 nextSequence = registry.providerSourceSequence(value.owner) + 1;

        value.voteSigner = address(this);
        settlement.authorize(value.owner, value.voteSigner);
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, nextSequence, keccak256("governance-signer-source"));

        value.voteSigner = REPUTATION_AUTHORITY;
        settlement.authorize(value.owner, value.voteSigner);
        vm.prank(REPUTATION_AUTHORITY);
        vm.expectRevert();
        registry.setProvider(value, nextSequence, keccak256("authority-signer-source"));

        value.voteSigner = address(5003);
        settlement.authorize(value.owner, value.voteSigner);
        vm.prank(REPUTATION_AUTHORITY);
        registry.setProvider(value, nextSequence, keccak256("independent-signer-source"));
        require(registry.voteSignerOwner(address(5003)) == value.owner);
        require(registry.voteSignerOwner(signers[0]) == address(0));
    }

    function testRuntimeFitsEIP170() public view {
        require(address(registry).code.length <= 24_576, "EIP170");
    }
}
