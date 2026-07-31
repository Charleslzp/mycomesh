// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MycoSettlementV5} from "../contracts/MycoSettlementV5.sol";
import {TestUSDC} from "../contracts/TestUSDC.sol";

interface VmV5 {
    function addr(uint256 privateKey) external returns (address);
    function expectRevert(bytes calldata revertData) external;
    function prank(address sender) external;
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract MockRewardTokenV5 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
}

contract MycoSettlementV5Test {
    bytes32 internal constant CHANNEL = keccak256("codex-standard-v1");
    uint256 internal constant CONSUMER_KEY = 0xA11CE;
    uint256 internal constant PROVIDER_KEY = 0xB0B;
    uint256 internal constant SESSION_KEY = 0x5E5510;
    uint256 internal constant RELAY_SIGNER_KEY = 0xA11A7;
    uint256 internal constant OTHER_RELAY_SIGNER_KEY = 0xBAD;
    VmV5 internal constant vm = VmV5(address(uint160(uint256(keccak256("hevm cheat code")))));

    TestUSDC internal usdc;
    MockRewardTokenV5 internal reward;
    MycoSettlementV5 internal settlement;
    address internal consumer;
    address internal provider;
    address internal relay = address(0x1002);
    address internal pool = address(0x1003);
    address internal treasury = address(0x1004);
    address internal relaySigner;
    uint256 internal saltNonce;

    function setUp() public {
        consumer = vm.addr(CONSUMER_KEY);
        provider = vm.addr(PROVIDER_KEY);
        relaySigner = vm.addr(RELAY_SIGNER_KEY);
        usdc = new TestUSDC();
        reward = new MockRewardTokenV5();
        settlement = new MycoSettlementV5(
            address(usdc), address(reward), treasury, address(this), 2_000, CHANNEL, _defaultConfig()
        );
        usdc.mint(consumer, 100_000);
        vm.prank(consumer);
        usdc.approve(address(settlement), type(uint256).max);
        vm.prank(consumer);
        settlement.deposit(100_000);
    }

    function testRelayedSessionBindsRoutesAndUsesPullCredits() public {
        bytes32 sessionId = _openRelayedSession(5_000);
        MycoSettlementV5.Session memory opened = settlement.sessionInfo(sessionId);
        require(opened.provider == provider, "provider not bound");
        require(opened.relay == relay, "relay not bound");
        require(opened.relaySigner == relaySigner, "relay signer not bound");
        require(opened.pool == pool, "pool not bound");

        settlement.settleSignedReceipt(_signed(_receipt(sessionId, 0)));

        require(settlement.claimableBalance(provider) == 2_550, "provider credit mismatch");
        require(settlement.claimableBalance(relay) == 90, "relay credit mismatch");
        require(settlement.claimableBalance(pool) == 60, "pool credit mismatch");
        require(settlement.claimableBalance(treasury) == 300, "treasury credit mismatch");
        require(settlement.totalClaimable() == 3_000, "total credit mismatch");
        require(usdc.balanceOf(relay) == 0, "relay payout was pushed");

        vm.prank(relay);
        settlement.claim();
        require(usdc.balanceOf(relay) == 90, "relay claim mismatch");
    }

    function testReceiptCannotChangeBoundRelayOrPool() public {
        bytes32 sessionId = _openRelayedSession(10_000);
        MycoSettlementV5.SessionReceipt memory changedRelay = _receipt(sessionId, 0);
        changedRelay.relay = address(0xBEEF);
        vm.expectRevert(bytes("session relay"));
        settlement.settleSignedReceipt(_signed(changedRelay));

        MycoSettlementV5.SessionReceipt memory changedPool = _receipt(sessionId, 0);
        changedPool.pool = address(0xCAFE);
        vm.expectRevert(bytes("session pool"));
        settlement.settleSignedReceipt(_signed(changedPool));
    }

    function testTamperedRelayAttestationAndSignatureAreRejected() public {
        bytes32 sessionId = _openRelayedSession(10_000);
        MycoSettlementV5.SignedSessionReceipt memory changedRequest = _signed(_receipt(sessionId, 0));
        changedRequest.relayAttestation.requestHash = keccak256("tampered request");
        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(changedRequest);

        MycoSettlementV5.SignedSessionReceipt memory changedSequence = _signed(_receipt(sessionId, 0));
        changedSequence.relayAttestation.sequence = 1;
        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(changedSequence);

        MycoSettlementV5.SignedSessionReceipt memory changedProvider = _signed(_receipt(sessionId, 0));
        changedProvider.relayAttestation.provider = address(0xBEEF);
        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(changedProvider);

        MycoSettlementV5.SignedSessionReceipt memory changedRelay = _signed(_receipt(sessionId, 0));
        changedRelay.relayAttestation.relay = address(0xCAFE);
        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(changedRelay);

        MycoSettlementV5.SignedSessionReceipt memory changedDeadline = _signed(_receipt(sessionId, 0));
        changedDeadline.relayAttestation.deadline += 1;
        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(changedDeadline);

        MycoSettlementV5.SignedSessionReceipt memory badSignature = _signed(_receipt(sessionId, 0));
        badSignature.relaySignature = _sign(
            OTHER_RELAY_SIGNER_KEY,
            settlement.relayRequestAttestationDigest(badSignature.relayAttestation)
        );
        vm.expectRevert(bytes("bad relay signature"));
        settlement.settleSignedReceipt(badSignature);
    }

    function testRelayedSessionRejectsMissingRelayProof() public {
        bytes32 sessionId = _openRelayedSession(5_000);
        MycoSettlementV5.SignedSessionReceipt memory input = _signed(_receipt(sessionId, 0));
        input.relaySignature = new bytes(0);

        vm.expectRevert(bytes("missing relay signature"));
        settlement.settleSignedReceipt(input);
    }

    function testRelayAttestationCannotReplayAcrossSessions() public {
        bytes32 firstSession = _openRelayedSession(5_000);
        bytes32 secondSession = _openRelayedSession(5_000);
        MycoSettlementV5.SignedSessionReceipt memory first = _signed(_receipt(firstSession, 0));
        MycoSettlementV5.SignedSessionReceipt memory second = _signed(_receipt(secondSession, 0));
        second.relayAttestation = first.relayAttestation;
        second.relaySignature = first.relaySignature;

        vm.expectRevert(bytes("relay attestation mismatch"));
        settlement.settleSignedReceipt(second);
    }

    function testDirectSessionAllowsIndependentPoolWithoutRelayProof() public {
        bytes32 sessionId = _openDirectSession(5_000, pool);
        MycoSettlementV5.Session memory opened = settlement.sessionInfo(sessionId);
        require(opened.relay == address(0), "direct relay not zero");
        require(opened.relaySigner == address(0), "direct signer not zero");
        require(opened.pool == pool, "direct pool not bound");

        MycoSettlementV5.SignedSessionReceipt memory input = _signed(_receipt(sessionId, 0));
        require(input.relaySignature.length == 0, "direct proof present");
        settlement.settleSignedReceipt(input);

        require(settlement.claimableBalance(relay) == 0, "direct relay credited");
        require(settlement.claimableBalance(pool) == 60, "direct pool credit mismatch");
        require(settlement.claimableBalance(treasury) == 390, "direct treasury fold mismatch");
    }

    function testDirectSessionRejectsUnexpectedRelayProof() public {
        bytes32 sessionId = _openDirectSession(5_000, pool);
        MycoSettlementV5.SignedSessionReceipt memory withSignature = _signed(_receipt(sessionId, 0));
        withSignature.relaySignature = hex"01";
        vm.expectRevert(bytes("unexpected relay proof"));
        settlement.settleSignedReceipt(withSignature);

        MycoSettlementV5.SignedSessionReceipt memory withAttestation = _signed(_receipt(sessionId, 0));
        withAttestation.relayAttestation.sessionId = sessionId;
        vm.expectRevert(bytes("unexpected relay proof"));
        settlement.settleSignedReceipt(withAttestation);
    }

    function testRelayAttestationStructHashMatchesEip712Schema() public {
        bytes32 sessionId = _openRelayedSession(5_000);
        MycoSettlementV5.SignedSessionReceipt memory input = _signed(_receipt(sessionId, 0));
        MycoSettlementV5.RelayRequestAttestation memory proof = input.relayAttestation;
        bytes32 expected = keccak256(
            abi.encode(
                settlement.RELAY_REQUEST_ATTESTATION_TYPEHASH(),
                proof.sessionId,
                proof.requestHash,
                proof.provider,
                proof.relay,
                proof.sequence,
                proof.deadline
            )
        );
        require(settlement.relayRequestAttestationStructHash(proof) == expected, "attestation type mismatch");
    }

    function testOpenSessionRejectsHalfConfiguredRelay() public {
        vm.prank(consumer);
        vm.expectRevert(bytes("relay signer mismatch"));
        settlement.openSession(
            _nextSalt(),
            provider,
            relay,
            address(0),
            pool,
            vm.addr(SESSION_KEY),
            CHANNEL,
            1,
            5_000,
            uint64(block.timestamp + 5 days)
        );

        vm.prank(consumer);
        vm.expectRevert(bytes("relay signer mismatch"));
        settlement.openSession(
            _nextSalt(),
            provider,
            address(0),
            relaySigner,
            pool,
            vm.addr(SESSION_KEY),
            CHANNEL,
            1,
            5_000,
            uint64(block.timestamp + 5 days)
        );
    }

    function testOpenSessionRequiresIndependentRelaySigner() public {
        address sessionKey = vm.addr(SESSION_KEY);
        address[4] memory forbidden = [relay, provider, sessionKey, consumer];
        for (uint256 i = 0; i < forbidden.length; ++i) {
            vm.prank(consumer);
            vm.expectRevert(bytes("bad relay signer"));
            settlement.openSession(
                _nextSalt(),
                provider,
                relay,
                forbidden[i],
                pool,
                sessionKey,
                CHANNEL,
                1,
                5_000,
                uint64(block.timestamp + 5 days)
            );
        }
    }

    function testDuplicateReceiptAndSequenceSettlementRejected() public {
        bytes32 sessionId = _openRelayedSession(10_000);
        MycoSettlementV5.SignedSessionReceipt memory first = _signed(_receipt(sessionId, 0));
        settlement.settleSignedReceipt(first);

        vm.expectRevert(bytes("receipt settled"));
        settlement.settleSignedReceipt(first);

        MycoSettlementV5.SessionReceipt memory sameSequence = _receipt(sessionId, 0);
        sameSequence.receiptHash = keccak256("different receipt");
        sameSequence.requestHash = keccak256("different request");
        vm.expectRevert(bytes("bad sequence"));
        settlement.settleSignedReceipt(_signed(sameSequence));
    }

    function _openRelayedSession(uint256 amount) internal returns (bytes32 sessionId) {
        vm.prank(consumer);
        sessionId = settlement.openSession(
            _nextSalt(),
            provider,
            relay,
            relaySigner,
            pool,
            vm.addr(SESSION_KEY),
            CHANNEL,
            1,
            amount,
            uint64(block.timestamp + 5 days)
        );
    }

    function _openDirectSession(uint256 amount, address poolAddress) internal returns (bytes32 sessionId) {
        vm.prank(consumer);
        sessionId = settlement.openSession(
            _nextSalt(),
            provider,
            address(0),
            address(0),
            poolAddress,
            vm.addr(SESSION_KEY),
            CHANNEL,
            1,
            amount,
            uint64(block.timestamp + 5 days)
        );
    }

    function _nextSalt() internal returns (bytes32) {
        ++saltNonce;
        return keccak256(abi.encode("v5 session", saltNonce));
    }

    function _receipt(bytes32 sessionId, uint256 sequence)
        internal
        view
        returns (MycoSettlementV5.SessionReceipt memory receipt)
    {
        MycoSettlementV5.Session memory session = settlement.sessionInfo(sessionId);
        receipt = MycoSettlementV5.SessionReceipt({
            receiptHash: keccak256(abi.encode("receipt", sessionId, sequence)),
            acceptedHash: keccak256(abi.encode("accepted", sessionId, sequence)),
            sessionId: sessionId,
            requestHash: keccak256(abi.encode("request", sessionId, sequence)),
            responseHash: keccak256(abi.encode("response", sessionId, sequence)),
            channel: CHANNEL,
            pricingVersion: 1,
            pricingHash: settlement.channelPricingHash(CHANNEL, 1),
            consumer: consumer,
            provider: session.provider,
            relay: session.relay,
            pool: session.pool,
            inputTokens: 1_000,
            outputTokens: 500,
            sequence: sequence,
            quotedFee: settlement.quote(CHANNEL, 1, 1_000, 500),
            deadline: block.timestamp + 1 days
        });
    }

    function _signed(MycoSettlementV5.SessionReceipt memory receipt)
        internal
        returns (MycoSettlementV5.SignedSessionReceipt memory input)
    {
        MycoSettlementV5.RelayRequestAttestation memory attestation;
        bytes memory relaySignature;
        if (receipt.relay != address(0)) {
            attestation = MycoSettlementV5.RelayRequestAttestation({
                sessionId: receipt.sessionId,
                requestHash: receipt.requestHash,
                provider: receipt.provider,
                relay: receipt.relay,
                sequence: receipt.sequence,
                deadline: receipt.deadline
            });
            relaySignature = _sign(RELAY_SIGNER_KEY, settlement.relayRequestAttestationDigest(attestation));
        }
        bytes32 receiptDigest = settlement.receiptDigest(receipt);
        input = MycoSettlementV5.SignedSessionReceipt({
            receipt: receipt,
            relayAttestation: attestation,
            sessionKeySignature: _sign(SESSION_KEY, receiptDigest),
            providerSignature: _sign(PROVIDER_KEY, receiptDigest),
            relaySignature: relaySignature
        });
    }

    function _defaultConfig() internal pure returns (MycoSettlementV5.ChannelConfig memory) {
        return MycoSettlementV5.ChannelConfig({
            inputPer1K: 1_000,
            outputPer1K: 4_000,
            minimumFee: 2_000,
            providerBps: 8_500,
            relayBps: 300,
            poolBps: 200,
            treasuryBps: 1_000,
            providerRewardBps: 9_000,
            consumerRewardBps: 1_000,
            rewardPerTreasuryUnit: 1e12,
            active: true
        });
    }

    function _sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
