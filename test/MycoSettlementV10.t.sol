// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {MycoSettlementV10 as V10} from "../contracts/MycoSettlementV10.sol";
import {ProviderJuryRegistryV1 as JuryRegistry} from "../contracts/ProviderJuryRegistryV1.sol";
import {MockExactTokenV9 as Token, VmV9} from "./MycoSettlementV9.t.sol";

contract JuryRegistryBindingMockV10 {
    address public settlement;
    uint16 public constant threshold = 2;
    constructor(address settlement_) { settlement = settlement_; }
    function canFormJuryFor(bytes32) external pure returns (bool) { return true; }
}

contract MycoSettlementV10Test {
    VmV9 constant vm = VmV9(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant CKEY=101; uint256 constant PKEY=102;
    uint256 constant KEY=1; uint256 constant PSIGN=2; uint256 constant RSIGN=3;
    bytes32 constant PRICE=keccak256("v10-price");
    Token token; V10 s; JuryRegistry registry; address consumer; address provider;
    address key; address psigner; address rsigner;
    address constant TREASURY=address(90); address constant POOL=address(91); address constant REPORTER=address(92); address constant PENALTY=address(99);
    uint256 constant J1KEY=81; uint256 constant J2KEY=82; uint256 constant J3KEY=83;
    address constant REPUTATION_AUTHORITY=address(97);
    address J1; address J2; address J3;
    bytes32 id;
    function _voteDigest(bytes32 key_,bytes32 assignment,bool confirmed,bytes32 report,uint256 nonce,uint64 deadline,bytes32 decision) internal view returns(bytes32) {
        bytes32 typehash=keccak256("DisputeVote(bytes32 settlementKey,bytes32 assignmentHash,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        bytes32 structHash=keccak256(abi.encode(typehash,key_,assignment,confirmed,report,decision,nonce,deadline));
        return keccak256(abi.encodePacked("\x19\x01",s.DOMAIN_SEPARATOR(),structHash));
    }
    function setUp() public {
        vm.warp(1000);consumer=vm.addr(CKEY);provider=vm.addr(PKEY);key=vm.addr(KEY);psigner=vm.addr(PSIGN);rsigner=vm.addr(RSIGN);
        J1=vm.addr(J1KEY); J2=vm.addr(J2KEY); J3=vm.addr(J3KEY);
        token=new Token();registry=new JuryRegistry(address(this),REPUTATION_AUTHORITY,PENALTY,80,3,2,1);
        vm.prank(REPUTATION_AUTHORITY);registry.setProvider(JuryRegistry.Provider(address(181),J1,keccak256("operator-1"),keccak256("peer-1"),keccak256("capability-1"),100,true),1,keccak256("source-1"));
        vm.prank(REPUTATION_AUTHORITY);registry.setProvider(JuryRegistry.Provider(address(182),J2,keccak256("operator-2"),keccak256("peer-2"),keccak256("capability-2"),100,true),1,keccak256("source-2"));
        vm.prank(REPUTATION_AUTHORITY);registry.setProvider(JuryRegistry.Provider(address(183),J3,keccak256("operator-3"),keccak256("peer-3"),keccak256("capability-3"),100,true),1,keccak256("source-3"));
        s=new V10(address(token),address(0),TREASURY,address(this),PRICE,
            V10.ChannelConfig(1000,4000,2000,8500,300,200,1000,true),
            V10.DisputePolicy(100,200,30,100,5000,2000,5000,600,0,0,0,0,PENALTY),address(registry));
        vm.prank(address(181));s.authorizeProviderSigner(J1);
        vm.prank(address(182));s.authorizeProviderSigner(J2);
        vm.prank(address(183));s.authorizeProviderSigner(J3);
        registry.bindSettlement(address(s));
        token.mint(consumer,101000);vm.prank(consumer);token.approve(address(s),type(uint256).max);vm.prank(consumer);s.deposit(100000);
        token.mint(provider,100000);vm.prank(provider);token.approve(address(s),type(uint256).max);vm.prank(provider);s.depositStake(100000);
        vm.prank(consumer);s.registerKey(key,50000,0);vm.prank(provider);s.authorizeProviderSigner(psigner);
        token.mint(REPORTER,1000);vm.prank(REPORTER);token.approve(address(s),type(uint256).max);
        id=_open(_config(20000));vm.warp(1600);
    }
    function _config(uint256 capacity) internal view returns(V10.OpenChannel memory c){
        c=V10.OpenChannel(consumer,key,provider,psigner,rsigner,rsigner,POOL,PRICE,1,s.channelPricingHash(PRICE,1),capacity,capacity,uint64(block.timestamp+600),uint64(block.timestamp+6000),uint64(block.timestamp+15000),s.consumerAllocationNonce(consumer),s.providerAllocationNonce(provider),uint64(block.timestamp+100));
    }
    function _sig(uint256 k,bytes32 h) internal returns(bytes memory){(uint8 v,bytes32 r,bytes32 ss)=vm.sign(k,h);return abi.encodePacked(r,ss,v);}
    function _permit(V10.OpenChannel memory c) internal returns(V10.ChannelPermit memory){bytes32 h=s.channelIdFor(c);return V10.ChannelPermit(c,_sig(CKEY,h),_sig(PKEY,h));}
    function _permitFor(V10.OpenChannel memory c,uint256 providerKey) internal returns(V10.ChannelPermit memory){bytes32 h=s.channelIdFor(c);return V10.ChannelPermit(c,_sig(CKEY,h),_sig(providerKey,h));}
    function _open(V10.OpenChannel memory c) internal returns(bytes32){V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);s.openCapacityChannels(p);return s.channelIdFor(c);}
    function _receipt(bytes32 channel,uint256 n,uint256 maxFee) internal returns(V10.SignedReceipt memory r){
        r.authorization=V10.PaymentAuthorization(channel,bytes32(n),keccak256(abi.encode(n)),key,maxFee,uint64(block.timestamp),uint64(block.timestamp+100),uint64(block.timestamp+9000));
        bytes32 a=s.authorizationStructHash(r.authorization);bytes32 d=s.dispatchStructHash(a,channel);
        r.receipt=V10.UsageReceipt(channel,a,d,keccak256(abi.encode("response",n)),100,100,2000);
        r.keySignature=_sig(KEY,s.authorizationDigest(r.authorization));r.providerSignature=_sig(PSIGN,s.receiptDigest(r.receipt));r.relaySignature=_sig(RSIGN,s.dispatchDigest(a,channel));
    }
    function _settle() internal returns(bytes32){V10.SignedReceipt memory r=_receipt(id,1,10000);s.settleReservedReceipt(r);return s.settlementKeyFor(id,bytes32(uint256(1)));}
    function _assign(bytes32 k) internal returns(bytes32 assignment){
        (,uint64 selectionBlock,,,,,,)=registry.assignmentInfo(k);
        vm.roll(uint256(selectionBlock)+1);vm.setBlockhash(selectionBlock,keccak256(abi.encode(k,selectionBlock)));
        require(registry.finalizeJury(k));assignment=registry.assignmentHash(k);require(assignment!=bytes32(0));
    }
    function _quorum(bytes32 k,bytes32 assignment,bool confirmed,bytes32 report,bytes32 decision,uint64 deadline) internal returns(V10.DisputeVotePermit[] memory permits){
        permits=new V10.DisputeVotePermit[](2);
        permits[0]=V10.DisputeVotePermit(assignment,confirmed,report,decision,0,deadline,_sig(J1KEY,_voteDigest(k,assignment,confirmed,report,0,deadline,decision)));
        permits[1]=V10.DisputeVotePermit(assignment,confirmed,report,decision,0,deadline,_sig(J2KEY,_voteDigest(k,assignment,confirmed,report,0,deadline,decision)));
    }
    function _invariants() internal view {
        require(token.balanceOf(address(s))==s.stableLiabilities(),"liabilities");
        require(s.providerStake(provider)>=s.lockedStake(provider)+s.allocatedStake(provider),"stake partition");
    }
    function testOpenLocksBothAndLeavesNoUnreservedSelector() public {
        require(s.availableBalance(consumer)==80000 && s.allocatedStake(provider)==20000);
        (bool ok,)=address(s).call(abi.encodeWithSignature("settleSignedBatch(bytes[])",new bytes[](0)));require(!ok);_invariants();
    }
    function testReservedCreditCannotWithdraw() public {vm.prank(consumer);vm.expectRevert();s.requestWithdrawal(80001);}
    function testAllocatedStakeCannotWithdraw() public {vm.prank(provider);vm.expectRevert();s.withdrawStake(80001);}
    function testBadOwnerPermitAndNonceRollback() public {
        V10.OpenChannel memory c=_config(1000);V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);p[0].providerSignature=_sig(KEY,s.channelIdFor(c));
        vm.expectRevert();s.openCapacityChannels(p);require(s.consumerAllocationNonce(consumer)==1 && s.providerAllocationNonce(provider)==1);
    }
    function testDuplicatePermitAtomicBatch() public {
        V10.OpenChannel memory c=_config(1000);V10.ChannelPermit[] memory p=new V10.ChannelPermit[](2);p[0]=_permit(c);p[1]=p[0];
        vm.expectRevert();s.openCapacityChannels(p);require(s.consumerAllocationNonce(consumer)==1 && s.totalAllocatedCredit()==20000);
    }
    function testSharedOwnerCannotOverallocateAcrossRelays() public {
        V10.OpenChannel memory c=_config(50000);_open(c);c=_config(40000);c.relay=address(0x1234);
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);vm.expectRevert();s.openCapacityChannels(p);_invariants();
    }
    function testOpenNeedsFutureActivationAndCoveringGrant() public {
        V10.OpenChannel memory c=_config(1000);c.validFrom=uint64(block.timestamp);V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);vm.expectRevert();s.openCapacityChannels(p);
        c=_config(1000);vm.prank(consumer);s.registerKey(key,50000,c.claimUntil-1);p[0]=_permit(c);vm.expectRevert();s.openCapacityChannels(p);
    }
    function testOpenRejectsJuryThatOnlyWorksBeforeChannelRoleExclusion() public {
        V10.OpenChannel memory c=_config(1000);c.relay=address(181);
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);
        vm.expectRevert();s.openCapacityChannels(p);
    }
    function testOpenRejectsUnboundOrWrongBoundRegistry() public {
        _expectBindingFailure(address(0));
        _expectBindingFailure(address(0x1234));
    }
    function _expectBindingFailure(address boundSettlement) internal {
        JuryRegistryBindingMockV10 mock=new JuryRegistryBindingMockV10(boundSettlement);
        V10 other=new V10(address(token),address(0),TREASURY,address(this),PRICE,
            V10.ChannelConfig(1000,4000,2000,8500,300,200,1000,true),
            V10.DisputePolicy(100,200,30,100,5000,2000,5000,600,0,0,0,0,PENALTY),address(mock));
        token.mint(consumer,1000);vm.prank(consumer);token.approve(address(other),type(uint256).max);vm.prank(consumer);other.deposit(1000);
        token.mint(provider,1000);vm.prank(provider);token.approve(address(other),type(uint256).max);vm.prank(provider);other.depositStake(1000);
        vm.prank(consumer);other.registerKey(key,1000,0);vm.prank(provider);other.authorizeProviderSigner(psigner);
        V10.OpenChannel memory c=V10.OpenChannel(consumer,key,provider,psigner,rsigner,rsigner,POOL,PRICE,1,
            other.channelPricingHash(PRICE,1),1000,1000,uint64(block.timestamp+600),uint64(block.timestamp+6000),
            uint64(block.timestamp+15000),0,0,uint64(block.timestamp+100));
        bytes32 channelId=other.channelIdFor(c);
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);
        p[0]=V10.ChannelPermit(c,_sig(CKEY,channelId),_sig(PKEY,channelId));
        vm.expectRevert();other.openCapacityChannels(p);
        require(other.consumerAllocationNonce(consumer)==0 && other.providerAllocationNonce(provider)==0);
    }
    function testChannelDurationAllowsSevenDayRunwayAndCapsThirtyDays() public {
        require(s.MAX_CHANNEL_DURATION()==30 days);
        V10.OpenChannel memory c=_config(1000);
        c.validFrom=uint64(block.timestamp+600);
        c.admitUntil=uint64(block.timestamp+8 days);
        c.claimUntil=uint64(block.timestamp+9 days);
        _open(c);
        c=_config(1000);
        c.admitUntil=uint64(block.timestamp+20 days);
        c.claimUntil=uint64(c.validFrom+30 days);
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(c);
        vm.expectRevert();s.openCapacityChannels(p);
    }
    function testRevokesDoNotInvalidateAlreadyLockedReceipt() public {
        vm.prank(consumer);s.revokeKey(key);vm.prank(provider);s.revokeProviderSigner(psigner);_settle();_invariants();
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permit(_config(1000));vm.expectRevert();s.openCapacityChannels(p);
    }
    function testProviderCanSettleAfterExecuteByWithoutRelayResigning() public {
        V10.SignedReceipt memory r=_receipt(id,1,10000);vm.warp(1800);vm.prank(provider);s.settleReservedReceipt(r);_invariants();
    }
    function testMaxFeeDifferenceNeverRecycles() public {
        s.settleReservedReceipt(_receipt(id,1,10000));s.settleReservedReceipt(_receipt(id,2,10000));
        V10.CapacityChannel memory c=s.channelInfo(id);require(c.creditRemaining==16000 && c.settledMaxFee==20000);
        V10.SignedReceipt memory r=_receipt(id,3,2000);vm.expectRevert();s.settleReservedReceipt(r);_invariants();
    }
    function testBadDispatchProviderAndReceiptBinding() public {
        V10.SignedReceipt memory r=_receipt(id,1,10000);r.relaySignature=_sig(RSIGN,s.receiptDigest(r.receipt));vm.expectRevert();s.settleReservedReceipt(r);
        r=_receipt(id,1,10000);r.providerSignature=_sig(KEY,s.receiptDigest(r.receipt));vm.expectRevert();s.settleReservedReceipt(r);
        r=_receipt(id,1,10000);r.receipt.actualFee=2001;vm.expectRevert();s.settleReservedReceipt(r);
    }
    function testDuplicateReceiptAndDifferentPayloadRejected() public {
        _settle();V10.SignedReceipt memory r=_receipt(id,1,10000);vm.expectRevert();s.settleReservedReceipt(r);
        r.receipt.responseHash=bytes32(uint256(99));r.providerSignature=_sig(PSIGN,s.receiptDigest(r.receipt));vm.expectRevert();s.settleReservedReceipt(r);
    }
    function testSameRequestIdAcrossChannelsIndependent() public {
        bytes32 second=_open(_config(10000));vm.warp(2200);s.settleReservedReceipt(_receipt(id,1,10000));s.settleReservedReceipt(_receipt(second,1,10000));_invariants();
    }
    function testBatch32LimitAndAtomicFailure() public {
        V10.SignedReceipt[] memory receipts=new V10.SignedReceipt[](2);receipts[0]=_receipt(id,1,10000);receipts[1]=receipts[0];vm.expectRevert();s.settleReservedBatch(receipts);require(s.totalPendingFees()==0);
        receipts=new V10.SignedReceipt[](33);vm.expectRevert();s.settleReservedBatch(receipts);
    }
    function testNoEarlyCloseAndOnlyOwnersReceiveRemainder() public {
        vm.expectRevert();s.closeExpiredChannel(id);_settle();vm.warp(16001);vm.prank(REPORTER);s.closeExpiredChannel(id);
        require(s.availableBalance(consumer)==98000 && s.allocatedStake(provider)==0 && s.lockedStake(provider)==2000);_invariants();vm.expectRevert();s.closeExpiredChannel(id);
    }
    function testExpiryBoundaryAndLateReceiptRejected() public {
        V10.SignedReceipt memory r=_receipt(id,1,10000);vm.warp(10601);vm.expectRevert();s.settleReservedReceipt(r);
        vm.warp(16000);vm.expectRevert();s.closeExpiredChannel(id);vm.warp(16001);s.closeExpiredChannel(id);_invariants();
    }
    function testDisputeQuorumRefundSlashDoesNotInvadeAllocation() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        s.voteDisputeBySig(k,_quorum(k,assignment,true,report,bytes32(uint256(3)),uint64(block.timestamp+100)));
        require(s.availableBalance(consumer)==82000 && s.providerStake(provider)==99000 && s.allocatedStake(provider)==18000 && s.lockedStake(provider)==0);s.claimDisputeBond(k,report);
        require(s.claimableBalance(consumer)==600 && s.claimableBalance(REPORTER)==0);_invariants();
    }
    function testDismissedOwnerReportForfeitsOnlyItsBond() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        s.voteDisputeBySig(k,_quorum(k,assignment,false,bytes32(0),bytes32(uint256(3)),uint64(block.timestamp+100)));
        require(s.settlementInfo(k).status==V10.Status.Dismissed && s.totalReporterBonds()==0);
        require(s.claimableBalance(consumer)==0 && s.claimableBalance(PENALTY)==100);
        require(s.claimableBalance(provider)==1700 && s.claimableBalance(rsigner)==60);_invariants();
    }
    function testNonOwnerCannotFrontRunTheSoleOwnerReport() public {
        bytes32 k=_settle();
        vm.prank(REPORTER);vm.expectRevert();s.openDispute(k,bytes32(uint256(1)));
        V10.Settlement memory settlement=s.settlementInfo(k);
        require(settlement.status==V10.Status.Pending && s.disputeInfo(k).reportCount==0);
        vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        require(s.disputeInfo(k).reportCount==1);
        vm.prank(REPORTER);
        (bool ok,)=address(s).call(abi.encodeWithSignature(
            "submitEvidence(bytes32,bytes32)",k,bytes32(uint256(2))
        ));
        require(!ok && s.disputeInfo(k).reportCount==1 && s.totalReporterBonds()==100);
    }
    function testConsumerWhoIsAlsoProviderOwnerCanOpenItsOwnDispute() public {
        uint256 extraSignerKey=84;address extraSigner=vm.addr(extraSignerKey);
        vm.prank(consumer);s.authorizeProviderSigner(extraSigner);
        vm.prank(REPUTATION_AUTHORITY);registry.setProvider(JuryRegistry.Provider(
            consumer,extraSigner,keccak256("operator-consumer-owner"),keccak256("peer-consumer-owner"),
            keccak256("capability-consumer-owner"),100,true
        ),1,keccak256("source-consumer-owner"));
        bytes32 k=_settle();require(registry.isJuryParty(k,consumer));
        vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        _assign(k);require(s.disputeInfo(k).reportCount==1 && !registry.isVoteSigner(k,extraSigner));
    }
    function testConsumerWhoIsAlsoProviderVoteSignerCanOpenItsOwnDispute() public {
        address extraOwner=address(184);
        vm.prank(extraOwner);s.authorizeProviderSigner(consumer);
        vm.prank(REPUTATION_AUTHORITY);registry.setProvider(JuryRegistry.Provider(
            extraOwner,consumer,keccak256("operator-consumer-signer"),keccak256("peer-consumer-signer"),
            keccak256("capability-consumer-signer"),100,true
        ),1,keccak256("source-consumer-signer"));
        bytes32 k=_settle();require(registry.isJuryParty(k,consumer));
        vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        _assign(k);require(s.disputeInfo(k).reportCount==1 && !registry.isVoteSigner(k,consumer));
    }
    function testDisputeQuorumCanBeRelayedAfterJudgeWalletApprovals() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        bytes32 decision=bytes32(uint256(3));s.voteDisputeBySig(k,_quorum(k,assignment,true,report,decision,uint64(block.timestamp+100)));
        V10.Settlement memory settlement=s.settlementInfo(k);
        require(settlement.status==V10.Status.Confirmed && s.adjudicatorNonce(k,J1)==1 && s.adjudicatorNonce(k,J2)==1);
        _invariants();
    }
    function testRelayedVoteNonceAndExpiryAreFailClosed() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        uint64 deadline=uint64(block.timestamp-1);bytes32 decision=bytes32(uint256(3));
        V10.DisputeVotePermit[] memory permits=_quorum(k,assignment,true,report,decision,deadline);
        vm.expectRevert();s.voteDisputeBySig(k,permits);_invariants();
        deadline=uint64(block.timestamp+100);
        permits=_quorum(k,assignment,true,report,decision,deadline);
        permits[0]=V10.DisputeVotePermit(assignment,true,report,decision,1,deadline,_sig(J1KEY,_voteDigest(k,assignment,true,report,1,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,permits);_invariants();
    }
    function testJurorNoncesAreIndependentAcrossConcurrentCases() public {
        bytes32 first=_settle();
        s.settleReservedReceipt(_receipt(id,2,10000));
        bytes32 second=s.settlementKeyFor(id,bytes32(uint256(2)));
        vm.prank(consumer);s.openDispute(first,bytes32(uint256(11)));
        vm.prank(consumer);s.openDispute(second,bytes32(uint256(12)));
        bytes32 firstReport=s.reportIdFor(first,consumer,bytes32(uint256(11)));
        bytes32 secondReport=s.reportIdFor(second,consumer,bytes32(uint256(12)));
        bytes32 firstAssignment=_assign(first);bytes32 secondAssignment=_assign(second);
        vm.warp(1700);bytes32 decision=bytes32(uint256(13));uint64 deadline=1800;
        s.voteDisputeBySig(first,_quorum(first,firstAssignment,true,firstReport,decision,deadline));
        s.voteDisputeBySig(second,_quorum(second,secondAssignment,true,secondReport,decision,deadline));
        require(s.adjudicatorNonce(first,J1)==1 && s.adjudicatorNonce(second,J1)==1);
        require(s.settlementInfo(first).status==V10.Status.Confirmed
            && s.settlementInfo(second).status==V10.Status.Confirmed);
        _invariants();
    }
    function testRelayedVoteRequiresAtomicConsistentQuorum() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        uint64 deadline=uint64(block.timestamp+100);bytes32 decision=bytes32(uint256(3));
        V10.DisputeVotePermit[] memory singleVote=new V10.DisputeVotePermit[](1);
        singleVote[0]=V10.DisputeVotePermit(assignment,true,report,decision,0,deadline,_sig(J1KEY,_voteDigest(k,assignment,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,singleVote);require(s.adjudicatorNonce(k,J1)==0);
        V10.DisputeVotePermit[] memory mixed=_quorum(k,assignment,true,report,decision,deadline);
        bytes32 otherDecision=bytes32(uint256(4));
        mixed[1]=V10.DisputeVotePermit(assignment,true,report,otherDecision,0,deadline,_sig(J2KEY,_voteDigest(k,assignment,true,report,0,deadline,otherDecision)));
        vm.expectRevert();s.voteDisputeBySig(k,mixed);require(s.adjudicatorNonce(k,J1)==0 && s.adjudicatorNonce(k,J2)==0);_invariants();
        mixed=_quorum(k,bytes32(uint256(123)),true,report,decision,deadline);
        vm.expectRevert();s.voteDisputeBySig(k,mixed);require(s.adjudicatorNonce(k,J1)==0 && s.adjudicatorNonce(k,J2)==0);_invariants();
    }
    function testRelayedVoteRejectsUnselectedProviderSigner() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));bytes32 assignment=_assign(k);vm.warp(1700);
        uint64 deadline=uint64(block.timestamp+100);bytes32 decision=bytes32(uint256(3));
        V10.DisputeVotePermit[] memory permits=_quorum(k,assignment,true,report,decision,deadline);
        uint256 outsiderKey=84;
        permits[0]=V10.DisputeVotePermit(assignment,true,report,decision,0,deadline,_sig(outsiderKey,_voteDigest(k,assignment,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,permits);
        require(s.adjudicatorNonce(k,vm.addr(outsiderKey))==0 && s.adjudicatorNonce(k,J2)==0);_invariants();
    }
    function testUnavailableJuryTimeoutRefundsConsumerAndReporterBond() public {
        bytes32 k=_settle();vm.prank(REPUTATION_AUTHORITY);registry.removeProvider(address(183));
        vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        require(registry.assignmentHash(k)==bytes32(0));
        V10.Dispute memory dispute=s.disputeInfo(k);vm.warp(dispute.resolveAt);s.resolveTimedOutDispute(k);
        require(s.settlementInfo(k).status==V10.Status.JuryUnavailable);
        require(s.availableBalance(consumer)==82000 && s.providerStake(provider)==100000 && s.lockedStake(provider)==0);
        require(s.claimableBalance(provider)==0 && s.claimableBalance(rsigner)==0 && s.claimableBalance(POOL)==0);
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));s.claimDisputeBond(k,report);
        require(s.claimableBalance(consumer)==100 && s.totalReporterBonds()==0);_invariants();
    }
    function testPendingJuryCannotFinalizeAtOrAfterTimeoutAndRefundIsDeterministic() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));
        (,uint64 selectionBlock,,,,,,)=registry.assignmentInfo(k);
        vm.roll(uint256(selectionBlock)+1);vm.setBlockhash(selectionBlock,keccak256(abi.encode(k,selectionBlock)));
        V10.Dispute memory dispute=s.disputeInfo(k);vm.warp(dispute.resolveAt);
        vm.expectRevert();registry.finalizeJury(k);
        s.resolveTimedOutDispute(k);
        require(s.settlementInfo(k).status==V10.Status.JuryUnavailable && registry.assignmentHash(k)==bytes32(0));
        vm.expectRevert();registry.finalizeJury(k);
        registry.expireJury(k);
        (JuryRegistry.AssignmentStatus status,,,,,,,) = registry.assignmentInfo(k);
        require(status==JuryRegistry.AssignmentStatus.Failed && registry.pendingAssignments()==0);
        require(s.availableBalance(consumer)==82000 && s.providerStake(provider)==100000 && s.lockedStake(provider)==0);
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));s.claimDisputeBond(k,report);
        require(s.claimableBalance(consumer)==100 && s.totalReporterBonds()==0);_invariants();
    }
    function testReadySilentJuryTimeoutReleasesProviderEarnings() public {
        bytes32 k=_settle();vm.prank(consumer);s.openDispute(k,bytes32(uint256(1)));_assign(k);
        vm.warp(16001);s.closeExpiredChannel(id);s.resolveTimedOutDispute(k);
        require(s.settlementInfo(k).status==V10.Status.TimedOut);
        require(s.availableBalance(consumer)==98000 && s.providerStake(provider)==100000 && s.lockedStake(provider)==0);
        require(s.claimableBalance(provider)==1700 && s.claimableBalance(rsigner)==60
            && s.claimableBalance(POOL)==40 && s.claimableBalance(TREASURY)==200);
        bytes32 report=s.reportIdFor(k,consumer,bytes32(uint256(1)));s.claimDisputeBond(k,report);
        require(s.claimableBalance(consumer)==100 && s.totalReporterBonds()==0);_invariants();
    }
    function testClaimReentrancyAndExactTokenChecks() public {
        bytes32 k=_settle();vm.warp(1700);s.release(k);token.setHook(address(s),abi.encodeWithSignature("claim()"));vm.prank(provider);s.claim();require(!token.hookSucceeded());_invariants();
        token.setModes(true,false,false,false);vm.prank(consumer);vm.expectRevert();s.deposit(1);
    }
    function testFuzzBudgetInvariant(uint64 seed,uint8 action) public {
        uint256 budget=2000+uint256(seed)%18001;V10.SignedReceipt memory r=_receipt(id,1,budget);s.settleReservedReceipt(r);_invariants();
        if(action%2==0){vm.warp(1700);s.release(s.settlementKeyFor(id,bytes32(uint256(1))));}
        vm.warp(16001);s.closeExpiredChannel(id);_invariants();require(s.availableBalance(consumer)==98000);
    }
    function testRuntimeFitsEIP170() public view {require(address(s).code.length<=24576,"EIP170");}

    function testGovernanceSponsoredCapacityBoundAndNonWithdrawable() public {
        address sponsoredProvider=vm.addr(103); address sponsoredSigner=vm.addr(104);
        token.mint(address(this),10000); token.approve(address(s),type(uint256).max);
        vm.expectRevert();s.sponsorProviderCapacity(sponsoredProvider,1);
        s.setSponsoredCapacityLimit(10000);
        s.sponsorProviderCapacity(sponsoredProvider,10000);
        require(s.providerStake(sponsoredProvider)==10000);
        vm.prank(sponsoredProvider);vm.expectRevert();s.withdrawStake(1);
        vm.prank(sponsoredProvider);s.authorizeProviderSigner(sponsoredSigner);
        V10.OpenChannel memory c=_config(10000);c.providerOwner=sponsoredProvider;c.providerSigner=sponsoredSigner;
        c.providerNonce=s.providerAllocationNonce(sponsoredProvider);
        V10.ChannelPermit[] memory p=new V10.ChannelPermit[](1);p[0]=_permitFor(c,103);s.openCapacityChannels(p);
        require(s.allocatedStake(sponsoredProvider)==10000);
        vm.expectRevert();s.sponsorProviderCapacity(sponsoredProvider,1);
    }
}
