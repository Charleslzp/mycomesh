// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {MycoSettlementV10 as V10} from "../contracts/MycoSettlementV10.sol";
import {MockExactTokenV9 as Token, VmV9} from "./MycoSettlementV9.t.sol";

contract MycoSettlementV10Test {
    VmV9 constant vm = VmV9(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant CKEY=101; uint256 constant PKEY=102;
    uint256 constant KEY=1; uint256 constant PSIGN=2; uint256 constant RSIGN=3;
    bytes32 constant PRICE=keccak256("v10-price");
    Token token; V10 s; address consumer; address provider;
    address key; address psigner; address rsigner;
    address constant TREASURY=address(90); address constant POOL=address(91); address constant REPORTER=address(92); address constant PENALTY=address(99);
    uint256 constant J1KEY=81; uint256 constant J2KEY=82; uint256 constant J3KEY=83;
    address J1; address J2; address J3;
    bytes32 id;
    function _voteDigest(bytes32 key_,bool confirmed,bytes32 report,uint256 nonce,uint64 deadline,bytes32 decision) internal view returns(bytes32) {
        bytes32 typehash=keccak256("DisputeVote(bytes32 settlementKey,bool confirmed,bytes32 reportId,bytes32 decisionHash,uint256 nonce,uint64 deadline)");
        bytes32 structHash=keccak256(abi.encode(typehash,key_,confirmed,report,decision,nonce,deadline));
        return keccak256(abi.encodePacked("\x19\x01",s.DOMAIN_SEPARATOR(),structHash));
    }
    function setUp() public {
        vm.warp(1000);consumer=vm.addr(CKEY);provider=vm.addr(PKEY);key=vm.addr(KEY);psigner=vm.addr(PSIGN);rsigner=vm.addr(RSIGN);
        J1=vm.addr(J1KEY); J2=vm.addr(J2KEY); J3=vm.addr(J3KEY);
        token=new Token();address[] memory judges=new address[](3);judges[0]=J1;judges[1]=J2;judges[2]=J3;
        s=new V10(address(token),address(0),TREASURY,address(this),PRICE,
            V10.ChannelConfig(1000,4000,2000,8500,300,200,1000,true),
            V10.DisputePolicy(100,200,30,100,5000,2000,5000,600,0,0,0,0,PENALTY),judges,2);
        token.mint(consumer,100000);vm.prank(consumer);token.approve(address(s),type(uint256).max);vm.prank(consumer);s.deposit(100000);
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
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));bytes32 report=s.reportIdFor(k,REPORTER,bytes32(uint256(1)));vm.warp(1700);
        vm.prank(J1);s.voteDispute(k,true,report,bytes32(uint256(3)));vm.prank(J2);s.voteDispute(k,true,report,bytes32(uint256(3)));
        require(s.availableBalance(consumer)==82000 && s.providerStake(provider)==99000 && s.allocatedStake(provider)==18000 && s.lockedStake(provider)==0);s.claimDisputeBond(k,report);_invariants();
    }
    function testDisputeQuorumCanBeRelayedAfterJudgeWalletApprovals() public {
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,REPORTER,bytes32(uint256(1)));vm.warp(1700);
        V10.DisputeVotePermit[] memory permits=new V10.DisputeVotePermit[](2);
        uint64 deadline=uint64(block.timestamp+100);
        bytes32 decision=bytes32(uint256(3));
        permits[0]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J1KEY,_voteDigest(k,true,report,0,deadline,decision)));
        permits[1]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J2KEY,_voteDigest(k,true,report,0,deadline,decision)));
        s.voteDisputeBySig(k,permits);
        V10.Settlement memory settlement=s.settlementInfo(k);
        require(settlement.status==V10.Status.Confirmed && s.adjudicatorNonce(J1)==1 && s.adjudicatorNonce(J2)==1);
        _invariants();
    }
    function testRelayedVoteNonceAndExpiryAreFailClosed() public {
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,REPORTER,bytes32(uint256(1)));vm.warp(1700);
        V10.DisputeVotePermit[] memory permits=new V10.DisputeVotePermit[](1);
        uint64 deadline=uint64(block.timestamp-1);bytes32 decision=bytes32(uint256(3));
        permits[0]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J1KEY,_voteDigest(k,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,permits);_invariants();
        deadline=uint64(block.timestamp+100);
        permits[0]=V10.DisputeVotePermit(true,report,decision,1,deadline,_sig(J1KEY,_voteDigest(k,true,report,1,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,permits);_invariants();
    }
    function testRelayedVoteRequiresAtomicConsistentQuorum() public {
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,REPORTER,bytes32(uint256(1)));vm.warp(1700);
        uint64 deadline=uint64(block.timestamp+100);bytes32 decision=bytes32(uint256(3));
        V10.DisputeVotePermit[] memory singleVote=new V10.DisputeVotePermit[](1);
        singleVote[0]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J1KEY,_voteDigest(k,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,singleVote);require(s.adjudicatorNonce(J1)==0);
        V10.DisputeVotePermit[] memory mixed=new V10.DisputeVotePermit[](2);
        mixed[0]=singleVote[0];bytes32 otherDecision=bytes32(uint256(4));
        mixed[1]=V10.DisputeVotePermit(true,report,otherDecision,0,deadline,_sig(J2KEY,_voteDigest(k,true,report,0,deadline,otherDecision)));
        vm.expectRevert();s.voteDisputeBySig(k,mixed);require(s.adjudicatorNonce(J1)==0 && s.adjudicatorNonce(J2)==0);_invariants();
        vm.prank(J1);s.voteDispute(k,true,report,decision);
        V10.DisputeVotePermit[] memory hybrid=new V10.DisputeVotePermit[](2);
        hybrid[0]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J2KEY,_voteDigest(k,true,report,0,deadline,decision)));
        hybrid[1]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J3KEY,_voteDigest(k,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,hybrid);require(s.adjudicatorNonce(J2)==0 && s.adjudicatorNonce(J3)==0);_invariants();
    }
    function testRelayedVoteRejectsAnyEarlierOppositeManualVote() public {
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));
        bytes32 report=s.reportIdFor(k,REPORTER,bytes32(uint256(1)));vm.warp(1700);
        bytes32 manualDecision=bytes32(uint256(2));vm.prank(J1);s.voteDispute(k,false,bytes32(0),manualDecision);
        uint64 deadline=uint64(block.timestamp+100);bytes32 decision=bytes32(uint256(3));
        V10.DisputeVotePermit[] memory permits=new V10.DisputeVotePermit[](2);
        permits[0]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J2KEY,_voteDigest(k,true,report,0,deadline,decision)));
        permits[1]=V10.DisputeVotePermit(true,report,decision,0,deadline,_sig(J3KEY,_voteDigest(k,true,report,0,deadline,decision)));
        vm.expectRevert();s.voteDisputeBySig(k,permits);
        require(s.adjudicatorNonce(J2)==0 && s.adjudicatorNonce(J3)==0);_invariants();
    }
    function testTimeoutAfterChannelCloseNeverSlashes() public {
        bytes32 k=_settle();vm.prank(REPORTER);s.openDispute(k,bytes32(uint256(1)));vm.warp(16001);s.closeExpiredChannel(id);s.resolveTimedOutDispute(k);
        require(s.providerStake(provider)==100000 && s.lockedStake(provider)==0);_invariants();
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
