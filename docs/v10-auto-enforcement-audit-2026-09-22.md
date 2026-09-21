# V10 自动反作弊执行审计（2026-09-22）

## 结论

V10 合约本身支持在独立裁决达到阈值后自动结算：确认后会退还 Consumer 全额费用，并按策略扣减 Provider stake；dismiss/timeout 不会罚没。`nonReentrant`、settlement key 去重、每个裁决者一次投票和同一 report 的 quorum 约束，覆盖了重放、双花和重复投票的主要路径。

当前不能把 Relay 的 keeper 直接改成“自动裁决器”。`gateway/relay_keeper_v10.py` 仍只允许 `release` 和非惩罚性 `timeout`，不会自己制造证据或替用户投票。新增的 `voteDisputeBySig` 只接受独立裁决者钱包对同一案件的 EIP-712 投票签名，Relay 可以在 quorum 已满足后代提交一笔交易；合约仍负责最终退款和 stake 扣减。

## 已确认的安全边界

- `settleReservedReceipt` / `settleReservedBatch` 以 `channelId + requestId` 去重，并验证 Consumer、Relay、Provider 三方签名以及费用和容量边界。
- `voteDispute` 要求裁决者是独立地址、未提交该案证据、每案只能投一次，确认票必须指向已提交的 report，并达到合约 quorum 才会进入 `_confirm`。
- `_confirm` 只由合约根据已确认的 quorum 执行退款和 stake 扣减；keeper 没有绕过 quorum 的入口。
- `voteDisputeBySig` 使用每个裁决者的单调 nonce、过期时间、独立地址校验和原子批量提交；失败或重复签名整笔回滚。
- Relay 健康状态继续保持 `monetary_enforcement_enabled=false`，直到下面的执行条件全部具备。源码执行存储默认关闭，必须显式传入 `enabled=true` 才允许调用广播回调。

## 自动执行前必须补齐

1. 独立用户裁决服务：每个 Ed25519 用户审批和 EVM 投票签名必须绑定 settlement key、evidence hash、report id、decision hash、部署域和过期时间；用户审批还必须声明并绑定自己的 EVM judge 地址；服务端必须拒绝重复 signer、低 reputation signer 和关联方。
2. 有资金隔离的 V10 probe channel：主动探针必须使用专用预算和 Consumer owner 授权，不能使用 Relay 自有余额，也不能由 Provider/Relay 共同控制。
   Relay 侧只接受权限为 `0400/0600` 的 `MYCOMESH_RELAY_V10_PROBE_CHANNELS_FILE`，并要求每个 Provider peer 映射到已确认的 channel；探针仍只写入证据，不会自行提交 report 或 vote。
3. 幂等交易 outbox：投票、确认后的 bond claim 必须按 `(deployment, settlementKey, actionHash)` 唯一，链上状态变化、nonce 和 reorg 要重新核对后才允许发送。
4. kill switch：任何证据哈希不一致、quorum 不足、RPC reorg、签名域不一致或用户关联性无法证明，都只能 quarantine 和人工复核，不能降级为自动支付。

## 可安全开启的开关

现在可开启：risk store、Provider quarantine、证据收集和非惩罚性 release/timeout keeper。

现在不可开启：`monetary_enforcement_enabled`、自动 report、自动 slash/refund。自动 vote 的合约入口已经完成，但必须在新 V10 部署上完成独立用户签名服务、funded V10 probe channel、幂等 outbox 和端到端测试后，才可打开 Relay 广播回调。
