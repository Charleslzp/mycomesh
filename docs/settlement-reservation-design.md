# 两小时 / 100 笔结算：最小预锁设计草案

2026-09-18。本文保留最初设计及取舍。用户现已选择固定预算通道，V10 合约、Python/Node wire 与 Provider 持久账本已经实现并经本地测试；新合约已部署，但网络切换与真实体验尚在进行。最新事实见 [实施进度](network-optimization-progress-2026-09-18.md)。现有 [批量调度](settlement-batching.md) 和 [三小时 TTL 候选](v9-authorization-ttl-candidate-2026-09-18.md) 都不提供余额预锁。

## 结论与当前缺口

建议一次链上批量开启若干**固定执行通道**，同时预锁 Consumer 余额与 Provider 质押；通道绑定 Consumer owner/key、Relay、Provider owner/执行 signer。Provider 执行前持久占额，持有完整收款凭据并能绕过离线 Relay 自行提交。这样可摊薄预锁交易成本，又不把跨 Provider 支付安全交给 Relay 的本地账本。

当前 V9 的事实：

- `gateway/relay.py:2184`、`gateway/p2p.py:2004` 起只读取当前 grant、余额/stake 与单请求 maxFee，没有减掉全网未结算敞口。
- `contracts/MycoSettlementV9.sol:637` 的 `_settle` 在推理完成后才扣余额、锁 stake。`revokeKey`、`revokeProviderSigner` 可立即改变结算资格，`withdrawStake` 可提走未锁部分；Consumer 提现也可与离线账单竞争。
- 同 owner 多 key 共享余额，多 Provider signer 共享 stake。例如余额 100、两 Relay 各执行费用 60，合约不会超付，但后一个 Provider 可能事后拒付。延长 TTL 不能修复。
- 当前历史价格版本只追加，没有回写/停用既有版本的接口；应保留这一性质，不能把可追溯改价当作已存在问题。

## 方案比较与范围

| 方案 | 执行前成本 | 安全边界 |
| --- | --- | --- |
| 仅本地余额缓存/锁 | 无交易 | 不能防跨 Relay、提现或同 owner 多 key，公共长等待不可用 |
| 链上分给每 Relay 独占 allowance | 每轮预分配 | 防跨 Relay 重用，但恶意/双主 Relay 仍可向不同 Provider 超额承诺；仅适合可信运营方 |
| **固定 Provider signer 的双边通道** | 一次可开多个通道，额度耗尽再开 | Consumer/Relay 不能挪用该通道；实际 Provider 对自己的原子执行账本负责；需要预选 Provider |
| 逐请求链上 reserve | 每请求先锁并确认，再执行 | 请求有链上唯一资金锁；支持任意请求动态分配，但增加延迟及每请求 storage/gas |

仅给 Relay 签名承诺加序号、累计金额或金额区间，不能防它向不同 Provider 签发重叠承诺；等上链发现重叠再拒付已经太晚。建议首版直接为三台 Provider 分配互不重叠的通道，不再增加可转让的二级 Relay 额度池。路由只能选择有额度的通道；执行结果未知时不能换 Provider 重发。

安全保证以诚实 Provider 保管执行 key、正确保存自己的额度账本以及链最终性/及时提交为前提。它不保证无限期离线、无限深 reorg 或自身双主复制私钥后的收入。

## 最小合约与签名

**以下均为拟议接口。** 每通道一个 Consumer key、一个 Provider execution signer、一个 Relay admission signer；多 key/Relay/Provider 分开通道，从 owner 总账户原子扣额。

```solidity
struct CapacityChannel {
    address consumerOwner; address consumerKey;
    address providerOwner; address providerExecutionSigner;
    address relayPayee; address relayAdmissionSigner; address pool;
    bytes32 pricingChannel; uint64 pricingVersion; bytes32 pricingHash;
    uint256 capacity; uint256 maxFeePerRequest;
    uint256 settledMaxFee; uint256 creditRemaining; uint256 stakeRemaining;
    uint64 validFrom; uint64 admitUntil; uint64 claimUntil; bool closed;
}
mapping(bytes32 => CapacityChannel) capacityChannels;
mapping(address => uint256) allocatedStake;
mapping(address => uint256) consumerAllocationNonce;
mapping(address => uint256) providerAllocationNonce;
uint256 totalAllocatedCredit;

openCapacityChannels(configs, consumerOwnerPermits, providerOwnerPermits);
settleReservedReceipt(receipt);
settleReservedBatch(receipts); // 1..32，按 gas 分块
closeExpiredChannel(channelId); // anyone，余额只回原 owner
channelCapacity(channelId); // view
```

开通许可由两边 owner 签完整配置、额度、单笔上限、期限、各自 nonce 和许可提交有效期；Relay 可代付 gas，但临时 payment key 无权任意锁 owner 资金。开通时校验 grant/signer、key 有效期、价格、收款地址与独立裁决人数。`channelId = hash(domain, 双 owner, 双 nonce, configHash)`，旧 ID 不得变更或补额，补额新开通道；数组有限长，双边锁资原子成功或全部回滚。

新签名建议 EIP-712 **版本 10**，绑定 chain ID 与新合约地址：

| 消息 | 核心签名字段 | 签名者 |
| --- | --- | --- |
| OpenCapacityChannel | 完整 config hash、双 owner/nonce、capacity、maxFeePerRequest、validFrom/admitUntil/claimUntil、许可 deadline | 双 owner |
| ReservedPaymentAuthorization | channelId、owner/key、requestId/hash、固定 Provider signer、Relay 身份、价格 hash/version、maxFee、issuedAt/executeBy/settleBy | Consumer key |
| RelayDispatch | channelId、authorization hash、Provider signer、固定 Relay/pool 收款地址、executeBy/settleBy | Relay admission signer，**执行前签署** |
| ReservedUsageReceipt | channelId、authorization hash、dispatch hash、response hash、Provider owner/signer、input/output tokens、actualFee | Provider signer |

字段可通过不可变 channel/config hash 间接绑定，但必须有统一编码与真实 type hash，不能只放在未签名 JSON。结算不再要求执行后的 Relay usage 签名，否则 Relay 扣留签名仍可阻止付款。Provider 持有全部材料，任意 gas sponsor 可提交且不能改变收款地址。

结算唯一键为 `hash(channelId, requestId)`；同键不同 request hash 拒绝。不要沿用 V9 全局 `(owner,key,requestId)` 冲突拒付：恶意 Consumer 可在两个已预付通道签同 ID，让第二个诚实 Provider 执行后被拒。不同通道授权是独立消费；客户端必须控制逻辑请求重发，不能靠拒付实现跨通道幂等。

## 金额、质押与权限不变量

设通道 capacity 为 C，两边各锁 C：Consumer `available -= C; totalAvailable -= C; totalAllocatedCredit += C`；Provider 要求 `providerStake - lockedStake - allocatedStake >= C`，然后 `allocatedStake += C`，totalStake 不变。Consumer 提现只看自由 available；Provider 提现必须减掉 allocated 和 locked。已有提现申请与开通按上链顺序竞争，不能静默取消用户提现。

首版**不循环复用 maxFee 差额**：Provider 每接一笔就永久消耗本通道 maxFee 预算，直到通道结束；包括已结算、执行中与 unknown。合约结算累计 `settledMaxFee += maxFee <= capacity`，实际只收 actualFee。差额在通道到期后返还，避免结算后立即复用预算遇 reorg 再次超接单。

结算转账记账：`creditRemaining/totalAllocatedCredit -= actualFee; totalPendingFees += actualFee`；同时 `stakeRemaining/allocatedStake -= actualFee; lockedStake += actualFee`。之后保留 V9 争议、释放、退款/罚没状态机。正常释放解相应 locked stake；欺诈退款回 Consumer 自由余额，罚没不得超过该 receipt 锁额或侵占其他通道 allocated stake。释放、退款不自动回填旧通道。

```text
providerStake[p] >= lockedStake[p] + allocatedStake[p]
sum(channel.stakeRemaining for p) == allocatedStake[p]
sum(channel.creditRemaining) == totalAllocatedCredit
0 <= settledMaxFee[channel] <= capacity[channel]
stableLiabilities = totalAvailable + totalAllocatedCredit + totalClaimable
                  + totalPendingFees + totalStake + totalReporterBonds
stablecoin.balanceOf(contract) >= stableLiabilities
```

totalStake 已包含两类 stake 锁，不能重复加进 liabilities。关闭仅在 `block.timestamp > claimUntil` 后返还剩余 credit、解除剩余 allocated stake；已托管/争议的 locked stake 不受影响。任何人可调用，但不能替 owner 提现、转给自己。治理/keeper/AI 不获新增退款或罚没裁量权。

## 执行账本、撤销与恢复

Provider 在调用模型前，用数据库事务原子核验 `sum(历史已接受 maxFee)+本笔 <= capacity`，写入唯一 `(contract,channelId,requestId)`、请求 hash、全部签名、maxFee、链锚点和 reserved 状态并 durable commit。完成后先持久保存响应/usage/receipt，再返回。重复请求返回原状态；unknown 不释额、不重跑。现有 Provider 入驻钱包发送 fence **不是**此金额账本。

一个 execution signer 只能有一个受 fencing 保护的额度写入方；多 worker 共享原子账本，无共享事务的多机器用不同 signer/通道。丢失账本就停接单并对账/等通道过期，不能根据余额创建空账本。Relay 与 Provider 各持收据；Provider 必须有自行提交 gas 或独立 sponsor 路径。

**首版选择固定到期、不可单方提前撤销的通道权限。** owner 的 revoke 只禁止未来开通；已有 key/signer 的快照权限继续至 claimUntil。钱包必须展示仍锁定金额、最后到期时间和密钥被盗后的有限敞口，不能只显示“已撤销”。admitUntil 要求诚实 Provider 停止新执行，但离线签名时间不能证明真实签署先后，不能声称它等价于链上即时撤销。没有单方提前退款入口，避免抢先撤回已执行账单的资金。

若必须“撤销确认后任何尚未锁定请求都不可花钱”，选择逐请求 `reserveRequests`：每项链上绑定 exact authorization hash、owner/key、Provider、Relay、request hash、maxFee、价格与 claim deadline，双边各锁 maxFee；确认后才执行。已有 reserve 保持可结算，revoke 禁新 reserve；结算退 maxFee 差额，超期未结算返回原 owner。可以批量锁已知请求，但不能用未知 request hash 的总额预锁冒充逐请求保证；每请求 storage 与执行前确认成本仍存在，需实测 gas。

## 7200/100 与期限

保持从上次成功结算起 **7200 秒或 100 笔先到触发**；首单等待不超过周期，空队列不发交易，单交易仍最多 32/default 8。deadline 提前 flush、失败重试、unknown 恢复优先，不重新等待两小时。

- `executeBy <= admitUntil`、`settleBy <= claimUntil`；接单剩余期限须覆盖最大执行预算 + 7200 + 提交/恢复余量，否则拒绝长等待或明确提前提交。当前最大执行预算 300 秒；9000 秒剩余窗口可留 1500 秒余量，但不是入块保证；完整 TTL 还要包含时钟回溯，并核验实际链上 cap。
- `claimUntil - admitUntil` 同样覆盖最后接单后的预算。旧通道残额不能提前用于下一轮；滚动开通需要额外余额/stake。争议期从实际托管上链开始，通道结束不终止 Pending/Disputed。
- 未确认/广播未知的开通不执行。结算 unknown 保存原交易、nonce/hash 和 receipt 集合，先查链/业务状态，不清账、不重新执行。重启不清额度或计时水位。
- 开通依赖固定 manifest 的确认/最终性策略，记录 block hash/number/log index。浅 reorg 回滚事件投影，保留执行占额并重播收据；深 reorg 撤销已依赖开通则停单。六确认不等价于绝无重组，必须明确 finalized 或有限确认风险政策。
- 到期释放由链上时间和交易顺序决定；超期未托管收据失效。离线时间超过期限仍可能损失收入，保护性 flush 与双路径提交必须验收。

新增 health 应含 allocated/free、通道剩余接单额度、claim deadline、执行 unknown/未托管金额、账本完整性与链锚点；公开端点只放聚合值，不暴露签名和用户明细。

## 迁移与有限验收

**这是新协议，建议 V10 reserved settlement，不是当前 V9 地址兼容升级。** storage、签名、Relay 签名时点、撤销及唯一键均改变。单独延长 TTL 的候选仍可用 V9 名称；不能把它当成本设计完成。

先实现合约/性质测试，再接 Provider 金额账本与消息协议，最后接钱包、发现和 Relay。manifest 固定新地址/code hash/domain、`reservation_mode=provider_bound_channel`、TTL 与最终性策略，任一端缺能力就拒绝，不能默默降级为无预锁。

旧 V9 停新增长授权，保留旧 outbox、unknown、争议和 keeper；可用资金经 owner 明确交易退出/充值新地址，旧 pending/disputed stake 不计作新可用余额。新旧链上义务分别对账，回滚入口也不能删除新收据。先用三台受控 Provider、两台 Relay、测试币有限验证，再开放普通用户长等待。

待写验收共八组，并非已有通过记录：

1. 同 owner 多 key/多 Relay 并发开通与提现；三 signer 共用 stake，锁资与罚没后会计不变量始终成立。
2. Relay 超发/重叠票据、跨 Provider 错绑在执行前被拒；双主、事务竞争与数据库丢失停单。
3. 同通道重复请求幂等、不同 payload 拒绝；不同通道同 ID 不抢付款；跨域/nonce/角色/价格篡改不可重放。
4. maxFee 差额不复用、结算与关闭同块边界、revoke 仅作用未来通道；钱包准确展示残余锁资。
5. 执行各阶段崩溃后恢复不丢额度、不重跑；Relay 失联后 Provider 独立提交。
6. 开通/结算广播 unknown、nonce 冲突、浅/深 reorg、到期恢复；遵守最终性政策。
7. 7200/100 OR、短期限提前 flush、最大 32 分块、批量开通/结算 gas 测量。
8. 通道关闭后的争议/退款/罚没/timeout、permissionless 释放、独立裁决人数、所有会计守恒。

落实现前仍须决定三项：接受固定通道不可即时撤销的授权，还是采用逐请求 reserve；通道金额/有效期与最终性政策；是否接受预选 Provider 的路由限制。上述决定不影响结论：TTL 和 gas 充值都不能代替双边资金锁。
