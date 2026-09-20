# Relay 按时间或笔数批量结算

本文件说明 2026-09-18 工作树中的调度实现、配置和上线约束。实现与测试已完成，**不代表已部署到当前受控网络，也不代表已批准向普通用户开放两小时的未结算信用敞口**。现网最初的 V9 合约授权上限为一小时；工作树中的三小时候选是另一份待验收、待部署的合约代码。

## 触发语义

默认任一条件成立就开始提交：

1. 距上次成功结算达到 **7200 秒**。从未成功结算的队列从首笔入队开始计时；任何最老待提交账单都不会因为之后的交易或新账单而重新等待超过一个周期。
2. 累计 **100 笔 pending receipt**。重复上传同一 receipt 不增加计数。
3. 现有签名即将到期，达到最早截止时间减去安全余量。这是保护性的提前提交，可以早于两小时和 100 笔。

空队列不发送交易。计时中的“成功结算”是已核验的结算交易结果：V9 为进入合约托管，**不是争议期结束、收益可领取或钱包已收款**。V9 的争议窗口从实际上链托管开始，延迟提交也会相应延后 Provider 获得可领取收入的时间。

**100 是队列触发阈值，不是单笔链上交易大小。** 每笔交易仍使用独立的 `batch_size`，默认 8，合约最多 32，并保留原有估算 gas、失败缩批机制。例如 batch size 32 时，100 笔会提交为 32、32、32、4；第一笔交易成功后，剩余 68 笔不会回到两小时等待。

触发时将队列的 rowid 水位和原因持久保存为待处理批次。重启继续排空该批次；之后到来的普通账单留待下一轮。之后到来的紧急短授权账单可以加入当前批次并优先处理，但不重置原批次时间。

相关实现：[outbox 调度](/Users/lzp/mycomesh/gateway/session_relayer.py:536)、[worker 调度入口](/Users/lzp/mycomesh/gateway/session_relayer.py:1050)。

## 配置

| 环境变量 | CLI 参数 | 默认值 | 作用 |
| --- | --- | ---: | --- |
| `MYCOMESH_RELAY_SETTLEMENT_INTERVAL_SECONDS` | `--settlement-interval-seconds` | 7200 | 队列最长正常等待周期 |
| `MYCOMESH_RELAY_SETTLEMENT_COUNT_THRESHOLD` | `--settlement-count-threshold` | 100 | 触发提交的 pending 数 |
| `MYCOMESH_RELAY_SETTLEMENT_DEADLINE_MARGIN_SECONDS` | `--settlement-deadline-margin-seconds` | 300 | 签名截止前的提前提交余量 |
| `MYCOMESH_RELAY_SETTLEMENT_BATCH_SIZE` | `--settlement-batch-size` | 8 | 每笔交易包含的 receipt 数，最多 32 |

三个新设置分别接入 CLI、`serve_relay`、`RelayState` 和 `RelaySettlementSubmitter`；Compose 传入对应参数。部署示例位于 [.env.deploy.example](/Users/lzp/mycomesh/.env.deploy.example:227)，不是通用 `.env.example`。

周期允许 1–604800 秒、数量阈值允许 1–4096、配置的 deadline margin 允许 1–86400 秒。有效 margin 至少覆盖当前一次交易准备、回执等待和轮询预算之和；配置比这个值更小时会使用更大的安全值，health 展示实际值。链拥堵、连续故障或长队列可能超过余量，因此它不是入块时限承诺。

默认值也影响使用同一 worker 的 **V5、V6、V7、V8**。需要维持原有尽快提交行为的部署应显式配置 `MYCOMESH_RELAY_SETTLEMENT_COUNT_THRESHOLD=1`。这只取消等笔数/周期的等待，不等于消除了瞬时并发资金竞争。

## 一小时现网与三小时候选

初始 V9 合约 `0x8ed70585cb60082e6f8e64f5190a3d8014e42367` 使用一小时 `MAX_AUTHORIZATION_TTL`，此前 Consumer 默认授权 900 秒。合约在 `settleSignedReceipt/Batch` 执行时仍检查 `deadline`，不能等两小时后直接使用过期签名。默认 margin 300 秒时，一份剩余约 900 秒的授权会在约 600 秒后提前触发；执行推理已消耗的时间会进一步减少实际等待时间。

当前 Solidity 工作树将候选上限改为三小时，配套协议代码将 3600 与 10800 分别识别并固定到部署清单。**三小时候选尚未部署，不能修改旧清单的数字来冒充旧合约已升级。** 新合约需要独立部署验证、明确合约地址、与链上 `MAX_AUTHORIZATION_TTL()` 一致的清单及客户端/Provider/Relay 协议适配；现有合约中的资金、授权和未决账目也不能被新地址自动继承。

运行时也必须防止未使用官方 Consumer 的请求绕过清单约束：V9 Relay 与 Provider 对 `deadline-issued_at > 3600` 的授权额外读取目标合约 `MAX_AUTHORIZATION_TTL()`，上限不足或 RPC 无法核验时在实际推理前拒绝。短授权保留原有上限兼容路径，不增加 TTL getter RPC。Relay 使用已读取的 grant、Provider 另行读取 grant，核验 key 有效、额度足够且 `valid_until=0` 或覆盖整个授权 deadline。相关实现见 [Relay runtime](/Users/lzp/mycomesh/gateway/relay.py:2198)、[Provider runtime](/Users/lzp/mycomesh/gateway/p2p.py:2004)。这些读取不构成资金预留，也不能阻止核验后发生的链上撤销。

deadline 提前提交目前取签名 authorization、签名 receipt、Relay attestation 和 Provider settlement receipt 中已有 deadline 的最小值。它不代表已经覆盖以下可变化的链上条件：

- payment key 在接单核验之后被撤销或修改；接单时已有 grant 有效期覆盖检查，之后的变更仍由合约在结算时重新判断。
- Provider signer 被撤销、价格版本被停用或其他合约准入条件变化。
- V5/V6 链上 session 自身的有效期及状态。

不能延长收到的旧签名，也不能忽略合约重新检查的条件。升级 TTL 只解决“签名在等待后仍有可能有效”，**不会预留 Consumer 余额或 Provider 质押**。

## 未结算余额与质押：公共两小时等待的上线门槛

当前 V9 接单过程读取 `account_balance >= 当前请求 max_fee`，再读取 `provider_stake.available >= 当前请求 max_fee`。这是单次快照检查，不是链上锁定，也没有扣除该 owner 在其他 Relay 或本 Relay 先前已完成但未提交的全部费用。见 [Relay 接单](/Users/lzp/mycomesh/gateway/relay.py:2187)、[Provider 质押检查](/Users/lzp/mycomesh/gateway/p2p.py:2004)。

名称中含 reservation 的现有机制不能替代资金预留：

- submitter `reserve_admission` 预留的是本 Relay 的提交 gas 容量。
- Provider/Relay load reservation 限制的是调度槽位。
- `OperatorBudget` 是单节点、固定周期内的用量预算，不按全网 Consumer owner/Provider owner 清算；它的 in-flight 预留在重启后不作为持久资金锁保留。
- V9 payment authorization 中的 `max_fee` 是单笔授权上限，不是预付金中已独占的额度。

例如同一账户余额为 100，两台 Relay 各接受一笔实际费用 60 的请求，两次接单读取都可能通过；两次推理已经执行，第二次结算时却可能因余额不足失败。单 Relay 连续接收多笔也有同样问题。三台 Provider 若共用一个 owner，其质押也必须合并计算，不能每台都视为独立拥有整份 available stake。

合约在结算时仍检查余额和 available stake，因此不会凭空支付超额资金；实际风险是 **已执行服务无法收款、批次回滚及后续结算被影响**。扩大等待时间会扩大这一风险窗口。消费者可以申请提现或撤销 key；Provider owner 还能提走当时未锁定的 stake、撤销 signer。仅在 UI 隐藏按钮或要求并发为 1 不能防止直接链上操作和连续消费。

**公共普通用户的长等待结算应保持关闭，直到有可强制执行的额度预留/隔离方案。** 可采用有明确合约约束的预先锁定额度、互不重叠的 Relay allowance，或其他经过验证的等价协议；仅改 TTL、增加缓存余额或单机锁不够。需要同时处理撤销/提现与已接受请求的优先级，以及重启和跨 Relay 故障恢复。

### 受控试验可以怎样限制敞口

若仅在现有受控测试网演示延迟结算，必须在放行前留下可以复核的预算与执行记录：

1. 限定实际测试的 Consumer owner/key、Provider owner/signer 和 Relay 集合，关闭未计入预算的入口、探测调用和直接调用路径。优先把一个 Consumer owner 和一个 Provider owner 的请求固定到唯一 Relay；仅限制 key 不能隔离同一 owner 下其他 key 的余额。
2. 以固定区块核验各 owner 的余额/available stake，给全网所有 Relay 分配不重叠额度，并将未结算、in-flight、未知执行/广播的保守敞口合并计算。对 Consumer owner 的总额不得超过可用余额减安全余量；对 Provider owner 同理不得超过可用 stake 减安全余量。
3. 未完成/未知执行按 `max_fee` 占额；已完成且回执已验证但未确认结算按可核实 actual fee 占额。释放额度必须依据明确的未派发证据或已确认链上结果，不能仅因进程退出、RPC 失败或等待时间结束释放。已包含在链上余额/locked stake 的账目要按同一核验区块正确对账，避免既漏记也重复扣减。
4. 最简单的受控试验是预先确定有限的一组请求，并保证它们的 `sum(max_fee)` 全部可覆盖；超过该组就停止，而非自动开启下一轮预算。若要持续接单，需要持久的逐 owner 敞口账本及原子接单预留，而非操作人员口头承诺。
5. 测试期间由同一受控操作方保证不提现、撤销签名或变更价格，保留足够的 Relay gas，并负责及时处理 pending/unknown。这个限制只适用于自有测试身份，不能作为对不受控用户的安全保证。

当前调度实现没有声称已经提供上述跨 Relay 敞口账本。gas 预留保持原有保守下界，仍扣除每笔 pending/submitted/broadcast_unknown 和 in-flight admission，不因批次扩大就把预留 gas 除以批次数。

## 失败、重启与停机

- Pending 重试带有错误/attempt 状态时不等两小时；原始 `enqueued_at` 不随重试变化。持久批次水位也不随重启变化。
- 已提交交易优先恢复其原 tx hash 和持久签名数据。只可能重新广播完全相同的交易，不分拆已签名批次，也不重取 nonce 构造新交易。
- 旧记录为 `broadcast_unknown` 且没有可恢复 tx hash 时停止新交易，等待明确对账；不能绕过它继续使用 nonce。
- 已广播的交易即使 authorization 现在过期也不丢弃，因为它可能已经在截止前执行；先恢复回执和业务状态。
- `stop()` 目前只是停止 worker 并做有界 join，**没有自动清空 settlement 队列**。Relay 的 probe drain 也不是 settlement drain。计划停机必须先停止接单、等在途执行结束、让所有 pending 触发提交并对账，确认需要保留的 submitted/unknown 均已处理后再停；必要时在维护配置使用 count threshold 1。不能删除 outbox、切换空数据库或换交易身份来“清掉”未知状态。
- 短暂重启保留时间与队列；超过签名期限的离线仍可能导致未广播 pending 永久无法结算。持久化本身不能消除这个业务损失。

## Health 字段

Relay health 的 `settlement_submitter.batching` 增加以下公开字段，不返回签名和原始交易：

| 字段 | 含义 |
| --- | --- |
| `interval_seconds`, `count_threshold`, `deadline_margin_seconds` | 实际调度配置 |
| `pending_count` | 尚未广播的 pending receipt 数 |
| `oldest_pending_at`, `oldest_pending_age_seconds` | 不因重试重置的最老入队时间与账龄 |
| `earliest_authorization_deadline` | 当前 pending 的最早已记录签名截止时间 |
| `last_settlement_at` | 最近一次已核验成功结算的本地记录时间，重启保留 |
| `next_trigger_at`, `next_trigger_reason` | 下一次开始提交的计划时间和触发原因，不是最终入块时间 |
| `flush_active`, `due` | 是否正在排空持久批次，以及现在是否应处理 |

`next_trigger_reason` 为 `empty`、`interval`、`count`、`authorization_deadline`、`retry`、`recovery` 或 `broadcast_unknown`。空队列和无法恢复的未知广播没有正常下一触发时间。已有 `outbox`、`settlement_ready`、`gas_capacity_remaining`、最近成功/失败字段继续有效；deadline 保护并不绕过 unknown、身份或 gas 检查。

建议告警直接使用最老账龄、最早签名剩余时间、低 gas、unknown、永久失败数和到期未释放数。不要只检测进程在线，也不要把 pending receipt 数当作金额预留。

## 本地验证记录

新增 [test_session_relayer_batching.py](/Users/lzp/mycomesh/tests/test_session_relayer_batching.py) 的 14 项测试覆盖 7200 秒/100 笔 OR、空队列、重复入队、从上次结算计时、首单等待上界、短授权提前触发、紧急新账单、跨重启分批排空、重试、整批广播恢复、旧未知记录阻断、旧 schema 迁移和公开 health 字段。时间阈值测试使用合成 receipt，不会把超出现网一小时 TTL 的 fixture 当作可真实结算的签名。

六个相关 suite 共 **113 项通过**：batching、session relayer、health、submission、connections、V9 runtime。二次只读配置复核中，现有 gas 配置与部署配置测试另外 **30 项通过**；CLI 默认解析为 7200/100/300/8，自定义环境值也正确透传到解析结果。所有验证使用 localhost、模拟 RPC 或配置读取；没有签名广播、资金操作或远端部署。新批量默认对旧版本的语义变化和停机 drain 限制已在上文明确，局部测试通过不代表现网的长期敞口风险已解决。

补充真实执行入口保护后，新增 9 项 V9 runtime 测试，验证三小时签名遇一小时合约被拒、三小时合约允许匹配授权、getter/grant RPC 失败拒绝、grant 在 deadline 前到期拒绝及短授权无需 TTL RPC。V9 runtime、Relay security、V7/V8 Provider、controlled V9 与 scheduler 六个 suite 共 **132 项通过**（与上面的 suite 有重叠，不应把计数简单相加）。测试用真实签名生成逻辑与模拟网络状态，没有启动真实模型或广播链上交易。
