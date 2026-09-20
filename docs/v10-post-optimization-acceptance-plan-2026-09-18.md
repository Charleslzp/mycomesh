# V10 优化后验收计划（2026-09-18）

这是验收条件和证据要求，不是已完成部署声明。只有现场产出的交易、账本及模型执行证据才能把对应项目改为通过。

## 当前证据边界

| 层级 | 已验证内容 | 不能据此声称的内容 |
|---|---|---|
| Node 本地测试 | `node --test packages/mycomesh-cli/test/consumer-reserved.test.mjs`：11 项通过。真实 Node/Python 密码学互通；本地 HTTP fixture；错误标签不触发重放；未知结果占额；撤销后的快照语义；旧 Key 预算展示 | 真实 Relay/Provider 已运行、实际模型已执行、Sepolia 已结算 |
| Provider 本地测试 | 账本与 Provider V10/V7/V8/bootstrap 相关原 65 项通过，随后新增两项 Provider V10 检查并重跑全部 14 项 V10 测试通过；另有 canonical RPC 边界检查 | fixture RPC 不是链上资金证明，fixture inference 不是 Codex 模型执行 |
| 合约及本地 EVM | 使用独立合约测试、本地 EVM 回执报告验收，保存命令及输出 | 加速时间/本地挖块不等于真实两小时运行 |
| 真实测试网 | 待逐项附现场证据 | 不得将 `eth_call`、calldata 计划、receipt 排队、交易提交或托管描述成已到账 |

## 三条实际路线

| 路线 | 执行端 | 固定 Relay | 必须记录 |
|---|---|---|---|
| A | P2 | R1 | capacity channel ID、Provider owner/signer、Relay owner/signer、模型、请求 ID |
| B | P3 | R1 | 同上，Provider 签名必须来自 P3 |
| C | P4 | R3 | 同上，固定 Relay 签名必须来自 R3 |

每通道计划容量为 20,000,000 个最小单位、每请求上限 100,000；以最终已确认 manifest 和链上 `channelInfo` 为准。核对测试币 decimals 后才能展示人类金额。`valid_from` 留出约 20 分钟，六个确认后由 Provider 预激活，且当时距开始仍超过 300 秒。三个执行 signer 分别只运行一个 writer；禁止通过复制 signer 和账本增加并行实例。

## 发布前检查

1. 保存最终 Git revision/构建摘要、包 tarball 内容、节点运行版本、manifest SHA-256。安装实际打包产物验证启动，确保 `consumer-reserved.mjs` 和 `consumer-request-journal.mjs` 在 npm `files` 内，而不仅是源码目录可运行。
2. Consumer 加载顶层网络文件和它引用的 deployment，得到相同三条 capacity channel ID；固定预算通道、链 ID、合约、价格版本与哈希不可由 Relay health 替换。
3. 使用 canonical、hash-pinned RPC 读取已确认通道、链上代码和 TTL。核对 owner/key、Provider signer、Relay signer、资金和质押预留、时间边界。
4. 验证三个 Provider 的原账本、anchor、独占 writer 锁和预激活记录；重启正常恢复。缺失文件/旧备份拒绝继续的测试只在隔离 fixture 做，不删除真实账本。
5. 两个 Relay 的持久 dispatch/outbox/nonce journal 就绪。分别确认 `settlement_interval_seconds=7200`、`settlement_count_threshold=100`、链上 batch 最大 32、deadline 提前排空参数。未满足 100 的待结算也必须由定时器处理。
6. 清晰显示“Key 可登录”“预算已锁定”“通道等待开始”“通道可推理”四种不同状态。撤销 Key 只影响新通道；已有固定预算仍按原始快照有效。轮换 Key 后仍可查看和到期释放旧预算。

## 三路线冒烟与费用闭环

每条路线至少完成一次真实短推理。按用户要求的实际模型调用，保存 model capability 的来源及真实上游记录，不能用 mock 输出冒充。

每次保留以下无秘密证据：Consumer request ID/hash、capacity channel ID、authorization hash、dispatch hash、Provider response hash、输入/输出 token、MAX 占额与 actual fee、节点版本、耗时。每条路线的完整签名在本地验证，API 返回内容必须与 Provider response commitment 相符。不得在公开报告保存 payment key、钱包私钥或完整敏感 prompt。

通过条件：Consumer 预发送记录可见；Provider 调模型前已永久占额；返回前已保存响应和独立回执；Relay 不要求模型完成后的新签名；真正签名者和链上固定路线一致。排队状态显示待结算，链上成功后显示托管；争议期后释放及领取是后续独立状态。

## 100 条触发：按每个 Relay 的 outbox 计数

“100 条”是触发排空的队列阈值，不是一个能容纳 100 条回执的链上交易，也不是两个 Relay 的合计阈值。合约每次最多 32 条，所以 100 条通常形成 32/32/32/4 四批。

- R1：在干净、已记录基线的队列周期内，A、B 各产生 50 条真实短推理，共 100 条。
- R3：C 产生 100 条真实短推理，独立证明 R3 的计数阈值。
- 单独观察达到 99 条时仍未因 count 触发，达到 100 后出现 `reason=count`。不能混入其他流量、之前的未清账单或迫近截止日期的优先排空；这些都可能提前触发。
- 保存每批交易哈希、实际提交条数、六个确认后的 receipt/escrow event，以及全部 100 个 request 的 settlement key。第一批确认后余下 68 条不能重新等待两小时。可在第一批确认后受控重启一次 worker，确认排空周期被持久恢复。
- 三个 Provider 的 `reserved` 增量等于各自接受请求的 MAX 总和；actual fee 较小也不能补充本通道执行额度。Consumer 两台设备同时调用相同通道时，由同一个 Provider 账本原子限制，不能依赖某一设备的 history 来保证全局额度。

若只向 R1/R3 合计发送 100 条而两边都不足 100，只能证明网络请求量，不能声称验证了 count=100。

## 两小时触发：必须真实等待

计数验收完成并记录该 outbox 的 `last_settlement_at` 后，在 R1 和 R3 各放入少于 100 条的新回执，记录调度器公布的最早待处理时间、下次触发时间和截止余量。保持正常 `7200` 秒配置，观察真实墙钟时间到期后的 `reason=interval` 排空。持续检查无授权过期、无无故退回队列、无虚假已到账。

不能把本地快进时钟、把 interval 临时改成几十秒、强制 `process_once(force=True)` 或 deadline 安全排空当成两小时自然触发。两小时验收至少需要完整现场观察窗口，再加交易确认时间；若最后一次成功结算已很久，调度器可能立即认为周期到期，应根据实际 schedule 选择基线。

## 故障与独立提交

| 场景 | 通过条件 | 证据环境 |
|---|---|---|
| Relay 在 Provider 完成后丢失 HTTP 返回 | Consumer 结果未知且不自动重发；Provider 原请求只执行一次，MAX 保留；同身份查回完整回执 | 本地 fixture 必须；真实短请求至少一次受控演练 |
| 未签名错误声称 `not_dispatched` | V10 不释放本地 MAX、不换另一路再次 POST | Node 回归已覆盖 |
| Provider/Relay 重启 | 同 channel/request/auth/dispatch 返回原结果；dispatch 签名字节从持久表恢复；unknown 不重跑 | 本地与受控现场 |
| Relay 结算 worker 不可用 | Provider 独立 CLI 先做 plan，再用专用 gas identity 和持久 submission outbox 提交；不需要 Consumer owner/Relay 再签名 | 现场至少一条 |
| Provider 独立提交先成功，Relay 后恢复 | Relay 根据 canonical `(channel, request)` 对账为托管，不把 already-settled 当丢款或再次扣费 | 本地与现场 |
| 签名错角色/错合约/错价格/改响应 | 拒绝执行或拒绝当作验证成功的内容；无“已托管”伪状态 | 本地完整矩阵；现场只做不花费的无效请求 |
| RPC 不可用、变链、reorg、低 gas | 不伪造成功；已产生的回执/未知 nonce 保存并可恢复 | 故障注入与现场 health |
| 预算耗尽、过 admission、未到 start | 不执行模型；提示明确。已开始但不确定的请求仍保留占额 | 本地边界；现场观察 start 与受控预算 |
| claim 截止后释放 | 从链上确认可释放时间；仅 owner 的剩余通道余额回到账户。关闭后不得新接单 | 本地 EVM；现场等待真实期限 |

独立提交完成只证明托管成功。还需等待真实 dispute window，执行 release/claim 并核对 Provider payout 的测试币到账，才能把收益闭环标为已完成。受控委员会和测试币范围应在验收结论中保持明确。

## 最终报告格式

每项写 `通过 / 未通过 / 未执行`，附命令、UTC 起止时间、节点版本、request/channel ID、交易哈希及确认高度。统计实际模型执行次数、签名回执数、未知数、链上托管数、已释放数、已领取数；这些数字不能合并成一个“成功率”。另报端到端 p50/p95、上游耗时和恢复耗时。

真实三路线、每 Relay 的 count=100 和真实两小时定时触发、独立 Provider 提交、至少一笔最终领取均有对应证据后，才称“固定预算网络完整验收通过”。若仅完成部署或部分冒烟，应明确剩余项目和最早可确认时间。

## 外层 SDK 重试补充验收

Consumer 内部不重发，不代表调用它的 SDK 不重发。OpenAI 官方 Python SDK 默认会重试连接故障以及 408、409、429、5xx 响应；默认重试次数为两次，正文中的“不会重放”文字不会阻止它。[官方 SDK 重试文档](https://developers.openai.com/api/reference/python#retries)

因此已向 Relay POST 后的结果未知、已收到有效支付回执但内容验证失败、成功 HTTP 返回的回执损坏，均不能直接使用普通可重试 502/503 来宣称端到端防重复。409 也不是可靠替代。最小响应修复应使用不会默认自动重试的错误状态，明确未知状态、逻辑请求 ID 和禁止自动重试提示；具体 SDK 的提示 header 行为需实测。

现场验收还需模拟“本地 Consumer 已发出模型请求，但 SDK 在收到错误响应前断线或超时”。跨多个 HTTP 尝试必须绑定同一持久 logical request identity / Idempotency-Key，或明确限制支持的客户端重试配置。相同 key、相同请求查回原结果或未知状态；相同 key 不同请求必须拒绝；重启不能丢失这个对应关系。只有本地 Consumer 的单次函数调用未重试，不足以通过这一项。

本地已实现 `consumer-request-journal.mjs` 并接入 V10 Consumer：按 chain/contract/payment key address 隔离；只存 caller key 与规范请求的哈希，O_EXCL 原子建档和 fsync 后才准许执行；未知状态永不因超时重新开放，成功缓存删除支付证明头并限制大小、以 0600 文件保护。原始请求和私钥不进入此账本。首次及重放均使用同一份清理后的响应。

2026-09-18 本地测试 `node --test packages/mycomesh-cli/test/consumer-request-journal.test.mjs packages/mycomesh-cli/test/consumer-reserved.test.mjs` 共 26 项通过，包含八进程竞争只获得一个执行权、重启后重放、未知结果不重新 POST、同 key 不同 body 拒绝、无 key 的 SDK retry-count 请求拒绝。这是本地文件系统和 HTTP fixture 证据，不代表真实网络与 SDK 断线场景已验收。去重保证要求调用方稳定传递同一 Idempotency-Key，并保留同一 Consumer 账本；未传 key 的初次请求，以及丢失账本或在另一台未共享账本的 Consumer 上重试，不能称为端到端 exactly-once。
