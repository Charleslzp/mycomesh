# V10 Provider-AI 动态陪审执行审计（2026-09-23）

## 结论

V10 不再把固定裁决地址或人工裁决名单写进 Settlement。争议发生后，
`ProviderJuryRegistryV1` 从当前活跃、达到最低 reputation、且 operator 身份互不重复的
Provider 中抽取案件级陪审团；被抽中的 Provider 通过自己的推理服务读取同一份规范化证据，
生成并签署结构化 AI 判定。Relay 只负责传递任务、收集达到阈值且内容完全一致的签名，
以及代付链上提交交易，不能指定陪审员、修改判断或绕过 quorum。

这实现的是“高 reputation Provider 随机 AI 陪审”，而不是预置 adjudicator roster。
当前的 Sepolia manifest 和合约仍是旧的 controlled-test 部署，因此源码能力不能被描述为
已经在现网启用；必须完成新 Registry、Settlement、Provider roster、capacity channel 和运行时
证据的整体切换后，才能打开货币执行。

## 信任与执行边界

- `reputationAuthority` 只发布从 Pool/reputation 数据源得到的 Provider 快照，不能参与案件
  判定。每个 Provider 更新都绑定严格递增的 `sourceSequence` 和非零 `sourceDigest`；删除再
  注册也不能重放旧快照。该 authority 必须与 governance 使用不同身份。
- Registry 对 Provider owner、vote signer、operator、peer 和 capability 做唯一性及冲突检查。
  候选人必须达到 `minimumReputation`，并排除 Consumer、被告 Provider、Relay、Pool、Treasury、
  以及这些角色的相关签名身份。案件 reporter 固定为该笔 Settlement 的 Consumer owner，因此
  已通过 Consumer 角色排除，不再依赖可被第三方抢先占用的 reporter 候选过滤。
- V10 的 `openDispute` 只允许 `ReceiptEscrowed.owner` 调用，并在同一调用中写入唯一一份
  `EvidenceSubmitted` 承诺和 owner 的 reporter bond。V10 不暴露 `submitEvidence` 多 reporter
  接口；Provider、陪审员或任意第三方都不能抢先开案或追加报告，但 V9 行为保持不变。
- 每个案件先冻结候选快照，再使用未来区块哈希随机抽取 operator-distinct 的 Provider。
  assignment 固化 owner、vote signer、operator、peer、capability 和 reputation，后续 roster
  变化不能改写已经抽出的陪审团。
- Provider 只接受与链上 assignment、Settlement、Registry、chain/genesis、证据哈希和
  `decisionPolicyHash` 完整一致的内部陪审任务。任务和结果都有持久化幂等键，不通过公开
  HTTP 接口接收任意案件。
- `voteDisputeBySig` 只接受恰好达到阈值的一致批次。每张 EIP-712 permit 绑定案件、assignment、
  report、`decisionHash`、每案 signer nonce 和 deadline；确认/驳回、report 或 decisionHash
  任一不一致都会整笔回滚。确认票绑定唯一 owner report，驳回票必须绑定零 report id；两种
  资金结论都必须达到至少 9000 bps confidence 才能生成可执行 permit。
- Settlement 仍是唯一资金裁决者。确认作弊才会全额退款并按封顶策略扣减 Provider stake；
  高置信驳回会释放正常收益并没收 owner 的 reporter bond；证据不足或歧义不是高置信驳回，
  不生成 permit，最终只能进入不罚款的超时路径。无结论或陪审不可用也不会被解释成作弊。
  Relay/worker 没有直接转账、改余额或制造 quorum 的权限。

## 已接通的源码闭环

1. `ReceiptEscrowed`、`DisputeOpened`、唯一的 owner `EvidenceSubmitted`、`JuryRequested`、`JuryAssigned`、
   `JuryAssignmentFailed`、`JuryUnavailable` 和 `DisputeResolved` 由固定 chain/genesis/contract
   的确认后事件入口读取。入口会核对 evidence reporter 与 escrow owner 完全相同，并在同一
   settlement key 出现多个 report 时 fail-closed，而不会选择任意第一条记录。
2. SQLite cursor、事件去重和案件 delivery fence 支持进程重启；尚未交付的浅重组可回退重放，
   已交付案件发生深重组时会持久熔断，禁止在替代分叉上自动再次执行推理或签名。
3. 陪审 runtime 读取 assignment 的不可变 Provider 证据，向被选 Provider 的受认证内部
   transport 发任务，验证结果身份、策略哈希、证据哈希和签名域，再只聚合完全一致的 verdict。
4. 链上 worker/outbox 将执行状态分为 admitted、executing、submitted、confirmed、uncertain；
   nonce、raw transaction、receipt、事件和确认块都与固定部署域核验。崩溃恢复不会把
   `executing` 或未知广播误记为 confirmed。确认与驳回都走同一条耐久执行路径；驳回只有在
   receipt 内的精确 `DisputeVote(false, 0x0, decisionHash)` quorum、唯一 `DisputeResolved`
   事件和确认块上的 `Dismissed` 状态共同匹配，并证明唯一 report bond 进入没收分支后，才会
   标记 confirmed。
5. Provider reputation sync 同样使用持久 outbox；Registry 与 Settlement 必须双向绑定，且
   链上 source sequence/digest 与已批准的 Pool 快照一致后才确认成功。

## 上线前仍需满足

1. **独立 reputation authority**：部署时提供与 governance 分离的受保护 signer，并明确 Pool
   快照生成、轮换和紧急撤销流程。不要把静态“裁决名单”重新引入 manifest。
2. **真实 roster**：至少有 `jurySize` 个达到门槛、operator/peer 独立、Provider signer 已授权、
   且能执行指定 AI 判定策略的在线 Provider；发布门禁必须在同一确认块证明
   `canFormJury=true`，普通 channel 还要按其实际角色证明 `canFormJuryFor(channelId)=true`。
3. **固定 AI 判定策略**：模型族、规范化 prompt、证据 schema、输出 schema、超时和版本必须
   生成非零 `juryDecisionPolicyHash`，由部署与发布证据共同固定。模型输出本身不能代替
   Provider 的 EVM vote-signer 签名。策略必须明确区分“未证明作弊”和“明确证明不构成约定
   欺诈”：前者返回低于 9000 bps 的 false 并禁止执行，后者才允许高置信 dismiss。
4. **全新部署与通道**：按 Registry → 确认和 getter/runtime 校验 → Settlement → 确认校验 →
   `bindSettlement` 的顺序部署，再建立新 capacity channels。旧 V10 合约、旧 ABI、旧 outbox
   和过期 channel 不能混用。
5. **运行证据**：至少完成一次真实 RPC 的 assignment、AI 推理、quorum、
   `voteDisputeBySig`、receipt/event reconcile、Provider/Relay 重启和重组演练；健康接口必须
   显示真实 SQLite/outbox/intake 状态，而不是仅显示配置开关。
6. **受控启用**：上述证据通过前，`monetary_enforcement_enabled` 必须保持关闭；允许启用的
   只有事件跟踪、证据收集、quarantine、reputation 同步 dry-run 和非惩罚性恢复路径。

## 已知的 controlled-test 限制

- `future_blockhash_v1` 适合 Sepolia 候选验证，不是生产级不可操纵随机源；生产网络应换成
  VRF 或等价的可验证随机方案。
- Registry 在存在 pending assignment 时冻结全局 roster 更新。这避免抽签中途换人，但也会
  阻塞密钥轮换；生产版需要案件 epoch 或可撤销快照设计。
- `canFormJuryFor` 是建 channel 时的确认块快照。之后 roster 萎缩可能导致案件无法组成陪审团；
  当前安全结果是 `JuryUnavailable` 并退款，而不是误罚 Provider。若要提供强可用性保证，需要
  对 channel/epoch 预留陪审容量或引入保险，而不是把一次 readiness 检查当永久承诺。
- 已 Ready 的陪审团若全部沉默，超时会释放正常 Provider 收益；这是“沉默不是作弊证据”的
  安全选择，但必须配套 jury 响应率、告警和 reputation 惩罚策略。

## 启用判定

只有当新 deployment manifest、编译产物、链上 runtime/getter、动态 Provider roster、
`juryDecisionPolicyHash`、Provider/Consumer npm tarball、OCI revision/digest 和真实 E2E 证据全部
指向同一个源码提交时，才能将该候选标记为可发布。源码测试通过或 source release gate 通过，
都不能单独证明现网已经具备自动资金裁决能力。
