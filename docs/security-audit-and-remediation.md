# Myco 协议安全审计与修复说明

审计日期：2026-07-12

## 结论

当前代码已经补上了 URL 身份、API key 注册、账单索引、回执证据和
Settlement V3 的多项关键安全边界，但还不能作为无许可公开主网直接上线。

当前支持的验证范围是：

- 单机或受控私网内的功能验证；
- `local` profile 的明文兼容测试，以及 `testnet` profile 的签名密钥绑定、
  端到端密封 provider/relay 消息测试；
- Sepolia 上使用无价值测试币验证 V3 存款、reservation、签名和结算；
- 单主机 SQLite，以及 PostgreSQL 共享 billing/replay 后端的自动化验证；
- 本地 ledger 文件系统的 URL+key proxy 验证。

此前确认的三个硬阻断项，当前处理状态是：

1. **传输代码已解决**：非本地 direct/relay 使用 Ed25519 身份签名的 X25519
   transport-key binding，以及 HKDF-SHA256 + ChaCha20-Poly1305 密封帧；pool
   拒绝明文降级，relay 不能读取 prompt/result，持久 replay store 拒绝重放。
   这仍是消息层加密，不是带前向保密的 Noise session；流量大小、时间和路由元数据
   仍可见，独立密码学审计与公网压力测试仍是发布门槛。
2. **共享状态代码已解决**：billing、key challenge/indexer/outbox 与 provider/relay
   replay claim 支持同一 PostgreSQL DSN 下的事务、行锁和 advisory lock；Compose
   默认提供共享 PostgreSQL。SQLite 保留给单机兼容。真实生产数据库的迁移、HA、
   故障注入和负载测试仍须在部署环境完成。
3. **风险已解决为 fail closed，生产能力仍缺失**：非 `local` Gateway 强制
   production-strict 并在启动时检查 `settlement_ready`。当前 Codex app-server
   有原生 usage 事件但没有原生 output cap，Codex CLI 两者都不可信，任意通用
   OpenAI-compatible URL 也未绑定可验证计量契约，因此都会拒绝生产启动。明天登录
   后的 canary 可以验证真实推理和原生 usage 事件，不能证明不存在的上游硬 cap。

因此，V2 应视为迁移兼容路径；V3 是更安全的新结算基线，但不是完整生产
网络的安全证明。本报告也不替代独立 Solidity 审计、形式化验证、渗透测试
和实际部署字节码复核。

## 范围与威胁模型

本次范围包括：

- Gateway/OpenAI-compatible HTTP 接口、上游转发和身份认证；
- Gateway discovery、canonical public URL 与钱包注册 API key；
- Bridge/pool、P2P provider、relay、签名 descriptor 和 replay 防护；
- 本地 billing、链上余额同步、事件 indexer 和 receipt outbox；
- payment reservation、provider settlement attestation、consumer acceptance；
- MycoSettlement V2/V3、MYCO token、测试部署器和 Python 链交互层；
- Docker/环境变量部署边界。

假设攻击者能够读取公开链数据、复制 descriptor/reservation、重放网络消息、
控制恶意 provider/consumer、返回伪造 RPC 数据，并诱导 operator 使用错误 URL。
不假设 operator 主机、私钥、上游模型账号或治理多签已经被完全攻破；这些场景
需要单独的密钥管理和灾难恢复设计。

## 发现与处理状态

| ID | 严重度 | 问题 | 当前处理 | 状态 |
| --- | --- | --- | --- | --- |
| MYCO-01 | Critical | V2 trusted/operator settlement 可以绕过逐笔双边授权 | V3 删除 trusted operator 路径；每笔 receipt 使用 EIP-712 双签或逐笔 delegate authorization，支持 EIP-1271 | V3 已修复，V2 遗留 |
| MYCO-02 | Critical | provider/relay 明文 TCP 不能保护提示词和输出，签名也不能提供机密性 | 非本地使用签名 X25519 key binding 和 ChaCha20-Poly1305 密封帧；pool/relay 拒绝明文降级，持久去重，relay 不持有解密密钥，transport key 带重叠窗口轮换 | 代码已修复；元数据可见、无 session PFS，待独立审计 |
| MYCO-03 | High | “服务使用者 URL”来源不明确，容易被 Host header、回调 URL 或恶意 registry 替换 | 使用 operator 配置的 canonical URL；非本地强制 HTTPS/public DNS；descriptor 绑定 node/network/chain/settlement/sequence/expiry | 已修复 |
| MYCO-04 | High | 同一 API key/钱包签名可能被拿到另一 Gateway 重放 | 注册 challenge 绑定 origin、network、chain、settlement、key hash、nonce、expiry；只存 key hash；凭证持久绑定并逐请求核对 origin/network/chain/settlement | 已修复 |
| MYCO-05 | High | V3 reservation 可被用于与付款意图不同的 off-chain 请求 | request v2 的 SHA-256 同时绑定 endpoint、model、canonical `input`/`messages` 和 `max_output_tokens`；provider 在 confirmed block 对比链上承诺 | 已修复；旧 input-only reservation 必须重建 |
| MYCO-06 | High | 多个独立 SQLite proxy 可能同时预留同一逻辑余额或重复认领 key challenge | PostgreSQL billing store 使用共享事务、行锁/advisory lock、reservation 幂等键和 challenge verification lease；Compose 默认共享 DSN | 代码已修复；待真实 HA/迁移/负载测试 |
| MYCO-07 | High | 未确认事件、reorg 或错误网络可污染本地可用余额 | 余额状态绑定 chain/settlement/block hash；默认要求至少 6 confirmations；过期或落后缓存 fail closed；事件按 tx hash/log index 去重并支持 rewind | 已修复，仍需生产 RPC 策略 |
| MYCO-08 | High | provider 可在响应后替换 model/output/usage/pricing/payment party | provider 强制请求 model 等于 config/descriptor；response 与 attestation 绑定 request/response hash、usage、fee、双方身份、pricing、reservation 和 deadline；执行前固定 output cap | 协议绑定已修复；usage 来源可信性见 MYCO-36 |
| MYCO-09 | High | V2 channel economics 可变导致旧授权按新价格解释 | V3 pricing version 不可变；reservation 和 receipt 同时绑定 version 与 pricing hash | V3 已修复，V2 遗留 |
| MYCO-10 | High | 结算失败、重复执行或跨 reservation 复用同一 receipt hash 造成阻断/重复付款 | V3 锁定 consumer balance；结算状态以 `(reservationId, receiptHash)` 复合键记录；reservation 只能结算一次，batch 有上限 | 已修复 |
| MYCO-11 | Medium | 直接使用请求 URL 或 redirect 访问内网形成 SSRF/密钥泄漏 | 上游和 Provider Gateway 禁止 redirect；canonical URL 限制 scheme/host；远程 Provider Gateway 只允许显式 HTTPS | 已修复；DNS/TLS/出口策略仍需监控 |
| MYCO-12 | Medium | 匿名 Gateway、公开注册、无界输入/输出在费用校验前消耗模型资源 | 默认关闭匿名/公开注册；ASGI 在路由和 JSON parser 前限制声明及流式请求体；provider 在调用 AI 前检查 input/output/费用；网络、子进程和服务器连接有上限 | 已修复 |
| MYCO-13 | Medium | descriptor 自报 weight/latency 可操纵推荐排序 | registry 不再按自报性能排序；只接受匹配 network/chain/settlement 且未过期的记录 | 已修复；独立信誉系统未完成 |
| MYCO-14 | Medium | 非标准稳定币可能破坏内部余额与真实 token 余额的一致性 | V3 对 deposit、withdraw 和全部分账执行严格的发送方/接收方余额差检查；仅支持标准 non-rebasing、无转账费稳定币，其他行为回滚 | 已修复；代币升级/冻结仍是外部风险 |
| MYCO-15 | Medium | MYCO reward mint 失败可能回滚稳定币付款或错误消耗 epoch 额度 | V3 捕获 mint 失败并记录 `RewardMintFailed`；仅成功 mint 增加 `epochMinted`，稳定币结算不回滚 | 已修复 |
| MYCO-16 | Medium | 治理可立即更换价格/treasury，或用不透明 hash 调度错误参数 | V3 仅公开 `scheduleChannelVersion`、`scheduleTreasuryUpdate`、`scheduleRewardEnable` 等 typed 调度；风险增加操作延迟两天，`pauseRewards` 即时 | 已修复；治理密钥仍需多签 |
| MYCO-17 | Medium | reward token 可无限增发或由错误实体 burn 用户余额 | MycoTokenV2 固定 mint authority 和 immutable max supply，不提供任意第三方 burn | 已修复 |
| MYCO-18 | Critical | 测试稳定币 `mint` 无权限控制 | 文档、部署记录和迁移流程明确仅限测试 | 设计如此，生产严禁使用 |
| MYCO-19 | Medium | open network 缺少 staking/slashing/dispute，恶意节点无经济惩罚 | `open` profile 保留并拒绝启动 | 功能未完成 |
| MYCO-20 | High | provider 已提供服务后，consumer 可拒绝最终 EVM 签名；反之默认 fallback 会让 provider 无验收扣费 | fallback 默认关闭，consumer 必须逐 reservation 显式 opt-in；仅在 `acceptedHash == 0` 时结算不可退 `minimumFee`，只按 `providerBps` 付 provider，余款给 treasury，无 relay/pool/reward | 已修复基础费授权边界；不代表服务或质量证明 |
| MYCO-21 | High | 仅凭自签回执发奖励可被 Sybil 刷取 | `rewardsEnabled` 部署时全局为 false；启用需要 typed timelock，暂停即时；抗 Sybil/质量信号上线前必须保持关闭 | 风险默认关闭 |
| MYCO-22 | Medium | 固定 EIP-712 domain separator 在 chain ID 变化后可能错误复用旧域 | `DOMAIN_SEPARATOR()` 在当前 chain ID 与部署 chain ID 不同时动态重算 | 已修复 |
| MYCO-23 | Medium | emission 使用绝对 Unix epoch 会让晚部署实例跳过早期发行阶段 | `emissionStartedAt` 固定为部署时间；每周一个 epoch，每 208 周约四年减半 | 已修复 |
| MYCO-24 | High | 最终 V3 `Reservation`/`createReservation`/settlement query ABI 与早期 V3 不兼容 | 最终 create 增加 fallback bool、getter 为 9 words、settlement query 使用复合键；要求重部署并重建 reservation | 需要运维迁移，不能原地升级 |
| MYCO-25 | Medium | CLI 只能提交 65-byte EOA 签名，或 EIP-1271 本地预检与链上调用上下文不一致 | contract-signature flags 接受最长 16 KiB 任意 bytes；严格校验 bytecode/ABI magic；`eth_call.from` 固定为 Settlement 合约 | 已修复 |
| MYCO-26 | High | 原始请求很小但 system/agent/routing 注入使实际上游输入大于 reservation，provider 承担超额成本 | canonical JSON bytes 只做准入；费用按完整 `reserve_input_tokens` 配置和 resolved output cap 在上游调用前完成 local/on-chain quote | 已修复；operator 必须覆盖完整 prompt pipeline |
| MYCO-27 | Medium | receipt deadline 太短，provider 完成推理后没有链上提交时间 | prepare、外部签名和最终提交共用时间窗校验；V3 要求 `deadline >= ceil(now + provider timeout + 60s)` 且 `deadline <= expiry`；wallet RPC 后再次校验 | 已修复 |
| MYCO-28 | Medium | Chat 把 `messages` 转成字符串后哈希、或接受与 descriptor 不同的 model，会破坏承诺/报价一致性 | request v2 绑定原始结构化 `messages`；provider 强制 model 等于配置和签名 descriptor | 已修复 |
| MYCO-29 | Medium | OpenAI 客户端的三种 output-limit 字段可冲突或被忽略 | 支持 `max_output_tokens`/`max_completion_tokens`/`max_tokens`；非 null 值须为原生正整数，多字段必须相等，否则 422 | 已修复 |
| MYCO-30 | High | Ed25519 传输身份未与 consumer EVM 钱包绑定时，获准或泄漏的链下 key 可冒用链上 reservation | `mycomesh.evm.session.v1` EIP-191 一次性授权绑定完整 reservation/request/payment scope、唯一 nonce 和 Ed25519 session key；provider 在 confirmed block 校验 EOA/EIP-1271 | 已修复为单 reservation/request scope；不是可复用 session registry |
| MYCO-31 | High | 同一未结算链上 reservation 可被重复或并发触发多次推理，链上付款上限不能防止重复算力消耗 | 执行前把 request、payment nonce、reservation ID、session nonce 四键原子 claim；PostgreSQL 为多主机共享事务后端，TTL 到 expiry；执行开始后的不确定失败不可重试 | 代码已修复；多主机必须共用 DSN |
| MYCO-32 | High | 小型内联压缩 PDF 可在 provider 内解压成巨量文本，并在费用 claim 前消耗 CPU/RAM | Gateway 与 P2P 对大小写、参数和非 base64 变体统一拒绝 `data:application/pdf`；只接受在隔离、限额工具中预提取后提交的精确 `input_text` | 已修复；未内置 PDF sandbox |
| MYCO-33 | High | 无效 reservation 可先占执行 semaphore/链 RPC；无界 request ID/签名 nonce 可扩张 RAM/SQLite；分步 claim 会留下垃圾键 | 外层签名和 reservation 离线预检先于容量/RPC；request ID 限 128 字节 canonical ASCII，两层 Ed25519 nonce 固定 32 个小写 hex；V3 四键原子 claim | 已修复 |
| MYCO-34 | Medium | confirmed block 的 `closed=false` 可能已过时，wallet RPC 也可能跨过 settlement deadline | confirmed block 校验全部不可变字段；latest 只做 closed/expiry 拒绝；全部 wallet RPC 后、claim 前再次检查 deadline | 已修复 |
| MYCO-35 | High | RPC、Pool、Relay、upstream、Codex stdout/stderr 或慢连接可造成无界内存、进程、线程或等待 | 响应按协议做 Content-Length 预检和流式累计上限；timeout 有最大值；请求体有总 deadline；Codex CLI/App 共用默认 4、最大 64 的进程许可并清理整个进程组；ASGI/Pool/P2P/Relay 均有并发或连接硬上限 | 已修复；仍需外层 DDoS/WAF |
| MYCO-36 | High | Codex CLI usage 不是模型原生计量，且请求 output cap 没有在实际生成时强制 | 后端公开结构化 production capabilities；非本地启动强制 `production_ready`，严格模式拒绝缺失/畸形/不一致 usage 和不可强制的 cap；Codex/generic upstream 当前全部 fail closed | 安全门已修复；可用生产后端仍是发布阻断 |
| MYCO-37 | Low | 用户直接把稳定币 `transfer` 到 Settlement 会增加合约余额但不会增加内部 `availableBalance` | 只通过 `approve` + `deposit` 入账；界面和 runbook 必须禁止直接转账；误转没有自动归属依据 | 运维约束，不能安全自动找回 |
| MYCO-38 | High | V3 immutable reward token、stablecoin 或 mint authority 部署接错后无法靠治理修正 | 发布时复核 constructor 参数、目标 bytecode、token proxy/admin、`mintAuthority` 和标准转账语义；奖励保持关闭直到验证完成 | 部署阻断检查 |
| MYCO-39 | High | 钱包注册响应标注 `origin_only`，但数据库不存受众、鉴权也不核对；复制 DB 或更换域名后旧 key 仍有效 | 新 key 持久绑定 canonical origin、network、chain、settlement；每次鉴权同时核对静态上下文和请求 `Host`；非本地默认拒绝历史 unscoped key，管理员轮换可完成迁移 | 已修复；反向代理必须保留并限制 canonical Host/SNI |
| MYCO-40 | Medium | 本节点推荐 URL 未签名、registry 可在验签后改写 URL，且 descriptor 一小时 expiry 与通用 300 秒签名 age 冲突 | discovery 返回本节点签名 `recommended_gateway.descriptor`；签名前 URL 必须已 canonical；专用 verifier 分离注册新鲜度与消费 expiry，并限制签名生命周期和未来时间戳 | 已修复；consumer 不得单独信任 `recommended_base_url` |
| MYCO-41 | Medium | `UPSTREAM_BASE_URL` 仅去尾斜杠且完整暴露在公开 health，userinfo/query 等会误路由或泄漏配置 | 启动时仅接受结构正确的 HTTP(S) base URL，拒绝 userinfo、query、fragment、path params、控制字符和反斜杠；公开 health 不再返回 URL | 已修复 |
| MYCO-42 | High | MycoMesh 在 async route 内同步执行 Pool/Relay/P2P，单个慢请求可阻塞事件循环；截止时间异常还可能遗留余额和 peer lease | 推理移入有界 worker（默认 8、最大 64），满载 503；全流程使用单一单调 deadline，P2P socket 使用绝对关闭 timer；余额 reservation 在所有退出路径幂等释放，peer lease 用 finally 清理；已 capture 的 outbox 导出失败不再把成功推理变成失败响应 | 已修复 |
| MYCO-43 | High | ASGI body 限制只在完整请求头后生效，慢请求头和大量半开连接可在进入应用前耗尽 Uvicorn | CLI 启动固定传入 Uvicorn concurrency、keep-alive 和 h11 incomplete-event 上限；公开部署必须在前置代理配置连接/header 总 deadline、连接数和速率限制 | 代码已缓解；反向代理是发布门槛 |
| MYCO-44 | High | Compose 默认发布到所有网卡且示例 admin token 可随 profile 切换误带到公网，导致明文端口或管理 API 暴露 | 所有 Compose published port 默认绑定 `127.0.0.1`；非本地 profile 拒绝占位 token 和短于 32 字符的 admin secret，并使用常量时间比较 | 已修复；公网仍必须经 HTTPS 反向代理 |
| MYCO-45 | High | 十六进制、八进制、单整数或缩写 IPv4 hostname 可绕过普通 IP literal 检查，再被 libc 解析到 loopback/内网 | Gateway registry 与 upstream 统一拒绝 libc `inet_aton` 风格的 legacy numeric hostname | 已修复 |
| MYCO-46 | High | 匿名 key challenge 可无界写 SQLite；精确到期边界仍可消费，并发注册可能重复消费 | challenge 在单事务内清理、限制 active capacity 和每分钟签发量；`expires_at <= now` 即失效；条件更新保证只能消费一次 | 已修复；公网仍需按来源限流 |
| MYCO-47 | High | Reorg 只回滚事件游标，或并发旧 indexer 在新 writer 后提交，可能遗留孤链 receipt、回退游标并高估余额 | DB 全局游标为权威；`revision`/expected snapshot 拒绝 stale writer、同高度异 hash 和非连续事件范围；canonical log、receipt、账户余额与全局游标在同一事务发布；rewind 保持 sticky reorg | 已修复；仍需多 RPC 与 soak test |
| MYCO-48 | High | 外层 504/客户端取消后 worker 仍可能 reserve/capture；capture 后的 route-state/outbox 异常又可能把已扣费成功改成 500 | 单一 monotonic deadline、取消 barrier 与资金锁覆盖排队到 capture；capture 已提交时返回已提交成功，后置 telemetry/outbox 为 best effort | 已修复 |
| MYCO-49 | Medium | socket 的逐次 read timeout 会被慢速分块持续刷新，造成响应体无限慢滴 | async upstream 和同步 RPC/Pool/Relay/Gateway 客户端均使用从请求开始计算的总 deadline，并在每次分块读取前缩短 socket timeout | 响应体已修复；DNS/TLS/header 硬超时依赖代理 |
| MYCO-50 | Medium | SQLite capture 与 JSONL append 之间崩溃可能造成回执重复、半行或 claim 状态丢失；逐次全文件去重会形成 O(n²) 和混合锁竞态 | SQLite 保持 authoritative outbox；所有 append API 共用文件锁；持久 sidecar SQLite 索引按 inode/offset 增量修复并校验 `job_id`/payload hash；冲突 payload fail closed，单记录限 16 MiB；JSONL 修复半行并 file/dir `fsync` | 同一本地文件系统内已修复；不是多主机 ledger |
| MYCO-51 | Medium | 每次匿名 discovery 都签发新 sequence 并写 SQLite，可形成写放大；多进程内存缓存又会返回倒序 sequence | 有效本节点 descriptor 在 SQLite 中原子复用，配置变化或临近过期才持久签发更高 sequence | 已修复 |
| MYCO-52 | Medium | 钱包 API key 注册只支持 EOA recovery，Safe 等 contract wallet 无法按同一身份边界注册 | 配置 `ETH_RPC_URL` 时先用 `eth_getCode` 严格分流；contract wallet 使用 settlement 作为 caller 校验 EIP-1271，签名最大 16 KiB | 已修复；未配置 RPC 时仅支持 EOA |
| MYCO-53 | Medium | contract-wallet 注册在 async route 内同步执行多个 RPC，既阻塞事件循环又可能把每次 timeout 累加 | 事件循环提交前无阻塞抢槽；校验移入独立有界 executor；wallet 分类和 EIP-1271 复核共享最大 30 秒绝对预算；超时 worker 退出前不释放槽 | 已修复；公网仍需请求限流 |
| MYCO-54 | High | freshness 检查与余额 reserve 分属两个事务，检查后发生 reorg/invalidate 仍可能预留旧余额 | `reserve_with_chain_guard` 在同一 `BEGIN IMMEDIATE` 中重检 chain/settlement/reorg/age/lag/confirmations 并扣减余额 | 已修复 |
| MYCO-55 | High | V3 合约按 `(reservationId, receiptHash)` 防重，但 indexer 只按 receipt hash/consumer 确认，复制 hash 到另一 reservation 会错配 | usage 持久化 `onchain_reservation_id`；V3 confirmation 必须同时匹配 hash、reservation 和 consumer，V2 保持兼容键 | 已修复 |
| MYCO-56 | Medium | sticky reorg 清零后，release/expire/capture refund 可重新增加派生可用余额 | sticky reorg 期间退款只更新 reservation/pending 状态，不恢复可用余额；canonical recovery 统一按 observed、pending、locked 重算 | 已修复 |
| MYCO-57 | High | 相同 challenge nonce 可跨进程并发触发昂贵钱包 RPC，失败重试也没有应用内次数上限 | 进程内 single-flight 加 SQLite verification token；未到期 challenge 禁止 stale takeover，worker 主动释放；消费必须匹配当前 token；默认每 challenge 最多 5 次验签 | 已修复；公网仍需按来源限流 |
| MYCO-58 | High | 手工 `sync-balance` 先写余额再写游标，后一步失败会留下无可信元数据的余额；调用者还能伪装 `events` source 或降级事件索引 | 余额、账户 freshness、全局游标和 revision 在单事务 direct publication 中提交；强制完整链元数据和 `direct` source；已进入 events 模式后禁止降级 | 已修复；生产优先使用事件 indexer |
| MYCO-59 | High | 单账户 direct publication 推进全局 latest block 后，旧账户仍用自己的旧 latest 计算 lag，可继续预留过期余额 | 快速检查和最终 `reserve` 都读取全局状态；在同一写事务中以 `max(account.latest, global.latest)` 计算账户 lag | 已修复 |
| MYCO-60 | High | challenge 先消费、key 后登记时，唯一键冲突会永久作废挑战；RPC 池满也会白白消耗验签次数 | 先通过非阻塞 RPC 槽再领取 SQLite 验证租约；challenge 消费与 key 登记在同一事务提交或回滚 | 已修复 |
| MYCO-61 | Medium | EIP-1271 RPC 超时与钱包明确拒绝都映射为 403，掩盖基础设施故障并影响重试策略 | typed rejection 保持 403；RPC/transport `ChainError` 映射 503；总 deadline 仍映射 504 | 已修复 |
| MYCO-62 | Medium | 多 worker 同时启动旧数据库时，`PRAGMA table_info` 与 `ALTER TABLE` 之间存在重复加列竞态 | schema inspection/migration 使用 `BEGIN EXCLUSIVE` 串行化，并增加并发旧库升级回归测试 | 已修复；生产仍需单独迁移流程 |
| MYCO-63 | Medium | 已领取 challenge verification claim 后，executor 若拒绝提交仍会消耗一次尝试；固定 35 秒 lease 还允许另一进程在超时 worker 退出前接管同一 nonce | executor 未接受任务时按不可猜 token 原子清除 claim 并回退一次计数、返回 503；已提交任务的失败/超时仍计次，未到期 challenge 不允许跨进程 stale takeover，worker 退出后主动释放 | 已修复 |
| MYCO-64 | Low | challenge 在到期前进入数据库写锁等待，可能在到期后仍被领取或消费 | 创建、领取和最终原子消费均在取得 `BEGIN IMMEDIATE` 写锁后读取提交时钟；到期边界 fail closed，并增加锁竞争测试 | 已修复 |

## 服务使用者 URL 的正确设置

协议中实际有三种 URL，必须分开管理：

| URL | 权威配置者 | 示例 | 是否对 consumer 公布 |
| --- | --- | --- | --- |
| Consumer 访问 Proxy 的 canonical URL | Proxy/Gateway operator | `MYCOMESH_PUBLIC_GATEWAY_URL=https://gateway.mycomesh.xyz/v1` | 是，写入签名 descriptor |
| Provider 访问自己的 AI Gateway URL | Provider operator | `--gateway-url http://127.0.0.1:8000/v1` | 否，默认只能 loopback；远程必须显式 HTTPS |
| AI Gateway 访问模型厂商的 URL | Gateway operator | `UPSTREAM_BASE_URL=https://api.openai.com/v1` | 否，绝不能由 consumer 请求覆盖 |

浏览器页面来源是另一组独立配置，不是服务 URL：

```bash
MYCOMESH_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
MYCOMESH_POOL_CORS_ALLOWED_ORIGINS=https://mycomesh.xyz,https://app.mycomesh.xyz
```

第一项只允许 Consumer Proxy 的精确浏览器来源，支持带
`Authorization`/`Content-Type` 的 `GET`、`POST` 与预检，但不启用 cookie
credentials。第二项只让 Bridge 的 `/health`、`/peers` 接受跨域只读请求，所有
Bridge 写接口仍不可从浏览器跨域调用。两项为空时均不开放 CORS；通配符、
`null`、路径、查询参数、userinfo 与非 loopback HTTP 来源在启动时失败关闭。

用户所问的“服务使用者 URL”应当指第一项。它不应由请求中的 provider 字段
决定，也不应从 HTTP `Host`、`X-Forwarded-Host`、钱包输入或未验签 discovery
结果直接信任。唯一权威来源是该 Proxy operator 的静态部署配置。该值在所有
profile 都必须显式设置；本地 Docker 模板使用
`http://127.0.0.1:8100/v1`：

```bash
MYCOMESH_NETWORK_PROFILE=testnet
MYCOMESH_NETWORK_ID=mycomesh-testnet
MYCOMESH_PUBLIC_GATEWAY_URL=https://gateway.mycomesh.xyz/v1
ETH_CHAIN_ID=11155111
MYCO_SETTLEMENT=0x...
```

推荐上线顺序：

1. operator 持有 `gateway.mycomesh.xyz`，在反向代理或负载均衡器上终止 TLS；
2. `/v1` 转发到仅监听私网的 proxy，保留固定的 canonical path；
3. 在 proxy 中配置完整 `MYCOMESH_PUBLIC_GATEWAY_URL`，不要动态拼接；
4. 读取 `/.well-known/mycomesh.json`，验证 `recommended_gateway.descriptor`；
   `recommended_base_url` 仅为兼容字段，不能独立作为可信输入；
5. descriptor 必须包含 canonical `public_url`、`node_id`、`public_key`、
   `network_id`、`chain_id`、`settlement`、递增 `sequence`、`expires_at`、`status`、
   `weight`、`capacity` 和 `role`，且由节点 Ed25519 key 签名；
6. 通过 admin-authenticated `/gateways` 注册，定时用更高 sequence 续期；
7. consumer 使用 `verify_gateway_descriptor` 验签、重算 node ID，并 pin
   public key/network/chain/settlement；
8. consumer 在该 origin 单独完成 wallet key challenge，保存该 origin 专用 key；
   Gateway 持久化 origin/network/chain/settlement，并在每个认证请求上核对；
9. failover Gateway 使用新的 challenge 和不同 API secret，不复制原 key hash 数据库。

反向代理必须只接受 canonical SNI/Host，并把该 Host 原样转发给应用；其他 Host
应在代理层拒绝。新建和轮换的管理员账户 key 同样会写入 scope。旧数据库中的
unscoped key 始终拒绝，没有绕过开关，必须经管理员轮换。

规范化规则如下：

- 非本地环境只允许 `https://`；
- HTTP 例外只适用于 `local` profile 的 localhost/loopback；
- 拒绝首尾空白、控制字符和反斜杠，避免不同 URL parser 对 authority 产生歧义；
- 拒绝 URL userinfo、params、query、fragment；
- 拒绝 private、loopback、link-local 和 reserved IP literal；
- 拒绝十六进制、八进制、单整数和缩写形式的 legacy numeric IPv4 hostname；
- 非本地使用 public DNS hostname；
- 签名 descriptor 中的 URL 必须已经 canonical，禁止验签后静默改写；
- descriptor 剩余有效期限制为 30 到 3600 秒，签名生命周期最长 3600 秒，
  注册时签名年龄不超过 300 秒，内容变化必须提高持久 sequence；本节点有效
  descriptor 可原子复用，避免 discovery 写放大；
- verifier 除验签和重算 node ID 外，还应传入预期 `node_id`/`public_key` trust anchor；
- key challenge 有效期限制为 30 到 900 秒，`expires_at <= now` 即失效，nonce
  只能消费一次；默认最多 1024 个 active challenge、每分钟签发 120 个；验签前
  使用持久 SQLite token 跨进程独占，未到期时禁止接管，worker 退出主动释放；
  消费必须携带当前 token，默认最多尝试 5 次；
- EIP-1271 钱包注册必须配置可信 `ETH_RPC_URL`，RPC worker 默认 4、最大 32，
  总 timeout 默认 20 秒、最大 30 秒；只有取得 worker 槽后才增加 challenge 尝试次数，
  钱包明确拒绝、RPC 不可用和总 deadline 分别返回 403、503、504。

`sync-balance` 只用于受控的 direct/debug 同步。它要求完整 chain、settlement、
latest/synced block、canonical block hash 和 confirmations，并把余额、账户 freshness、
全局游标与 revision 原子提交。这些 metadata 是受信管理员声明，不是链上证明；只有
事件 indexer 会通过 RPC 和 canonical block hash 核验。HTTP/CLI 调用者不能把 source
标成 `events`；一旦事件 indexer 已成为全局来源，direct 路径不能覆盖或降级它。账户
freshness 还会与全局 latest block 比较。生产常态应运行事件 indexer。

要注意，DNS 名称本身仍依赖 DNS 与 CA/TLS 信任链，预解析到实际连接之间也仍有
DNS rebinding/TOCTOU 残余风险。生产环境应启用 DNS 变更和证书到期告警、反向
代理 allowlist、HSTS、出站防火墙，并在 consumer 连接侧拒绝 private、link-local、
loopback 和云 metadata 地址，持续从外部网络探测实际证书和解析结果。

## V3 安全设计摘要

Settlement V3 的核心约束是：

- 仅接受标准 non-rebasing、无转账费稳定币；所有转账检查严格余额差；
- `availableBalance` 与 `lockedBalance` 分离；
- reservation ID 绑定 settlement、chain ID、consumer 和 consumer salt；
- reservation 锁定 provider、channel、request v2 hash、immutable pricing version、amount、expiry 和默认关闭的 fallback opt-in；
- request v2 hash 绑定 endpoint、exact model、canonical `input`/原始 `messages` 数组和 positive output cap，不包含 routing metadata/request ID；
- provider 强制请求 model 等于 config/签名 descriptor；canonical JSON UTF-8 bytes 仅做 input admission，费用按覆盖完整 system/agent/routing context 的 `reserve_input_tokens` 和 resolved output cap 完成本地及链上最大报价；
- provider 在同一 confirmed block 读取 pricing hash、reservation 和 quote，链上与本地报价不一致即拒绝；随后在 latest block 只拒绝已经 closed/expired 的 reservation；
- receipt EIP-712 域绑定 chain ID 与 settlement address，chain ID 变化时动态重算 separator；
- request hash、response hash、accepted hash、reservation、双方地址、relay/pool、
  token usage、pricing 和 deadline 都在签名范围内；
- consumer 与 provider 每笔双签，或分别提交 receipt-scoped delegate signature；
- EOA 与 EIP-1271 contract wallet 都可校验；CLI 接受任意 contract signature bytes，并要求 `isValidSignature` 返回至少一个 32-byte ABI word 后解码 magic，预检调用的 `from` 与链上 Settlement caller 一致；
- 每次 V3 inference 还要求 `mycomesh.evm.session.v1` EIP-191 授权，把 chain、settlement、reservation、consumer/provider、channel、pricing、request hash、max fee、expiry、deadline、fallback、nonce 和 Ed25519 session key 绑定在同一 consumer 钱包签名中；session 路径的 EIP-1271 返回必须严格等于 32-byte magic word；
- 外层签名、canonical ID/nonce 和 reservation 离线签名在占用 capacity 或访问 RPC 前校验；capacity 不足时不消费授权；链校验通过后，request ID、payment nonce、reservation ID 和 session nonce 在默认持久 replay DB 中单事务 claim，再开始上游执行；开始后的不确定失败保持已消费并返回不可重试；
- settlement permissionless，但没有 trusted operator bypass；
- receipt 结算键为 `keccak256(abi.encode(reservationId, receiptHash))`，reservation 防重复消费，batch 最大长度固定；
- consumer 只有逐 reservation 显式 opt-in 才允许 provider fallback；该路径要求 `acceptedHash == 0`，只收不可退 minimum fee，剩余部分进 treasury，不给 relay/pool、不发 reward，也不作为服务或质量证明；
- deadline 至少覆盖 provider timeout 加 60 秒交易 inclusion buffer，且不晚于 reservation expiry；全部 wallet RPC 完成后、持久 claim 前再次检查；
- reward 默认全局关闭，启用需要 typed timelock，暂停即时；仅成功 mint 计入 epoch；
- emission 从部署时间开始，每 208 周约四年减半；
- channel version 不覆盖旧版本，治理变更使用公开参数的 typed timelock。

当前已实现的是“一次 reservation/request 的 wallet-to-Ed25519 session
authorization”：钱包签署的 EIP-191 canonical JSON 精确绑定这一笔授权，provider
在相同 confirmed block 按 `eth_getCode` 分流 EOA/EIP-1271 后校验。它有 nonce、额度、
expiry 和完整 request/payment scope，但不会跨 reservation 复用。consumer 可选择不
发布签名、按合约规则释放 reservation 或等待 expiry；当前没有面向可复用 session 的
通用链上主动 revocation registry，因此不能把它描述成任意可撤销的长期会话。

这些约束保护“已授权 receipt 的链上付款”，但不自动证明 AI 输出正确、有用或
唯一。语义质量、模型真实性和争议裁决仍需独立机制。

另外，receipt 对 usage 的签名只证明“双方签过这个数值”，不证明这个数值来自
真实 tokenizer。当前 Codex CLI 兼容桥接返回零值或空白词估算，也没有在模型生成
阶段强制 reservation output cap，因此不得用于生产按 token 计费。响应字节上限只能
防止资源耗尽，不能替代可信 token 计量。

## V2 到 V3 迁移

不能把 V2 deployment JSON 改成 V3 地址后继续使用。建议逐账户、逐区块迁移：

1. 公布 V2 cutoff block，停止创建新的 V2 工作和 delegate authorization；
2. 结算已接受 receipt，等待未使用 reservation 过期，并对账到 confirmed block；
3. 提取 V2 可用余额，确认 `Withdrawn` 后撤销旧 settlement allowance；
4. 核对 V3 部署字节码、chain ID、stablecoin、treasury、governance、EIP-712 domain；
5. 核对 channel version 和 pricing hash，从两个独立 RPC 等待确认；
6. 确认稳定币是标准 non-rebasing、无转账费 token，approve V3、deposit，并核对严格余额差；
7. 为具体 provider 和具体 request hash 创建 V3 reservation，确认后只发送该 inference；
8. provider 生成 evidence，consumer acceptance 后双方签署 EIP-712 receipt；
9. 任意 relayer 提交结算，indexer 按 tx hash + log index 记录并处理 reorg；
10. V2 数据保持只读，直至 cutoff 前所有余额、receipt 和奖励完全对账。

最终 V3 ABI 同样不能兼容早期 V3 部署。最终 create 签名是
`createReservation(bytes32,address,bytes32,bytes32,uint64,uint256,uint64,bool)`
（selector `0xd8f2bc55`），最后一项是 `providerFallbackAllowed`；
`reservations(bytes32)` getter 返回 9 words。结算查询改为
`receiptSettled(bytes32,bytes32)`（`0xaa061aa6`）和
`settlement(bytes32,bytes32)`（`0x28d93e69`），复合键 helper selector 为
`settlementKeyFor(bytes32,bytes32)`（`0x640b1ad5`）；已派生键查询
`settlementKeySettled(bytes32)` 的 selector 是 `0xe24b6931`。旧 V3 必须停止
接收新请求，部署新合约和新 deployment record，
对账/释放旧余额后重建每一个 request-bound reservation；使用旧 input-only hash 的
reservation 也必须按 `mycomesh.inference.request.v2` 重建。旧 reservation ID、
calldata、签名、settlement query key 和 ABI decoder 均不能复用。

V3 testnet deployer 创建的 `TestUSDC` 允许任何地址 mint。生产部署必须使用经过
评估的真实稳定币，并重新验证 decimals、transfer 行为、黑名单/暂停能力、升级
风险和合约会计兼容性。

## 生产发布门槛

以下项目全部完成前，不应启用公开无许可流量：

- 对已实现的 authenticated sealed provider/relay transport 做独立密码学审计、
  跨实现测试、密钥泄漏演练与公网压力测试；若要求 session 前向保密，升级为经过
  审计的 Noise/libp2p session transport；
- 生产 proxy/provider/relay 全部指向受管 PostgreSQL 共享 DSN；ledger 由集中
  exporter 持有，完成 schema migration、备份恢复、HA、并发和故障注入测试；
- 生产 AI backend 必须在生成阶段强制 output cap，并返回可验证的模型原生 usage；Codex CLI 兼容模式不得承载按 token 生产结算；
- 至少两个独立 RPC，confirmed-block 读取、reorg rewind 和长时间 indexer soak test；
- 治理与 treasury 使用硬件钱包支持的多签，完成 timelock runbook；
- 私钥分离、轮换、备份、泄漏响应和最小权限；
- Gateway/Bridge 限流、DDoS 防护、日志脱敏、监控和告警；
- 启用公开 wallet registration 前，对 challenge 和 register 两个端点配置按来源
  限流；应用内全局 capacity/rate/concurrency 不能替代边缘限流；
- 公网入口使用只接受 canonical SNI/Host 的反向代理，配置连接数、请求头总读取
  deadline、请求体 deadline 和速率限制；不能只依赖 ASGI middleware；
- 所有出站 HTTP/RPC 经过能对 DNS、连接、TLS、响应头和响应体实施总 deadline
  及私网地址策略的 egress proxy；Python 同步 DNS/header 阶段不能被线程强制终止；
- 对 V3 Solidity、EIP-712 编码和 Python calldata 进行独立审计与交叉实现测试；
- 对 deployment bytecode、constructor 参数和 source verification 做发布复核；
- 复核 immutable stablecoin/reward token 地址、token proxy/admin、MYCO `mintAuthority`；禁止直接向 Settlement 转稳定币，只允许 `approve` + `deposit`；
- 明确 provider 质量争议、退款、slashing 和 open network 准入规则；
- 抗 Sybil 的有效工作/质量信号完成独立评审前保持 `rewardsEnabled == false`；
- 禁止 production 配置引用 `TestUSDC` 或任何 unrestricted-mint token。

## 验证建议

每次发布至少运行：

```bash
python -m unittest discover -s tests -q
forge test
forge build --sizes
docker compose --env-file .env.deploy config
```

本工作区在 2026-07-12 的实际结果：Python `unittest` 396 项通过；Foundry 在
`--offline` 模式下 5 个 suite、50 项测试通过；`forge build --sizes --offline`
通过，`MycoSettlementV3` runtime 为 22,420 bytes，距离 EIP-170 限制还有
2,156 bytes。当前主机没有安装 Docker，因此未执行 compose 配置解析；这项必须在
部署机或 CI 补跑。系统 Python 环境的 `pip check` 还报告了与本项目无关的全局
`solana/websockets` 和 `grpcio` 环境冲突，生产构建应在隔离虚拟环境或容器内复验。

本轮额外使用 Slither 0.11.5 对 17 个 Solidity 合约做静态分析。工具报告的
`strict-equality`、`weak-prng`、`divide-before-multiply`、`reentrancy-no-eth`、
`calls-loop` 和余额差检查警告均已人工逐项复核：V3 的商/余数分解保持精确向下
取整，reward 路径受 `nonReentrant` 和 epoch cap 保护，batch 上限为 32，严格
balance delta 是拒绝 fee-on-transfer/rebasing token 的设计。这里不能写成“Slither
零告警”：结论依赖 immutable reward token 和标准 stablecoin 的部署假设，部署时
仍必须验证实际 bytecode、mint authority、proxy admin 和转账语义。

还应做人工故障演练：错误 chain/settlement/URL 必须 fail closed；reorg 后本地
余额必须 rewind；stale indexer 不能覆盖新 revision，`events` 不能降级为 `direct`，
账户 freshness 必须按全局 latest block 计算，sticky reorg 退款不能回充余额；错误
request v2 hash、超 input/output bound、费用不足、deadline
不足 timeout+60 秒、链上/本地 quote 不一致、跨 reservation 重复 receipt hash、过期
reservation、篡改 session scope、错误 EOA/EIP-1271 签名、重复/并发 reservation 或
session nonce、V3 同 hash 不同 reservation、未 opt-in provider fallback 和 reward mint
失败必须分别得到预期结果且不能多付稳定币。另需验证 key-registration claim/尝试次数、
executor 提交失败不计次、504 后跨进程不能接管未到期 claim、worker 退出后释放、锁等待跨过 challenge 到期时
拒绝提交、挑战消费与 key 登记回滚、ledger 并发 append/sidecar 重建、fee-on-transfer/rebasing mock
token 在存款、提款或结算
时回滚，capacity 拒绝不消费 V3 claim、执行开始后的不确定失败不可重试，以及 reward
mint 失败不增加 `epochMinted`。资源测试还必须覆盖 chunked/伪造 Content-Length、
压缩响应、超大 RPC/error body、Codex stdout/stderr/事件洪泛、PDF data URI 变体、
慢请求头/请求体、慢滴响应、连接槽耗尽、legacy numeric IPv4 hostname 和非有限 timeout。
