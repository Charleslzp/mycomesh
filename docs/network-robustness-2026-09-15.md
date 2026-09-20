# 网络鲁棒性修复 — 2026-09-15

这是在真实会话测试暴露结算问题之后的修复记录，不把旧版 5 次推理结果当作新版性能数据。范围为 Native Consumer 8111、Relay1/3、Provider2/3/4；Relay2、Provider1、Bridge 与 sidecar 未纳入此次代码发布。

## 行为变化

- Consumer 的统一 deadline 覆盖选路、重试和完整 HTTP body；坏 Relay 有指数冷却，不再退回十分钟前的健康缓存。已发送但结果未知的请求不自动重放，只有明确 `not_dispatched` 才可安全回退。
- 排队请求超时只取消该任务。执行中超时关闭不再可信的 Provider socket；该请求标为 unknown，未派发的排队任务单独标为 not_dispatched，不把它们误判成已经执行。
- Relay 的进程存活、Provider 可用和结算可用分开报告。结算 worker 健康、RPC 链正确且足够支付保守 gas 预算，才原子预留结算额度并允许推理。入队后额度转为持久 outbox 工作量。
- 交易广播前将本次完整签名交易的哈希持久化；广播结果未知时只查该哈希，不换 nonce 重新签名提交。确认超时保持未知，链上回滚与未广播授权过期有终态；后台扫描过期 pending 不被卡住的 submitted 阻塞。
- 健康探针在同一 RPC 完成 chain/balance/gas/block 整组读取，优先最近成功节点；总预算最多 8 秒，过期或失败仍拒绝接单，不靠沿用旧健康维持假就绪。
- Provider 的备用 Relay 必须在公开网络配置中明确列出，校验 TLS、host、URL、端口、收款及 attestation 身份。切换前停止旧 socket、注册回调和 Bridge 心跳；保留 Provider 的 peer、签名身份和 sidecar，不重放原执行。
- Consumer 后续请求只能跟随已经验证的原 Provider signer 换 Relay，不能借故障恢复换账号。账单区分已结算、待结算、失败和结果待核实，见 [账单说明](session-routing-and-consumer-history.md)。

## 历史结算与费用

14:17–14:18 测试中的 C 首轮与 A 续聊（合计 0.004198 tUSDC）因 Relay1 gas 不足而拖至授权过期，已是 failed；补 gas 不能恢复这两笔签名。此次未修改原付款、未重跑模型、未将其伪装成已确认。

此前已获授权的 Relay1 充值为 0.001 Sepolia ETH，交易 `0x82cbac9919210e16ccf81eb8777e5d7008569e2d29e5047f114b6009702134c4`。此次进一步在两个 Relay 的测试网 gas 账户间调拨 0.0003 ETH，最终交易 `0x447ea24b17d6f3e6240d2d867dc1771cb4932d0b10bc4fc8fab7730d9348cec0`，区块 11708626，手续费 0.0000525 ETH。

首次候选 `0x743b8c8f18902ffd6f403722a5b1ebc1a74c8721165c1853dc38a35d61ca421c` 广播没有获得确认。由于签名实现带随机性，不能仅凭原哈希重新构造相同 raw transaction；恢复过程在停止发送账户对应 Relay 后，严格使用同 nonce 6、同收款地址和同金额做替换，未创建第二个 nonce。两个候选至多一个可在同一规范链执行。后续 signed raw transaction 已限权保留用于同哈希恢复，不在日志或公开接口输出。

本机 Tenderly 与 Relay3 来源 Publicnode 独立核验均通过，核验时 22 个确认。调拨后余额分别为 R1 0.001012948025070628 ETH、R3 0.001034778515274406 ETH。这只是测试 gas：当时报价下每台支持 1 个保守结算预留，不是长期资金保证或持续并发容量；余额或 gas 价格变化会影响接单额度。

## 验证与限制

先完成本地 HTTP/TCP/socket 故障注入，再滚动发布。首次线上停机实测发现父启动器漏传备用配置，导致子进程仍只连接主 Relay；这不是恢复成功，已据此补父→子实际启动路径的修复与测试。

修复后的真实停机测试通过：先确认没有执行中/uncertain 请求、没有待广播/待确认结算，然后只停止 Relay1 角色。自停止命令开始，2.779 秒内在 Relay3 观察到 Provider2/3/4 三组原 peer + signer；3.337 秒时 finally 已完成 Relay1 的启动命令，未动 edge。恢复后 5 次采样没有主动抢回原 Relay。该数字是这一次空闲连接重注册的观测值，不是模型请求时延、持续可用率、网络黑洞 RTO 或上游线程恢复证明。

之后在逐台空闲检查下，仅重启 P2/P3 的 Provider 容器，恢复 R1 两个 Provider、R3 一个 Provider 的常态布局；这一步是人工恢复布局，不是自动抢回。三台 sidecar 的容器 ID 和启动时刻不变，执行计数未增加、incomplete=0，两 Relay 的 edge 不变，最终 inference_ready/settlement_ready 均为 true，outstanding=0。非故障期 R1 健康 10/10、结算就绪 9/10，未就绪的一个样本出现在刚启动且 checked_at=null 时；R3 两项均 10/10。小样本不代表长期可用率。

本轮没有声称新模型吞吐、P95 或 SLA 已达标。真实逐 token 流式仍未实现，SSE 仍为 buffered；持续压测、网络黑洞与任意上游线程持久恢复仍需单独验证。下述付费端到端回归在新版 Consumer 正常钱包登录之后进行，未绕过钱包门禁。

部署保留逐机源码备份、原支付 Key、Provider 登录卷、证书和数据库。`.codex-run/mesh/` 存放本地审计证据，但该目录也含部署私密材料，不可整体公开。

已完成的代码回归：Node 全套 122 项、Python 相关 228 项通过，`git diff --check` 通过。免费线上验收 6 项通过：Consumer 健康与原 Key 保持、匿名管理页隐藏记录和 Key、缺 Key/错误 Key 401、他人收据查询 404、篡改状态查询签名 401。以上不代替真实模型推理。

非敏感审计文件：

- `rolling-deploy-20260915-robustness-075504Z.json`：首次 5 节点滚动记录。
- `20260915-robustness-followup-081249Z.json`：RPC 健康与启动链漏参修复的二次 5 节点滚动记录。
- `robustness-gas-independent.json`：两路 RPC 的交易、费用及余额核验。
- `robustness-free-checks.json`：新版 Consumer 和公网状态查询鉴权验收。
- `robustness-runtime-diagnostic.json`：首次真实故障暴露的父/子启动参数缺口。
- `robustness-controlled-failover-20260915-081945Z.json`：修复后的真实断连、同身份迁移、恢复及 sidecar/执行计数核验。

## 钱包登录后的真实端到端回归（17:30–17:41，北京时间）

用户用原钱包正常登录后，经 `http://127.0.0.1:8111/v1` 和现有 API Key 调用真实 `gpt-5.5`。未重启 Consumer、替换支付 Key 或重做 Provider 授权。共 4 次尝试，其中 3 次收到真实模型响应和已验证签名回执，1 次在派发前拒绝；最多 3 笔付款，每笔授权上限 0.1 tUSDC，总授权上限 0.3 tUSDC。

| 场景 | 实际路径 | HTTP / 完整响应耗时 | 实际费用（tUSDC） |
| --- | --- | --- | ---: |
| A 首轮，Responses | Relay1 → Provider3 | 200 / 6.283 s | 0.006814 |
| B 新会话，Chat Completions | Relay3 → Provider4 | 200 / 5.357 s | 0.006816 |
| A 续聊，gas 不足 | Consumer 拒绝，未派发 | 503 / 3.730 s | 0 |
| 补 gas 后 A 续聊，SSE | Relay1 → 原 Provider3 | 200 / 4.045 s | 0.002150 |

三次成功响应均校验了预期输出、支付 Key、真实回执、独立付款 request ID、会话 ID 与 Consumer 账单。A 续聊仍是原 Provider signer，没有换账号；此次仅证明会话路由保持，不证明上游持久线程或完整历史恢复。SSE 返回 `buffered`，只有 1 个文本 delta，4.045 秒是完整响应耗时，不能当成真正逐 token 首字延迟。

### 结算、账单与拒绝路径

三笔新费用合计 **0.015780 tUSDC**。当前 Consumer 去重账本由 24 条增至 **27 条**，费用总和由 0.064994 增至 0.080774 tUSDC，差额一致。正常已登录页面刷新后，三条新记录均为 confirmed；原两条授权过期记录仍为 failed，未手工修改账本来伪造结算成功。账本费用总和包含旧失败记录，不等于全部链上扣款。

前两笔各消耗 gas 后，两台 Relay 都低于保守接单额度。续聊在 17:33 返回 `session_unavailable` / 503，没有付款回执；Provider 的窗口执行记录和账本增量均证明该尝试没有新执行或计费。确认这个前置拒绝后，才在补 gas 后发起新的续聊尝试，没有重放结果未知或已完成的请求。

三笔 Relay outbox 均为 confirmed，独立 Tenderly 核验三笔的 `settled`、唯一事件、费用、签名身份、提交地址、成功交易及规范区块均匹配。第二来源 Publicnode 对前两笔全部通过；最后一笔虽然 `settled=true`、唯一事件和成功交易均匹配，但其区块查询与自身交易回执的 block hash 不一致，初次 90 秒复核未通过 canonical-block 检查。保留该异常报告，不把它写成双源全通过；这与模型是否执行、Consumer 是否记录是不同的验收项。

进一步只读诊断定位到：Publicnode 收到 `eth_getBlockByNumber(0xb2aa94)`（11709076）却返回 `number=0xb2aa93`（11709075），即前一个区块；按交易回执的 block hash 查询则返回正确的 11709076，且包含本次交易。Tenderly 两种查询一致。证据表明 Publicnode 的这次按高度查询返回了错误高度，不能据此断言链发生重组，也没有放宽规范区块校验。公开配置中的 dRPC 备用核验未成功，未算作通过。

绕过项目 RPC 封装、改用新的字符串 JSON-RPC ID（响应 ID 精确匹配）并加 `Cache-Control` / `Pragma: no-cache` 后，Publicnode 仍返回前一高度，响应 `CF-Cache-Status=DYNAMIC`。因此没有将问题归因于 helper 高度换算或固定请求 ID；底层服务为何返回错误数据仍未确定。本轮到此停止探测，没有为了让验收变绿而跳过校验或修改线上结算逻辑。

### 按已授权范围补充 Relay 测试 gas

按用户此前的 Relay 费用授权，从原钱包向两个指定 Relay 提交账户各补 **0.01 Sepolia ETH**，共 0.02 ETH；两笔转账实际 gas 合计 **0.000123987806397 ETH**。两来源独立核验均通过，没有额外推理、支付 Key 变更或 Provider 授权变更。

- Relay1：`0x7126ac35ebddf119e295b39ebdd23cc7f1784e9d673f0a143aabcc9ad772ae67`，区块 11709069。
- Relay3：`0xd00e5e6bb71eba7297d28a267d1ffe6a55b01ad98245f3ad32fc5f35453ea935`，区块 11709070。

最终网络只读审计：两 Relay 的 inference_ready / settlement_ready 均为 true，队列、执行中任务、预留及未完成结算均为 0；当时报价下各有 9 个保守 gas 接单额度，这不是固定容量承诺。三笔请求跨 Provider2/3/4 查询，各只有一条 completed：P2 为 0 次、P3 为 2 次、P4 为 1 次；没有第四条执行或 uncertain。Provider、sidecar 的容器身份和启动时间、peer / signer 及配置未变。

此次是短请求功能与失败路径回归，不是全面压测，也没有覆盖真实付费请求执行中断连或 Relay2。此前 2.779 秒的迁移结果仍只适用于那次空闲连接停机试验。

本次非敏感证据（位于本地 `.codex-run/mesh/`，不要公开整个目录）：

- `robustness-e2e-20260915.json`：4 次尝试、3 笔回执、费用与正常 Consumer 账单状态。
- `robustness-e2e-settlement.json`：前两笔的独立双源核验。
- `robustness-e2e-final-settlement.json`：三笔复核及 Publicnode 区块视图异常的原始记录。
- `robustness-e2e-block-diagnostic.json`：错误返回前一区块的定点诊断。
- `robustness-e2e-block-nocache-stringid.json`：绕过项目封装、新字符串 ID 与 no-cache 下仍复现错误高度。
- `robustness-e2e-alternate-settlement.json`：dRPC 备用来源未成功的原始记录。
- `e2e-relay-gas-independent.json`：本次两笔 gas 补款的双源核验。
- `e2e-execution-after-window-20260915-093554Z.json`：前两笔完成以及 503 后没有新执行的窗口证据。
- `e2e-execution-after-three-20260915-094548Z.json`：三笔唯一执行、最终结算与网络健康；旧窗口证据保留，避免把执行表 TTL 清理误判为执行记录丢失。
