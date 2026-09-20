# 现有 IP mesh 性能评估 — 2026-09-15

结论：当时的网络已能完成真实调用，小规模控制面通信正常；同提示词并发样本出现集中执行，真正流式尚未实现。需要校准：该样本不是不同真实会话的对照测试，不能把同会话固定 Provider 本身认定为缺陷，也不能由此判断跨会话调度是否合格。样本不足以宣称生产 SLA 或持续高并发能力。

本文保留改造前的测量数据；后续会话级调度与账单修复见 [会话调度说明](session-routing-and-consumer-history.md)，不能把旧数据当作新版性能验证。

## 范围与方法

- 北京时间 12:59–13:01 采集控制面；13:04:56–13:05:18 发起并完成真实推理，之后只读核验执行记录、结算及服务状态。
- 范围为 Bridge1/2/3、Relay1/3、Provider2/3/4。Relay2 排除；Provider1 和原 8111 Consumer 保留原样。
- 使用既有 Key，经 `http://127.0.0.1:8112/v1`、`8113/v1` 的真实 Consumer → Relay → Provider → Codex 路径调用 `gpt-5.5`，不是 mock、健康检查代替推理或绕过付款验证。
- 共 5 个新逻辑请求，每个最大授权 100000 个最小单位，总授权上限 **0.5 tUSDC**。辅助脚本不重试；产品内部的 Provider/Relay 回退仍保持原样，按 request ID 核对结果。
- 公网探针均验证 IP 证书与专用 CA，未使用 TLS bypass。未重启、停止或修改线上服务；本次仅新增本地诊断记录和本文。
- 这是有限样本基准，不是饱和压测。控制面 p95 仅描述本批样本；5 次推理不能估计可靠的推理 p95、最大 QPS、长期可用率或模型 token/s。

## 1. 网络与控制面

本机对每个节点发起 10 次独立 HTTPS 健康请求，包含 TCP、TLS 和 HTTP 完整传输。单位为毫秒，不是裸网络 RTT。

| 本机访问目标 | 成功数 | 完整请求 p50 | 完整请求 p95 |
| --- | ---: | ---: | ---: |
| Bridge1 | 10/10 | 576 | 595 |
| Bridge2 | 10/10 | 578 | 583 |
| Bridge3 | 0/10 | 无成功样本 | 均 TCP 连接超时，阈值 2 秒 |
| Relay1 | 10/10 | 582 | 596 |
| Relay3 | 10/10 | 585 | 600 |

两台 Relay 各复用同一个已验证 TLS socket，再测 10 次完整 HTTP 请求：Relay1 p50/p95 为 **192/209ms**，Relay3 为 **198/238ms**，全部成功。相对新建连接，中位耗时少约 390ms，下降 66%–67%。这证明连接复用的重要性，但不代表现有 Consumer 每次都重新建连，也不能直接把该差额当作可新增获得的推理优化收益。

从 Bridge1 和 Provider3 两个远端来源，分别访问 3 个 Bridge 的 `/health`、`/peers` 及 2 个 Relay 的 `/health`，每组合 10 次冷连接，共 **160/160 HTTP 200**。合并样本 p50 **6.55ms**、p95 **12.36ms**、最大 **21.51ms**，未出现限流或传输错误。远端健康与发现接口响应快，但这些轻请求不能代表转发吞吐上限。

Bridge3 的本机连通性与远端结果不同：本机 10 次均连接超时，两个远端来源访问正常。故不能称它宕机，也不能宣称现有入口对所有用户网络都可达。

本地 Consumer 共 40 项轻量检查符合预期：8112/8113 的 `/ready`、`/v1/models` 成功，缺 Key/错误 Key 均返回 401。ready/models 首次约 0.58–0.61 秒，随后缓存命中小于 1ms；无效 Key 拒绝中位耗时约 0.34–0.82ms。这不是有效付款签名验证或推理时延。

统计方法：本地 p95 使用线性插值；远端使用 nearest-rank，因此远端单组合 n=10 的 p95 就是最大样本。两类原始记录保留方法说明，不用于 SLA 对比。

## 2. 真实推理、并发与流式

短请求输入完全一致：`Reply with exactly PERF_MESH_OK. Do not use any tools.`，`max_output_tokens=256`；流式请求输出 1–80，每行一个整数，`max_output_tokens=512`。并发批次以屏障同时释放三个线程。所有请求 HTTP 200，输出符合要求，付款回执 accepted。

| 场景 | 最终路径 | 用户侧完整耗时 | 回执费用 tUSDC |
| --- | --- | ---: | ---: |
| 单次短响应 | 8112 → Relay1 → Provider3 | 4.661 秒 | 0.002155 |
| SSE，输出 1–80 | 8113 → Relay3 → Provider4 | 7.832 秒 | 0.002846 |
| 三并发中第一个完成（burst-2） | 8112 → Relay1 → Provider3 | 4.289 秒 | 0.006807 |
| 三并发中第二个完成（burst-3） | 8112 → Relay1 → Provider3 | 6.217 秒 | 0.002000 |
| 三并发中第三个完成（burst-1） | 8112 → Relay1 → Provider3 | 9.077 秒 | 0.002000 |

并发批次总墙钟时间 9.078 秒，观测窗口完成率 **3 / 9.078 = 0.330 请求/秒**，中位请求耗时 6.217 秒。这不是稳态最大吞吐，不能外推为每分钟或全天容量。

### 调度没有充分利用现有容量

本批 3 个并发请求全部交给 Provider3，没有使用 Provider2 或 Provider4 来分担这批请求。当前部署每个 Provider 的 Codex 并发为 1，Relay 对每个 Provider socket 也是逐个任务发出并等待完整响应。故同一 Provider 上这三个请求实际串行执行。

Provider3 的只读执行记录进一步确认顺序为 burst-2 → burst-3 → burst-1，网关调用耗时分别为 **3.182、1.836、2.746 秒**。对应端到端减去网关耗时的差额为 **1.107、4.381、6.331 秒**；后两项明显增加，但差额包括排队、网络、RPC 校验及签名等，不能全部称为精确排队时间。claim/完成时间戳只有整秒精度。

静态原因与观测一致：

- Consumer 按配置顺序选择第一个健康 Relay，不按实时负载分流。8112 优先 Relay1，即便 Relay3 有空位也不主动使用。[consumer-runtime.mjs](../packages/mycomesh-cli/src/consumer-runtime.mjs) `chooseRelay`，约 1060 行。
- 同一 Relay 内，Provider 亲和排序优先于队列长度；baseline 对相同输入建立的亲和会影响随后的并发批次。亲和默认 900 秒。队列长度还不包含正在执行的任务，不能准确代表忙闲。[relay.py](../gateway/relay.py) `_v7_provider_candidates`，约 1829–1907 行。
- 单 Provider 的串行工作循环见 `relay.py` 约 592–615 行；部署并发为 1 见 [ip_mesh_provider.py](../scripts/ip_mesh_provider.py) 约 169 行。

配置允许全网 3 个 Provider 同时生成，但这不是已测得的全网吞吐；仅用 8112 且主 Relay 健康时，通常只能触达 Relay1 的两个生成槽，本批相同输入又集中到了其中一个。

### SSE 只是完整结果的流式封装

该次 SSE 响应带 `x-mycomesh-streaming-mode: buffered`：

- 收到响应头：7.831876 秒。
- 第一个文字 delta：7.832355 秒。
- completed 事件：7.832446 秒。
- 只有 **1 个文字 delta**，包含全部 80 行；首个文字到完成间隔约 **0.09ms**。

这不是逐 token 流式。用户需等约 7.83 秒才看到全文；不能用最后这 0.09ms 计算模型生成速度。代码先 await 完整 `relayInference`，再构造并发送 SSE，见 `consumer-runtime.mjs` 约 1352–1373、1564 行。流式请求与短请求输入、输出长度不同，也不能直接比较两者生成速度。

## 3. 发现与故障恢复边界

跨约 36 秒观察，三个 Bridge 均持续返回相同的 3 个 Provider，所有租约到期时间均前进；两台 Relay 的 Provider 数稳定为 2 和 1。这里确认的是发现列表和续约连续性，没有新增节点去测首次发现耗时，也没有独立重新验证每条描述符签名。

代码中的心跳间隔为 10 秒、租约 TTL 为 30 秒；每个 Provider 分别联系三个 Bridge，并非 Bridge 自动 gossip。初次注册逐 Bridge 尝试，故障入口可能增加启动等待；各 Bridge 后续独立续约，任意有效租约即可提供服务。不能把 TTL 当作所有异常场景的精确恢复时延。

本轮没有再次停机注入故障。此前同日部署验证已有两个独立场景，不能并入本轮性能样本：

| 此前故障场景 | 已验证行为 | 当次请求耗时 |
| --- | --- | ---: |
| 停 Provider3 | Relay1 由 Provider2 完成真实请求 | 5.360 秒 |
| 停 Relay1 edge | 同一 8112/Key 自动转 Relay3 → Provider4 | 6.436 秒 |

这是单次请求的完成时间，不是从故障发生到恢复的精确 RTO。详见 [部署报告](ip-mesh-deployment.md)。当前 Provider 仍固定重连原 Relay，不会自动迁移到另一 Relay；Consumer 请求回退成功不等于 Provider 连接也能跨 Relay 自动迁移。

从代码审查发现的压力/异常风险（尚未做本轮极端场景实测）：

- 每 Provider 可等待 64 个任务，而仅串行生成。任务排队计入 300 秒超时；超时会断开整个 Provider session，可能连带失败其他排队任务。见 `relay.py` 约 1499–1512 行。
- Provider 和 Relay 回退是逐个尝试，没有统一整体截止时间；Consumer fetch 的计时器在响应头到达后清除，后续 body 读取未被同一个计时器覆盖。见 `consumer-runtime.mjs` 约 537、1113 行。
- 健康缓存正常保留 30 秒，网络错误时可使用 10 分钟旧成功状态；缺少失败冷却，坏的优先 Relay 可能被后续请求再次尝试。见同文件约 1032 行。
- 当前 V8 `/v1` 未使用旧 `/infer` 的每 Consumer 32 并发限制；不能把 health 中该配置值当作 V8 已有的限流保护。edge 配有每 IP 20 请求/秒、burst 40、32 连接；这些保护阈值不等于实际推理能力。

## 4. 开销、资源和费用

每次有效请求，Relay 都在推理前同步读取链上 grant 和余额。它们进入关键路径；本轮未对 RPC、签名、队列等待分别插桩，因此不能把端到端耗时全部归因于模型、网络或队列。

控制面阶段的 8 台主机均为 2 CPU；1 分钟负载约 0.09–0.71，可用内存约 1320–1611MiB。它们只是低负载快照，不足以证明峰值 CPU、内存或网络容量充足。

额外 4 轮资源采样发生在 13:07:17 以后，已经错过真实推理窗口，明确不作为负载峰值证据。该阶段 Relay1 的 SSH 管理连接失败，未取得相应资源数据；Provider4 的执行数据库读取也在直连、Bridge1 跳板两次 SSH 尝试中失败。P2/P3 已读记录未发现这些 request ID 的重复执行，但不能声称完成了全部 Provider 的重复执行排查。事后两台 Relay 的 HTTPS 健康检查仍成功，分别有 2/1 个 Provider；SSH 检查失败不能等同于推理入口故障。

5 次回执费用合计 **15808 个最小单位，即 0.015808 tUSDC**，低于 0.5 tUSDC 授权上限。费用不含 Relay 支付的 Sepolia ETH 交易 gas。相同短输入费用也不固定：本批缓存命中量不同，且有最低费用，不能简单用完整 input token 数推算实际扣费。

### 结算核验

独立 RPC 验证本轮 **5/5 请求均已在 Sepolia 成功结算**：每个 request ID 各有一个匹配的 `ReceiptSettled` 事件，交易状态、submitter、Provider signer、费用及结算标识均与 Consumer 回执匹配，合计 0.015808 tUSDC；核验时有 59–61 个区块确认。两台 Relay 的只读 outbox 中每 ID 各一条记录，状态 confirmed、提交 attempts=1。本轮未发现重复扣款；这不等于已完整排除所有 Provider 的重复执行，后者仍有上述 Provider4 数据库读取缺口。

5 个请求对应 **4 笔独立链上交易**：burst-1 与 burst-3 在同一笔交易中批量结算，各自仍有唯一事件，并非重复或遗漏。

| 场景 | outbox 入队至 confirmed 更新时间 | 入队至链上所在区块时间（近似） |
| --- | ---: | ---: |
| baseline | 13 秒 | 11 秒 |
| stream | 5 秒 | 4 秒 |
| burst-2 | 12 秒 | 11 秒 |
| burst-3 | 22 秒 | 21 秒 |
| burst-1 | 20 秒 | 19 秒 |

结算在响应之后异步推进，不应把它再加到用户收到答案的耗时上。outbox 时间戳只有整秒精度，confirmed 更新时间包含轮询等开销；与链上区块时间的差值还依赖主机时钟，不能当作精确链上确认时延或 SLA。

### 事后服务验收

北京时间 13:15:51–13:15:55 独立检查通过：5 个 Bridge/Relay 的 role 与 edge 服务全部 active、running、enabled，`NRestarts=0`；Provider2–4 的 Provider 与 sidecar 容器全部 running、healthy、`OOM=false`、`RestartCount=0`；8111/8112/8113 `/health` 均返回 200。Bridge3 使用 Bridge1 跳板做管理检查，不改变本机直连 Bridge3 超时的结论。

5 个请求的独立本地审计也通过：授权数量日志恰好 5 项、request ID 唯一、响应正文正确、usage 与缓存计费算术匹配、费用合计正确。它与链上交易确认是不同层次的验证。

## 5. 优先改进建议（本轮未实施）

1. **先修调度**：区分正在执行与等待任务，原子预留空位；亲和有明确的最大可接受等待时间，超过阈值转空闲 Provider；Consumer 能在 Relay 间按容量与失败状态分流。保留同 request ID 的防重复结算约束。
2. **实现端到端真实流式**：从 Provider 到 Relay、Consumer 逐段传递，而非只改变 HTTP 格式；同时设计最终计量回执、客户端断开、取消与费用边界。
3. **补背压与总超时**：按实际容量限制等待，队列满及时返回可重试结果；区分排队超时与 Provider 故障，避免单个超时断开整条连接；增加请求整体 deadline 和失败冷却。
4. **先观测再调优关键路径**：增加 queue_wait、active_jobs、gateway_elapsed、chain_rpc、首文本和结算延迟指标；测量后优化连接池/RPC读取，不能靠放宽授权、撤销或余额校验来降低耗时。

下一轮容量测试应在明确预算后进行：固定输出工作量，分别测相同输入亲和与不同输入分流，再测 1/2/3/6 并发、多 Key、持续负载及网络黑洞。当前报告不假装这些场景已经完成。

## 非敏感原始证据

- 本地控制面：`.codex-run/mesh/perf-local-control.json`。
- 两个远端来源及租约：`.codex-run/mesh/perf-control-remote.json`。
- 5 次真实请求、逐事件计时、授权数量日志：`.codex-run/mesh/perf-inference-20260915/`。
- Provider 执行记录及读取失败边界：`.codex-run/mesh/perf-provider-executions.json`。
- 后测资源样本（未覆盖负载窗口）：`.codex-run/mesh/perf-load-resources.json`。
- 最终服务状态与请求独立审计：`.codex-run/mesh/perf-final-service-check.json`。
- 五个请求的链上结算、事件、费用与时间戳核验：`.codex-run/mesh/perf-settlement-verification.json`。
- 一次性测试脚本：`.codex-run/mesh/perf_inference.py`。已有结果目录时拒绝再次执行，防止意外重复付费。

以上文件只记录公开指标，不含支付 Key 或原始付款签名。不要整体分享 `.codex-run/mesh/`，其其他子目录含部署用 CA/TLS 私钥。
