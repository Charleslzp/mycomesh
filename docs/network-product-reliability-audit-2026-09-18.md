# Consumer、Relay、Bridge 跨组件可靠性复核

日期：2026-09-18。目标是普通用户可试用、Provider/Relay 受控准入、测试币结算且不发代币奖励。本报告来自当前工作树源码、小范围 localhost 回归和已有真实 V9 调用记录；没有新增远端推理、交易、部署或运行配置变更。真实网页体验和实时节点状态由并行审计另记，不能把此处的源码行为当作所有旧进程的运行行为。

结论：签名、付款绑定、重放防护、结算持久化和多 Bridge 发现已有相当完整的实现；当前最影响试用的是版本入口不一致、执行后输出超限、等待过程不可见、未知执行后的恢复和到期资金处理。现有证据可以支持受控 smoke test，不能推出普通用户已经能顺畅完成全流程，或网络已通过长时间故障运行验收。

## 1. P0：让普通入口真正抵达拟开放的 V9 网络，并同步运行版本与文档

Native Consumer 默认网络仍为 V8，见 [consumer-runtime.mjs:107](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:107)。V9 普通入口要求独立委员会证明，见 [consumer-runtime.mjs:708](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:708)、[consumer-runtime.mjs:740](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:740)。现网 `controlled_test`、`independence_attested=false` 因而不符合普通入口策略；这属于正确的安全限制，不能改为虚假证明或默认绕过。之前 V9 成功调用使用专用测试 Consumer，不能代替普通 npm/浏览器路径验收。

主审现场另核验：旧 8111 的 `/ready` 为 503，原因是其两台 443 Relay 已无 V8 Provider；当前源码以默认配置启动的隔离 8120 则 `/ready=200`，指向 `https://bridge.mycomesh.xyz` 的 V8/5.5 路线。因此这里的问题是用户入口与目标 V9 部署不一致，不能写成所有 Consumer 均不可用，也不能把另一个 V8 网络可用计入 V9 验收。

另有直接可复现的文档问题：[local-consumer.md:38](/Users/lzp/mycomesh/docs/local-consumer.md:38) 和 [CLI README:44](/Users/lzp/mycomesh/packages/mycomesh-cli/README.md:44) 推荐匿名 `curl /credentials` 后 `eval`，但当前 handler 在已解锁状态仍要求 management bearer，见 [consumer-runtime.mjs:2098](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:2098)。本次临时 Consumer 测试确认：解锁后匿名为 401，management bearer 为 200；未读取真实用户凭证。主审现场观察旧 8111 进程匿名接口为 200、8110 为 423，这说明存在运行版本差异，不能把新源码结果伪称为旧 8111 的实测。

`--codex` 有有效通道：等待解锁后直接从同一进程状态把凭证交给子进程，不依赖匿名凭证接口，见 [consumer.mjs:232](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer.mjs:232)。浏览器复制 export 也是现有有效路径。

建议先决定并公开试用网络身份：若仍为受控测试委员会，提供单独命名、显式选择且醒目标识的预览入口；若使用普通 V9 入口，则先满足其独立委员会要求。发布匹配的 Consumer/Provider 镜像、清单和文档，保留已有安全限制。文档直接使用浏览器复制或 `--codex`，不要让用户 `eval` 错误响应。

验收：从干净用户目录按公开说明启动，页面显示正确网络/合约，完成钱包连接、授权、第一笔请求及账单；重启后按文档再次接入，无隐含专用 Python 脚本步骤。

## 2. P1：把模型目录和启动模型做成一致的用户选择

`/v1/models` 只返回 `chooseRelay()` 当前选中单台 Relay 的 models，见 [consumer-runtime.mjs:2103](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:2103)。本次无推理 localhost fixture 中，两个 Relay 分别公布 `[gpt-5.5]` 与 `[gpt-5.5,gpt-5.6-sol]`，两次目录请求即返回两个不同列表。因此 Sol 只在部分 Provider 上启用时，客户端可能看不到网络实际可用模型。`--codex` 默认参数仍写入 `gpt-5.5`，见 [consumer.mjs:246](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer.mjs:246)；后附 Codex 参数可覆盖，但不是明确的产品选择入口。

不应重复实现已有模型约束：实际显式请求已按模型过滤 Relay，见 [consumer-runtime.mjs:1451](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1451)；有 catalog 时拒绝未公布模型，见 [consumer-runtime.mjs:1594](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1594)；Relay 再按 Provider 模型能力筛选，见 [relay.py:2969](/Users/lzp/mycomesh/gateway/relay.py:2969)。响应与付款中的模型也有签名绑定。旧无 catalog 路径仍允许别名映射，侧车对未公布 slug 有内部 fallback，见 [main.py:1017](/Users/lzp/mycomesh/gateway/main.py:1017)；不能把旧兼容行为宣传为上游模型独立认证。

建议聚合经过身份和健康验证的 Relay 模型目录，保留每个模型的可用容量、能力和更新时间；增加一致的显式模型选择，V9 指定模型不可用时清楚报错。短期优先解决 Sol 在目录中时隐时现，不需要重写调度算法。

验收：Sol 只在一台 Provider 上启用时目录仍稳定展示；指定 Sol 不会变成 5.5；该 Provider 离线后给出明确不可用状态。

## 3. P0：处理输出预算执行后超限，否则真实用户会等待后拿不到结果

后端能力明确声明 `native_output_token_cap=false`、`post_execution_output_cap_validation=true`、上限 2000，见 [codex_app_backend.py:218](/Users/lzp/mycomesh/gateway/codex_app_backend.py:218)。校验在执行后依据 `outputTokens`，其中包含 reasoning 用量，见 [codex_app_backend.py:462](/Users/lzp/mycomesh/gateway/codex_app_backend.py:462)、[codex_app_backend.py:493](/Users/lzp/mycomesh/gateway/codex_app_backend.py:493)。

这不是假设：此前糖果请求设置 3000 在执行前被拒绝；改为 2000 后实际输出 2355，执行后 HTTP 422，没有付款回执或链上结算，见 [真实调用记录:22](/Users/lzp/mycomesh/docs/consumer-candy-run-2026-09-18.md:22)。用户没有这笔链上扣费，但已经等待、Provider 已消耗计算，任务也没有交付。简短答案/low reasoning 能降低风险，不能提供严格保证。

建议短期把后端预算能力暴露到请求预检和用户错误提示，明确区分“未执行”与“已执行但结果超预算”；设置与测试用途一致的默认预算和清晰任务范围。长期使用能原生约束授权预算的后端，或经协议设计验证的可中断、可计量分段执行。不能用截断计量、忽略超额或仅增加文字提示冒充修复，也不能自动重试导致 Provider 再次计算。

验收：覆盖普通短回答、推理较长回答和工具返回三类任务；每类都记录实际执行状态、是否交付、Provider 成本和是否产生用户费用，避免“无回执=未执行”的错误解释。

## 4. P1：当前 SSE 是结果完成后重放事件，等待体验仍然需要补齐

Consumer 先 `await state.relayInference` 获得完整响应，再生成 SSE，且明确标记 `x-mycomesh-streaming-mode: buffered`，见 [consumer-runtime.mjs:2007](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:2007)、[consumer-runtime.mjs:2022](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:2022)。实际后端 `supports_streaming=false`，测试计量模式在启动前拒绝 streaming，见 [codex_app_backend.py:233](/Users/lzp/mycomesh/gateway/codex_app_backend.py:233)、[codex_app_backend.py:501](/Users/lzp/mycomesh/gateway/codex_app_backend.py:501)。

两次成功糖果任务分别耗时 46.533 秒和 27.342 秒；它们是不同模型/节点/上下文的单次样本，不能作为 Sol 全面更快的基准。当前“支持 SSE 接口”也不等于用户在执行中收到文本。

建议先提供可理解的排队、执行、验签、账单提交状态与耗时，区分上游取消成功和仅客户端停止等待。真正流式需要处理增量内容验证、最终完整性、用量及付款收敛，不能只提前发送未验证文本就沿用“已验签结果”标签。

验收：记录首个状态、首个实际文本、完整答案三个时点；断开客户端时检查 Provider 是否仍执行、账单如何恢复。宣传和 API 能力声明应与实际时点一致。

## 5. P1：已有安全 failover，但未知执行结果缺少可恢复的用户请求记录

已有正确限制：只有明确 `execution_status=not_dispatched` 的可重试错误才换 Relay；POST 后丢连接返回 `relay_outcome_unknown`，不会自动重复推理，见 [consumer-runtime.mjs:1723](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1723)、[consumer-runtime.mjs:1795](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1795)。会话恢复限定同一已验证 Provider，见 [consumer-runtime.mjs:1553](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1553)。这些能力不需要再作为待开发项。

缺口是每次调用现场生成随机 request ID，见 [consumer-runtime.mjs:1649](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1649)，只在收到有效 receipt 后写账单；状态同步也仅从 accepted 历史条目开始，见 [consumer-runtime.mjs:1117](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1117)、[consumer-runtime.mjs:1767](/Users/lzp/mycomesh/packages/mycomesh-cli/src/consumer-runtime.mjs:1767)。本次 localhost 模拟 POST 后断连确认：HTTP 502、仅一次 POST、`history_rows=0`、只返回 session ID、没有返回 request ID。协议有按 request ID 的签名状态查询，但该次丢回执调用没有用户可见的持久入口。

建议在派发前持久记录请求意图（网络域、request ID/hash、Relay/Provider、金额上限），把未知执行显示为“待核实”；利用现有状态查询和链上证据恢复账单。SDK/用户显式重试应关联同一操作标识和请求 hash，结果未知时继续查询，不能重新随机 ID 后自动再次计费。是否恢复结果正文需要单独设计授权和保留时限。

验收：POST 后断网、Consumer 重启、回执丢失、用户再次点击四种情形，都能定位原请求且不触发第二次未知重复执行。

## 6. P0：复用已有 operator，补到期 release/仲裁 timeout 的调度与值守

release/timeout 已有成熟度检查、固定网络、持久交易 outbox、未知广播恢复、业务状态复核。入口见 [relay_adjudication_v9.py:326](/Users/lzp/mycomesh/gateway/relay_adjudication_v9.py:326)、[relay_adjudication_v9.py:355](/Users/lzp/mycomesh/gateway/relay_adjudication_v9.py:355)。CLI 要求具体 settlement key，见 [relay_adjudication_v9.py:613](/Users/lzp/mycomesh/gateway/relay_adjudication_v9.py:613)；它不是自动扫描服务。现有部署运行手册也明确自动调度尚未上线，见 [v9-activation-runbook.md:86](/Users/lzp/mycomesh/docs/v9-activation-runbook.md:86)。

建议在现有操作器之上实现有界扫描、到期队列、单一发送者互斥、gas 预算和告警，并明确人工兜底责任。正常托管释放、争议超时、用户退款、可领取收入、实际钱包领取分别展示。AI 证据整理和人类委员会签名不能被 keeper 替代；timeout 按合约规则执行，也不能推定为欺诈成立。

验收：跨重启只执行一次、广播结果未知先核账、RPC 切换/重组后重新验证；在争议期结束后的约定时限内完成释放；到期无人处理能告警。已完成的小样本手动 release 不能代替该运营验收。

## 7. P1：把现有健康字段接成运营告警和故障验收，而非重复开发健康检查

Relay 已区分 inference readiness 与 settlement readiness，见 [relay.py:836](/Users/lzp/mycomesh/gateway/relay.py:836)。提交器已有 worker 心跳、outbox 分类、gas 容量、预留、最近成功/失败时间，并在 gas 不足或未知广播时停止接单，见 [session_relayer.py:789](/Users/lzp/mycomesh/gateway/session_relayer.py:789)。因此不能把“缺少 gas gate、持久结算或健康检查”当作新发现；缺的是将这些状态转成持续可用的运营工作流和可量化的服务结果。

Bridge 发现也已有多源请求、准入签名 quorum、公告 TTL、持久 sequence 防回滚、容量/响应大小限制与独立 Relay 身份探测，见 [relay_discovery.py:260](/Users/lzp/mycomesh/gateway/relay_discovery.py:260)、[relay_discovery.py:321](/Users/lzp/mycomesh/gateway/relay_discovery.py:321)、[relay_discovery.py:455](/Users/lzp/mycomesh/gateway/relay_discovery.py:455)、[relay_discovery.py:484](/Users/lzp/mycomesh/gateway/relay_discovery.py:484)。多 Bridge 断连时保留未过期缓存的行为已被本次回归覆盖。

建议先接入少量直接影响用户的指标：按模型的可用 Provider/空闲槽位、排队/完整交付 p50/p95、执行后拒绝率、未知执行数、结算积压年龄、gas 可服务笔数、公告剩余寿命、到期未释放数量。每个告警给出节点、request ID、责任人和恢复动作。再以现有 3 Provider/2 Relay/3 Bridge 做有界故障演练：单节点退出、1–2 台 Bridge 失联、RPC 不可用、结算提交器重启、gas 逼近阈值；记录恢复时间、重复执行和资金状态，而不是只数容器在线数。本轮未执行破坏性远端故障演练。

## 本次验证证据与范围

- Node：`consumer-local-boundary`、`consumer-resilience`、`consumer-v9`、`consumer-discovery` 共 **68 项通过**。覆盖本机 management 保护、预算共享、不重放未知请求、相同 Provider 会话恢复、V9 付款/内容绑定、链上状态核验、多 Bridge 缓存和防回滚。运行时为现有 Node，并将已有部署 venv 的 Python 放在 PATH 首位；最初系统 Python 缺少 Crypto 导致混合签名 fixture 失败，修正测试运行环境后全部通过，没有修改产品代码。
- Python：`tests.test_codex_metering`、`tests.test_v9_lifecycle_operator`、`tests.test_relay_discovery`、`tests.test_relay_v9_runtime` 共 **99 项通过**，耗时 11.933 秒。采用现有 `/tmp/mycomesh-mesh-deploy-venv/bin/python -B -m unittest -q`，RPC/后端由测试 fixture 提供，没有实际模型调用或链上交易。
- 两个一次性 localhost 复核：模型目录随所选 Relay 改变；未知执行只发生一次 POST，但无历史记录和可见 request ID。临时目录已清理，没有改动用户密钥或现有 Consumer。
- 真实调用数据引用 [GPT-5.5 记录](/Users/lzp/mycomesh/docs/consumer-candy-run-2026-09-18.md)、[Sol 记录](/Users/lzp/mycomesh/docs/consumer-candy-sol-run-2026-09-18.md)，不是本轮重新产生的性能测试。
- 未执行全量测试、真实钱包新用户流程、持续压测或远端断网/重启。不能由 167 项局部测试推出当前每台运行进程都使用这份工作树或网络达到生产可靠性。
