# MycoMesh 全网评估与下一阶段计划

评估时间：2026-09-18 05:27–05:33，Asia/Shanghai。

## 结论

MycoMesh 已经达到“小规模、多节点、有真实推理与测试链付款记录的受控测试网”阶段。原生 Consumer、会话级路由、Provider 身份与签名回执、Relay 异步结算已构成可用闭环。当前主要短板是发布一致性、结算持续可用性、用户可见账单闭环与真实容量验证。自动发现和 V9 的本地实现领先于实际部署。

下一阶段应先交付一个可复现、可观测、可恢复的 V8 稳定版本，再启用发现、改造流式，最后单独评估 V9。节点数量、单元测试数量和合约功能数量都不能代替网络可靠性验收。

## 方法与证据边界

- 阅读本地源码、部署文档、发布工作流及任务记录；核查当前工作区。
- 从本机直接访问公开 HTTPS 接口，校验证书链和 IP SAN，未绕过 TLS。
- 使用既有受信 SSH 主机密钥，读取服务状态、文件描述符、指定源码哈希和容器健康；没有重启或发布。
- 执行本地关键 Python 回归、原生 Consumer 全部顶层测试、Web 测试与构建、全量离线 Forge 测试。
- 本轮未发送模型推理、付款交易、充值或故障注入。真实推理和结算闭环引用 9 月 15–18 日已有证据，不能视为本轮重新验证。
- 当前覆盖 IP mesh 的 Bridge1–3、Relay1–3、Provider2–4 和本地 8110–8113。Provider1、旧域名兼容服务、官网线上版本、第三方账号配额、独立机房/运营商分布、灾备恢复和长期性能没有完整复验。
- 这是一轮源码与运行评估，不是逐行安全审计、独立密码学审计或经济审计。

证据文件（本机忽略目录）：

- `.codex-run/mesh/current-network-assessment.json`：实时严格 TLS health。
- `.codex-run/mesh/current-runtime-assessment.json`：SSH/容器检查及本地 Consumer。首轮 SSH 未加载系统 known_hosts 的拒绝结果保留；以补充的 `system_known_hosts_recheck` 为准，未自动信任新主机密钥。
- `.codex-run/mesh/current-discovery-assessment.json`：公开清单与发现端点。
- `/tmp/mycomesh-assessment-{python,node,web,build,forge}.log`：本轮本地测试输出。

## 实际网络与任务完成度

| 部分 | 本轮状态 | 判断 |
| --- | --- | --- |
| Bridge1/2/3 | HTTPS health 成功；每台报告 3 个 peer；服务 active，FD 各 4 | 三个入口可用；是同一组 Provider 的多份目录，不是 9 个 Provider |
| Relay1 | 2 Provider；2 执行槽；推理/结算 ready；9 confirmed、2 failed | 正在提供服务，但交易持久化恢复版本落后 |
| Relay3 | 1 Provider；1 执行槽；推理/结算 ready；7 confirmed、1 failed | 正在提供服务，已安装最新广播恢复补丁 |
| Relay2 | 8 秒 HTTPS 握手超时，SSH 检查失败 | 尚未验证恢复，不能计入可用冗余 |
| Provider2/3/4 | Provider 和 sidecar 六个容器均 running/healthy；重启计数 0，无 OOM | 容器健康成立；不等于上游账号余量或真实推理通过 |
| 本地 Consumer | 8110/8111/8112/8113 health 均成功 | 多实例同时存在，不能由 health 判定版本一致或已完成钱包认证 |
| 自动发现 | Bridge `/relays`、Relay `/relay-announcement` 均 404；公开清单无 `relay_discovery` | discovery-only 代码已部署，但生产发现未启用 |
| 完整返回正文证明 | 现网 Relay health 未声明 `response_proof` | 本地能力不可当作线上保护；需协调升级并固定要求 |
| V9 | 合约、客户端、裁决工具与本地测试已有实现 | 文档明确尚未部署 Sepolia、未迁移现网 |

当前拓扑可概括为：Consumer → Relay1 → Provider2/3，或 Consumer → Relay3 → Provider4；Bridge1/2/3 提供目录入口，Sepolia RPC 和结算提交器参与服务可用性。所有在线 Relay 报告同一个 V8 结算合约和模型标签 `gpt-5.5`。

历史上已验证：三个不同会话分配到三个 Provider；两次续聊保持原 Provider；真实请求取得签名回执并结算；维护 Relay3 时三个 Provider 转到 Relay1。上述样本很有价值，但没有证明静默黑洞、执行中断线、跨 Provider 上下文无损迁移、持续负载或 SLA。

## 关键发现

### P0：两个在线 Relay 的结算恢复能力不一致

只读 SSH 确认：

- Relay1 `session_relayer.py` SHA256 为 `a6e38bc8b575d10c8b7ac7923c2b504300fcf187911b117cda59ff6a69735b66`，没有 `raw_transaction TEXT` 持久化字段；仍为关闭 SQLite 连接的补丁版本。
- Relay3 对应 SHA256 为 `80eac99fd872f018d9876aed13fb1c9c47cde6d0e7fa9977f47d87860dac03c4`，包含该字段，与恢复记录中的新功能一致。
- 当前 FD 为 7/6，systemd MemoryCurrent 约 54 MiB，没有再次观察到此前 8192 FD 耗尽；单次快照不能证明长期无泄漏。

Relay3 曾因广播结果不确定而阻断新请求。Relay1 尚不能依靠完整签名交易字节安全恢复同类问题。应将已经验证的 V8 恢复补丁做成可发布版本，空闲排空后受控升级 Relay1；保留身份、账本、配置和备份。不能简单覆盖整个本地工作区，因为其中混有 V9 和尚未联调的协议变更。

验收：广播前持久化；广播成功但响应丢失、进程重启、多个 RPC 返回 null/错误时，始终只恢复同一交易；没有新 nonce 重付、重复推理或虚构确认。旧无原始交易字节记录仍需独立核对。

### P0：gas 与 RPC 是当前业务可用性的直接约束

本轮 Relay1/Relay3 报告 gas 余额约 0.010329/0.010492 Sepolia ETH，`gas_capacity_remaining` 分别为 12/13。这个指标按当前 gas 报价、单回执 gas、安全系数、待办和预留计算；不是确定还能完成的交易数，也不是持续供给承诺。两台都有历史 `rpc_unavailable`，但本次状态为 ready。

建议建立低余量、最老待结算年龄、授权到期剩余时间、RPC 错误率、未知交易状态告警；补充 gas 应有明确预算与操作记录。余额足够而广播不确定时，充值也不能解决 nonce 阻塞。

已有 batch_size=8，不需要重新“增加批量结算”。应测量实际批量填充率、每请求 gas、等待批次时间和授权有效期，确定批次策略。不要依据测试币费用判断主网利润。

### P0：发布基线尚未收敛

评估时已有 51 个受版本控制文件变更、75 个未跟踪项（包括源码、测试、文档和一个 Excel 临时文件），不含本报告。大量已验证工作仍只存在于工作区或逐文件远端补丁中。

- `.github/workflows/test.yml` 未包含 Forge 或显式 opt-in 的 V9 真实本地链测试。
- Consumer CI 在测试前没有显式安装该包依赖，也未固定 Node 运行时；本机已有依赖下的成功不能证明干净 runner 成功。
- 镜像发布 workflow 独立响应 main push；当前文件没有等待测试 workflow 通过的依赖。源码中未见“所有测试通过后才推广 latest”的门槛，远程分支规则未核验。
- 全量 Forge 测试仍有三个失败，不能将核心 V9 通过描述为全仓绿色。

建议拆出“线上 V8 稳定分支”和“V9 实验分支”，为提交、npm 版本、镜像 digest、部署清单及能力声明建立一一对应。先做干净环境安装验收，再推广镜像；旧测试要调查并修复，不能直接降低断言。遗留版本若停止支持，需要明确归档和保留安全回归。忽略 Excel `~$` 临时文件，发布前检查包内容和秘密信息。

### P1：账单最终状态与用户体验仍有断点

9 月 18 日恢复请求已有两个 RPC 核验链上成功，但当时 8113 历史仍为 pending。这是已有证据中的未闭环项；本轮未绕过管理鉴权读取账单，因此不声称此刻仍未同步。

源码 `refreshReceiptStatuses()` 依赖已认证的钱包及 management token。应在正常登录后验证自动收敛；进一步评估把已经绑定公开 owner/key/request 的只读链上对账移到独立后台，页面访问仍保持鉴权。不能为了刷新状态绕过钱包登录或再次发起推理。

另外 V8 的 `settled` 读取默认用 `latest`，然后将 confirmed 从后续待查列表排除；V9 则使用 safe 区块和哈希绑定。建议统一“提交、链上包含、达到确认深度、最终确认”的定义，补 reorg 测试，避免 V8 提前显示不可逆确认。

验收：同一 request 只显示一次，费用一致；重启、重新登录、RPC 切换后仍收敛；失败、广播未知和确认中分别显示；内容验证失败与是否已扣费分别表达。

### P1：自动发现实现已具备，但当前仍是显式成员制网络

上线发现需要独立 discovery 身份、受信清单、Relay admission 证书、Bridge 同步配置及 Provider/Consumer 协同升级。建议采用文档提出的 2-of-3 策略，但三个密钥应由独立操作者保管；同一个人持有三把钥匙不能提供独立治理。

应保留静态回退、过期检查、防重放高水位和健康连接不主动迁移的规则。当前各 Bridge 的 `bootstrap_pools=[]`，不能将尚未配置的同步能力计入现网。

验收：新增一个不在客户端静态列表中的 Relay，通过证书和公告传播被发现；逐一禁用 Bridge，验证有效缓存和静态回退；全部目录不可用并过期后拒绝新动态路由；旧会话只恢复到原 Provider，未知执行结果不重放。身份和信任策略需要实际运营决定，不能凭测试夹具选择。

### P1：隐私、内容完整性和模型真实性是三个不同承诺

当前 V8 OpenAI 路径中，Consumer 向 Relay 发送普通 JSON 请求；Relay 构造发往 Provider 的加密消息并持有返回解密密钥。见 `consumer-runtime.mjs:1704`、`relay.py:2109`、`relay.py:2455`、`relay.py:2476`。

因此 TLS 和 Relay–Provider 密封传输不能支持“当前 Relay 无法读取提示词/回答”的整体表述。旧透明转发路径的隐私说明不应套用到现行 V8 OpenAI 路径。产品需明确受信 Relay 模式；若要提供 Relay 不可见内容的模式，需要 Consumer–Provider 端到端密钥协商、路由元数据分离和独立审计。

完整正文证明能够防止 Relay 替换 Provider 承诺内容，不能隐藏内容，也不能证明上游实际运行某个品牌模型。上线这项能力需要 Provider/Relay/Consumer 配套，并在受信 V8 manifest 中要求 `require_response_proof=true`，避免能力降级。

当前 Codex backend 明确 `native_output_token_cap=false`，使用测试网事后输出限制验证，且 `production_ready` 可在 testnet 条件下为 true。建议拆分字段为测试网服务就绪、计量可信度、原生硬限额、主网可用性；健康页不应混淆这些含义。

### P1：性能下一步应优化首字时间，并先建立可归因的基线

现有 Consumer 明确返回 `x-mycomesh-streaming-mode: buffered`，将完整结果再封装为 SSE；上游 capability 也声明不支持流式。改前端逐字显示不能降低实际 TTFT。

应先在同一 request trace 中分离：路由、RPC 校验、队列、上游首字、生成、证明验证、返回、结算。基准覆盖不同会话并发 1/2/3，再用 4/6 验证过载行为；同时测试同会话续聊，不能为分流而破坏会话粘性。

真正流式需贯通 sidecar → Provider → Relay → Consumer，并设计序列号、增量承诺或分块签名、最终 usage/receipt、取消和断线语义。若某个分块尚不可验证，不能作为可信工具指令执行。它是协议和后端改造，不是简单去掉缓冲。

历史短请求约 4–10 秒只适合作为样本，不能估算 P95 或最大 QPS。当前仅有三个执行槽，增加 Bridge 或 Relay 不会增加模型执行容量；应在测清队列与上游账号限制后再增加独立 Provider。

### P2：V9 需要独立上线门槛

V9 已实现 escrow、争议、退款、质押与奖励相关本地逻辑，不能把这些能力算到线上 V8。它是新合约而非自动升级，V8 余额/签名/授权不自动迁移。

需明确独立裁决者、资产、争议窗口、资金责任、质押参数、争议处理成本和身份轮换/退出机制；完成外部合约与密码学审查。特别验证多个 Relay 并发接单时对同一 Provider 可用 stake 的竞争：本地读取 stake 不是全网抵押预留。

完整成本应包含模型服务成本、Relay/Bridge 运维、链上 gas、失败但已发生的计算、对账/争议与资金占用。签名和探针不能自动证明真实模型或抗女巫有效劳动，奖励不应早于这些边界的验证。

## 本轮测试

| 范围 | 结果 | 限制 |
| --- | --- | --- |
| Python 关键 12 个模块 | 192 通过 | 包括结算恢复、发现、真实 loopback 故障、调度、完整性和 V8/V9 Consumer；非全仓 |
| Native Consumer 顶层测试 | 212 通过，无跳过 | `--test-concurrency=1`；没有复跑浏览器扩展或真实钱包 |
| Web | 19 文件、103 测试通过；类型检查和构建通过 | 未跑线上浏览器 E2E；主 JS 约 864 kB，gzip 255 kB，构建有大包提示 |
| Forge 全量离线 | 89 通过、3 失败；V9 30 通过 | V4 `testFailedClaimRetainsCredit` 遇已移除 testFail 命名；V5 两项预期 revert 未发生，需调查 |

本轮未重跑 opt-in V9 localhost EVM 集成，也未运行可能进入交互向导的全量 Python discovery。既有记录中的测试计数与本次有重叠，不应相加。

## 建议执行顺序与完成条件

1. **稳定现网 V8。** 统一 Relay1/3 交易恢复补丁，做好备份、排空和回滚；配置 gas/outbox/RPC/FD 指标与告警；核验原请求没有重复执行、待结算有明确去向。
2. **建立一个正式稳定发布。** 收敛本地工作、修复测试、补 CI 安装和运行时 pin，将测试成功与镜像推广绑定；升级到一个规范 Consumer 版本，正常登录验证完整账单闭环。
3. **激活并验收动态发现。** 明确信任根后配置证书和同步；恢复或替换 Relay2，优先确认独立故障域；逐项执行新增节点、目录故障、过期和原会话恢复验收。
4. **发布安全能力并做耐久测试。** 协调上线完整正文验证；明确 Relay 隐私边界；运行 24–72 小时持续测试与受控故障注入，记录成功率、重复执行数、结算完成率、最老 pending、FD/RSS 趋势和恢复时间。测试预算与负载需事先确定。
5. **优化端到端体验。** 根据 trace 结果实现真正流式、过载背压、连接复用和清晰错误；做首次安装到首个成功 API 请求的真人验收，再考虑 Web 按路由拆包。
6. **另立 V9 候选发布。** 审查经济与治理方案、验证并发抵押与争议闭环，明确迁移/回退后小范围上线。

建议首先交付的成果是：一份 V8 稳定版发布清单、Relay1 恢复能力与 Relay3 对齐、一个用户正常登录即可自动对账的 Consumer，以及可重复运行的网络验收报告。
