# 会话调度与 Consumer 账单

## 会话级调度

新会话在 Relay 之间按容量、当前工作量及绑定数量选路；Relay 在其 Provider 内原子选择、绑定、预留。相同会话后续请求保持同一 Provider，正常情况下也保留原 Relay，不能因为另一个节点更空闲就换号。原 Relay 故障时，只有原 Provider 已连到显式配置的备用 Relay，且没有执行中或结果未知的请求需要重放，后续请求才可跟随同一 signer 换路。

支持的会话标识（多个同时出现时必须一致）：

- HTTP `X-MycoMesh-Session-Id`、`X-Session-Id` 或 `session_id`。
- 请求 `metadata.mycomesh_session_id`。
- Responses 的 `conversation` 字符串或 `conversation.id`。

标识为 1–128 个可打印 ASCII 字符，不含空白或逗号。不同支付 Key 的相同标识互不共享 Provider 绑定。付款 request ID 仍是每个请求单独生成，不等于会话 ID。

没有标识的请求获得独立随机 ID，响应以 `X-MycoMesh-Session-Id` 返回；调用方可在后续轮次复用。相同提示词、相同 Key 或相同 `prompt_cache_key` 都不再等于同一会话。缓存键仍可用于缓存，但不控制会话路由。

例如，SDK 可将自己已有的会话 ID 放进 `extra_headers`；不要求用户手工管理 Provider 账号：

```json
{
  "model": "gpt-5.5",
  "input": "继续这个对话",
  "metadata": {"mycomesh_session_id": "conversation-123"}
}
```

路由标识放入现有付款请求哈希覆盖的 metadata，不把未签名的转发头当作 Relay 的路由依据，也不向 Provider 注入启用 Gateway 隐式历史的头。

### 续接与故障

- 成功响应的 `previous_response_id` 或工具 `call_id` 可恢复该 Consumer 记住的原会话；未知、过期或矛盾的续接返回 409，不随机选另一个 Provider。
- 完整自包含的工具调用历史可配合新会话 ID 创建分支；孤立工具输出不能这样迁移。
- 原 Provider 忙碌时仍在原节点排队；原节点离线、能力不匹配时明确返回错误，不悄悄切号。
- 已验证回执的 Provider signer 被用于后续签名请求的 `metadata.mycomesh_provider_signer` 约束。即使 Relay 内存绑定过期或重启，也不能忽略这个约束换号。旧版未公布 signer 的 Provider 无法满足此恢复约束。
- Consumer 可从本机、当前 Key 的账单恢复已成功会话的 Relay 与 signer。上游工具进程及尚未收到结果的会话不是持久会话存储；服务重启不能保证恢复这些上游状态。
- 同一 Consumer 入口的并发首轮会原子绑定；不同 Consumer 进程同时首次创建同一新 ID，尚无跨进程原子占位保证，应让该会话使用同一个入口。若共享历史已出现该 ID 对应多个不同 Provider signer，恢复时返回 409，不擅自挑选其中一个账号；同 signer 的历史 Relay 变化不视为换号。
- 收到 HTTP 成功响应后，解析/回执验证失败不自动重放；POST 发送后断连导致结果未知，也不会自动再发另一台 Relay。仅有 `error.execution_status=not_dispatched` 明确证明未派发时，初始独立请求才可安全回退；普通 5xx 和 `retryable` 不足以触发重试。因此不声称任意故障下均实现跨 Provider 的“恰好执行一次”。

Relay `/health` 的 `v8.scheduler` 提供 `version`、`session_affinity`、`total_slots`、`available_slots`、`outstanding_jobs`、`reserved_jobs`、`queued_jobs`、`active_jobs`。一个 Provider socket 目前是一个执行槽；`outstanding_jobs` 是完整入场工作量，不能简单用等待队列长度代替。

内存表有上限。Relay 默认空闲绑定 TTL 为 900 秒、最多 4096 条；运行中的绑定不会被驱逐。Consumer 对一次性请求的闲置路由做有界回收，显式绑定不会为接纳新请求而被随意替换；续接原路由丢失且无可验证本地路由记录时返回错误。续接响应/工具 ID 映射默认空闲 30 分钟。

这属于路由改造，不代表每轮普通请求复用同一个 Codex thread，也未把 buffered SSE 改成真正逐 token 流式。

## 同一个支付 Key 的本机账单

此前 8111、8112、8113 分别只读取自身 `data-dir/receipt-history.jsonl`。性能测试的 5 条记录在 8112/8113 中，8111 因此看不到；公共链上 Indexer 已能查到这些结算，并非漏扣或未结算。

现在合并当前实例历史和同机共享账本，按链、合约、支付 Key、request ID 隔离并去重。共享位置默认：

```text
~/.mycomesh/consumer-history/<chain-id>/<settlement-contract>/<payment-key-address>/receipts.jsonl
```

可用 `MYCOMESH_CONSUMER_HISTORY_DIR` 配置专用目录。目录 0700、文件 0600；账本只保存公开回执字段，不保存支付私钥、原始签名、请求提示词或模型响应正文。不会扫描整个磁盘搜寻其他 Consumer。旧记录必须能关联当前 Key 才能迁入；跨机器同步和公共 Indexer 是另一个数据源，不应与同机账本混称。

页面显示实际 Provider signer、会话和结算状态，费用保留 tUSDC 的 6 位小数。费用分为已结算、待结算、结算失败；`broadcast_unknown` / 确认超时单独显示结果待核实，不认定成功或失败。进入消费记录、切回页面及登录后每 15 秒刷新；后台以已登录钱包、当前 Key 和 request ID 计算结算键，查询 `settled(bytes32)`，只有独立链上结果才可确认成功。未结算记录还会用当前支付 Key 签署不可付款的域隔离查询，向原 Relay 查询其白名单公开状态，因此过期失败不再永远显示 pending。查询不会泄露原付款签名或其他 Key 的记录。

每轮最多检查 20 条记录，活跃与终态记录分别轮转；大量新失败记录不会挡住较老 pending，未变化的结果不重复追加账本。RPC 失败仅保留原记录；已确认不回退、终态失败不被陈旧 pending 覆盖。

`wallet_unlocked` 不等于浏览器管理鉴权。未正常钱包登录的页面仍不能读取账单或 Key；服务更新后仍需原钱包完成一次登录签名，不能绕过这个检查。此次改造不需要重新注册支付 Key、重新授权 Provider 或充值。

账单落盘失败不会触发第二次推理；响应会带 `X-MycoMesh-History-Status: persistence-error`，应保留本次付款回执并检查磁盘状态。

## 验证与发布边界

单测包含同会话首轮并发、跨会话分流、续接与分支、会话故障不迁移、计数释放、容量回收、损坏响应不重放，以及跨实例账单去重、跨 Key 隔离、管理鉴权和链上状态同步。Mock Relay 测试仅用于验证协议与调度，不算真实模型性能数据。

更新运行环境时需同时更新 Relay 的调度逻辑与 Provider 的签名身份描述，再启用新版 Consumer；原 Key、Provider 登录卷、证书与结算数据库都应保留。真实调用回归应在新版 Consumer 完成正常钱包登录后进行，并单独记录费用与请求 ID。

### 2026-09-15 实际发布状态（14:15，北京时间）

- Provider2 → Provider3 → Provider4 → Relay3 → Relay1 已完成逐台更新。只替换对应的 `p2p.py` / `relay.py` 并重启目标角色，未重启侧车或修改登录卷、私钥、链上授权、Bridge、Nginx。每机保留原源码备份；更新期间有短暂重连，不声称零中断。
- Relay1 / Relay3 分别有 2 / 1 个在线 Provider，TLS 验证开启，均公布 `scheduler.session_affinity=true`；验收时 active / queued / reserved / outstanding 全为 0。
- 本地 `http://127.0.0.1:8111/v1` 已运行新版 Consumer，连接这两个 IP Relay，保留原 data-dir 和支付 Key。旧 8112 / 8113 测试进程未升级，不能当作本次新版真实回归的入口。
- 经独立链上证据核验，已将其他测试实例中缺少的 9 条账单补回 8111；原有 10 条字节保留，合计 19 个不同 request ID、54,262 最小单位，即 **0.054262 tUSDC**。这 9 条标记为已结算；旧 10 条的状态由新版登录后的后台检查同步。账单、共享账本已备份，没有额外扣费。
- Consumer Node 测试 102 项通过；Relay / Provider 相关 Python 测试 124 项通过。另一次较宽范围 Python 回归为 230 / 231 通过，剩余 `tests/test_p2p.py` 的旧错误文本断言与已有多模型报错文本不符，未为本次任务改动它。
- 上线后的免费验收通过：`/health`、`/ready`、`/v1/models`，新版页面及脚本解析，匿名 dashboard 隐藏记录和 Key，缺失或错误 Bearer 的推理请求返回 401，去重账本仍为 19 条。

14:15 的免费验收时 Consumer 按设计重新锁定。随后用户通过原钱包正常完成登录，才开始下面的新版真实回归；未读取钱包私钥或绕过管理鉴权。

本机审计证据（未提交运行目录）：`rolling-deploy-20260915-session-routing-061057Z.json`、`consumer-8111-post-update-verification.json`；账单备份为 `.codex-run/mesh/history-backup-YrxgUZ/`。

### 新版真实回归（14:17–14:18，北京时间）

使用同一 `http://127.0.0.1:8111/v1` 与当前已授权的支付 Key，先发三个独立会话，再并发续聊 A / B；共 5 次真实请求，没有自动重试。Responses 和 Chat 两种 API 均经过真实 Relay / Provider。

| 请求 | 实际路径 | 响应耗时 | 费用（tUSDC） |
| --- | --- | ---: | ---: |
| A 首轮 | Relay1 → Provider2 | 7.441 s | 0.002190 |
| B 首轮 | Relay3 → Provider4 | 5.849 s | 0.002136 |
| C 首轮 | Relay1 → Provider3 | 6.715 s | 0.002198 |
| A 续聊，改变提示词 | Relay1 → Provider2 | 4.194 s | 0.002000 |
| B 续聊，改变提示词 | Relay3 → Provider4 | 3.942 s | 0.002208 |

五次均 HTTP 200，真实签名回执验证通过，付款 request ID 各不相同。三个新会话实际覆盖了两个 Relay、三个 Provider；两次续聊各自保留原 Relay 与 Provider signer。续聊复用显式会话 ID，没有用旧响应 ID 推断上下文持久化；此测试不证明上游线程恢复或缓存命中率。

五条新记录均已在当前 Consumer 账本找到并匹配真实会话和 signer，新费用合计 **0.010732 tUSDC**；账本由 19 条增加到 **24 条**，总费用由 0.054262 增加到 **0.064994 tUSDC**，差额一致。该费用合计包含待结算记录，不等同于已链上扣款总额。网页登录后的自动刷新读取此去重账本。

独立 RPC 在区块 11708108 核验：A 首轮、B 首轮、B 续聊各有唯一结算事件，signer、费用、owner / key / request ID、提交地址和交易状态均匹配，分别有 27 / 26 / 25 次确认；共 **0.006534 tUSDC** 已结算。C 首轮和 A 续聊共 **0.004198 tUSDC** 尚无事件，`settled=false`。

未结算原因已由 Relay1 只读 outbox 查实：提交账户 `0xa0121ad2dc2bb48f2c8b3435b5e491f0c3013ad3` 的 Sepolia ETH 不足支付 gas。检查时余额为 0.000365448025070628 ETH，本次待发交易成本要求为 0.000512052295316250 ETH；该报价随 gas 价格变化。两行均为 `pending`、`tx_hash=null`，RPC 已拒绝发送；`attempts=0` 只表示尚无成功广播的交易哈希，不表示 worker 没有尝试。

两笔付款尚未完成链上结算；需要另行补充 Relay gas，**不应重跑模型请求**。当前 Consumer 的付款授权截止时间为签发后 15 分钟，合约在结算时检查到期；这两笔约在北京时间 14:33 到期，因此不能承诺任意时间补 gas 都能结算原回执。授权有效期内，现有 outbox 会自动重试；超过期限需要另行核对，不应修改已签名付款或伪造确认。本轮未补款、未手工发送交易，也未将这两条伪标成已结算。独立证据为 `session-e2e-settlement.json` 和 `session-e2e-outbox-relay1.json`。

测试后 5 个更新节点均健康，3 个 Provider 执行库中每个测试 request ID 恰好有一条 `completed`，均落在上表对应 Provider；没有未完成或 uncertain 记录。Relay 调度的工作量计数全部归零。这里的推理健康不代表提交账户 gas 充足；证据为 `session-e2e-final-network.json`。

这些是短请求的小样本响应耗时，不应与此前不同提示词和输出长度的性能测试直接比较，也不能当作负载吞吐量或 P95 结果。原始公开证据为 `.codex-run/mesh/session-e2e-20260915.json`。

### 后续鲁棒性修复与真实回归（17:30–17:41，北京时间）

上面的 14:17–14:18 记录保留为当时快照；其中两笔未结算付款后来授权过期，现已明确显示 failed，未重放模型请求。修复并重新正常登录后，8111 上又完成了 3 笔真实请求，覆盖两个 Relay 的 Responses / Chat 接口及同 Provider 续聊；另一次 gas 不足的尝试在派发前被拒绝，未执行、未计费。

本轮新增 **0.015780 tUSDC**，当前去重账本合计 **27 条**，三条新记录通过正常页面刷新均为 confirmed。完整响应耗时分别为 6.283 / 5.357 / 4.045 秒，SSE 仍是 buffered。测试 gas 补款、唯一执行核对和独立 RPC 区块视图差异均记录在 [鲁棒性回归报告](network-robustness-2026-09-15.md)，不将历史失败记录改写为成功。
