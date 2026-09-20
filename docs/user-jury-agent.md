# 高信誉用户 + 本人 Codex 辅助的 V9 裁决

本版实现用户裁决入口：争议分配给自愿参与且达到信誉门槛的用户，用户在自己的设备上复核证据，可用自己的 Codex 登录获得解释，最后由本人钱包签署投票。多数票达成后，已有 V9 合约执行相应的托管、退款与罚没规则。Codex 没有钱包或发交易接口。

状态：本地实现与测试；没有上线、没有真实用户收到任务、没有实际模型调用。远端此前分发的冻结候选不含这次新增模块。此文不代表 V9 已部署。

## 身份与选择

“独立裁决者”可以由普通用户担任，独立性指与本次交易没有利益关联，并由不同的人控制签名密钥。当前 V9 合约的名单和阈值在部署时固定，agent 只能给名单内的合格用户生成任务。默认发布方案是三位真实用户、两票达成裁决；自动吸纳新用户、轮换、申诉和链上按信誉抽取仍需合约扩展。

既有 Provider 的路由评分不是用户信誉。首版使用单独固定公钥签发的用户信誉快照：

```json
{
  "schema": "mycomesh.jury.user-reputation.v1",
  "domain": {"chain_id": 11155111, "settlement_contract": "<V9地址>", "runtime_code_hash": "<hash>", "genesis_hash": "<hash>", "policy_hash": "<hash>"},
  "issued_at": 0,
  "expires_at": 0,
  "users": [{
    "address": "<小写用户钱包地址>",
    "operator_id": "<与本地V9配置一致的用户标识>",
    "score": 100,
    "score_source_hash": "<真实信誉记录的非零bytes32承诺>",
    "affiliated_addresses": [],
    "opt_in": true
  }]
}
```

示意值不能用于上线。运营者先核对真实信誉记录、用户参与意愿和关联地址，再用现有 `gateway.identity.sign_document` 签名：purpose 为 `mycomesh.jury.user-reputation.v1`，audience 为 `evidence_hash(config.domain)`，timestamp 与 issued_at 一致。快照有效期最多 24 小时。用户本地另外固定信誉签发公钥和最低分，不能接受任务自行指定的信任根。

这里的签名证明是签发方的信誉声明，`score_source_hash` 只承诺原始记录，不能证明评分正确、身份真实独立或没有遗漏关联地址。当前未实现用户信誉的自动累积、抗女巫机制、签发密钥轮换或快照即时撤销；上线前必须建立真实的用户信誉记录，不能用虚构积分填名单。

agent 根据实际链上结算排除付款人、消费密钥、Provider、Relay、相关签名人、池、金库、举报人和罚没接收人，同时检查声明的关联地址。它按信誉排序，为当前委员会内所有合格且尚未投票/举报的用户生成任务，避免少量排名靠前的成员阻塞其他用户。此排序不是随机抽签。

## 实际使用路径

代码入口是 `python3 -m gateway.user_jury_agent`。以下变量均由操作者从已核验的本地配置提供；命令不会生成身份、充值或自动派发私密证据。

先使用现有 V9 举报流程把准确的 incident 承诺提交到链上；进入投票时间窗口后生成任务：

```sh
python3 -m gateway.user_jury_agent \
  --config "$JURY_CONFIG" \
  --reputation-public-key "$JURY_REPUTATION_PUBLIC_KEY" \
  --minimum-score "$JURY_MINIMUM_SCORE" \
  assign --incident "$JURY_INCIDENT" --roster "$JURY_ROSTER" \
  --settlement-key "$JURY_SETTLEMENT_KEY" \
  --observed-at "$JURY_OBSERVED_AT" --observation-source "$JURY_OBSERVATION_SOURCE" \
  --output-directory "$JURY_NEW_TASK_DIRECTORY"
```

每份任务包含完整原始证据，输出目录权限为 0700，文件为 0600，不覆盖已有文件。只把任务交给对应的受邀用户，通过已有经认证的私密渠道传递；本版没有消息推送、公开下载地址或后台分发服务。任务哈希是内容承诺，任何人都能重新计算，不是分配者的签名；安全性依赖用户本地信任根及重新核验的实际链上报告。

用户从独立可信的观察记录取得 `JURY_OBSERVED_AT` 与 `JURY_OBSERVATION_SOURCE`，不能直接从收到的任务复制。原观察者签名的时间锚是授权签发时间，不能替代可信观察时间。用户复核时，两者必须与任务完全匹配。

```sh
python3 -m gateway.user_jury_agent \
  --config "$JURY_CONFIG" \
  --reputation-public-key "$JURY_REPUTATION_PUBLIC_KEY" \
  --minimum-score "$JURY_MINIMUM_SCORE" \
  review --task "$JURY_TASK" --reviewer "$JURY_USER_ADDRESS" \
  --observed-at "$JURY_OBSERVED_AT" --observation-source "$JURY_OBSERVATION_SOURCE" \
  --use-own-codex --codex-home "$JURY_PERSONAL_CODEX_DIRECTORY" --model "$JURY_MODEL" \
  --output "$JURY_NEW_REVIEW_FILE"
```

不加 `--use-own-codex` 可以只运行确定性核验。使用 Codex 时，复用用户已有登录，临时空目录、只读沙箱、无工具、无网页访问、并发为一。模型只收到八项固定枚举事实：承诺、签名、证据分类、协议版本、链上绑定、举报绑定、用户资格和投票时间窗口。完整证据保留给用户本地查看，不会自动发给模型。此版适用于已有可复现的协议矛盾，不能判断任意主观回答质量，也不能证明实际模型身份。

模型输出必须严格满足建议 schema；不自动修补 JSON。超时、无效输出或与证据不符的建议会被丢弃，原始核验结论保留。最长 60 秒；2,000 输出 token 是执行后的验收上限，不是费用保证。此代码路径尚未用真实个人登录调用模型验收。

用户独立审查后另行写入以下文件，不能将 `codex_advice` 直接当成投票：

```json
{
  "task_hash": "<本次任务承诺>",
  "reviewer": "<本人钱包地址>",
  "incident_record_hash": "<准确证据承诺>",
  "outcome": "confirmed",
  "reason": "<本人核对的证据、理由和结论，至少20个字符>"
}
```

`confirmed` 表示确认违规，`dismissed` 表示驳回；证据不足本身不等于任何一方有罪。弃权时不创建投票。agent 检查本人审查文件与任务绑定后，生成未签名的交易计划：

```sh
python3 -m gateway.user_jury_agent \
  --config "$JURY_CONFIG" \
  --reputation-public-key "$JURY_REPUTATION_PUBLIC_KEY" \
  --minimum-score "$JURY_MINIMUM_SCORE" \
  plan-vote --task "$JURY_TASK" --reviewer "$JURY_USER_ADDRESS" \
  --observed-at "$JURY_OBSERVED_AT" --observation-source "$JURY_OBSERVATION_SOURCE" \
  --approved-review "$JURY_USER_DECISION" --output "$JURY_NEW_VOTE_PLAN"
```

最终签名继续走既有 `gateway.relay_adjudication_v9 execute`，由用户本人提供受保护的专用钱包文件、准确 `--approve-plan-hash`、`--send` 和三个 gas 上限，持久化 outbox 后广播；`reconcile` 查询确认。签名流程独立于 Codex 进程，不把签名文件交给模型。

**当前强制边界：** 信誉、任务有效期和声明的关联地址在 agent 审查/生成计划时检查。既有 outbox 在发送时重新检查链上状态、实际交易方、委员会、票数和报告，但不再检查信誉快照或任务有效期；用户应在签名前重新生成计划。普通 V9 操作入口也不会强制经过本 agent。合约当前强制的是固定委员及交易方回避，尚未强制信誉或链下任务分配。要将这些条件约束到所有投票，需要合约和最终签名入口一并扩展。

## 验证

```sh
python3 -B -m unittest tests.test_user_jury_agent tests.test_adjudication_agent_model
```

单元测试使用真实签名的 Relay/Provider 证据；链读取和 Codex 后端使用模拟。覆盖信誉签名/过期、任务篡改、独立观察时间、利益回避、重复投票、模型不可升级证据或授权交易、用户明确批准以及私密文件权限。实际 localhost EVM 用例由 `scripts/run_v9_local_chain_tests.py` 统一执行；测试身份仅用于本地模拟链。

2026-09-18 验证：新增模块 44 项通过，连同 V9 操作器和证据验证的定向回归共 88 项通过。真实 localhost EVM 共 9 项通过、0 跳过，包括完整的真实签名证据 → 用户任务 → 两名用户分别签名 → 第一票保持托管 → 第二票合约退款与罚没。未实际调用 Codex 或改动真实网络。
