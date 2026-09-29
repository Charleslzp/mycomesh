# V10 去信任化设计：Relay 盲转发、探针 + 争议仲裁、去中心化信誉与陪审

状态：设计稿，待评审。适用网络：V10 dynamic Provider-AI（当前 Sepolia `controlled_test`）。

## 0. 目标与边界

目标（按依赖顺序）：

- **A. Relay 盲转发**：Relay 看不到 prompt 和 response 明文，但仍能校验付款、预留容量和结算。
- **B. 探针 + 争议仲裁**：用与真实流量不可区分的探针发现欺诈，客观证据直接开链上争议，交给 Provider-AI 陪审。**不引入 TEE。**
- **C. 去中心化信誉与陪审**：reputation 由链上结果推导，不再由单一 `reputation_authority` 写入；Provider 质押即可准入；陪审自主从网络中按信誉和质押随机选出；治理改为多签 + 时间锁。

不在本轮范围：开源权重模型 Provider（等 OpenAI、Claude 跑通后再加）；TEE/zkTLS。

前置：Claude 后端当前不存在（只有 `openai_http` 和 `codex_app_server`）。多厂商陪审（见 C.5）依赖它，建议与 A 并行作为 Phase 0 实现。

### 当前事实（2026-09-29 核实）

| 项 | 现状 |
| --- | --- |
| 请求明文 | Consumer → Relay 是明文 JSON；Relay 用 `_v7_normalize_request` 读取 input/messages 并重算 `request_hash`；陪审证据中存有完整明文 |
| Relay → Provider | 已有 `seal_json_frame`（X25519-HKDF-ChaCha20Poly1305），但由 Relay 封装，Relay 可见明文 |
| 探针 | `json_arithmetic_v1` 能力探针；V10 未启用（缺资金 channel 映射）；失败只记本地软观察，**没有链上争议出口** |
| 探针可区分性 | 探针使用专用赞助 channel，Provider 可按 channel 识别探针 |
| 信誉 | `ProviderJuryRegistryV1.setProvider/removeProvider` 仅 `reputation_authority` 可调 |
| 陪审选取 | 已是从注册表按 reputation ≥ 75、运营者去重后随机抽 3 个、2/3 票决；随机数为 `future_blockhash_v1` |
| 准入 | Relay 环境变量白名单 `MYCOMESH_RELAY_PROVIDER_PUBLIC_KEYS` |
| 治理 | governance = deployer = treasury，单一 EOA，无时间锁；合约不可升级、无暂停 |
| 服务容量 | 3 个 capacity channel 全部绑定 provider1；provider2/3/4 只作陪审 |

## A. Relay 盲转发（不改合约）

### A.1 原则

`request_hash` 已经是对明文的承诺，并由 Consumer 在 EIP-712 授权中签名。所以 Relay 不需要明文：

- Relay 校验：授权签名、channel、预留额度、Provider 路由提示。
- **Provider 校验**：解密后重算 `request_hash`，与授权不一致就拒绝执行。这保护 Provider 不被 Relay 替换内容，也保护 Consumer。
- Consumer 校验：解密响应后比对收据里的 `response_hash`（现有逻辑不变）。

### A.2 线格式 `mycomesh.v10.sealed.v1`

请求体（`/v1/responses` 或 `/v1/chat/completions`，endpoint 仍由路径决定）：

```json
{
  "model": "gpt-5.5",
  "max_output_tokens": 2000,
  "metadata": {"mycomesh_provider_signer": "0x…"},
  "mycomesh_sealed": {
    "schema": "mycomesh.v10.sealed-request.v1",
    "frame": "<base64url sealed frame>",
    "plaintext_bytes": 18234
  }
}
```

- 明文仅保留定价和路由需要的字段：`model`、`max_output_tokens`、`metadata.mycomesh_provider_signer`。
- `frame` 用 Provider 的 transport key 封装，内容为 `{endpoint, model, input|messages, max_output_tokens, options, reply_transport_key}`，发送方为 Consumer 的临时身份。
- 输入预留额度按密文长度计算。AEAD 只增加固定开销，所以按密文长度估算只会偏保守，不会少收。
- 响应：Provider 用请求里的 `reply_transport_key` 封装响应体；`PAYMENT-RESPONSE` 收据保持明文（只含哈希、用量、费用、签名）。

### A.3 Provider 身份绑定（防 Relay 替换公钥）

Consumer 从 Relay `/health` 的 Provider 描述中取 transport binding。Relay 可能伪造，所以要求两层签名：

1. transport binding 由 Provider 的 P2P 身份签名（已有）。
2. Provider 用 channel 绑定的 **EVM signer** 对“P2P 身份公钥 + transport key_id + 过期时间”签名（**新增** `provider_transport_attestation`）。Consumer 用 channel 的 `provider_signer` 核验。

Relay 无法同时伪造这两层签名，也就无法做中间人。

### A.4 陪审证据改为“当事方揭示”

- Relay 只持久化密文、`request_hash`、`response_hash`、收据和签名。
- 发起争议的一方（Consumer 或探针方）在证据文档中揭示明文请求和响应。它能揭示，是因为请求由它加密、响应加密给它的临时密钥。
- 证据校验：`inference_request_hash(明文请求) == request_hash`，且 `sha256(明文响应) == receipt.response_hash`。任一不符，证据无效。
- 证据文档按现有方式上链，只登记 `evidence_hash`，全文由证据解析器提供给陪审员。

### A.5 兼容与切换

1. Relay、Provider 发布同时支持明文和 sealed 的版本；Relay `/health` 的 V10 能力中增加 `sealed_request: "mycomesh.v10.sealed.v1"`。
2. Consumer 在 Relay 支持时默认使用 sealed。
3. 所有 Consumer 升级后，Relay 在清单中增加 `require_sealed_request`，拒绝明文请求。
4. 公共网关：在非托管网关场景下，sealed 请求由用户本地（SDK 或浏览器）封装，网关同样只转发密文。

### A.6 工作项

- Python：`secure_transport` 增加“Consumer 临时身份 → Provider”封装入口；Relay 增加 sealed 分支（不解析 input）；Provider 解封装、校验 `request_hash`、封装响应；新增 `provider_transport_attestation`；陪审证据改造。
- JS（Consumer）：新增依赖 `@noble/ciphers`（ChaCha20-Poly1305）和 `@noble/curves/ed25519` 的 x25519；实现与 Python 互通的 frame 编解码，并用跨语言测试向量固定。
- 测试：跨语言测试向量；Relay 看不到明文的断言（sealed 请求在 Relay 日志、证据库中不出现明文）；替换内容被 Provider 拒绝；用 sealed 证据揭示走通争议全流程。

## B. 探针 + 争议仲裁（不用 TEE）

### B.1 不可区分性（探针有效的前提）

- 探针请求使用 A 的 sealed 格式，Relay 和 Provider 看到的形态与真实流量一致。
- 探针 channel 与普通 Consumer channel 同构：由多个轮换的探针 Consumer 身份开设，额度、有效期和普通 channel 在同一分布内，不使用可识别的赞助 channel。
- 探针内容从“真实任务模板库”中采样（代码、问答、摘要等），不是固定算术题；发送时间服从泊松分布。
- 探针可以由任意 Relay 发出，也可以由任意 Consumer 客户端随机发出（Consumer 侧抽查），不依赖某一个 Relay。

### B.2 探针类别与判定强度

| 类别 | 检测对象 | 判定 | 去向 |
| --- | --- | --- | --- |
| P1 交付 | 已签收据却无内容、内容与请求无关、截断 | 客观 | 直接开争议 |
| P2 用量虚报 | 收据 `input_tokens`/`output_tokens` 超过厂商分词器计数加容差（OpenAI 用 tiktoken；Anthropic 用 token count API） | 客观、可复算 | 直接开争议 |
| P3 可验证任务 | 答案可机器验证的任务（精确计算、代码执行结果、格式约束） | 客观，但以同一模型的基线通过率为准 | 连续失败达阈值后开争议 |
| P4 模型身份指纹 | 模型特定行为组合（知识截止、分词敏感任务、拒答风格、自我标识），多样本统计 | 统计性 | 只扣信誉（进入 C），不单独罚没 |

原则：**客观可复算的证据才进入罚没争议；统计性证据只影响信誉**，避免误罚。

### B.3 探针失败 → 链上争议

新增 `relay_dispute_v10`（争议发起器），流程：

1. 从本地事件库挑出 P1、P2 客观失败或 P3 达到阈值的案例。
2. 组装证据文档：揭示的明文请求和响应、收据、分词器复算结果、判定依据。
3. 计算 `settlement_key` 和 `evidence_hash`，在争议窗口内调用 `openDispute` 并缴纳 `reporter_bond`，再提交证据。
4. 已有的事件接入、陪审运行时、执行 outbox 接管后续：抽取陪审员 → 裁决 → 退款、罚没、赏金。

约束：reporter bond 在争议被驳回时没收，这会约束探针方不滥开争议；每日预算与争议上限按运营者配置，并持久化防重复开启。

### B.4 陪审策略 v2

`provider-jury-policy` 升级为 v2，在“确认欺诈”条件中明确列出：未交付、内容与请求无关、**用量虚报超出容差**、**可复算的模型替换证据**；并要求陪审员引用具体证据字段。

策略哈希固定在部署清单的 `jury_decision_policy_hash` 中，所以升级需要随 C 的重新部署一起进行。

### B.5 近期可立即做的部分

在 A 完成前，可以先用现有代码在 V10 上开启 P1/P3 探针，把观测数据接入信誉统计。此时探针可被区分，只作参考，不开争议。

## C. 去中心化信誉与陪审（ProviderJuryRegistryV2，需重新部署）

### C.1 信誉：链上推导，无写入权限

删除 `reputation_authority` 和 `setProvider` 的授权写入。每个 Provider owner 的信誉分由合约根据以下链上事实计算：

| 来源 | 作用 | 抗操纵设计 |
| --- | --- | --- |
| 质押 | 基础权重，罚没直接降低 | 质押可被罚没，是作恶成本的主体 |
| 已结算收据 | 按结算费用加分，按 epoch 设上限 | **按不同对手方去重并设单对手方上限**，防止自买自卖刷分；手续费进入 treasury 的部分使刷分有真实成本 |
| 已确认争议 | 大幅扣分，并罚没 | 由陪审裁决触发，非人工写入 |
| 陪审表现 | 与多数一致加分；与多数相反、缺席扣分 | 抵制“随便投”或合谋少数派 |
| 在网时长 | 新身份需要最短在网时间才能进入陪审池 | 提高女巫攻击的时间成本 |
| 衰减 | 按时间指数衰减 | 旧的良好记录不能永久吃老本 |

B 的 P4 统计信号不直接写入合约（避免给某个 Relay 写入权），而是作为 Consumer 和 Relay 本地的路由偏好；只有经陪审确认的争议才改变链上信誉。

### C.2 准入：质押即加入

- `register(owner, voteSigner, peerId, capabilities)` 并质押不少于最低额度即可进入注册表，无需许可。
- Relay 准入从环境变量白名单改为读取链上注册表（有质押且未被罚没出局），Relay 仍可按本地策略临时隔离某个 Provider，但不能单方面把其移出网络。

### C.3 陪审抽取

- 候选：信誉 ≥ 阈值、在网时长 ≥ 最小值、质押 ≥ 最低额度。
- 排除：当事 Provider、与其同一 owner 的身份、承接该请求的 Relay 运营者。
- 权重：`min(质押, 上限) × 信誉系数`，单一 owner 权重设上限，防止“大户”常驻陪审。
- 陪审员事先不可知，揭示后不可替换。

### C.4 随机数

| 方案 | 优点 | 缺点 | 建议 |
| --- | --- | --- | --- |
| drand quicknet（BLS12-381，经 EIP-2537 预编译在链上验证） | 公共信标，不可被任何参与方操纵，任何人都能提交该轮签名 | 需要实现 BLS 验证合约和 gas 评估 | **首选** |
| commit-reveal | 不依赖外部 | 需要对拒不揭示者设惩罚，流程更长 | 备选 |
| `prevrandao` + 延迟 | 实现简单 | 出块者可施加 1 bit 影响 | 仅测试网过渡 |
| Chainlink VRF | 成熟 | 依赖外部服务与订阅资金 | 不采用 |

### C.5 陪审模型多样性

Claude 后端接入后，陪审抽取增加“后端多样性”约束：同一案件的 3 名陪审员尽量覆盖不同厂商，减少同源模型的同向误判。

### C.6 治理

- governance 改为 Safe 多签（建议 2/3 或 3/5）+ TimelockController（建议 48 小时）。
- 保留的治理动作只剩：treasury 地址、赞助容量上限。**不能**修改信誉、陪审结果或罚没参数。
- 路线：稳定运行后放弃治理权（设为零地址）。

### C.7 迁移

新合约（Settlement 如需钩子也要新版）→ 新部署清单与网络 ID → Provider 重新注册质押 → Consumer 重新开 channel → 旧网络停止接纳新请求，托管到期后正常结算退出。沿用本次上线的蓝绿切换、单一提交发布、门禁与演练流程。

## D. 实施顺序与里程碑

| 阶段 | 内容 | 依赖 | 是否改合约 |
| --- | --- | --- | --- |
| 0 | Claude 后端 | 无 | 否 |
| A | Relay 盲转发（兼容模式） | 无 | 否 |
| B1 | V10 探针开启（参考模式）+ 用量复算器 | 无 | 否 |
| B2 | sealed 探针 + 同构探针 channel + 争议发起器 | A | 否 |
| C | Registry V2、drand、多签时间锁、陪审策略 v2、重新部署迁移 | B2 | 是 |
| A′ | 强制 sealed（拒绝明文） | A 全量升级 | 否 |

## E. 需要确认的决定

1. 多签签名人地址与门槛（签名人私钥由各自保管，开发方不代管）。
2. 随机数采用 drand quicknet（建议），或 commit-reveal。
3. C 阶段重新部署后的网络 ID 命名与旧网络退出时间表。
4. 探针方身份：由各 Relay 运营者出资，还是设独立的探针预算账户；reporter bond 与每日预算上限。
