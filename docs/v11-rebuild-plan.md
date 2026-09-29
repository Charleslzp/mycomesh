# V11 重建与旧代码清理计划

决定（2026-09-30）：

- 仓库只保留 V11。另起一个精简的 Python 包 `mycomesh/`，只实现 V11；把与版本无关的模块移植进去。V11 在 Sepolia 上验证通过后，一次性删除所有旧代码。
- 删除托管式公共代理（API Key 账户、计费、Postgres、两个 indexer）。公共网关只保留非托管路由：校验用户签名后转发。
- 删除 `web/` 浏览器前端，V11 稳定后按 V11 重做。
- 合约可升级，单一管理员，无升级延迟。经济模型见 `docs/v10-trust-minimization-design.md` 和 V11 合约注释。

在切换之前，线上 V10 节点继续运行各自固定的 release 目录，不受 main 分支上删除代码的影响。

## 新包结构 `mycomesh/`

| 模块 | 职责 | 来源 |
| --- | --- | --- |
| `mycomesh/evm.py` | secp256k1、keccak、EIP-712、ABI 编码 | 从 `gateway/chain.py` 提取基础原语 |
| `mycomesh/rpc.py` | 多端点 RPC、传输失败重试、确认数读取 | 从 `gateway/chain.py` 移植 |
| `mycomesh/settlement.py` | V11 授权、派发、收据的签名与校验，结算 calldata，链上读取 | 新写 |
| `mycomesh/identity.py`、`mycomesh/secure_transport.py` | 节点身份与加密信封 | 原样移植 |
| `mycomesh/provider/` | Relay 多宿主传输、执行日志、收据签名；后端支持 Codex、OpenAI，之后加 Claude | 重写，复用后端模块 |
| `mycomesh/relay/` | Provider 会话与调度、请求准入、密文转发、批量结算、探针与作废 | 重写，复用调度和探针逻辑 |
| `mycomesh/bridge/` | 发现与租约 | 移植并去掉旧版本分支 |
| `mycomesh/jury/` | 陪审策略、执行、V11 注册表与 drand 抽签、事件接入 | 移植 `provider_jury_*` 并适配 V11 |
| `mycomesh/gateway.py` | 非托管公共路由 | 移植 `gateway/v10_gateway_route.py` |
| `packages/mycomesh-cli` | Consumer：一份押金、按请求签名、密封请求 | 精简为只支持 V11 |

## 里程碑

1. `mycomesh/evm.py`、`rpc.py`、`settlement.py`：在本地 anvil 上部署 V11 合约，用 Python 签名并完成真实结算，以此验证。
2. Provider 与 Relay 的 V11 最小闭环：密封请求 → 执行 → 收据 → 批量结算 → 释放，在本地 anvil 上端到端跑通。
3. Consumer（Node）V11：存入押金、注册 key、按请求签名、密封请求、核验收据。
4. 陪审：V11 注册表、drand 抽签提交、争议发起、投票执行；探针与作废。
5. 部署到 Sepolia：部署合约，从部署者账户给 Relay、Bridge 和陪审执行账户分配 gas，生成清单，滚动迁移节点。
6. 删除旧代码：`gateway/`、V2～V10 合约与测试、旧脚本、旧清单、旧文档、`web/`、托管代理相关的 compose 服务；同时更新 Dockerfile、compose、CI 与发布门禁。

每个里程碑都要做到：测试全绿、合并 main、有可复现的证据。
