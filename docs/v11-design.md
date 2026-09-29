# MycoMesh V11 设计

状态：已实现，部署在 Sepolia（`deployments/sepolia-myco-v11.json`）。网络类别 `controlled_test`。

## 角色

| 角色 | 需要什么 | 做什么 |
| --- | --- | --- |
| Consumer | 一份托管在结算合约里的押金，一把本地 payment key | 每个请求签一份 EIP-712 `PaymentAuthorization`，把请求密封给选中的 Provider |
| Relay | owner 账户（付 gas、持探针押金与举报保证金）和 signer | 准入、转发密文、签 `RelayDispatch`、批量结算、释放、探针、收集陪审票 |
| Provider | owner 账户（收款、付注册 gas）和 signer，**不需要押金** | 解密执行、签收据；被抽中时当陪审 |
| Bridge（keeper） | 一个付 gas 的账户 | 跟随链上日志做任何人都能做的兜底调用：release、finalizeJury、超时裁决 |

没有白名单：Provider 只要在链上把 signer 绑定到 owner 就能接入任意 Relay；陪审资格完全由链上结算结果推导。Relay 的 `/v11/requests` 就是非托管的公共路由：它只校验 Consumer 的签名授权后转发，不托管任何人的资金或 API key。

## 请求与结算

1. Consumer 从 Relay 的 `/providers` 取 Provider 描述，校验 Provider signer 对传输密钥的 EIP-712 `ProviderTransport` 证明。
2. 请求明文是规范 JSON，`request_hash = sha256(明文)`，其中包含 Consumer 的回复密钥 id。明文用 X25519-HKDF-ChaCha20Poly1305 密封给 Provider，Relay 只看到价格、路由字段和密文（Relay 盲转发）。
3. Relay 检查 key 授权、押金减去在途额度、Provider 敞口上限，签派发后转给 Provider。
4. Provider 校验授权与派发签名，按 settlement key 只执行一次（崩溃后不重放），把响应密封给 Consumer，签 `UsageReceipt`（response_hash、token、实际费用 ≤ max_fee）。
5. Relay 把三方签名的收据放入持久队列，批量 `settleBatch`。费用先进入托管，24 小时争议窗口后 `release`：Relay 拿 5%，10% 进 Provider 的 7 天 holdback，其余可领取。

新 Provider 的未释放敞口上限 50 USDC，随干净成交额增长（最高 5000 USDC）。这替代了押金：Provider 最多能骗走的就是自己的敞口和 holdback。

## 探针

Relay 先用 `commitProbeKeys` 提交一批新探针 key 的 Merkle 根，再用这些 key 给自己的 Provider 发普通的密封请求（已知答案的算术题，随机端点和提示词）。结算前它和真实流量没有区别。

- 通过：`voidProbe` 作废，探针 key 退款、Provider 不收钱——探针成本由 Provider 承担。每个 Relay 对每个 Provider 每天最多 10 次免费作废。
- 失败：Relay 以证据发起争议，并在本地暂停路由到该 Provider。

## 争议与陪审

- 只有结算的 owner 能在窗口内 `openDispute(key, evidenceHash)`，同时缴 1 USDC 举报保证金。证据自证：公开请求和响应明文，必须哈希到 Provider 签过的 `request_hash` / `response_hash`。
- 注册表在开案时固定候选快照（排除当事各方），用开案 60 秒后的 drand quicknet 轮次抽 3 人。drand 签名在合约里用 EIP-2537 预编译验证（RFC 9380 hash-to-curve），任何人可以 `finalizeJury`。
- 每个陪审 Provider 自己回链上核对证据哈希、自己是否被抽中，再用自己的模型按固定策略判断，签同一个 decision hash。2 票一致即可 `voteDisputeBySig`。
- 确认欺诈：退款给 Consumer，从 holdback 罚没，50% 奖励举报人，退还保证金，Provider 信誉纪元清零并冷却 30 天。驳回：保证金没收。陪审沉默到超时：已抽出陪审则放款，未能组成陪审则退款。

陪审资格：干净成交额 ≥ 0.1 USDC、至少 1 个对手方、30 天欺诈冷却；每个对手方最多计入 10 USDC，防止自刷。

## 升级与管理

合约是 UUPS 代理，单一管理员，无升级延迟、无多签。管理员可以 `setParams` / `setEligibility` / 升级实现。这是测试网阶段的有意取舍。

## 代码

| 路径 | 内容 |
| --- | --- |
| `contracts/` | `MycoSettlementV11`、`ProviderJuryRegistryV11`、`DrandQuicknet`、`MycoUpgradeable`、`TestUSDC` |
| `mycomesh/` | Relay、Provider（Codex / OpenAI 兼容 / Anthropic 后端）、keeper、陪审、探针 |
| `packages/mycomesh-cli` | Node Consumer：押金、按请求签名、本地 OpenAI 兼容端点、争议 |
| `scripts/deploy_v11.py`、`scripts/rollout_v11.py` | Sepolia 部署与节点滚动 |
