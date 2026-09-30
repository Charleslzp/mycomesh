# MycoMesh V11 设计

状态：已实现，部署在 Sepolia（`deployments/sepolia-myco-v11.json`）。网络类别 `controlled_test`。

## 角色

| 角色 | 需要什么 | 做什么 |
| --- | --- | --- |
| Consumer | 一份托管在结算合约里的押金，一把本地 payment key | 每个请求签一份 EIP-712 `PaymentAuthorization`，把请求密封给选中的 Provider |
| Relay | owner 账户（付 gas、持探针押金与举报保证金）和 signer | 准入、转发密文、签 `RelayDispatch`、批量结算、释放、探针、收集陪审票 |
| Provider | owner 账户（收款、付注册 gas）和 signer，**不需要押金** | 解密执行、签收据；被抽中时当陪审 |
| Bridge（keeper） | 一个付 gas 的账户 | 跟随链上日志做任何人都能做的兜底调用：release、finalizeJury、超时裁决 |

没有白名单：Provider 只要在链上把 signer 绑定到 owner 就能接入任意 Relay；陪审资格完全由链上结算结果推导。

Relay 不需要域名，也不需要证书机构：Relay 用自签证书，把证书的 SHA-256 指纹和地址一起写进链上目录（`https://IP:端口#sha256=指纹`），客户端完成 TLS 握手后先比对指纹再发送任何数据。官方 Relay 也按这种方式登记了指纹。`mycomesh-relay` 启动器让任何人几条命令就能运行独立 Relay（可选同时运行 keeper）。

Relay 的发现不依赖清单发布者：`RelayDirectoryV11` 是无管理员、不可升级的链上目录，任何 Relay owner 都能公布自己已绑定 signer 的 HTTPS 地址和 Provider 连接地址；signer 一旦撤销，条目自动失效。Consumer 和 Provider 把清单里的 Relay 当作引导，再从目录发现其余 Relay，并用 `/health` 或连接握手里的 signer 核对。Relay 的 `/v11/requests` 就是非托管的公共路由：它只校验 Consumer 的签名授权后转发，不托管任何人的资金或 API key。

## 请求与结算

1. Consumer 从 Relay 的 `/providers` 取 Provider 描述，校验 Provider signer 对传输密钥的 EIP-712 `ProviderTransport` 证明。
2. 请求明文是规范 JSON，`request_hash = sha256(明文)`，其中包含 Consumer 的回复密钥 id。明文用 X25519-HKDF-ChaCha20Poly1305 密封给 Provider，Relay 只看到价格、路由字段和密文（Relay 盲转发）。
3. Relay 检查 key 授权、押金减去在途额度、Provider 敞口上限，签派发后转给 Provider。
   流式请求（`Accept: application/x-ndjson`）里，Provider 把生成中的文本分批密封给 Consumer 的回复密钥，Relay 逐行转发密文；最终响应和收据到达后，Consumer 核对这些增量拼起来等于收据对应的响应文本。
4. Provider 校验授权与派发签名，按 settlement key 只执行一次（崩溃后不重放），把响应密封给 Consumer，签 `UsageReceipt`（response_hash、token、实际费用 ≤ max_fee）。
5. Relay 把三方签名的收据放入持久队列，批量 `settleBatch`。费用先进入托管，24 小时争议窗口后 `release`：Relay 拿 5%，10% 进 Provider 的 7 天 holdback，其余可领取。

### 多租户账户

一个 owner 的押金可以服务任意多个租户：每个租户一把付款 key，链上限定单次上限（`registerKey`）和总预算（`setKeyBudget`，0 表示不限，退款会恢复额度）。Relay 在派发前就检查"已用 + 在途 + 本次上限"是否超出预算，所以预算花完的请求不会让 Provider 白干。托管服务、团队、SaaS 都可以在协议之上做衍生产品，协议不收任何额外费用；租户的每笔交易照常付 Relay 分成和 Provider 费用。托管方的押金就在合约里，任何人都能核对它的储备。

Consumer 自带租户管理（`mycomesh-consumer tenant add|list|budget|revoke` 和控制台的"租户"页），每个租户拿到一个 API key，可以从任何主机调用本机的 `/v1` 接口。

新 Provider 的未释放敞口上限 50 USDC，随干净成交额增长（最高 5000 USDC）。这替代了押金：Provider 最多能骗走的就是自己的敞口和 holdback。

## 探针

Relay 先用 `commitProbeKeys` 提交一批新探针 key 的 Merkle 根，再用这些 key 给自己的 Provider 发普通的密封请求。探针题目有六类，都能客观判分：四位数乘法、多个数求和、数字母、字符串反转、单词排序、推算星期几。题目外面套上随机的上下文、系统提示、多轮对话和端点，结算前与真实流量没有区别。这些题对前沿模型很简单，对偷换的小模型不稳定，所以偷换模型会在统计上暴露。

- 答对或答错：都用 `voidProbe` 作废，探针 key 退款、Provider 不收钱，探针成本由 Provider 承担。每个 Relay 对每个 Provider 每天最多 10 次免费作废。答错计入 Relay 本地的探针得分，最近 10 次里失败达到 40% 时，Relay 停止向它派单。
- 空答或完全不相关：Relay 以自证证据发起链上争议，并立即停止派单。

探针结论公开且可以复核：Relay 把题目参数、Provider 签名的收据和双方明文作为证据发布，并在 `ProbeLedgerV11` 上记录结论。只有作废该探针的 Relay 能记录，而且只能记一次。任何人都能重新判分；Relay 无法伪造诚实 Provider 答错，因为伪造不了 Provider 对错误答案的签名。

Consumer 选择 Provider 时，先看链上能证明的：近期是否被确认欺诈、经本机重新判分的探针失败率、累计计入的干净成交，最后才看价格。

## 争议与陪审

- 只有结算的 owner 能在窗口内 `openDispute(key, evidenceHash)`，同时缴 1 USDC 举报保证金。证据自证：公开请求和响应明文，必须哈希到 Provider 签过的 `request_hash` / `response_hash`。
- 注册表在开案时固定候选快照（排除当事各方），用开案 60 秒后的 drand quicknet 轮次抽 5 人，按各自计入的成交额加权抽取（每个 Provider 权重上限 100 USDC）。drand 签名在合约里用 EIP-2537 预编译验证（RFC 9380 hash-to-curve），任何人可以 `finalizeJury`。
- 每个陪审 Provider 自己回链上核对证据哈希、自己是否被抽中，再用自己的模型按固定策略判断，签同一个 decision hash。3 票一致即可 `voteDisputeBySig`。
- 确认欺诈：退款给 Consumer，从 holdback 罚没，50% 奖励举报人，退还保证金，Provider 信誉纪元清零并冷却 30 天。驳回：保证金没收。陪审沉默到超时：已抽出陪审则放款，未能组成陪审则退款。

陪审资格：计入的干净成交额 ≥ 1 USDC、来自至少 5 个不同对手方、注册满 7 天、30 天欺诈冷却；每个对手方最多计入 10 USDC。女巫攻击者要控制陪审团，必须在很多独立对手方上累计超过所有诚实 Provider 的真实成交额，并为此支付每笔 5% 的 Relay 分成和锁定的 holdback；注册再多空账户没有用。候选不足时陪审组不成，争议超时后全额退款给 Consumer。

## 升级与管理

合约是 UUPS 代理，单一管理员，无升级延迟、无多签。管理员可以 `setParams` / `setEligibility` / `setJury` / 升级实现。这是测试网阶段的有意取舍。

管理员可以随时用 `setUpgradeSunset(时间)` 在链上承诺升级截止时间，这个时间只能提前、不能推后；到期后代码永久冻结。这样早期可升级、但信任有期限而且公开可查。

退出路径是单向的：先对每个代理调用 `renounceUpgrades()` 永久冻结代码，再调用 `renounceAdmin()` 删除最后一把特权钥匙。之后没有人能改规则或动用托管资金。

## 运营

- 测试网水龙头（relay1 的 `/v11/faucet`）：给新地址 0.02 ETH 和 100 tUSDC，每地址每天一次、每个 IP 每天 5 次。Consumer 的 `setup` 在余额不足时自动调用。
- Keeper（bridge1、bridge2）：跟随链上日志做 release、finalizeJury、超时裁决的兜底调用。
- 监控（bridge1 的 `mycomesh monitor`）：检查每个 Relay 的健康、签名和结算工作线程，以及 keeper、水龙头、Relay owner 的 gas 余额；状态变化时写日志，配置 `MYCOMESH_ALERT_WEBHOOK` 后推送到 Slack、飞书或任意 JSON webhook。
- 收益：`mycomesh-provider earnings` 查看托管中、holdback、可领取和陪审信誉；`claim` 把到期的 holdback 和可领取余额一次打到 owner。

## 本地控制台（不需要域名）

和比特币节点一样，Web 界面由用户自己的节点在本机提供，浏览器只访问 `127.0.0.1`；连接网络、核对 Relay 的 CA 和签名身份、解密与核对收据，全部由本机进程完成。所以 Relay 不需要域名，也不需要公共证书，公网上也没有任何托管的前端。

- Consumer：`npx mycomesh-consumer` 自动生成付款 key 并打开 `http://127.0.0.1:8110/`。欢迎卡片两步完成：创建本机加密钱包、一键领水并存入押金。之后可以对话（快速、均衡、深度三种模式）、查看钱包与记录、发起争议、查看网络与 Provider 信誉、管理租户。
- Provider：`npx mycomesh-provider` 直接打开 `http://127.0.0.1:8120/`，网页里完成全部设置：生成签名密钥、用页面显示的设备码登录 ChatGPT、创建加密收款钱包、注册上链（测试网自动领 gas）、启动。之后查看收益、敞口、陪审资格进度，领取收益。
- 本机接口只接受本机页面：Host 必须是 `127.0.0.1` / `localhost`（防 DNS rebinding），带 Origin 的请求必须来自本机端口（防其他网站借用户的押金发请求），写操作只接受 JSON。

## L2 验证

完整生命周期已在 Base Sepolia 上跑通（`docs/release-evidence/v11-l2-base-sepolia.json`）：部署、存款、10 张收据批量结算、窗口后释放、争议、用实时 drand 信标在链上抽陪审、2 票确认欺诈。每张收据的批量结算约 33.3 万 gas，在 Base Sepolia 上约 0.0000024 ETH；链上验证 drand 签名的 `finalizeJury` 约 45 万 gas。OP Sepolia 和 Arbitrum Sepolia 同样提供 EIP-2537 预编译，合约不需要任何修改即可迁移。

## 代码

| 路径 | 内容 |
| --- | --- |
| `contracts/` | `MycoSettlementV11`、`ProviderJuryRegistryV11`、`RelayDirectoryV11`、`DrandQuicknet`、`MycoUpgradeable`、`TestUSDC` |
| `mycomesh/` | Relay、Provider（Codex / OpenAI 兼容 / Anthropic 后端）、keeper、陪审、探针 |
| `packages/mycomesh-cli` | Node Consumer：押金、按请求签名、本地 OpenAI 兼容端点、争议 |
| `scripts/deploy_v11.py`、`scripts/rollout_v11.py` | Sepolia 部署（可先对分叉链演练）与节点滚动 |
| `scripts/verify_l2.py` | 在 L2 测试网上跑完整生命周期并记录费用 |
