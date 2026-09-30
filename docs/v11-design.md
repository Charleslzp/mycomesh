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
5. Relay 把三方签名的收据放入持久队列，批量 `settleBatch`。费用先进入托管，24 小时争议窗口后放款：Provider 85%、Relay 5%、国库 10%；Provider 那份里的 10% 进 7 天 holdback，其余可领取。
   放款用 `releaseBatch(keys)`，一笔交易最多 64 张收据：未到期、有争议或已放款的自动跳过；入账和发给注册合约、产出合约的通知按 (Provider, Consumer, Relay) 合并，每批只调用一次。Sepolia 分叉实测：单张放款 20–65 万 gas；32 张同方收据一批约 2.3 万 gas/张，20 张各不相同的线上收据一批约 10 万 gas/张。钩子的 gas 下限随批量增长，任何 gas 上限下交易要么回滚、要么记全奖励（测试会扫描一段 gas 上限来验证）。

### 多租户账户

一个 owner 的押金可以服务任意多个租户：每个租户一把付款 key，链上限定单次上限（`registerKey`）和总预算（`setKeyBudget`，0 表示不限，退款会恢复额度）。Relay 在派发前就检查"已用 + 在途 + 本次上限"是否超出预算，所以预算花完的请求不会让 Provider 白干。托管服务、团队、SaaS 都可以在协议之上做衍生产品，协议不对它们另外收费；租户的每笔交易和其他交易一样分给 Provider、Relay 和国库。托管方的押金就在合约里，任何人都能核对它的储备。

Consumer 自带租户管理（`mycomesh-consumer tenant add|list|budget|revoke` 和控制台的"租户"页），每个租户拿到一个 API key，可以从任何主机调用本机的 `/v1` 接口。

新 Provider 的未释放敞口上限 50 USDC，随干净成交额增长（最高 5000 USDC）。这替代了押金：Provider 最多能骗走的就是自己的敞口和 holdback。

## 网络定价（像比特币难度一样自动调整）

全网统一价：每个档位（例如 OpenAI 前沿模型、Anthropic Claude，以后的开源模型）有一套基础价（输入、输出每 1000 token 的价格和最低费用），实际价格 = 基础价 × 价格系数。结算合约强制每笔费用正好等于网络价（以 Consumer 签的上限封顶）；Provider 不能自己定价，只比质量和信誉。

| 比特币 | MycoMesh |
| --- | --- |
| 难度 | 价格系数（初始 1.0，限制在 0.1×–10×） |
| 目标出块时间 10 分钟 | 目标利用率（默认 70%） |
| 每 2016 个区块调整，最多 4 倍 | 每天调整，单日最多 ±10% |
| 实际出块速度 | 前一天的利用率 = 已结算工作量 ÷ 在线产能 |

- **需求**：当天链上结算的工作量，按基础价折算，不同模型可以直接相加。
- **供给**：当天在线的 Provider 的计入产能之和。结算即证明在线；Relay 保证每个 Provider 每天至少被探测一次。
- **产能是约束性的**：Provider 每天最多结算自己的计入产能，Relay 在派发前就检查，所以 Provider 不会白干。计入产能 = 声明值，但不超过最好一天成交的 2 倍；新 Provider 按档位的基础产能。
  - 少报产能只会减少自己的收入，涨价的好处由全网分享，所以没有动机少报。
  - 多报受已证明的成交量限制，刷假 Provider 压不低价格。
- **结果**：接近满负荷时价格上涨，吸引新的 Provider；产能闲置时价格下降，吸引新的 Consumer。

## 协议收入与 MYCO 代币

**稳定币分账**：每笔释放的费用 Provider 85% / Relay 5% / 国库 10%。国库是项目方的收入（结算参数里的 `penaltyRecipient`，同时收欺诈罚金的剩余部分），用来给 keeper 付赏金、在市场上回购 MYCO。项目方和任何人一样，只有在交易真实发生时才有收入。

**MYCO**：总量 10 亿，18 位小数，**没有预挖**，每一枚都由 `MycoEmissionV11` 按时间表铸造（`MycoToken` 的唯一铸币者，销毁不会腾出额度）。

| 比特币 | MycoMesh |
| --- | --- |
| 工作量证明：算力 | 费用证明：链上释放的真实费用 |
| 10 分钟一个区块 | 1 小时一个"块"（按时间聚合；不用 L1/L2 的区块，太快） |
| 每 21 万个区块减半 | 第一个周期 1 周，之后每个周期长度翻倍（2 周、4 周、8 周……），最长 4 年，此后每 4 年减半；每个周期产出速率减半 |
| 区块奖励给矿工 | 每小时的产出按比例分给四种角色 |

周期长度翻倍、速率减半，所以前 8 个周期（1 周到 128 周，共约 4.9 年）每个周期都产出约 1.04 亿，合计约 8.3 亿；第一个月约 2.4 亿。之后每 4 年减半（约 8460 万、4230 万……），剩余约 1.7 亿持续产出，趋近 10 亿。

每小时产出的分配（按该小时内释放的费用计点）：

| 角色 | 份额 | 计点方式 | 何时可领 |
| --- | --- | --- | --- |
| Consumer | 80% | 该小时付出的费用：花得多、分得多 | 该小时结束后 |
| Provider | 10% | 该小时服务的费用 × 成功率（释放数 ÷ (释放数 + 确认欺诈数)），差额留在时间表里 | 该小时结束 48 小时后（争议窗口已过） |
| Relay | 7% | 该小时派发的费用 | 该小时结束后 |
| Bridge（keeper） | 3% | 该小时调用的 release 费用和陪审抽签次数 | 该小时结束后；另外每次调用从国库赏金池拿稳定币赏金 |

- **冷启动**：每小时的费用达到 `minSpendPerBlock`（测试网 0.1 tUSDC）才发放全额；不足时按比例发放，其余滚入下一个有交易的小时。没有交易的小时整体顺延。所以刷量只能分到与自己真实付出的费用相称的份额，而付出的费用有 10% 进了国库、85% 给了 Provider。
- **领取**：`claim(blocks, role)` 按块领取，谁都可以先调用 `poke()` 结算上一个块。
  - `mycomesh-consumer rewards [claim]` 和控制台"钱包"页领取 Consumer 奖励。
  - `mycomesh-provider earnings/claim` 与仪表盘同时显示、领取 Provider 的 MYCO 和稳定币。
  - `python -m mycomesh rewards show|claim` 适用于任意角色；keeper 每 6 小时自动领取自己的 MYCO 和赏金。
- **钩子不能被跳过**：奖励记账是 try/catch 通知，永远不会阻塞付款；但结算和注册合约要求调用时留足 gas，否则直接回滚，避免 `eth_estimateGas` 找到"刚好付款、却把奖励钩子饿死"的 gas 上限。

## 探针

Relay 先用 `commitProbeKeys` 提交一批新探针 key 的 Merkle 根，再用这些 key 给自己的 Provider 发普通的密封请求。探针题目有六类，都能客观判分：四位数乘法、多个数求和、数字母、字符串反转、单词排序、推算星期几。题目外面套上随机的上下文、系统提示、多轮对话和端点，结算前与真实流量没有区别。这些基础题检查 Provider 是否在认真作答；偷换模型要靠下面的能力探针来抓。

- 答对或答错：都用 `voidProbe` 作废，探针 key 退款、Provider 不收钱，探针成本由 Provider 承担。每个 Relay 对每个 Provider 每天最多 10 次免费作废。答错计入 Relay 本地的探针得分，最近 10 次里失败达到 40% 时，Relay 停止向它派单。
- 空答或完全不相关：Relay 以自证证据发起链上争议，并立即停止派单。

探针结论公开且可以复核：Relay 把题目参数、Provider 签名的收据和双方明文作为证据发布，并在 `ProbeLedgerV11` 上记录结论。只有作废该探针的 Relay 能记录，而且只能记一次。任何人都能重新判分；Relay 无法伪造诚实 Provider 答错，因为伪造不了 Provider 对错误答案的签名。

### 能力探针：抓"偷换便宜模型"

同一档位全网同价，偷换成便宜模型就是纯利润。上面的基础探针只能抓"不答题"，现在任何小模型都能通过。能力探针是另外六类需要多步推理、答案唯一可验的题：循环迭代求值、中国剩余定理、9 位 × 8 位乘法、12 个城镇的最短路、一段文字里数字母、几万天之后是星期几。题目由参数重建，Python 和 Node 判分逐字一致（共享测试向量）。

- 判分看模型最终给出的答案：最后一个 `\boxed{}`，否则最后一行给出数值的那行，最多 3 个数（罗列候选不算回答）。能力题答错只降低通过率，**永远不发起争议**。
- 每个 Relay 70% 的探针是能力题，给足 16k–32k 输出 token，推理模型不会被截断。
- 判定用统计量：最近 100 道能力题的通过率，其 99% 单侧置信上界（Wilson）低于档位下限时，Relay 停止向它派单。档位 1 下限 85%，档位 2（Claude）还没有校准，暂不启用。
- 链上 `ProbeLedgerV11` 用独立的结论代码记录能力题（3 通过 / 4 答错）。Consumer 统计每个 Provider 的能力通过率，失败只在本机重新判分后才计入；达到同样的判定就标为"疑似降级"，排序放到最后，控制台"网络"页显示。

校准（`scripts/calibrate_capability.py`，同一批题，结果在 `docs/release-evidence/capability-calibration.json`）：

| 模型 | 通过率 |
| --- | --- |
| gpt-5.5（Codex 默认推理强度） | 94–100% |
| gpt-5.5（低推理强度） | 92–98% |
| qwen3:8b（本地 8B 推理模型） | QWEN3_RESULT |
| llama3.2:3b | 4–6% |

按下限 85%、窗口 100 道：诚实的 gpt-5.5（按 92% 算）每次判定被误判的概率约 10⁻⁶；llama 级别的替身十几道题内必被抓；qwen3:8b 这种小型推理模型差距较小，100 道题时被抓的概率约 90%。以每个 Relay 每天约 7 道能力题计，大约两周。

Consumer 选择 Provider 时，先看链上能证明的：近期是否被确认欺诈、是否疑似降级、经本机重新判分的探针失败率、累计计入的干净成交，最后才看价格。

## 争议与陪审

- 只有结算的 owner 能在窗口内 `openDispute(key, evidenceHash)`，同时缴 1 USDC 举报保证金。证据自证：公开请求和响应明文，必须哈希到 Provider 签过的 `request_hash` / `response_hash`。
- 注册表在开案时固定候选快照（排除当事各方），用开案 60 秒后的 drand quicknet 轮次抽 5 人，按各自计入的成交额加权抽取（每个 Provider 权重上限 100 USDC）。drand 签名在合约里用 EIP-2537 预编译验证（RFC 9380 hash-to-curve），任何人可以 `finalizeJury`。
- 每个陪审 Provider 自己回链上核对证据哈希、自己是否被抽中，再用自己的模型按固定策略判断，签同一个 decision hash。3 票一致即可 `voteDisputeBySig`。
- 确认欺诈：退款给 Consumer，从 holdback 罚没，50% 奖励举报人，退还保证金，Provider 信誉纪元清零并冷却 30 天。驳回：保证金没收。陪审沉默到超时：已抽出陪审则放款，未能组成陪审则退款。

陪审资格：计入的干净成交额 ≥ 1 USDC、来自至少 5 个不同对手方、注册满 7 天、30 天欺诈冷却；每个对手方最多计入 10 USDC。女巫攻击者要控制陪审团，必须在很多独立对手方上累计超过所有诚实 Provider 的真实成交额，并为此支付每笔 5% 的 Relay 分成和锁定的 holdback；注册再多空账户没有用。候选不足时陪审组不成，争议超时后全额退款给 Consumer。

## 升级与管理

合约是 UUPS 代理，单一管理员，无升级延迟、无多签。管理员可以 `setParams` / `setEligibility` / `setJury` / 升级实现。这是测试网阶段的有意取舍。

结算合约分成两个实现、共用一个代理：`MycoSettlementV11`（资金、结算、放款、探针）和 `MycoSettlementDisputesV11`（争议、陪审投票、超时），前者对自己没有的函数用 delegatecall 转给后者。两者继承同一个 `MycoSettlementBaseV11`，存储布局与拆分前逐槽一致，代理的 ABI 不变（只增加了 `releaseBatch`）。拆分后主合约 20.3 KB、争议模块 14.3 KB，离 24 KB 上限都有余量。

管理员可以随时用 `setUpgradeSunset(时间)` 在链上承诺升级截止时间，这个时间只能提前、不能推后；到期后代码永久冻结。这样早期可升级、但信任有期限而且公开可查。

退出路径是单向的：先对每个代理调用 `renounceUpgrades()` 永久冻结代码，再调用 `renounceAdmin()` 删除最后一把特权钥匙。之后没有人能改规则或动用托管资金。

## 运营

- 测试网水龙头（relay1 的 `/v11/faucet`）：给新地址 0.02 ETH 和 100 tUSDC，每地址每天一次、每个 IP 每天 5 次。Consumer 的 `setup` 在余额不足时自动调用。
- Keeper（bridge1、bridge2）：跟随链上日志做放款（每批最多 64 张）、finalizeJury、超时裁决的兜底调用。
- 监控（bridge1 的 `mycomesh monitor`）：检查每个 Relay 的健康、签名和结算工作线程，以及 keeper、水龙头、Relay owner 的 gas 余额；状态变化时写日志，配置 `MYCOMESH_ALERT_WEBHOOK` 后推送到 Slack、飞书或任意 JSON webhook。
- 收益：`mycomesh-provider earnings` 查看托管中、holdback、可领取、MYCO 和陪审信誉；`claim` 把到期的 holdback、可领取余额和到期的 MYCO 一次打到 owner。
- Keeper 赏金池：部署时国库注入 500 tUSDC，每次 release 或 finalizeJury 付 0.01 tUSDC（Relay 释放自己的收据不拿赏金）；管理员可用 `setBountyPerCall` 调整，任何人都可以 `fundBounties` 补充。

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
| `contracts/` | `MycoSettlementV11` + `MycoSettlementDisputesV11`（共用 `MycoSettlementBaseV11`）、`ProviderJuryRegistryV11`、`RelayDirectoryV11`、`ProbeLedgerV11`、`MycoEmissionV11`、`MycoToken`、`DrandQuicknet`、`MycoUpgradeable`、`TestUSDC` |
| `mycomesh/` | Relay、Provider（Codex / OpenAI 兼容 / Anthropic 后端）、keeper、陪审、探针与能力探针（`capability.py`）、MYCO 奖励 |
| `packages/mycomesh-cli` | Node Consumer：押金、按请求签名、本地 OpenAI 兼容端点、争议 |
| `scripts/deploy_v11.py`、`scripts/rollout_v11.py` | Sepolia 部署（可先对分叉链演练）与节点滚动 |
| `scripts/verify_l2.py` | 在 L2 测试网上跑完整生命周期并记录费用 |
| `scripts/calibrate_capability.py` | 用同一批能力题测各个模型的通过率，确定档位下限 |
