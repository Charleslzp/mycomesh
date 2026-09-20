# V9 部署执行状态

更新日期：2026-09-18，Asia/Shanghai。以下记录实际部署、真网验收和仍未覆盖的范围。

## 当前结论

**V9 受控测试网已完成部署与本轮验收：3 台 Bridge、2 台 Relay、3 台 Provider 在线；三台真实推理、链上结算与释放、收益到账、合成争议退款罚没及测试清理均已完成。** 公开用户试用和真实独立用户裁决尚未开放。

本次目标是先用现有 3 个 Provider 完成真实网络调度和结算联调。`network_id=mycomesh-v9-controlled-test`，节点必须显式设置 `MYCOMESH_ALLOW_CONTROLLED_V9_TEST=1`。委员会为**同一运营者控制的 3 个测试钱包、2/3 阈值**，清单如实声明 `committee_mode=controlled_test`、`independence_attested=false`；不能描述为三位独立用户或独立裁决委员会。

10443 HTTPS 入口采用 IP 白名单，允许部署时记录的运营端来源、节点地址和 loopback；Provider 接入还须通过公钥白名单及协议验证。本次使用专用测试客户端，不将普通 Consumer 接入受控网络。测试稳定币与零代币奖励政策不变。

## 已部署合约

| 项目 | 实际值 |
| --- | --- |
| 网络 / chain ID | Sepolia / `11155111` |
| V9 合约 | `0x8ed70585cb60082e6f8e64f5190a3d8014e42367` |
| 部署交易 | `0x986cd0969a9b4d96762d04d221c6859f931e3b1e29945352d3c3100bb35f15f5` |
| 部署区块 | `11728132` |
| 专用 deployer | `0xae4a4c86c2b6c340c8198d0958b223f5d0c8caa2` |
| 核验状态 | `confirmed`，实际 runtime 和构造政策已核对 |
| runtime code hash | `0x004fdd15fe7dc8bb0b41dd133ae1b80fd9009cba288d808f879ac15f019511ed` |
| 奖励代币 | 零地址；四项 `token_*` 奖励参数均为 0 |

实际部署清单和核验记录分别为 `.codex-run/mesh/v9-controlled-test-20260918/deployment.json`、`deployment-verification.json`。该清单使用专用测试账户；旧的 `docs/v9-deployment-policy.draft.json` 不是本次实际部署依据。不能把草案缺少正式独立用户名单的状态继续写成“V9 未部署”。稳定币保证金、罚没和赏金机制仍存在，零代币奖励不等于没有稳定币激励。

专用 Provider owner 为 `0x94515c8903cca8e5aedb1437e947db39970792cc`。三个 Provider 继续使用各自既有服务签名身份，但在新合约上须由这个测试 owner 重新授权，并共用其 stake。链上初始化已读回：共享 stake 5,000,000 单位（5 测试稳定币），Consumer 余额 1,000,000 单位，消费 key active、单笔上限 100,000。初始化区块 `11728229`；详见 `status-provider.json`。后续余额随真实及合成测试变化。

## 当前候选与隔离节点

- Bridge 和 Provider 的 archive SHA256：`d1dd8d57d88ecae5f220383b85eb1da04547281df02cfaaa198b76a6751e5a0c`，目录 `/opt/mycomesh-mesh/releases/v9-candidate-d1dd8d57d88ecae5`。
- 两台 Relay 的最终 archive SHA256：`5acc9cc4b8d610fa9d75ef53a7e65046b33303f9a0780f9b8ae21c18e9c76989`，目录 `/opt/mycomesh-mesh/releases/v9-candidate-5acc9cc4b8d610fa`。此包增加可配置结算 gas 下限，旧冻结目录未修改。
- 初次分发核验：8 台每台 252 个文件、184 个 Python 文件解析，核心模块导入成功。最终逐节点候选、bundle、配置一致性见 `final-runtime-check.json`，不能再用同一个 archive hash 描述全部角色。
- 独立运行根：`/opt/mycomesh-v9-controlled-test-20260918`，其中 `config/`、`data/`、replay/outbox/incident/probe 数据与 V8 分开。
- 新 systemd 服务：`mycomesh-v9-test-bridge`、`mycomesh-v9-test-relay`、`mycomesh-v9-test-edge`；新 Provider 容器：`mycomesh-v9-test-provider`。

| 角色 | 节点 | 本次状态 |
| --- | --- | --- |
| Bridge | bridge1 / bridge2 / bridge3 | 3/3 provision；3/3 激活，服务 active，专用 CA 验证的 TLS 10443 健康检查通过 |
| Relay | relay1 / relay3 | 2/2 已激活，两台均实际提交过 V9 账单；RPC 备用端点和重启后的 gas 下限已生效 |
| Provider | provider2 / provider3 / provider4 | 3/3 已激活；各一笔真实请求成功，签名及付款绑定验证通过 |

端口为 Bridge `10443 → 127.0.0.1:11080`、Relay HTTP `10443 → 127.0.0.1:11090`、Relay Provider TLS `10991 → 127.0.0.1:11991`。沿用已验证的 CA/节点证书，原 nginx、原服务和公共 V8 配置保留。

Provider provision 后只读复核：旧 Provider 和 sidecar 均 healthy、容器 ID 未变、新容器不存在；身份副本与原文件一致，独立 data 为 `0700`，身份文件为 `0600`、UID 10001。未复制旧 operator-config，避免覆盖新网络配置。激活时只暂停旧 Provider role，复用仍运行的旧 sidecar 和已有认证，不并发复用同一 Codex 登录。

证据均位于 `.codex-run/mesh/v9-controlled-test-20260918/`：`staging.log`、`provision-bridge*.log`、`provision-relay*.log`、`provider-provision-results.json`、`activate-bridge*.log`。Relay2 不在本次 8 台范围内。

三台推理容量已全部保留在 V9，原 V8 Provider worker 停止；V8 入口、原 sidecar、登录与旧账本保留。这三台当前不向 V8 提供推理，不能把 V8 HTTP 健康描述为原推理容量仍在。

## 本次和历史验证的区别

本次受控模式的真实 localhost EVM 套件为 **10 项通过、0 跳过，8.495 秒**，包括显式 opt-in 的受控委员会部署及诚实清单检查。证据：本次目录的 `local-chain.log`。这是本地模拟链测试，不是真网推理或独立用户裁决验收。

最终 Relay gas 配置改动的定向回归 **127 项通过**，包括无配置时默认兼容、无效输入拒绝、边界与重新创建 Relay 后保留 750000 配置下限。实际部署后两台健康端点均报告 `gas_per_receipt=750000`；这是配置下限持久生效，不代表运行时学习到的所有估算都会落盘。证据 `relay-gas-floor-release-result.json`。

下列数字属于此前发布准备或 agent 开发轮次，**并非对当前受控候选重新执行的全量结果，不能相加或描述为本次全量回归**：

| 先前验证 | 当时记录 |
| --- | --- |
| 全量 Python | 1565 项，0 失败、0 错误、10 项条件跳过，78.789 秒 |
| 全量 Forge | 109 通过，0 失败 |
| Native Consumer 顶层测试 | 212 通过，0 失败、0 跳过 |
| 先前 localhost EVM | 初期 7 项生命周期 + 1 项部署，8 项通过；后续用户裁决 agent 轮次为 9 项通过、0 跳过 |
| 候选包构建器自检 | 20 项通过 |
| 远端分发流程本地自检 | 15 项通过 |
| Provider 安装回归 | 13 项通过，已包含在当时全量 Python 中 |
| 用户裁决 agent 定向测试 | 88 项通过，其中新增 agent/模型适配器测试 44 项；模型使用模拟后端 |
| diff 格式检查 | 当时通过 |

当时 Python 的 10 项跳过包含 8 项本地链集成及 2 项环境条件检查；后两项涉及固定 Codex CLI 版本、Python 3.10 缺少 tomllib，不能声称已通过。先前日志位于 `.codex-run/mesh/v9-release-20260918/`，用户裁决轮次为 `user-jury-local-chain.log`、`user-jury-tests.log`。

先前候选 archive `f11c60394eb62281e746ceaf360e275095a0b3fb1e5e1c6286796fcfed95dcc6` 及 snapshot `3744ae7f105e4c5693e209b6d382939ab8bc33d11fcd9b96916f3a256c2eab8d` 是历史分发，已由本次候选取代其“当前候选”地位。此前 244 个源码文件、246 个分发文件、178 个 Python 文件的统计也仅适用于旧包。

强制本地链 CI 使用 Node 22.22.2、Foundry 1.4.4、Solc 0.8.28 / Prague、锁定 Hardhat 3.0.6；用例数已随测试增加，skip 不算通过。**GitHub runner 尚未实际执行本次修改**，本地通过不能描述为远端 CI 已通过。

## 完成公开试用仍需满足的范围

1. 本轮已覆盖三台真实推理、两个 Relay、签名与链上托管；其余实际结果见末尾。重复请求、驳回、超时和提现等已有 localhost EVM 覆盖，不能把它们当作本轮 Sepolia 全部重测。
2. 共享 stake 的跨 Relay 并发和持续负载仍需专项验收；本轮按台发送三个独立请求。
3. 落实释放/超时的持续执行责任；现有工具有计划与持久执行入口，尚不能宣称自动扫描调度服务已上线。
4. 本次每个 Relay 当前 gas 储备仅能覆盖有限次数请求，开放持续流量前需配置日常 gas 补充。

用户裁决 agent 的既有能力见 [用户裁决 agent](user-jury-agent.md)。信誉目前来自显式信任的签名快照，未实现自动信誉累积、动态吸纳或链上信誉选举。本次同一运营者测试不能证明真实独立用户治理成立。正式开放普通用户前，仍需实际独立参与者、适用的治理配置、业务闭环和持续运行验收；本次清单不能冒充正式独立委员会清单。

## 真网运行结果

三台返回均为 `V9-OK`，无 POST 重发，响应内容及签名独立验证通过：

| Provider | Relay | 耗时 | 结算交易 | 测试稳定币最小单位 |
| --- | --- | --- | --- | --- |
| Provider2 | Relay1 | 8.237 秒 | `0x66aec269c86b0ae797f910d8cd1eced85df018ffca09fe9c2d2b4be6ccc11a73` | 2196 |
| Provider3 | Relay1 | 7.743 秒 | `0x24c1578dfe98f5a861336e8428d4dc77624e0c8a89c9606e1b808af70ac3a843` | 2152 |
| Provider4 | Relay3 | 7.264 秒 | `0x6e4bf95d9acbf4c6fb5deaff712aeae71744c12dfe58a2184b4869809cb3dc55` | 2152 |

原始签名证据在 `inference/provider{2,3,4}-first/`。Provider3 首次启动因原 RPC 列表在该机不可用而自动回退；按 chain/genesis、V9 代码和质押核验后，仅该节点改用可用的 Tenderly，第二次启动成功；没有重复发推理请求。配置差异、备份及 hash 在 `provider3-rpc-override/`。

8 节点的持久化设置已实做：10 个 V9 systemd unit enabled+active，3 个 V9 Provider 容器 `unless-stopped`。3 个 Bridge 均发现 3 个 Provider。证据 `persistence-results.json`。3 个旧 V8 Provider worker 现已停止，原 sidecar/登录与旧账本保留；不将两套 worker 同时宣称为两份容量。本次将三台推理容量保留在 V9。

两台 Relay 的 RPC 列表为已从本机验证 chain/genesis/runtime 的 PublicNode + Tenderly；Provider3 独立使用 Tenderly。逐台重启后，Relay1 连接 Provider2/3，Relay3 连接 Provider4，3 个 Provider 的 Bridge lease 正常。两台均为 `settlement_ready=true`、`inference_ready=true`，gas 配置下限 750000；最终快照下各可额外接纳 1 笔结算，请求容量随 gas 价格和余额变化。配置、备份、候选差异及审计在 `relay{1,3}-rpc-fallback/`、`relay{1,3}-gas-floor/`。不要执行旧的全量 `prepare` 覆盖这些节点差异。

收尾时一次 Relay1 健康读取出现 `URLError`，同次部署清单和 Provider 名单仍可读取；随后两次严格 TLS 检查分别在 1.226 秒、0.951 秒内返回 HTTP 200，均为两台 Provider、推理及结算就绪，未重启服务。原失败和恢复证据保留在 `network-check-1789706951.json`、`relay1-health-recheck-1789706997.json`；只支持瞬时读取失败判断，未确定具体网络原因。

三笔真实账单已到期释放，释放交易均完成至少 6 个区块确认。随后 owner 实际领取 **5717 个最小单位（0.005717 测试稳定币）**，钱包余额从 0 增至 5717；本轮 Provider 与 Relay 收款地址相同，因此这是两项服务分成合计，不能写成纯 Provider 分成。收益交易 `0x52c7d7a695c25228c7e658dd306764f354994f9cd12e97ea6430931e457f6847`，6 确认，证据 `provider-revenue-claim.json`。该领取发生在合成测试账单释放之前，金额不混入合成收益。

两个 Relay 的无付款授权请求均返回 HTTP 402，无签名付款回执、无新增 outbox 账单，证据 `payment-gate-check.json`。这两次请求没有执行模型推理。

### 合成争议的实际结果

使用专用合成 signer `0x14dd74ff293dc18121d18365f0900f773113a708` 构造用量矛盾证据。这不是三台真实 Provider 的作弊，也未调用用户个人 Codex 代替其决策；两把测试裁决钱包按既定测试案例签名，只验证合约机制。

首个合成账单 V1 已托管，但举报阶段遇到 RPC/测试 gas 不足，未广播举报并错过 300 秒窗口。它没有进入争议；后续按到期未举报账单正常释放，记录完整保留，不能算成“争议超时处理通过”。重测 V2 使用新请求、同一专用合成 signer，并在开始争议窗口前核验 gas 预算。

V2 在 Sepolia 的实际结果：

- 第一票后仍为 `disputed`，Consumer 余额、stake 均不变，罚没与赏金均为 0。
- 第二票达到 2/3 后变为 `confirmed`，Consumer 余额从 989500 回升至 991500（退还全部 2000 费用），共享 stake 从 5000000 减至 4998000（罚没 2000）。
- 举报人稳定币赏金 400，代币赏金 0。第二票交易 `0xdb16145d5ac376e98060e44a8d91ecdabe0c8e98517f3c67fa39513218b2fc5f`；状态及前后余额证据在 `synthetic-dispute-v2/vote{1,2}-{before,after}.json`。

举报保证金与赏金已实际领取到钱包：从 90000 增至 **100400**，净增加 **10400**（保证金 10000 + 稳定币赏金 400），代币赏金 0。领取交易 `0x3d03dd0e486df49ef284f8a332edb754fc7ddc169f33f218ddd246bc7ebcbd31` 完成 6 个区块确认；证据 `reporter-wallet-payout.json`。领取前的一次 RPC 只读失败发生在广播前；恢复后沿用原 intent 和交易记录，没有重复领取。

本轮的投票、释放及收益领取由显式操作工具完成，不是已上线的无人值守裁决/清算服务。

### 最终清理与核账

合成 signer 授权已撤销，交易 `0x9a00aa496bf4ba99df36295b6fe81804bd9bff679e0f56b6a62b9aec4fab10bb` 完成至少 6 个区块确认，并读回授权为 false。首次撤销后的只读核账遇到 RPC 连接失败；操作脚本只对允许的读取增加备用 RPC 和有界重试，交易发送路径及原交易记录保持不变，恢复时确认原交易，没有再次发送撤销。

最终固定区块 **11728485**：合约测试稳定币资产与 `stableLiabilities` 均为 **5993883** 最小单位；共享 stake **4998000**、locked **0**、Consumer 可用余额 **991500**。V1 为已释放、V2 为争议确认；没有遗留测试锁仓。证据 `cleanup-revoke-synthetic.json`、`cleanup-audit.json`。V1 释放产生的合成分成仍与三笔真实收益记录区分，不计入上文 5717 的到账金额。

最终全网快照为 `network-check-1789707030.json`，8 节点部署/持久化核验为 `final-runtime-check.json`。可分享的脱敏验收汇总为 `acceptance-summary.json`，记录本轮受控检查结果及证据 hash；它是已保存证据的汇总，不是未来健康保证。公开试用、独立用户治理、持续负载与自动执行责任仍以本文“完成公开试用仍需满足的范围”为准。

## 后续模型配置变更（同日）

为用户指定的 Sol Consumer 调用，2026-09-18 05:29 UTC 仅在 Provider2 主机将 Provider 与实际侧车的模型名单扩展为 `gpt-5.5,gpt-5.6-sol`，默认及内部模型仍为 5.5。Provider2 与侧车容器已重建，原镜像、HostConfig、命令、挂载、登录/密钥内容、账本和 2000 输出预算经核对保留；原容器已停止并留作回退。其他节点源码和合约未修改。

Provider2 新 bundle 为 `08b4c4d9911567f86df6d33275bfca4e24ca153da260af5e3f16fb9f347554bb`；模型改动审计在本次目录 `provider2-sol/audit.json`。上文 `final-runtime-check.json`、`acceptance-summary.json` 保留初次验收时的容器 ID 与运行状态，不能将“初次 sidecar ID 未变”套用到这次重建后。模型启用后的 Relay1 正确公布 Sol，随后单次 Consumer 请求成功；具体模型调用与费用另记于 [Consumer Sol 运行记录](consumer-candy-sol-run-2026-09-18.md)。
