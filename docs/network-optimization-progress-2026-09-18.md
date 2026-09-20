# 2026-09-18：Relay 充值与结算优化进度

后续部署、恢复修复与复验结果见 [2026-09-19 进度](network-optimization-progress-2026-09-19.md)。本文件保留此前各阶段证据。

本轮按“每个 Relay 转入 1 Sepolia ETH，随后优化，2 小时或 100 笔先到批量结算，并重新体验”的要求推进。

## 最新状态：固定预算通道实施中

用户已明确选择固定预算通道。新协议使用独立 V10 合约与签名域，原 V9 账单继续由原合约处理。**新合约已部署并完成至少 6 次确认后的字节码、政策、委员会、域与价格校验，线上节点尚未切换；不要将本文件中的本地测试写成全网验收完成。**

- 合约：`0xbb7adaaaa5bea35ee0d82581151c7056e3e14e86`；部署交易：`0xd6f1fb1a5ee3d5211a7bc02f56fb2b3cad41e1f7fae4e8cd405f1b4819a0edd6`，区块 11729655。
- Consumer 与 Provider 双边锁款；Provider 执行前持久占用 maxFee，未知结果不释额、不重跑；Provider 持有执行前 RelayDispatch 及完整签名回执，可以独立提交。
- 两个 Relay 各 1 ETH 已完成。部署钱包补入 0.04 ETH、专用 keeper 补入 0.003 ETH；三个 Provider 各补至本轮合计 0.25 ETH 独立结算 gas。全部为 Sepolia 测试 ETH，有独立交易记录，未挪用两个 Relay 的 1 ETH。
- 新网络初始化十笔已确认；Consumer credit 与 Provider stake 各 60 TestUSDC。P2→R1、P3→R1、P4→R3 三条各 20 TestUSDC 通道已开通，交易 `0x5d87a73dbfb4e448df7b9c56766d3f60b9f1a1293c6fe5b8dd120a51121b1606`。2026-09-18 09:25 UTC 核验时有 8 次确认，三个 `channelInfo`、两侧 allocation nonce 与总预留均正确；开始时间 09:35:48 UTC，接单六小时，之后另有三小时申领窗口。
- V9/V10 组合 keeper 已部署到 Bridge1，专用 actor 与单一 outbox 串行恢复，不自动投票、退款、罚没或 claim。两笔旧账单已实际 release；keeper 另补入 0.05 ETH，支持本轮负载验收。
- Node Consumer 新增受控测试显式 opt-in、固定预算状态/到期释放、按通道记账、执行歧义非自动重试响应，以及持久 Idempotency-Key 去重。两个最终本地 tarball 已离线安装、模块导入和首次启动检查；未发布 npm。实际 Consumer 已在 `127.0.0.1:8120` 启动并通过测试 owner 钱包签名登录，正在等待节点切换及通道开始。
- 本地验证：V10 合约 21 项（含 256 fuzz）、Python wire 14 项、真实本地链 8 项；Node 全套 251 项通过，后续预算 UI 专项 35 项通过。Relay canonical finality 修复独立复核通过，最终八节点候选为 `e654336adbae73b0c799c55b67ee9c6202a4045794f665bb086887e2645abd36`。集合有重叠，不相加宣称总数。

最新部署证据位于 `.codex-run/mesh/v10-fixed-budget-20260918/`，节点候选与切换证据位于 `.codex-run/mesh/optimization-rollout-20260918/v10/`。后续以实际激活和端到端验收记录更新。

以下内容是选择固定预算方案之前的阶段记录，其中“未部署/未启用”不覆盖上述最新状态。

## 充值状态

当前 V9 网络只有两个 Relay，已通过实时节点身份和 Sepolia 链身份核验：

| Relay | Gas 钱包 | 本轮已转入 |
|---|---|---|
| Relay1 | `0x7c4ec6822150c5f5b6b8c861c08f30686ba234f9` | 1 ETH |
| Relay3 | `0x349be2a4e18ad0a2cecfe4348eaededba79b28af` | 1 ETH |

本轮通过用户明确提供的资金来源，在内存中验证签名身份 `0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1`，其转账前余额为 **43.840159003210143334 Sepolia ETH**。仅向两个已核实的 Relay 地址各发送 1 ETH，手续费合计 **0.000060403931784 ETH**；转账后来源余额为 **41.840098599278359334 ETH**。

| Relay | 交易 hash | 入块高度 | 本次确认数 | 充值后余额 |
|---|---|---:|---:|---:|
| Relay1 | `0x6fba65a4e89100adbd6cd67c4c8b691668a8f96f16d4a033aaa86fdae6610f73` | 11729441 | 9 | 1.001650396418192348 ETH |
| Relay3 | `0x1a506bca47caee9f8dd798ca06a048dc6a7b968a8bef4cd73fbd8deae1e916f0` | 11729444 | 6 | 1.001474268605806200 ETH |

两笔交易在 head 11729449 核实了规范区块、发送方、收款方、金额、nonce、空 calldata 和成功状态。独立实时服务核验显示两台 `settlement_ready=true`、`inference_ready=true`，gas 安全容量当时各 425 笔，无在途/排队请求。现网旧 health 没有 `admission_ready` 字段，不据此臆测该字段值。Keeper 尚未充值或启用，旧托管账单尚未因本次充值自动释放。

脱敏证据：`.codex-run/mesh/v9-controlled-test-20260918/relay-one-eth-funding-result.json`，以及 `.codex-run/mesh/ux-network-audit-20260918/after-funding-1789719024.json`。原 `funding-plan.json` 保留之前缺少可用签名时的历史核验，并新增完成记录。来源私钥通过隐藏输入只用于本地内存签名，未写入项目代码、配置或本地日志文件；保护目录只保留这两笔交易的签名数据用于恢复。该私钥已经在聊天中暴露，后续应更换钱包并迁移剩余资产及权限。

原先请求向受控 deployer 补入 2.001 ETH 的充值方案已被本次直接转账替代，无需为这两笔 Relay 充值重复汇款。

## 本轮已实现的候选

| 范围 | 改动 | 当前状态 |
|---|---|---|
| Relay 批量结算 | 默认 7200 秒或 100 笔，任一先到；触发后持续排空该轮；单交易仍遵守最多 32 条，默认 8 条 | 本地测试通过，未上线 |
| 重启和截止时间 | 持久保存原始入队时间、上次成功时间、待排空水位；临近授权截止提前提交；已广播/未知交易优先恢复 | 本地测试通过，未上线 |
| 合约授权窗口 | 新 V9 候选最多 3 小时；显式配置剩余授权 9000 秒，含时钟回退后 9300 秒；签名之前、Relay/Provider 执行之前校验真实合约和 key 有效期 | 新合约未部署；旧合约仍 1 小时 |
| 到期处理 | Keeper 自动扫描已确认托管事件，按规则 release/timeout；专用签名、持久日志、默认只读；不自动裁决、退款、罚没或领取 | 代码及测试完成，未充值/启用 |
| Consumer 模型目录 | 汇总同一网络所有可用 Relay 的模型并显示路由数量 | 源码完成，未发布 |
| Consumer 请求恢复 | 派发前落盘 request ID、hash、预算和目标；断连不重放；可通过安全块核实托管并回填费用；错误 hash 拒绝 | 源码及回归完成，未发布 |
| Consumer 费用展示 | 未知费用显示 `--`，单独显示待核实笔数与授权上限；不把未知费用当作已知 0 元 | 源码及回归完成，未发布 |
| Provider 设置体验 | 无下载的只读 doctor；Docker/Compose/daemon/Make 分项诊断；配置保存、授权确认、可服务分开表示；配置模型明确标为未探测 | 源码及回归完成，未发布 |
| 接入文档 | 删除无需认证即可 curl 导出凭据的过时步骤，改为已登录设置页复制或现有 Codex wrapper | 文档已更新 |

## 两小时上线前的必要条件

当前合约不可原地把 `MAX_AUTHORIZATION_TTL` 从 1 小时改为 3 小时，现有 Consumer 授权还只剩 15 分钟。新调度器连接旧合约时会提前提交，不能称为已经实现真实两小时等待。新合约必须使用显式新 manifest、核验字节码及 TTL、重新完成配置；旧账单继续由原合约处理，不能清空或搬写其历史。

更重要的是，现有 gas 预留不是 Consumer 余额或 Provider 质押预留。多个 Relay 或单 Relay 连续执行时可以同时看见尚未扣减的余额，延迟上链会扩大执行后无法结算的风险。**因此本轮没有启用面向普通用户的两小时等待。** 公开启用前必须完成链上额度预锁、互不重叠的 Relay 额度，或具有等效约束的协议。受控测试也必须核对全网待结算上限与真实余额/质押，不能用单 Provider 并发 1 或新 gas 余额代替资金约束。

批量提交周期、链上争议期、释放后的 Provider 领取是三个不同阶段。修改提交周期不会缩短现有争议期，也不意味着 Provider 已收到钱包转账。当前 keeper 为保守 nonce 恢复每轮只发送一笔并等待确认，大批账单释放有吞吐限制，详见 [keeper 文档](v9-keeper.md)。

当前停止服务没有自动清空队列功能。上线和回滚应先停止接新请求，处理已有回执并核账，再逐节点切换；不可删除 SQLite 数据来绕过未知交易。

## 验证记录

- Node CLI/Consumer 全套：220 项通过；随后对复核新增的未知费用、慢磁盘截止、GNU Make 回退及未知回执链上核实运行了针对性回归。
- 根任务综合 Python 检查：346 项，344 通过、2 项显式环境跳过；对应本地链另由下列真实测试覆盖。
- Forge 离线合约测试：32/32，包括两小时后提交、超过三小时拒绝。
- Hardhat 真实本地链：11/11，包括新部署 TTL getter 读回。
- Keeper 专项：63 项；批量调度专项含 14 项新增边界；Relay/Provider 长授权新增 9 项边界。上述专项可能与综合集合重叠，不相加宣称总数。
- shell/Node 语法检查及 `git diff --check` 通过。
- 最终 keeper 真实只读扫描已核验旧合约 runtime/policy pins，分别在已确认块 11729399、11729403 为 5.5 和 Sol 两笔到期账单生成 release 计划。交易 outbox 为 0，没有签名、广播或 Provider 到账。证据：`.codex-run/mesh/v9-keeper-20260918/dry-run-summary.json` 与 `dry-run-resumed.json`。

这些结果不能代替线上充值、端到端验收、故障演练或 48 小时稳定性运行。V9 普通用户入口切换、跨 Relay 资金预留、真正流式、上游可验证计量、Sol 多 Provider 冗余、独立用户裁决准入等尚未全部完成。

相关设计：[结算调度](settlement-batching.md)、[授权窗口候选与迁移](v9-authorization-ttl-candidate-2026-09-18.md)、[到期处理 keeper](v9-keeper.md)、[原始体验评估](network-experience-review-2026-09-18.md)。
