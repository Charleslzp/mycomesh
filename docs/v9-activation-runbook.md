# V9 受控联调激活顺序

更新日期：2026-09-18。当前是同一运营者管理的 3 Provider / 2 Relay / 3 Bridge 隔离系统测试，使用 Sepolia 测试币，关闭代币奖励。**不是普通用户公开部署，也不是独立裁决委员会验收。** 合约与全部 8 个节点已部署运行；三台真实推理及服务收益到账已验证。

## 当前落点与身份

| 项目 | 当前实际值 |
| --- | --- |
| network ID / chain ID | `mycomesh-v9-controlled-test` / `11155111` |
| V9 settlement | `0x8ed70585cb60082e6f8e64f5190a3d8014e42367` |
| 部署交易 / 区块 | `0x986cd0969a9b4d96762d04d221c6859f931e3b1e29945352d3c3100bb35f15f5` / `11728132` |
| 专用 deployer / governance / treasury | `0xae4a4c86c2b6c340c8198d0958b223f5d0c8caa2` |
| 测试稳定币，6 位小数 | `0xeb487c6e778248e16361dc313e4223c20d4c23b5` |
| 新 V9 测试 Provider owner | `0x94515c8903cca8e5aedb1437e947db39970792cc` |
| Consumer owner / key | `0x452bfe4c9b59455504068b2594979bcd531c9e49` / `0x5e69a109b24e623da7af21d0137f942e6f3a65d4` |
| Relay1 / Relay3 独立提交器 | `0x7c4ec6822150c5f5b6b8c861c08f30686ba234f9` / `0x349be2a4e18ad0a2cecfe4348eaededba79b28af` |
| 裁决配置 | 同一运营者的 3 个测试钱包，2/3 阈值，`committee_mode=controlled_test`、`independence_attested=false` |

工作目录为 `.codex-run/mesh/v9-controlled-test-20260918/`，以下证据文件均相对此目录：`deployment.json` 是实际清单，`deployment-verification.json` 为 confirmed 核验结果；runtime hash 为 `0x004fdd15fe7dc8bb0b41dd133ae1b80fd9009cba288d808f879ac15f019511ed`。公钥和公开地址在 `public-identities.json`；私钥仅在受保护文件/目标节点使用，不应写入日志或命令参数。

旧 V8 owner `0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1` 的余额与授权不自动迁移。三个 Provider 签名身份沿用 `../provider-identities.json` 的记录，但新 owner 必须在 V9 合约上分别授权。V9 stake 按 owner 记账，三个节点共用一份抵押，不能重复计算成三份。

委员会中三把测试钱包均声明相同 operator；不同地址不证明独立控制。真实高信誉用户 + 本人 Codex 辅助 + 本人钱包签名方案见 [用户裁决 agent](user-jury-agent.md)，其独立用户治理不由本次测试证明。

## 本次阶段状态

| 阶段 | 此快照状态 |
| --- | --- |
| 实际部署、runtime 与政策核验 | 已完成 |
| 新候选分发至 8 台 | 已完成 |
| 8 台隔离 provision | 已完成 |
| Bridge1/2/3 激活 | 已完成；服务 active 与专用 CA 严格 TLS 10443 健康检查通过 |
| 链上资金、授权/质押、Consumer key 初始化 | 已完成；初始化读回区块 11728229 |
| Relay1/3、Provider2/3/4 激活 | 已完成；Provider 分布 2+1，3 个 Bridge 均发现 3 个 Provider |
| 专用客户端真实推理与结算闭环 | 三台各一笔成功，结算、释放及 5717 最小单位实际领取均已确认 |
| 运行持久化、RPC 与 gas 配置 | 10 个 systemd unit 自启，3 个容器 unless-stopped；两台 Relay 双 RPC，gas 下限 750000 |

初始 candidate 为 `/opt/mycomesh-mesh/releases/v9-candidate-d1dd8d57d88ecae5`，archive SHA256 为 `d1dd8d57d88ecae5f220383b85eb1da04547281df02cfaaa198b76a6751e5a0c`。8 台每台已核对 252 个文件、184 个 Python 文件解析与核心模块导入，证据为 `staging.log`。Bridge/Provider 仍运行此包；两台 Relay 最终改用 `/opt/mycomesh-mesh/releases/v9-candidate-5acc9cc4b8d610fa`，archive SHA256 为 `5acc9cc4b8d610fa9d75ef53a7e65046b33303f9a0780f9b8ae21c18e9c76989`，使 `MYCOMESH_RELAY_SETTLEMENT_GAS_PER_RECEIPT=750000` 在重启后继续生效。逐节点实际路径与配置见 `final-runtime-check.json`。

两台 Relay 保留 PublicNode + Tenderly RPC；Provider3 使用已验证的 Tenderly。已有本地/远端配置、bundle、bootstrap 和冻结包一致性审计；**不要重新全量执行 `prepare` 覆盖这些差异**，修改须先核对每台的 `node.json` 与 `node.py` 候选路径。旧候选 `v9-candidate-f11c60394eb62281` 属于历史分发。

## 已执行的链上初始化与恢复规则

以下初始化已经完成。需要恢复操作时，先检查 `chain_actions.py` 同目录的持久交易记录，未知广播只恢复原交易，不能重新分配 nonce。不要重复入金、重新部署或继续使用旧空白草案。

1. 已向专用账户、两台新 Relay submitter 分配测试 gas 和测试稳定币，并读回余额；持续服务仍需补充 gas。
2. 已在实际 V9 合约上授权 Provider2/3/4 的三个 signer，并读回授权。
3. 已通过有限 allowance 和 `depositStake` 建立共享质押 5 测试稳定币；后续合成争议罚没 0.002，最终余额见验收记录。
4. Consumer 已独立入金 1 测试稳定币并注册 key，单笔限额 0.1；旧 V8 余额和账单保留。
5. 已准备 reporter 保证金与测试裁决钱包 gas，并完成两票触发的合成争议验证。三个钱包的签名只能验证 2/3 机制，不能证明运营者独立。

关闭代币奖励要求 `reward_token` 为零地址，`token_reward`、`token_reward_cap`、`token_minimum_exposure`、`token_minimum_penalty` 均为 0，实际清单已满足。合约配置不可变，不能承诺在该测试实例稍后直接启用代币奖励。

## 隔离服务与入口

独立根目录：`/opt/mycomesh-v9-controlled-test-20260918`。新配置在 `config/`，身份副本、replay/outbox/incident/probe 数据在 `data/`。保留原 `/opt/mycomesh-mesh`、原 nginx、公共 V8 服务和已有账本。

| 服务 | 新入口 | 内部监听 |
| --- | --- | --- |
| Bridge HTTPS | 各 Bridge IP 的 TLS `10443` | `127.0.0.1:11080` |
| Relay HTTPS | 各 Relay IP 的 TLS `10443` | `127.0.0.1:11090` |
| Relay Provider TLS | 各 Relay IP 的 `10991` | `127.0.0.1:11991` |

10443 的 nginx 配置包括 IP 白名单和 `deny all`；来源为部署记录中的运营端、8 台测试节点和 loopback。10991 保持 CA 验证的 TLS，Provider 注册还需签名及明确公钥白名单。节点都须显式设置 `MYCOMESH_ALLOW_CONTROLLED_V9_TEST=1`，并使用专用 network ID 和实际 V9 清单。普通 Consumer 与公共 V8 入口不重定向到本次受控网络。

新 systemd 服务使用 `mycomesh-v9-test-*` 名称；新 Provider 容器名为 `mycomesh-v9-test-provider`。Provider 固定已检查的现有镜像 ID，挂载冻结候选源码/独立清单和新 data；旧 `/agent` 只读复用，旧 Codex 登录由既有 sidecar 保持。不要另启共享登录的第二个 sidecar。

## 逐台激活与恢复

执行入口为工作目录中的 `rollout_controlled.py`，本地 Python 为 `/tmp/mycomesh-mesh-deploy-venv/bin/python`。`prepare` 只生成本地文件；`provision` 上传并准备独立环境；`activate` 和 `recover` 修改指定节点的运行状态。远端阶段都要求 `--node`，没有全部 Provider 同时激活的默认入口。

1. 已完成的 provision 不重复冒充激活。记录每台当前 bundle、旧容器 ID/健康与 data 权限；Provider 的身份副本与原文件相同，未复制旧 operator-config。
2. 三台 Bridge 已激活。接着确认新 submitter 有 gas，逐台激活 Relay1、Relay3；检查严格 TLS、settlement-ready、V9 合约、Provider 白名单、独立 outbox 和提交器地址。
3. 按 Provider2 → Provider3 → Provider4 顺序进行。每次先检查旧 replay 无未完成执行，停止旧 Provider role，启动新独立容器并检查 Bridge lease、Relay 成员和链上 signer/stake。旧 sidecar 必须一直保持原 ID、运行状态和登录。
4. 每台成功后从允许来源用专用测试客户端发真实请求，记录实际被调度的 peer/signer、Relay、response/receipt 和结算交易，再推进下一台。
5. 三台已全部保留在 V9，旧 V8 Provider worker 停止，V8 的这部分推理容量为零，不能把 HTTP 健康描述为推理可用。若后续决定回退，应逐台恢复并核对公共 V8 成员和实际服务状态；本轮没有回退这三台推理容量。
6. Provider 激活失败时，脚本在没有未决执行的前提下停止候选并恢复旧 role。`recover --node providerN` 只处理匹配本次标记的候选；遇到 running/uncertain replay 或未知交易时停下核对，不强制丢弃。
7. Relay 恢复前先撤回候选 Provider，关闭候选入口，再检查 outbox。V9 已有 pending/submitted/broadcast_unknown 或资金托管时，保留必要结算、释放和争议处理能力，不因恢复 V8 而遗弃账目。

## 必须留下的业务证据

正常真实推理 → 签名 receipt → 链上托管 → 到期释放，以及争议确认退款/罚没、驳回、超时、收益领取和提现须分别执行并核对。`release` 转为可领取收益，不等于钱包已收款。测试客户端必须固定受控 network ID、实际合约与测试 owner/key，不能借用普通用户的 V8 授权。

多 Relay 同时读取共享 available stake 不是全网预留证明；三台共用测试 owner 的并发、重复请求、断连与重试行为需真实验收。已经通过的 localhost 测试、链上部署核验和 Bridge 健康不能替代这部分结果。

已有 operator 支持 `plan-release`、`plan-timeout`、持久执行和重启核验，但自动扫描调度服务尚未宣布上线；须明确执行责任与频率。小规模真网闭环后再安排 48–72 小时持续运行验收。真实流式、Relay 不可读取正文及旧 Web 完整 V9 钱包门户仍不属于本次已完成能力。

## 最终运行记录

本轮受控部署与验收完成。三台 Provider 各一笔真实请求成功，签名、付款绑定、链上结算和释放均已核对；Provider 与 Relay 共用 owner 钱包实际收到合计 5717 最小单位。合成争议第一票不动资金，第二票触发 2000 退款、2000 罚没；举报人保证金 10000 与稳定币赏金 400 已实际到账，代币奖励为 0。相关释放/领取与合成 signer 撤销均达到至少 6 个区块确认。

初次合成 V1 举报未广播并错过窗口，已按未举报账单释放；重测 V2 完成两票裁决，不能把 V1 写成已验证争议超时。临时合成 signer 已撤销，最终区块 11728485 的合约资产/负债均为 5993883，共享 stake 4998000、locked 0。三台真实 Provider 保持 V9 运行，旧 V8 worker 停止、原 sidecar 与账本保留。

最终证据为 `acceptance-summary.json`、`cleanup-audit.json`、`final-runtime-check.json`、`network-check-1789707030.json`；详细交易、RPC 修复、恢复记录及未覆盖范围见 [部署状态](v9-deployment-status-2026-09-18.md)。该结果限于受控测试网，未开放普通用户、未验收真实独立用户裁决，也未部署无人值守释放/超时服务。历史回归计数不得当作当前候选已重新全量测试。
