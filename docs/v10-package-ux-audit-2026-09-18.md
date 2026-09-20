# V10 候选发行物与首次启动检查

## 后续实际体验更新（09:33 UTC）

以下原始包检查记录保留。后续 Root 已从最终离线安装产物启动实际 Consumer `127.0.0.1:8120`，测试 owner 的真实签名登录通过，读取到已确认的三条预算通道：锁定 60 TestUSDC，开始时间前可用预算为 0，未误报推理就绪。

本轮 in-app browser 已可用：实际打开首页、点击连接钱包并检查截图。该浏览器没有钱包扩展，因此没有验证钱包扩展弹窗或浏览器内签名；签名登录证据来自真实本地 HTTP 流程。发现无钱包仅显示瞬时错误后，已补常驻的安装/换浏览器/刷新提示，并在重载后的实际页面中核实。三个旧版错误标签也已改为实际协议版本。

最终本地包位于 `artifacts/v10-fixed-budget-ux-final/`，均离线安装、导入和 CLI 检查通过；未发布 npm：

| 包 | SHA-256 |
| --- | --- |
| Consumer 0.1.51 | `d55c890cd93149f5df54559cc3ee1a9be8c1e87022a7ae5216c7467785eddc29` |
| Provider 0.1.37 | `98c1968768eb318717c5ebd736b91ec5e792c54a33b44162aa3ca3f024287498` |

此次更新仅说明实际启动与首页体验；模型、批量上链及收益领取仍以独立实网验收记录为准。

## 原始发行物检查

日期：2026-09-18。检查对象为冻结源码生成的本地 tarball，没有发布 npm、变更版本、连接钱包、签名交易或调用真实模型。没有操作 8110–8120 的实例。检查结束时 8130 已关闭，`lsof -nP -iTCP:8130 -sTCP:LISTEN` 无监听者。

## 发行物

文件位于 `artifacts/v10-fixed-budget/`：

| 文件 | 字节 | SHA-256 |
| --- | ---: | --- |
| `mycomesh-consumer-0.1.51.tgz` | 71938 | `b9159d1d088abab938225772594fa535270c77e6cb4b0ea38c0f5a70771afa31` |
| `mycomesh-provider-0.1.37.tgz` | 106342 | `ec6dd71675a4fc93eb93f608f03a8075d1e1747a7d625f39bd81851f4df69769` |

使用 `npm pack --ignore-scripts --json --pack-destination ...` 生成，再分别安装到隔离临时目录：`npm install --prefix ... --ignore-scripts --offline --no-audit --no-fund <tarball>`。两次安装均成功。Consumer 的 8 个源码模块、Provider 包内的 9 个源码模块均可实际导入；两个包都包含 `consumer-reserved.mjs` 与 `consumer-request-journal.mjs`。最终包中包含新的“可用请求预算”页面逻辑。

两个包的 `--help`、`--version`，以及 Consumer `--dry-run` 均以 0 退出。Provider `--doctor` 在禁止下载和安装子进程的 instrumentation 下执行，仅运行 `docker --version`、`docker compose version`、`docker info`、`make --version`。Docker CLI、Compose、GNU Make 通过；Docker daemon 未启动，工具以 1 退出并明确提示启动 Docker Desktop/Engine。此失败是本机依赖状态，不是打包缺文件。

Provider `--dry-run --no-browser --no-start --source-dir <temporary-directory>` 以 0 退出；它仍会下载 pinned bootstrap 和源码到指定临时目录，再打印计划。没有执行容器拉取、钱包签名或 Codex 登录。`--dry-run` 不能描述成完全不联网/不落盘；`--doctor` 才是无需下载的依赖检查。

机器可读证据：`release-candidate-pack.json`、`final-package-checks.json`、`provider-dry-run.json`。安装记录在 `package-audit-install.json`。包名版本未提升，因此这些哈希描述本次本地产物，不能以版本号推断 npm 上已发布了同样内容。

## 首次启动结果

从实际安装的 Consumer tarball 启动隔离数据目录，绑定 `127.0.0.1:8130`，显式传入 `--network-config <snapshot> --controlled-test --no-browser --no-codex`。网络快照来自本次 V10 受控配置，通道 ID 尚空；使用项目内测试网络 CA。生成的临时本地 Key 没有输出到证据文件。

| 请求 | 结果 |
| --- | --- |
| `GET /` | 200，首个标题为“连接钱包以继续”；页面包含无钱包提示；无明文 API credential |
| `GET /health` | 200，`mycomesh-consumer/v10`、`wallet_unlocked:false`；只证明本机进程启动 |
| `GET /credentials` | 423，要求先由 payment-key owner 钱包登录 |
| `GET /v1/mycomesh/local/dashboard` | 200，`authenticated:false`，不返回 credentials |
| 首次运行的 `GET /v1/models` | 503，`No ready Relay advertises models for this network`；没有把当时的 V9 节点冒充 V10 可用节点 |

CUA 的 in-app browser 不可用；浏览器 inventory 为空；原生 Chrome 控制在等待后仍返回 Accessibility/Screen Recording 权限未完成。没有再次请求权限，也没有截图。因此以上是 HTTP 和返回页面代码验证，**未完成浏览器视觉、按钮点击或真实钱包体验验收**。页面的无钱包路径目前只提示“未检测到浏览器钱包”；后续可加安装钱包及刷新页面的明确下一步，属于体验改进。

## 适用范围与未完成项

- 默认 npm Consumer 和 Provider 入口仍为既有 V8 网络。实际 Provider dry-run 使用 pinned `dee829958e959e7f84fb74650748597afd3415d3`、V8 manifest 和已固定镜像，不能称为公开 V10 一键接入。此次未擅自替换 ref、镜像或版本。
- 本次 V10 受控节点部署使用单独的部署 bundle；显式网络配置只适用于已配置的测试 Key 与固定预算通道。全新用户的双 owner 授权、Provider 联签及自动开通通道尚不能算自助闭环完成。
- 未授权钱包、充值、开通通道、模型执行、100 条结算、真实两小时定时结算、收益领取均不属于本次发行物检查证据。它们按 `v10-post-optimization-acceptance-plan-2026-09-18.md` 单独验收。

## 同日后续补充：Root 的 8120 浏览器实测

Root 随后报告 in-app browser 已恢复可用，并实际打开 8120 登录页、点击“连接钱包”、看到“未检测到浏览器钱包”提示并检查截图。因此，浏览器首屏视觉与无钱包按钮反馈已取得后续实际证据；上文 8130 检查当时的权限阻断记录仍保留。

该浏览器没有钱包扩展，钱包弹窗、浏览器内授权和签名仍未验证。Root 另已完成 HTTP 路径的 owner 签名登录；这属于 HTTP 认证证据，不能替代浏览器钱包交互验收。此补充依据 Root 的实测反馈，没有重新启动 8130 或修改 8120 与包源码。
