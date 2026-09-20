# Provider 用户流程实际体验审计（2026-09-18）

## 结论

Provider 的基础安全边界和重复启动体验已经有明显改善：只输入公开收款地址、自动维护签名身份、授权后端独立校验、拒签可以重试、不确定交易不会自动重复发送。但当前适合有运维支持的受控节点，尚未做到普通用户从安装到首单、再到领取收益的自助闭环。页面本身简单，页面外需要掌握的依赖和经济状态仍然多。

这次没有修改真实 Provider、Docker 配置、Codex 登录或钱包，也没有发送链上交易。已有线上三个 Provider 接单成功的事实，不能代替新人从零安装验收。

## 实际走过的步骤与范围

1. 运行仓库真实 `node bin/mycomesh-provider --help`，查看无参数入口、版本与固定镜像配置。
2. 运行真实 installer 的 `--configure-only`，在任何页面或设置写入前退出 64，显示 `error: Docker Engine/Desktop is not running`。直接运行 `docker info` 同样确认当前 Mac Docker socket 不存在。未安装或启动 Docker。
3. 为继续检查产品页面，使用现有 Python 环境启动真实 `gateway.operator_setup wizard provider --settlement-version 9`，输出和身份路径均指向全新系统临时目录，不引用用户的真实配置。该页没有配置网络 manifest，因此只体验设置步骤，未把缺少钱包连接按钮算作产品缺陷。
4. 使用 Codex 内置浏览器实际打开该 loopback 页面。首屏有 V9 标记、收款地址、默认折叠的容量选项、授权与质押提示。输入 `not-an-address` 并保存，页面立即显示 `payout_address is invalid: payment_address must be an EVM address`。改为仅供隔离测试的 `0x1111111111111111111111111111111111111111` 后保存成功，显示 `Settings saved. Return to the terminal to finish sign-in and connection checks.`。wizard 正常退出，测试浏览器页已关闭。
5. 运行已有回归：`python -m unittest tests.test_provider_onboarding_ux`，20/20 通过；`node --test packages/mycomesh-cli/test/provider.test.mjs packages/mycomesh-cli/test/provider-wallet.test.mjs`，30/30 通过。这些钱包用例是模拟钱包/HTTP/SQLite 测试，不是真实扩展钱包验收。

三步内能得到反馈：可以，设置页的地址错误和保存结果都很快。但三步内达到“可接单”：当前本机不能；Docker 在入口即阻断，而源码完整流程还包含钱包授权、Codex 登录、质押、网络准入及 readiness。

## 优先发现

| 优先级 | 发现及用户影响 | 可核验位置 | 建议和验收条件 |
|---|---|---|---|
| P1：公开试用前 | 入口仍默认 V8，和受控 V9 网络存在交付断层。launcher 固定 0.1.37 的旧 commit/image；installer 默认协议为 8。普通用户无参数启动不能被视为已经进入本轮 V9 部署。 | `packages/mycomesh-cli/src/provider.mjs:8`；`scripts/install-provider.sh:20`；`docs/operator-onboarding.md:45` | 发布同一批经过验证的 V9 launcher、image、manifest，入口展示网络及版本；用全新机器按公布的一条命令验收到首单。不要只修改版本标签而绕过 V9 准入检查。 |
| P1：Provider 自助闭环 | 质押和收益领取缺少连贯操作入口。V9 页只说明需要 funded stake、收益有托管期；`make provider-claim-payout` 对 V8/V9 明确退出并要求外部钱包流程。底层有 V9 stake/claim 编码与读链能力，但不能据此宣称普通 Provider 已能自助完成。 | `gateway/operator_setup.py:502`；`Makefile:439`；`gateway/chain_v9.py:516`；`gateway/chain_v9.py:596`；`docs/operator-onboarding.md:100` | 同一控制台显示“可用/锁定质押、待释放/可领取收益、gas 是否充足”；明确入口连接本人钱包、展示精确交易、验证到账。托管未到期时显示预计释放时间及卡住原因，不显示为可领取。受控准入阶段也应说明等待运营审核的状态。 |
| P2：首次安装转化 | 本机缺 Docker daemon 时只得到终端单行错误，首屏尚未出现。除了 Docker/Compose，installer 还要求 GNU Make；拉镜像也在 wizard 前。现在阻断准确，但新手恢复路径弱。 | `scripts/install-provider.sh:384`；`scripts/install-provider.sh:395`；`scripts/install-provider.sh:399`；`scripts/install-provider.sh:420` | 加只读 `doctor` 和统一预检页：Docker 已安装/已启动、Compose、镜像下载、代理连通性分别给出状态、修复提示与“重新检查”。提供预估下载体积；无需先填写钱包即可发现依赖问题。 |
| P2：流程连续性 | 保存设置后明确让用户回终端；钱包授权是第二个本地页面，之后再做 Codex 登录和 network health。表单很轻，但用户需要在浏览器、终端、钱包和登录页之间切换，当前页没有最终接单状态。 | `gateway/operator_setup.py:551`；`scripts/install-provider.sh:454`；`scripts/install-provider.sh:470`；`Makefile:401` | 保留一个可恢复的本地状态页，三组进度为“环境检查 → 账户与钱包 → 联网接单”。后台保存步骤状态；只有授权、质押、Codex、Relay/Bridge 全部验证通过才显示可接单。错误可在原步骤重试，状态未知的链上交易先查询，不能自动重发。 |
| P2：模型与运营可见性 | Provider 设置页只有地址和容量/周期限额，没有可服务模型、当前模型访问状态、首单测试或收益看板。默认 `PUBLIC_MODEL_IDS` 是配置列表，模型转发依赖列表；列表本身不能证明该账户当时可调用所有模型。 | `gateway/operator_setup.py:534`；`docker-compose.yml:22`；`gateway/main.py:1002`；`gateway/main.py:1017` | 登录后只读探测可用模型并与 network/运营允许列表取交集；分别显示“配置支持/账户可用/最近调用通过”。配置变化无需手工编辑多个 manifest 和 env。加入小额、显式预算的首单测试入口及结果、耗时、失败原因。 |

## 建议保留的设计

- 收款地址和签名身份分开；签名私钥不进入浏览器。容量默认 1，高级项折叠，重复启动复用验证过的设置。
- 钱包侧检查账户、链、合约、calldata、value，服务端再读链验证。`gateway/provider_onboarding_wallet.js:19`、`:58`、`:68`。
- 授权发送前使用持久化原子 intent，跨标签页及不同端口重启都防重复发送。拒签和“发送结果不确定”被区别处理。`gateway/provider_onboarding_wallet.js:69`、`:85`、`:98`。这块适合继续沿用到质押和领取流程。
- 健康检查包含 Codex 状态、settlement readiness 和 Bridge lease；不应简化为“容器启动即在线”。`Makefile:401`。

## 下一轮最小验收

在一台没有历史 MycoMesh 配置、Docker 已安装但未启动的机器上，从公布入口开始，验证可理解的恢复提示；由真实测试钱包持有人完成授权及测试币质押、Codex 登录后接一单。再验证关闭页面/重启后恢复、拒签重试、pending 禁止重发、失去 Relay/Bridge 后状态变更，以及托管释放后从同一页面领取收益。记录各步骤耗时与人工操作次数；首次设置目标可以定为三组进度、10 分钟内接到测试单，依赖大文件下载时间单独计量。此项是建议验收标准，尚未完成。

## 同日首批修复（源码候选，未部署）

- installer 新增 `--doctor`：GNU Make、Docker CLI、Compose、daemon 分项报告，并提供启动 Docker Desktop、检查 Docker context、安装 Compose/GNU Make 的恢复指引。只执行版本/可达性读取，不拉镜像、不写配置、不启动依赖。本机实测正确定位为只有 daemon 阻断。
- wizard 显示设置、钱包、登录/模型/联网的阶段；保存后显示原终端继续和同一启动命令恢复的明确说明。后端响应单独给出 `authorization_verified`，只在实际通过既有授权检查时为真；单纯保存不再可能被客户端理解为授权成功。保存成功后禁用按钮，避免对已经退出的临时服务重复提交。
- 额外信息区显示 pinned manifest 配置模型，明确标注“配置，未探测”；质押/gas/托管/可领取余额也明确尚未查询。继续沿用现有外部钱包边界，没有新增未经验收的转账/领取按钮。
- 验证：Provider/installer/operator/proxy/deploy 相关 Python 回归 89 项通过，现有 Node launcher/wallet 回归 30 项通过；真实隔离 V9 HTTP 表单保存返回 `authorization_verified=false`，生成的 JavaScript 语法检查通过；shell 语法通过。
- 修复后尝试再次打开实际浏览器，但 CUA 可用浏览器列表为空，因此这一轮未重新完成 GUI 交互验收，没有再请求录屏权限。上文修复前的浏览器实测仍有效；本轮只声称已完成的 HTTP/源码/测试验证。

尚未完成：统一 V9 launcher/image 发布、长期运行的同一状态页、模型账户探测、真实钱包质押及收益领取 UI、全新机器至首单的真人验收。当前改动减少入门阻断和状态歧义，不等于这些发布门槛已经消失。
