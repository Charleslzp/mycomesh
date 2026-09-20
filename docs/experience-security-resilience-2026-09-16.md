# 用户体验、服务真实性与网络韧性验收

经济参数暂不调整。本轮不部署新合约、不转移资金，也不把本地夹具当成真实上游模型。
以下是代码和测试结果；除明确标注的公网只读检查外，新增改动尚未发布到远端或 npm/Docker。

## 三个目标的实际边界

| 目标 | 已具备或本轮补齐 | 仍不能声称 |
| --- | --- | --- |
| Consumer 少操作 | 启动打开本地页，连接钱包；首次首页直接“启用 API 访问”；之后复用授权，复制 URL/Key 或整段 export。钱包私钥不交给程序 | 首次无需钱包确认、无余额也能付费；不应为省一次点击绕过钱包授权 |
| Provider 少操作 | 配置与内部签名身份自动保存、正常重启复用；钱包插件负责一次性授权，不要求用户填写私钥 | 现有 V8/V9 合约仍在接单前要求收款钱包授权内部 signer，不能承诺“只在提现时填地址” |
| Provider 保真 | 校验身份/签名、原请求绑定、完整返回正文承诺、回执及链上状态；篡改结果不得交付为成功 | 签名或探针无法证明机器实际运行的是某一个 GPT；自报 model 字段不是模型身份证明 |
| 多节点更稳定 | 多入口故障隔离、同 Provider 备用 Relay 迁移、未知结果不重复执行 | 节点数量不等于独立故障域；当前公网推理仍集中 Relay3，不是 BTC 式开放发现网络 |

## Consumer：少步骤，但不减少安全边界

- 首页直接提供首次访问授权入口，不再要求先找钱包页。
- 隐藏默认展示的协议版本和内部 Key 地址细节，仍可展开排查；优先选择 OKX 插件入口。
- 本地凭证导出必须持有管理令牌。管理页面和接口要求同源 loopback 连接，校验 Host/Origin，
  阻止 DNS 重绑定、跨站访问和 iframe 嵌套；API Key 不能代替管理令牌。
- 断线或 503 不说明上游没有执行。只有明确 `not_dispatched` 才允许自动换路重试，
  Node 和 Python Consumer 采用同一安全边界，不以重复扣款风险换取表面成功率。

真正启动了隔离的 headless Chrome，通过实际本地页面完成连接钱包、签名登录、
首页一次访问授权、显示 URL/Key、刷新不重复授权、退出锁定的流程。
钱包是 OKX 形状的测试适配器，链状态为夹具；没有加载用户浏览器资料、真实插件或真实钱包，
因此这不是对真实 OKX 扩展/公网钱包确认的验收。

复现：

```sh
MYCOMESH_TEST_BROWSER_BIN='/path/to/chrome' \
node --test packages/mycomesh-cli/test/browser/consumer-journey.mjs
```

## Provider：启动、授权与恢复

首次启动先选择收款钱包、保存设置并把内部签名身份落到保护卷，再打开钱包授权页。
页面由钱包插件签署固定网络、合约和 signer 的一次性授权；服务器独立检查链上授权，
不把配置保存或钱包返回交易哈希当成已上线。最后仍要经过登录和网络 readiness。

普通重启复用身份与设置并只读检查授权；中断过的授权仅续办该步骤，不重填配置。
发送前在专属私有目录建立 SQLite 原子发送记录，跨标签、随机端口、进程及 checkout 升级
保留未知交易状态。默认路径为 `~/.mycomesh/provider/authorization-state`；显式更换状态目录
会改变该安全边界，不能在未决时把它当作“重试”手段。未决结果不清楚时需要人工核实，
不会自动解除记录再发交易。

移除了 `make provider-authorize` 的钱包私钥输入及命令行传递，保留为未签名计划工具；
正常安装走钱包页面。V8/V9 提款入口都拒绝退回旧 V4 内部签名者路径，提款 UX 和经济参数
不在本轮实施。首次收款钱包授权仍是现有合约要求；若要完全推迟到提款时再绑定钱包，
需要另外设计身份和收益归属，不能只靠隐藏输入框实现。

Provider 测试使用模拟钱包及真实 localhost HTTP/SQLite，并独立验证多进程只允许一次预留。
未实际跑新 Docker 镜像安装或真实 OKX 交易；发布镜像/commit pin 未更新。

## 完整正文承诺：Consumer 不再只相信 Relay 的验签结论

Provider 现有 `response_hash` 是对完整承诺 JSON 的 SHA-256，覆盖请求、模型标签、peer、
usage、文本及原始结构化 API 返回，包括工具调用参数。

新协商协议：

1. Relay health 公布 `response_proof: mycomesh.provider-response-proof.v1`。
2. Consumer 用 `X-MycoMesh-Response-Proof` 请求该格式；Relay 将原承诺的精确 UTF-8 字节
   编为 base64，作为 HTTP 响应正文发送。签名回执仍在 `PAYMENT-RESPONSE`。
3. Consumer 先验回执签名及原付款授权，校验承诺字节的 SHA-256，再核对 request/model/endpoint，
   只从已认证的 `raw` 提取结果，最后才进行客户端格式兼容和 SSE 输出。

这避免 Python/JavaScript 浮点数、Unicode、数字键排序差异造成的重新序列化哈希错误。
不把整段回答塞进 HTTP header，也不重复发送一份未认证正文。base64 本身约增加三分之一体积；
目前仍是缓冲后验证/交付，不是真实上游逐 token 的低首字时延流式验证。

V9 客户端强制该能力，缺失时付款请求发出前失败。现有 V8 不改变合约即可使用，
但旧 Relay 兼容模式仍只有回执验证：**要防能力降级，必须在本地受信 Consumer manifest 设置
`require_response_proof: true`**。不能把未升级的公网节点描述为已经启用此保护。

正文缺失、被替换、坏 JSON、HTTP 错误甚至读取失败时，只要拿到了可验证的付款回执，
Node 会保留回执和账单，标记 `content_verification=failed`，向调用方返回付款回执，
不输出伪造正文、不重放、不假称没有费用。账单的结算状态与交付验证状态是两件事。
Python 同样保留已取得 HTTP 响应后的坏正文回执；其缓冲 HTTP 客户端若在取得响应对象前超时，
仍只能报告未知结果，不能声称已拿到回执。

这只能证明“这个签名者承诺了这些字节”，不能证明计算过程、上游品牌、回答质量，
更不能凭一次失败自动把 Provider 判作弊。恶意 Relay 替换内容也不应归罪于 Provider。

## 网络韧性：真实故障测试与现网状态分开

本轮修复多 Bridge 注册的串行等待及异常中断：最多 8 个并发共享 deadline，单个黑洞、
坏 JSON 或断连不阻止健康入口。新增真实 loopback HTTP/TCP 故障注入验证了注册/发现容错，
以及同一 Provider 在主 Relay 主动断连后转接备用 Relay。

原生 Consumer 现在读取所选受信网络清单的 `relay.public_url` 和 `relay_fallbacks`，
自动去重、拒绝无效或带凭据的地址；显式 `--relay` 仍可覆盖。不会把 discovery-only Bridge
误当成推理入口，也不采信远端任意推荐节点。可用 `--network-config` 指定清单，
默认安装的单入口网络配置不会凭空变成多入口。

公网只读检查仍显示 Bridge1/2 可用，Relay3 有 3 个 Provider；Relay1 没有 Provider，
Bridge3/Relay2 超时。因此当前服务面仍有明显集中点，不能称为多条同时可用的独立推理路径。

后续应依次验收：空闲连接心跳和静默黑洞恢复、多个实际可用 Relay 路径、发现控制面故障、
持续负载/丢包/执行中断线下的成功率与 P95。必须分别看新会话和原会话：
同一个有上游状态的会话不能随意切 Provider，未知执行结果不能自动重放。

具体测量、复现命令和仍存单点见 [网络韧性记录](network-resilience-flow-2026-09-16.md)。

收尾再次严格校验证书读取现网，状态不变：Bridge1/2、Relay1/3 返回 200，
Bridge3/Relay2 在 5 秒超时。Relay1/3 尚未广告新 `response_proof` 能力，证明本轮保护
并未悄悄发布到现网；不能用本地测试结果替代部署验收。

## 本轮收尾测试

- 395 项 Python：393 通过，2 项既有跳过。
- 188 项 Node：全部通过，无跳过。
- 独立 headless Chrome 页面流程：1 项通过，无跳过。
- 既有 V9 localhost Hardhat 真实链闭环：5 项重跑通过，无经济策略修改。
- shell 语法与 `git diff --check` 通过。

Node 完整回归使用 `--test-concurrency=1`：默认多文件并发曾触发时序敏感的
`consumer-resilience` 夹具 30 秒超时，单文件及顺序全量重跑通过；不把它隐藏为默认并发全绿。
上述不是全仓库验收，旧 operator/proxy/部署断言和 V4/V5 合约测试仍有已记录的遗留问题。

```sh
python3 -B -m unittest \
  tests.test_consumer_v8 tests.test_consumer_v9 \
  tests.test_relay_security_integration tests.test_relay_v9_runtime tests.test_relay_integrity \
  tests.test_network_resilience_flow tests.test_pool tests.test_client \
  tests.test_relay_robustness tests.test_relay_scheduler tests.test_provider_onboarding_ux \
  tests.test_provider_bootstrap tests.test_v9_network_config \
  tests.test_provider_identity tests.test_codex_provider_config tests.test_relay \
  tests.test_session_relayer_connections

node --test --test-concurrency=1 --test-timeout=30000 \
  packages/mycomesh-cli/test/*.test.mjs
```
