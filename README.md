# MycoMesh

去中心化的 AI 推理网络：**Consumer** 付费提问，**Provider** 用自己的模型作答，**Relay** 转发看不懂的密文，结算、定价、争议都在以太坊上（当前是 Sepolia 测试网）。

- 押金托管在合约里，每个请求由你本机签名授权；Relay 只转发密文。
- 全网统一价，按算力利用率每天自动调整（类似比特币难度）。
- Provider 不交押金；作弊靠免费探针和随机抽取的 Provider-AI 陪审团来抓，罚没 holdback。
- 每笔费用：Provider 85% / Relay 5% / 国库 10%。另有 MYCO 代币（总量 10 亿、无预挖、按小时减半产出），按真实付费额分给各角色。详见[白皮书](docs/whitepaper.md)。

> **测试网须知**：tUSDC 和 MYCO 没有任何价值；Provider 能看到请求明文；合约未经审计，项目方持有升级权限；现阶段陪审员都是项目方运营的 Provider。请勿发送敏感内容。

下面按角色说明怎么用。环境要求：Consumer 只要 Node.js 20+；Provider 和 Relay 另需 Docker；Keeper 和探针方需要 Python 3.10+。

---

## 我想用 AI（Consumer）

```sh
npx mycomesh-consumer
```

浏览器打开 `http://127.0.0.1:8110/`，两步开始：

1. **创建钱包**：设个密码，钱包只存在本机。
2. **领币并存押金**：一键从测试网水龙头领 gas 和 tUSDC，并存入押金。

之后就可以对话了，回答会实时显示。控制台里还能看余额、记录、网络和 Provider 信誉，对不满意的回答发起争议，领取 MYCO 奖励。

只有需要钱包签名的操作（存取押金、领 MYCO、管理租户、发起争议）才问密码；输入一次后 15 分钟内不再询问，可以随时点"锁定钱包"。对话、领测试币和查看都不需要密码。

命令行用法：

```sh
npx mycomesh-consumer init                          # 付款 key + 本机加密钱包
npx mycomesh-consumer setup                         # 存 20 tUSDC；测试网会先自动领水；其他金额：--deposit 50tUSDC
npx mycomesh-consumer request "什么是零知识证明？"
npx mycomesh-consumer dispute last --statement "答非所问"   # 24 小时内可争议，由陪审团判定
npx mycomesh-consumer rewards claim                 # 领取 MYCO
npx mycomesh-consumer withdraw                      # 取回押金（申请后等延迟期再执行一次）
```

**接到自己的工具里**：`npx mycomesh-consumer serve` 在本机 `http://127.0.0.1:8110` 同时提供三种格式，都支持流式，计费的 token 数来自 Provider 签名的收据：

| 格式 | 接口 | 例子 |
| --- | --- | --- |
| OpenAI | `/v1/responses`、`/v1/chat/completions`、`/v1/models` | OpenAI SDK、Codex：base URL 设为 `http://127.0.0.1:8110/v1` |
| Anthropic | `/v1/messages` | Anthropic SDK：`base_url="http://127.0.0.1:8110"` |
| Gemini | `/v1beta/models/{模型}:generateContent`、`:streamGenerateContent` | Google GenAI SDK 指向 `http://127.0.0.1:8110` |

同一段对话的后续轮次会自动发给同一个 Provider，复用上游的提示缓存；客户端带了会话标识（`session_id` 请求头、`prompt_cache_key`、Anthropic 的 `metadata.user_id`）就按它认，否则按对话开头认。

任何格式都可以调用网络上的任何模型（例如用 Anthropic 格式问 gpt-5.5），**包括工具调用和图片**：Claude Code、Codex CLI、Gemini CLI 这类智能体可以直接接入，截图也能发给模型看。PDF 等文件只会发给能读文件的 Provider（用 API key 接入的 OpenAI、Anthropic、Gemini 后端），测试网目前的 Codex Provider 读不了文件。工具在你本机执行（读写文件、跑命令都在你自己的电脑上），网络只传"模型要调用哪个工具、参数是什么"和执行结果。`GET /v1/models` 返回模型目录（厂商、档位、能力），控制台"网络"页也能看到。

接入编程智能体（先运行 `npx mycomesh-consumer serve`）：

```sh
# Claude Code（如果 ~/.claude/settings.json 里设置了 env.ANTHROPIC_BASE_URL，它会覆盖下面的环境变量，需先删掉）
ANTHROPIC_BASE_URL=http://127.0.0.1:8110 ANTHROPIC_API_KEY=local ANTHROPIC_MODEL=gpt-5.5 ANTHROPIC_SMALL_FAST_MODEL=gpt-5.5 claude

# Codex CLI
MYCO_KEY=local codex -c model_provider=mycomesh \
  -c 'model_providers.mycomesh={name="MycoMesh",base_url="http://127.0.0.1:8110/v1",wire_api="responses",env_key="MYCO_KEY"}' -m gpt-5.5

# Gemini CLI（~/.gemini/settings.json 里 security.auth.selectedType 设为 "gemini-api-key"）
GEMINI_API_KEY=local GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8110 gemini -m gpt-5.5
```

## 我是团队或托管服务（多租户）

一份押金可以分给多个租户，每个租户有自己的付款 key 和链上预算上限，可以从任何机器用 API key 调用：

```sh
npx mycomesh-consumer tenant add acme --budget 5000000 --max-per-request 200000
npx mycomesh-consumer tenant list
npx mycomesh-consumer tenant budget acme 8000000
npx mycomesh-consumer tenant revoke acme
```

协议不对托管方额外收费；租户的每笔交易照常分账，付费方同样拿 MYCO。

## 我有模型额度，想赚钱（Provider）

```sh
npx mycomesh-provider
```

浏览器打开 `http://127.0.0.1:8120/`，网页向导会依次完成：生成签名 key、登录 ChatGPT（设备码）、创建收款钱包、上链注册（测试网自动领 gas）、启动容器。之后在同一页面查看收益、敞口、陪审资格进度，并领取收益。

**用 API key 接入（推荐，不依赖 ChatGPT 登录）**：

```sh
npx mycomesh-provider init
npx mycomesh-provider wallet                        # 收款钱包，密码取自 MYCOMESH_KEY_PASSWORD
npx mycomesh-provider register --model claude-sonnet-4-6
npx mycomesh-provider start --backend anthropic --api-key-env ANTHROPIC_API_KEY --model claude-sonnet-4-6
# OpenAI：--backend openai --api-key-env OPENAI_API_KEY --model gpt-5.5
```

**接入任意模型（插件）**：后端是插件式的。内置 `codex`、`openai`（任何 OpenAI 兼容接口：OpenAI、vLLM、Ollama、DeepSeek、OpenRouter 等）、`anthropic`、`gemini`，以及 `exec`（任何语言写的程序）。自己的后端放进 `~/.mycomesh/provider/plugins/` 即可：

```sh
cp examples/provider-plugins/template_plugin.py ~/.mycomesh/provider/plugins/   # 一个 Python 文件 = 一个后端
npx mycomesh-provider backends                                                   # 列出可用后端
npx mycomesh-provider start --backend my-model --backend-option api_key=env:MY_MODEL_KEY --model my-model-v1
# 任何语言：程序放在 plugins/bin/，按 JSON 行协议读写
npx mycomesh-provider start --backend exec --backend-option "command=node /plugins/bin/my-model.mjs" --model my-model-v1
```

内置的 `codex` 后端默认常驻进程并透传：Consumer 的 system 消息替换 Codex 自带的指令，对话历史原样传入，首字更快、输入 token 更少。需要 Codex 原来的指令时加 `--backend-option instructions=codex`。

插件只决定"怎么调用模型"；模型必须属于网络已有的某个档位（档位决定价格、陪审和抽查），新模型档位由网络添加。`env:NAME` 形式的选项只把环境变量名传进容器，密钥不会出现在命令行里。模板和协议说明见 [examples/provider-plugins](examples/provider-plugins)。

- 不需要押金。新 Provider 的未结算敞口上限是 50 tUSDC，随干净成交增长。
- 价格由网络统一给出，不用自己定价；注册时按模型自动进入对应档位。测试网目前有 OpenAI 和 Claude 两个档位，开源模型档位以后开放。
- `status` 看是否真的在线：连上了几个 Relay、今天回答了多少、最近一次回答的时间、模型后端最近的错误（Codex 登录失效会直接提示）。`start` 会等到连上 Relay 才报告完成。
- `earnings` 查看收益，并写明每一笔什么时候能领：托管中的何时放款、保留金何时到期、MYCO 下一批何时解锁。`claim` 一次领完稳定币、到期的保留金和 MYCO；收款钱包没有 ETH 付 gas 时，测试网会先自动领水。网页控制台里是一个"全部领取"按钮。
- 达到陪审资格后会被随机抽进陪审团，自动用自己的模型判案、签名投票。
- 注意：Relay 和第三方探针方会用难题抽查。长期达不到档位应有的水平，会被停止派单，甚至被立案罚没。

## 我有服务器，想跑节点（Relay）

需要公网 IP，开放 10443 和 10991 端口，不需要域名和证书机构：

```sh
npm install --global mycomesh-relay
mycomesh-relay init                # 生成 owner、signer 和自签证书
mycomesh-relay register            # 上链绑定，并把证书指纹登记到链上 Relay 目录
mycomesh-relay start --with-keeper # 同时运行 keeper
mycomesh-relay earnings            # 收益：每笔费用的 5% 和 MYCO 的 7%；claim 领取
mycomesh-relay status              # 连上的 Provider、待结算/已结算/被拒的收据、结算账户还剩多少 gas
mycomesh-relay receipts [--retry]  # 没结算成功的收据和原因；--retry 把还在有效期内的重新排队
```

登记后，Provider 会自动连上来，Consumer 从链上发现你。Relay 还负责结算、放款、抽查 Provider、组织陪审，以及处理合约发起的链上推理请求。

## 我想跑 Keeper

Keeper 只做任何人都能做的兜底调用：批量放款、提交 drand 随机数抽陪审、陪审超时结案。报酬是每次调用的稳定币赏金，加上 MYCO 的 3%：

```sh
git clone https://github.com/Charleslzp/mycomesh && cd mycomesh && pip install -r requirements.txt
python -m mycomesh key new keeper.key        # 给打印出的地址转一点 Sepolia ETH 付 gas
python -m mycomesh keeper serve --network deployments/mycomesh-v11-sepolia.network.json --key keeper.key
```

赏金和 MYCO 会自动领取。

## 我想抓作弊的 Provider（探针方）

任何人都可以发探针：每个 Provider 每天给所有探针方共 20 次免费探针。抓到用便宜模型冒充的 Provider 后，由同档位陪审团用对照组复核定罪；探针方拿到罚没的一半，外加一个块的 MYCO。

```sh
python -m mycomesh key new hunter.key        # 转一点 ETH，以及 1 tUSDC 立案保证金
python -m mycomesh hunter serve --network deployments/mycomesh-v11-sepolia.network.json --key hunter.key \
    --questions my-questions.jsonl           # 可选，自带题目，每行 {"question", "reference", "grader": "number|choice|text"}
```

攒够证据后会自动立案，也可以手动执行 `hunter case --provider <被告 owner 地址>`。

## 我是合约开发者（链上推理）

合约可以直接问模型，在回调里拿到答案。每个请求由一个 Provider 作答，享有同样的签名收据、网络价、托管和陪审保障：

```solidity
settlement.deposit(amount);   // 先在结算合约里存押金
bytes32 id = oracle.request(MycoInferenceOracleV11.Ask({
    tier: 1, model: "gpt-5.5", prompt: bytes("Is 2027 prime? yes or no"), maxOutputTokens: 512, maxFee: 100_000,
    callback: address(this), callbackGas: 200_000,
    finality: MycoInferenceOracleV11.Finality.Immediate,   // 或 AfterDisputeWindow：争议期过后再回调
    disputer: msg.sender
}));

function onInference(bytes32 id, bytes calldata answer, bytes32 settlementKey) external {
    require(msg.sender == address(oracle));
    // 使用 answer
}
```

- 完整示例见 `contracts/examples/MycoInferenceExample.sol`。Sepolia 上已部署并充值，可直接调用 `ask(...)` 试用，实测约 40 秒拿到答案。
- 问题和答案都公开上链，不适合私密内容。
- 答案有问题时：`python -m mycomesh oracle dispute --request-id <ID> --key <disputer key>`。

---

## Sepolia 地址

| 合约 | 地址 |
| --- | --- |
| 结算 Settlement | `0xd46b7efb1e650e83cdeb4a36fdfef33499e54842` |
| 测试稳定币 tUSDC | `0xbce27efad4191277167fe76819581a97959048cf` |
| 陪审与定价 Registry | `0x0ff3210e8e8abf5f5bfa73a39e60db7416b6c8c7` |
| 链上推理 Oracle | `0x5ba28de9415c7bc2d14f3f31a12fbca226e38a8f` |
| 推理示例合约 | `0xe482ae1d02d90140bd4123e53d6baaaf4d06f329` |
| MYCO 代币 | `0x620d026ad854fb17c7b16534a0f28ef5499e2d4a` |
| MYCO 产出 Emission | `0x85ee0e8f63400041f0c76010c590c330bc135a8d` |
| Relay 目录 | `0xa0aaad9393f51cb5786c69f152133a174588bdab` |
| 探针记录 ProbeLedger | `0x1f26a2285eb366d0fd201bea6969abd1aaacb62b` |

完整清单：`deployments/mycomesh-v11-sepolia.network.json`（客户端读取的网络清单）和 `deployments/sepolia-myco-v11.json`（部署记录）。

## 进一步了解

- 白皮书（含经济模型）：[docs/whitepaper.md](docs/whitepaper.md)。
- 设计文档：[docs/v11-design.md](docs/v11-design.md)（结算、定价、MYCO、探针、陪审、链上推理）。
- 开发：`make test` 运行合约测试、本地链端到端测试和 Node 测试；需要 Foundry 1.4.4、Python 3.10+（含 `cryptography`）和 Node 20+。

| 目录 | 内容 |
| --- | --- |
| `contracts/` | 结算、陪审与定价、MYCO 产出与代币、链上推理、Relay 目录、探针记录 |
| `mycomesh/` | Python 实现：Relay、Provider、Keeper、陪审、探针、链上推理 |
| `packages/` | npm 包：`mycomesh-consumer`、`mycomesh-provider`、`mycomesh-relay` |
| `scripts/` | 部署、节点滚动更新、L2 验证、能力探针校准 |
| `examples/` | Provider 后端插件模板 |
