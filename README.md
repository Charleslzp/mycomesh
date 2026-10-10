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

命令行用法：

```sh
npx mycomesh-consumer init                          # 付款 key + 本机加密钱包
npx mycomesh-consumer setup --deposit 20000000      # 存 20 tUSDC（单位 1e-6）；测试网会先自动领水
npx mycomesh-consumer request "什么是零知识证明？"
npx mycomesh-consumer dispute last --statement "答非所问"   # 24 小时内可争议，由陪审团判定
npx mycomesh-consumer rewards claim                 # 领取 MYCO
npx mycomesh-consumer withdraw                      # 取回押金（申请后等延迟期再执行一次）
```

**接到自己的工具里**：`npx mycomesh-consumer serve` 在 `http://127.0.0.1:8110/v1` 提供 OpenAI 兼容接口（`responses`、`chat/completions`、`models`，支持流式），Codex、各种 SDK 改一下 base URL 就能用。

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

**接入任意模型（插件）**：后端是插件式的。内置 `codex`、`openai`（任何 OpenAI 兼容接口：OpenAI、vLLM、Ollama、DeepSeek、OpenRouter 等）、`anthropic`，以及 `exec`（任何语言写的程序）。自己的后端放进 `~/.mycomesh/provider/plugins/` 即可：

```sh
cp examples/provider-plugins/template_plugin.py ~/.mycomesh/provider/plugins/   # 一个 Python 文件 = 一个后端
npx mycomesh-provider backends                                                   # 列出可用后端
npx mycomesh-provider start --backend my-model --backend-option api_key=env:MY_MODEL_KEY --model my-model-v1
# 任何语言：程序放在 plugins/bin/，按 JSON 行协议读写
npx mycomesh-provider start --backend exec --backend-option "command=node /plugins/bin/my-model.mjs" --model my-model-v1
```

插件只决定"怎么调用模型"；模型必须属于网络已有的某个档位（档位决定价格、陪审和抽查），新模型档位由网络添加。`env:NAME` 形式的选项只把环境变量名传进容器，密钥不会出现在命令行里。模板和协议说明见 [examples/provider-plugins](examples/provider-plugins)。

- 不需要押金。新 Provider 的未结算敞口上限是 50 tUSDC，随干净成交增长。
- 价格由网络统一给出，不用自己定价；注册时按模型自动进入对应档位。测试网目前有 OpenAI 和 Claude 两个档位，开源模型档位以后开放。
- `earnings` 查看收益，`claim` 一次领取稳定币和到期的 MYCO。
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
