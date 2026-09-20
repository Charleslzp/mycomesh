# V9 合约部署工具

入口：`python3 -m gateway.v9_deployment`。规划只读；`execute` 和 `rebroadcast` 默认也不发送。该工具部署一个新的 V9 合约，不初始化 Provider、迁移 V8 余额、创建治理身份或声明尚未落实的独立裁决运营者。

## 输入

使用已审阅的 Forge `MycoSettlementV9.json` 编译产物和一份显式 policy JSON。部署时不会重新编译或隐式下载工具。policy 文件只包含以下字段，未知字段会被拒绝；所有金额都是代币最小单位，时间都是秒。

| 字段 | 含义 |
| --- | --- |
| `chain_id`, `genesis_hash` | 事先确认的链 ID 和创世区块哈希 |
| `deployer` | 专用部署账户公开地址；不能同时在其他钱包/进程使用其 nonce |
| `stablecoin`, `reward_token` | 已有 ERC-20 合约地址；禁用代币奖励时 `reward_token` 显式为零地址 |
| `treasury`, `governance` | 金库和治理实际地址 |
| `channel`, `channel_hash` | 渠道名称和 bytes32 渠道标识 |
| `network_id`, `channel_id`, `backend_policy` | 网络清单所需的公开标识 |
| `adjudicators`, `adjudication_threshold` | 裁决成员地址数组及严格多数阈值，至少两票 |
| `adjudicator_operators`, `independence_attested` | 地址到实际运营者标识的映射，以及真实的独立性声明 |
| `confirmations` | 导出正式清单前要求的确认数 |
| `initial_config` | 下述全部定价和分成字段 |
| `policy` | 下述全部不可变争议政策字段 |

`initial_config` 必须包含：

```text
input_per_1k, output_per_1k, minimum_fee,
provider_bps, relay_bps, pool_bps, treasury_bps, active
```

四种分成合计必须为 10000，`active` 必须为 `true`。`policy` 必须包含：

```text
dispute_window, arbitration_timeout, consumer_withdrawal_delay,
reporter_bond, slash_bps, slash_cap, reporter_bounty_bps, stable_bounty_cap,
token_reward, token_reward_cap, token_minimum_exposure, token_minimum_penalty,
bond_penalty_recipient
```

本次测试网要求禁用代币奖励：`reward_token` 为 `0x0000000000000000000000000000000000000000`，四项 `token_*` 金额显式为 `0`。这项构造选择不能在部署后开启；将来启用奖励需新部署。稳定币举报保证金、罚没和赏金规则仍然存在，须给出实际参数。

工具复用 `chain_v9.validate_deployment` 校验经济边界和裁决者声明。不同地址或不同字符串不证明独立控制，工具不会代填 `independence_attested`。没有真实配置时不能用单元测试 fixture 作为发布政策。

## 规划与执行

以下 `$DEPLOY_*` 均是操作者已明确配置的变量，没有内置经济预算。

```sh
python3 -m gateway.v9_deployment --rpc-url "$DEPLOY_RPC" plan \
  --policy "$DEPLOY_POLICY" --artifact "$DEPLOY_ARTIFACT" \
  --output "$DEPLOY_PLAN"
```

RPC 必须为单个 HTTP(S) 端点，不接受逗号回退列表，避免未验证的回退 RPC 参与发送。规划核对 chain/genesis、区块新鲜度、ERC-20 非空代码、无外部待处理 nonce、预测地址空闲，并通过 `eth_estimateGas` 执行构造模拟。计划包含构造 calldata、编译产物 SHA-256、运行时代码模板、token 代码哈希、预测地址、完整公开政策和 gas 估计。

`manifest_candidate` 只是构造预期，不能作为已部署证据或直接用于现网激活。完整计划保存在指定文件；该文件和正式清单都采用独占创建，不覆盖已有文件。

```sh
# 不提供 --send 时只验证计划文件，不读私钥、不广播。
python3 -m gateway.v9_deployment --rpc-url "$DEPLOY_RPC" execute \
  --plan "$DEPLOY_PLAN" --outbox "$DEPLOY_OUTBOX"

# 发送要求匹配完整计划哈希及三个显式预算上限。
python3 -m gateway.v9_deployment --rpc-url "$DEPLOY_RPC" execute \
  --plan "$DEPLOY_PLAN" --outbox "$DEPLOY_OUTBOX" --send \
  --approved-plan-hash "$DEPLOY_PLAN_HASH" --key-file "$DEPLOY_KEY_FILE" \
  --max-gas-price-wei "$DEPLOY_MAX_GAS_PRICE_WEI" \
  --max-gas-units "$DEPLOY_MAX_GAS_UNITS" \
  --max-total-gas-cost-wei "$DEPLOY_MAX_TOTAL_GAS_COST_WEI"
```

私钥文件仅接受当前用户所有、权限 `0400` 或 `0600` 的普通非符号链接文件，内容是一行十六进制专用账户私钥。不要将其放入 shell 参数、环境变量、仓库或报告。工具核对地址，并在签名前重新检查网络、政策、token 代码、nonce 和 gas；任何关键变化均要求重新生成计划。gas limit 使用估值的 120% 加 10000，并同时受总成本上限约束。

## 恢复与正式清单

SQLite outbox 使用 `synchronous=FULL`，在首次广播之前持久保存完整签名交易及本地计算的交易哈希。重启后再次 `execute` 同一计划只返回既有状态，不分配新 nonce、不重新签名。sender 存在未解决交易时，同一 outbox 阻止其他部署计划。

```sh
python3 -m gateway.v9_deployment --rpc-url "$DEPLOY_RPC" reconcile \
  --outbox "$DEPLOY_OUTBOX" --plan-hash "$DEPLOY_PLAN_HASH" \
  --manifest-output "$DEPLOY_MANIFEST"
```

确认数不足、receipt 不存在或执行失败时不会输出正式清单。成功需要 canonical receipt、预期合约地址、与编译模板一致的 runtime（仅忽略编译器声明的 immutable 字节位置），以及 stablecoin、rewardToken、governance、treasury、policy、完整裁决名单、阈值、EIP-712 domain、初始定价版本和 pricing hash 全部匹配。结果同时返回实际 runtime hash 和 genesis pin，正式 manifest 可被现有 V9 loader 读取。

每次核验先持久清除旧的 `confirmed` 和业务结果；RPC 错误、重组或验证失败会保持 `uncertain` 并阻止新 nonce，直到后续核验恢复。即使之前成功过，也不能将失败的当前核验视为成功。

仅在确需恢复广播时执行：

```sh
python3 -m gateway.v9_deployment --rpc-url "$DEPLOY_RPC" rebroadcast \
  --outbox "$DEPLOY_OUTBOX" --plan-hash "$DEPLOY_PLAN_HASH" --send
```

该命令先尝试核验，未终结时只重播 outbox 中相同的签名交易字节，因此 nonce、gas、交易哈希均不变。没有自动加价替换或跳过 nonce 功能。不要删除/新建 outbox 来绕过未知广播结果，也不要同时用不同 outbox 操作同一个部署账户。

## 验证

```sh
python3 -B -m unittest tests.test_v9_deployment
```

默认单测使用合成身份和模拟 RPC。设置 `RUN_MYCO_V9_LOCAL_CHAIN=1` 及 `tests/test_v9_local_chain.py` 所述本地 EVM/编译产物参数后，还会运行一次真实 localhost 部署和完整链上核验。

2026-09-18 验证：15 项单测及 1 项真实 Hardhat localhost 测试通过；使用 solc `0.8.28`、Prague 产物，metadata 中 `contracts/MycoSettlementV9.sol` 的源码 keccak 与当前文件一致。产物 SHA-256：`32224ec5a262c9d3d72578d8b7e79c8a9ce742fc2befeab243bb79ab6f1af1c2`；运行时代码 23455 字节。此记录只证明本地部署流程，不代表 Sepolia 已部署。
