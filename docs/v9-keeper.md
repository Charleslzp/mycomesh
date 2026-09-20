# V9 到期托管维护

`python -m gateway.relay_keeper_v9` 从已确认的 `ReceiptEscrowed` 日志发现账单，保存扫描游标和待处理账单，按当前链上状态释放已成熟且无争议的托管，或处理超过完整仲裁期限的非惩罚性 timeout。它不举报、不投票、不裁决、不罚没、不代用户 claim。释放后的收益是可领取余额，不能称为已到账。

默认 dry-run 只读取链，不加载签名密钥。SQLite 会保存扫描结果和可审阅的计划，因此重启后能继续扫描。链、genesis、合约 runtime、policy、委员会和确认数复用 `V9OperatorConfig`；每次执行前重新校验当前状态。新模块不改变合约参数或 Relay 的批量结算周期。

## 部署接线

1. 使用专用 keeper EVM 账户。不能复用 Relay submitter、reporter、juror、Consumer、Provider、treasury 或其他程序正在使用的密钥；所有 keeper 实例必须共享同一 durable SQLite 文件。`--dedicated-sender` 是对这一运维约束的显式声明，不能阻止外部钱包擅自复用密钥。
2. 密钥文件只允许当前服务用户拥有的 0400/0600 常规文件。数据库与其 `.lock` 文件位于持久 0700 目录，不能放在临时目录或多个独立容器卷中。SQLite `BEGIN IMMEDIATE` 跨进程保护 nonce 分配，cycle 文件锁串行化扫描与计划选择。
3. `--config` 指向已审核 `V9OperatorConfig` JSON；`--actor` 是专用 keeper 地址；`--start-block` 是准确部署区块。已部署受控网络为 chain `11155111`、合约 `0x8ed70585cb60082e6f8e64f5190a3d8014e42367`、部署块 `11728132`，应保持 controlled_test/false-independence 的诚实配置。
4. 先不带 `--send` 运行，查看候选动作与 calldata。确认与部署范围一致后启用 `--send --dedicated-sender`、保护的 key file 及每笔 gas 上限。服务样例为 `deploy/mycomesh-v9-keeper.service` 和 `.timer`，没有自动安装或启动。
5. `/etc/mycomesh/v9-keeper.env` 只放公开参数：`KEEPER_ACTOR`、`SETTLEMENT_DEPLOYMENT_BLOCK`、`RELAY1_SUBMITTER`、`RELAY3_SUBMITTER`、`KEEPER_MAX_GAS_PRICE_WEI`、`KEEPER_MAX_GAS_UNITS`、`KEEPER_MAX_TX_GAS_WEI`。不把私钥放在环境变量或命令行。

本受控部署必须排除的 Relay sender 分别为 `0x7c4ec6822150c5f5b6b8c861c08f30686ba234f9`、`0x349be2a4e18ad0a2cecfe4348eaededba79b28af`。通用 CLI 可用多次 `--reserved-sender` 排除更多发送者。

## 资金、恢复和能力边界

Keeper 只需要链上原生测试 ETH 支付 gas，不需要 token allowance、stablecoin 或治理权限。每次执行会用 `eth_estimateGas` 加 20% 和 10,000 gas 余量；必须同时不超过 gas price、gas units 和总 gas cost 三个上限。按 500,000 gas 与 5 gwei 的保守上限，每笔预算为 0.0025 测试 ETH，两笔最多 0.005；实际应先用 live dry-run 的 estimate 设定。此为费用上限，不是实际报价，也不是日累计花费限制。持续运营还需要余额告警与有上限的充值策略。

签名原文、tx hash、nonce、精确计划先持久提交，再广播。重启优先对既有 hash 做确认，任何 sending/submitted/uncertain 状态都会阻塞新 nonce。默认不重发；显式 `--resume-signed` 只会广播数据库中完全相同的已签名字节，不重新签名、提价或换 nonce。这样可恢复“持久化后、广播前崩溃”。nonce 已被其他交易使用、存储 hash 错误、业务状态不符或重组时停止处理并保留记录。

确认 EVM receipt 成功后还检查完整链上业务结果和区块确认；只有与原账单匹配的 released/timed_out 才记录业务成功。扫描游标区块发生重组会拒绝整个周期；需先核对已保存交易，再显式修复/重建扫描索引，不能删除 transaction outbox 清除未知状态。

首版每个周期最多广播一个新 nonce，等待其确认与业务核验后才继续。即使按每笔约一分钟确认估算，一轮 100 笔也可能需要约 100 分钟；RPC 调用和 30 秒 timer 还会增加耗时。它适合当前受控网络，不能宣称能持续消化任意规模的“100 笔先到”结算流量。公开持续服务前，需要批量 release/timeout 能力或经过验证的受限 nonce 流水线，以及 oldest mature escrow age、待处理数量、扫描延迟和 sender 余额监控。扫描块数和每周期候选数有上限，避免一次全链无限读取。
