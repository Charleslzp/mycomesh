# 独立钱包 Consumer 与归属提示修复

用户在 Chrome / OKX 签名后遇到 `this local payment key belongs to a different wallet`。只读链上核对确认：8120 是先前自动验收实例，支付 Key `0x5e69a109b24e623da7af21d0137f942e6f3a65d4` 属于测试钱包 `0x452bfe4c9b59455504068b2594979bcd531c9e49`；当前 OKX 钱包为 `0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1`。浏览器连接和钱包签名本身正常，原后端归属检查正确拒绝了不同钱包。

用户选择使用当前 OKX 钱包建立独立 Consumer，保留旧测试实例。

## 已完成

- 新入口：`http://127.0.0.1:8121/`，在 Chrome 新标签打开。
- 独立资料：`/Users/lzp/.mycomesh/consumer/profiles/sepolia-v10-0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1/`。
- 新支付 Key 公共地址：`0x9dc649f9cc1f9d8ef158de908dc63bfcccafa67a`。私密凭证保存在独立 `state/payment-key`，权限 0600，未输出凭证。
- 同一个受控 Sepolia V10 合约、固定 Relay 身份和 CA 校验；没有复制原测试钱包的 Key、会话、预算或历史。
- 创建资料时没有预算通道，链上 Key 未激活；初始创建和检查没有发送链上交易。后续开通记录见下文。
- 8120 仍运行原测试身份；新服务采用独立目录和端口，无需停止、重置或轮换旧实例。

## 软件修复

- 登录页显示本机支付 Key 的公开归属；选错钱包在请求签名前提示账户不符及恢复方法。
- 后端签名和归属检查保留，并返回稳定错误码 `payment_key_owner_mismatch` 及公共地址字段，不返回支付凭证或会话 token。
- 链上读取失败使用 `wallet_verification_unavailable`，不绕过核验。
- V10 的登录会话只在全部链上检查成功后写入，失败登录不会产生部分会话或覆盖已有正确会话。
- 登录错误持续展示，不再只有短暂英文 toast。

新增 7 项针对性测试，连同核心 Consumer、V10 固定预算、本地访问边界测试共 53 项通过，0 跳过。包括签名前阻止错误账户、后台强校验、RPC 故障、已有会话保护，以及未注册 Key 可登录但不能推理。

实际安装产物：`artifacts/consumer-wallet-profile-20260919/mycomesh-consumer-0.1.51.tgz`，SHA256 `027dc7bfb688f3559aefd91f6de4987ac9e0371c354e4e5ccefc729899186179`。已校验安装后的 runtime 与测试源码一致。修复已用于新 8121 实例，旧 8120 未重启或替换产物；未发布 npm。

## 初始浏览器检查记录

Chrome 已实际打开 8121，并在 OKX 连接当前账户。签名数据已核对为 `MycoMesh Consumer wallet login`，钱包为用户选择的账户、Payment key 为新独立地址，内容仅解锁本地 Consumer。点击确认后钱包窗口消失，随后 Chrome 读取连续超时，因此本轮不宣称已核验登录后的页面。服务健康检查仍正常；`wallet_unlocked=false` 表示推理访问尚未激活，不能单凭该字段判断登录签名是否已被接收。

1. 使用当前 OKX 钱包完成新入口的登录签名。
2. 在钱包中明确确认链上 Key 激活；激活不等于已开通请求预算。
3. 开通当前钱包和新 Key 的独立预算，并完成 Provider 预激活，才能执行付费推理。

不得为消除归属错误而删除旧 Key、导入测试钱包私钥、关闭归属校验或迁移旧账本。原测试预算属于原链上 owner，不会自动转给新钱包。

本机产物证据：`artifacts/consumer-wallet-profile-20260919/profile-start.json` 与 `profile-verification.json`。

## 用户继续授权后的开通进度

2026-09-19 后续通过 Chrome 扩展连接读取到 8121 的登录页面，显示钱包 `0x8d13…90e1`；初始签名已成功登录。用户提供的资金私钥也对应这个钱包，链上余额约 41.0119 Sepolia ETH，因而没有执行无意义的 2 ETH 自转，也没有给只签请求的支付 Key 转 ETH。

已使用仅在内存中的用户 owner 签名完成三笔交易，并核验规范链确认；私钥未写入项目文件或持久化执行日志：

| 操作 | 限额 | 交易 |
|---|---|---|
| 注册新 Key | 单次 0.1 tUSDC | `0x24ebc83a7bfda769fe39126d3ed7945eed03c4b2e3ff1b71a70046d05d61c3a1` |
| 授权稳定币 | 仅 5 tUSDC | `0xf24aa8f679f9d930270dc8ef161ae7030a2e11445c5b8d18dbf0f68387a5b715` |
| 充值 | 5 tUSDC | `0x7eb0c8df1b777044fe8135922694fda1db1c5ab602e4f5b2ab8bf76883a1e45c` |

Provider 原可用质押不足 5 tUSDC，且旧通道尚未到释放期。已为受控 Provider 补充并质押 4.596353 tUSDC 测试币，没有从用户消费余额划转；三笔操作实际 gas 合计 0.000234416336045598 ETH。首次 mint 广播未知后使用完全相同的持久化交易字节恢复，未换 nonce 或重复增发。

独立预算已双签开通并完成链上确认，交易 `0xbc4f8a48c461a2dc62823d95d5515b9b6bdadfde7ce8d7927eed45b8e1bf2d8a`。通道 ID：`0x305e07221a79d5cb0648ba5092da8163cf9c5bdb2ae2fc0d99f84bef1216949d`。预算 5 tUSDC，单次授权上限 0.1，绑定 P2 / R1，可用模型包含 GPT-5.6 Sol。

- 北京时间 2026-09-19 19:34:48 开始接受请求。
- 2026-09-20 01:34:48 停止接受新请求。
- 2026-09-20 04:34:48 后可释放剩余预算。
- 结算继续使用 2 小时或 100 笔先到触发，单批最多 32 笔。

P2 已于 11:18 UTC 完成预激活：只追加 1 条通道，原 2 条通道与 72 条执行记录完整保留，同一个容器和结算 timer 均恢复。证据：`channel-preparation/activate-independent-provider2-20260919T111813Z-ba80729c.json`。还需完成本地资料发布、登录和生效后的实际 Sol 请求。

同轮小修复：后续 UI 充值的 ERC20 approve 从无限额改为本次充值金额；已有足够 allowance 时仍跳过 approve。4 项新增额度边界测试连同相关登录/Consumer 测试共 31 项通过。新包保留旧产物另行冻结：`artifacts/consumer-wallet-profile-20260919/exact-topup/mycomesh-consumer-0.1.51.tgz`，SHA256 `d503b7d1d15f4f7b70dac5565d4901e133ea482eabeae23e7db8e5290243638a`。12 个包文件均与已测源码和独立安装内容一致，尚待本轮换入预算 manifest 时统一重启 8121。

交易计划和脱敏结果：`artifacts/consumer-wallet-profile-20260919/channel-preparation/`。原 8120 账本、Key 和运行实例保留。

通道生效后完成了一次真实验收请求：`gpt-5.6-sol` 返回 `391`，Provider response proof 通过，耗时 12.486 秒，实际费用 7,477 个最小 tUSDC 单位（约 0.007477 tUSDC），授权上限 100,000。请求 ID 为 `0x154716543ab7a2d8e58003c53fc278b4c295a5385da1cf29fc480d3cb1f37fa3`，当前记录为 pending settlement，剩余通道预算 4.9 tUSDC，约可按单次上限再发 49 次。结算仍遵守 2 小时或 100 笔先到、单批 32 笔。结果证据：`channel-preparation/consumer-after-request.json`。

最终本地包在 8121 重启前已冻结并安装，SHA256 为 `0f0f57129637fa1928b4d3c375dd6bd12381ba04d1e29e0b28e149a6ec87706d`；新增 onboarding 状态和额度边界后，相关 67 项测试通过，0 跳过。它让已匹配的链上 Key 跳过重复注册、空交易计划不再触发钱包或切网，并把“已充值但尚未分配预算”单独显示。验证记录：`onboarding-state-fix/package-verification.json`。
