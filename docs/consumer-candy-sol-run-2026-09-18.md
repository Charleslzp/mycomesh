# Consumer 糖果题：指定 GPT-5.6 Sol 的实际调用

2026-09-18，按用户要求完成一次 Consumer → Relay1 → Provider2 的实际推理。请求明确指定 `gpt-5.6-sol`，返回 HTTP 200，响应与付款绑定验签通过，没有重放或模型回退。端到端耗时 **27.342 秒**。

## Provider 原始回答

> 按主句最少21颗：摸9颗圆形、12颗五角星形。9颗圆形必有苹果或桃子味；12颗五角星必有相反口味，故保证异形异味配对。括号第二个“苹果味”应为“桃子味”；若按括号字面理解，需圆形苹果配任一非西瓜味五角星，最少摸18圆形、5五角星，共23颗。

题目主句要求不同形状的苹果与桃子，括号却将第二种组合写成两个苹果，存在歧义。主句解释下，利用手感选择形状，答案为 **21 颗（9 圆形 + 12 五角星形）**；括号字面解释下为 **23 颗（18 圆形 + 5 五角星形）**。原始回答中对笔误的判断不代表用户已确认题意。

## 调用与模型证据

| 项目 | 本次记录 |
| --- | --- |
| Relay | `https://136.0.3.126:10443` |
| Provider | Provider2 |
| 请求和返回模型 | `gpt-5.6-sol` |
| 请求推理强度 / 输出预算 | `low` / 2000 |
| 输入 / 输出 / 总 token | 7699 / 1147 / 8846 |
| Request ID | `0x4f3a43b069cf72b1e913f512f39745fd9ffa5255c3a899cf65ff08c3f84a4ea0` |
| Provider signer | `0x6b21fd92347f055802434f83685f8089dfb943c8` |
| Codex thread / turn | `01a0b2fe-549d-7692-bab2-13f433fca7d5` / `01a0b2fe-54e6-7882-b7f5-756598462386` |

调用前，实际账号的 `model/list` 确认可用 Sol。仅 Provider2 的 Provider 与侧车模型名单扩展为 `gpt-5.5,gpt-5.6-sol`，默认及内部模型仍为 5.5。运行代码对显式 Sol 请求按原值转发到 `thread/start` 和 `turn/start`；模型启用后 Relay1 正确公布 Sol。节点变更详见[部署记录](v9-deployment-status-2026-09-18.md)。

证据边界：后端使用 `ephemeral:true`，没有保存此次 `turn_context`，无法事后通过持久化运行上下文独立复核模型和推理强度。已核验的是账号模型可用性、实际配置与转发代码、请求模型及签名响应模型；协议签名不是上游模型身份的独立密码学证明。核查没有额外启动推理。

## 链上账单

实际费用 **12287 个最小单位，即 0.012287 测试稳定币**。Sepolia 合约 `0x8ed70585cb60082e6f8e64f5190a3d8014e42367` 已托管该账单。

- 结算交易：`0x1e35edf2cdba3e24b4c1e27a484a67885023c600596510e431977cd2a3984dfa`
- 结算键：`0x7da19b50faf6a2b2b6dcce2d0bd73597d92e147976c5576713b2121771d14562`
- 入块高度 11728673；核验快照 11728678，已有 **6 个确认**。
- 快照状态 `pending` 表示账单已托管、尚未释放，不是交易未入块；`release_at=1789709736`。本次未执行释放或收益领取。

## 本地证据

所有路径相对于仓库根目录下的 `.codex-run/mesh/v9-controlled-test-20260918/`：

- `consumer-runs/candy-20260918-sol/provider-answer.txt`：原始答案。
- `consumer-runs/candy-20260918-sol/verified.json`：验签后的响应及耗时。
- `consumer-runs/candy-20260918-sol/settlement-verified.json`：链上固定区块核验。
- `provider2-sol-readonly-model-audit.json`：账号模型列表与调用前配置核查。
- `provider2-sol/audit.json`：Provider2 模型名单变更审计。
- `provider2-sol/consumer-runtime-model.json`：精确转发核查及临时会话的证据限制。

此前 GPT-5.5 调用另见[原运行记录](consumer-candy-run-2026-09-18.md)，与本次账单分别保留。
