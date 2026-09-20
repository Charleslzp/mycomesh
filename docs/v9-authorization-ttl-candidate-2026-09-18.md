# V9 授权有效期升级候选（未部署）

本候选将新编译合约的 `MAX_AUTHORIZATION_TTL()` 从 3600 秒调整为 10800 秒，为两小时结算调度留出余量。EIP-712 版本、价格哈希、签名角色、委员会规则、费用及资金归属均不变。已经部署的旧 V9 合约仍是 3600 秒，修改源码不会改变链上合约。

**仅延长授权不能保证两小时延迟结算可用。** 请求执行后、上链前的 Consumer 余额和 Provider 质押敞口仍须由独立措施控制。未完成该保护及集成验收前，不应将这个候选宣称为可公开使用的两小时批量结算。

## Manifest 字段

字段位于 V9 deployment JSON 顶层，也可作为 `gateway.v9_deployment` 输入 policy 的可选顶层字段：

```json
{
  "max_authorization_ttl_seconds": 10800,
  "authorization_deadline_seconds": 9000
}
```

- `max_authorization_ttl_seconds`：合约允许的完整 `deadline - issuedAt` 上限，只支持 3600 或 10800。缺省为旧值 3600。
- `authorization_deadline_seconds`：从客户端当前时间到 `deadline` 的秒数。缺省为 900，因此旧 manifest 仍保留 15 分钟剩余有效期。
- Consumer 将 `issuedAt` 回溯 300 秒容纳时钟差，必须满足 `authorization_deadline_seconds + 300 <= max_authorization_ttl_seconds`。候选的实际完整签名窗口为 9300 秒，剩余窗口为 9000 秒。
- 字段必须为 JSON 整数，不接受布尔值、字符串、零或越界值。旧默认字段在 Python canonical 输出中省略，避免重写既有部署计划/manifest 的哈希。

## Python 与部署校验

普通旧 manifest 路径保持原有 900 秒 deadline，不增加 RPC 依赖。显式配置超过 900 秒时，Consumer 在生成签名前调用 `verified_authorization_window`：从固定 manifest 的 RPC 校验链 ID，读取最新块并检查头时间与本地时间差不超过 300 秒，再在同一 `blockHash`、`requireCanonical=true` 快照上读取 `MAX_AUTHORIZATION_TTL()` 与 `keyGrants(address)`。

链上上限必须与 manifest 精确相同；消费 key 必须存在、active、单笔上限覆盖报价上限，且 `validUntil` 为 0（合约定义的不限期）或足够覆盖整个 deadline。任何不匹配、RPC 失败或 key 将提前到期都拒绝生成该长授权，不自动改成短授权后继续执行。

底层签名构造函数默认仍限制 3600 秒；显式长授权必须由调用者传入已验证的 `max_authorization_ttl`。通用 V9 验签函数支持至 10800 秒，以允许新旧凭据验证；这不替代 Relay/Provider 对自己固定合约上限的执行前检查。

部署工具会把 TTL 字段纳入批准的计划，并在确认阶段对精确部署块读回 getter。与声明不符时不会输出已验证 manifest。部署当前新编译 artifact 时应显式填写上述 10800/9000；旧无字段 policy 仍被解释为 3600，不会自动升级。

## 迁移约束

1. 旧合约地址和新合约地址属于不同 EIP-712 domain。不能把旧凭据改地址后提交，也不能重新签名伪装旧交易。
2. 在旧合约上排空已执行但尚未结算的有效凭据；已过期或结果未知的凭据必须单独核对，不重新执行请求来掩盖旧账单。
3. 旧合约中 pending/disputed 的费用、stake 锁定及 claimable 款项继续在旧合约处理。切换发现入口不迁移余额、不删除旧 outbox/journal、不取消争议。
4. 新合约部署和身份授权、测试币资金及 stake 初始化完成并逐项读回后，再切换新的固定 manifest。需要有覆盖新旧地址的明确账单/keeper 处理策略。
5. 在 Consumer、Relay、Provider 都能验证新上限，且两小时离链敞口保护通过后，才启用长窗口。失败时切回短授权和旧入口必须保留新合约已有账务，不能假定不存在已执行请求。

本文件描述源码候选；没有向外部链发送部署、转账或授权交易，也没有修改线上 manifest。
