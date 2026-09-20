# 网络冗余与故障恢复验收（2026-09-16）

范围：经济模型不变；仅做免费公网健康读取、本地真实 HTTP/TCP 故障注入和一处注册恢复修复。
没有 SSH、远程发布、模型推理、链上交易或身份配置变更。测试私钥为仅用于本地夹具的固定值。

## 当前判断

现有实现具备多入口注册、发现、Relay 备用连接、同 Provider 会话粘性和未知结果不重放。
这些是有效的冗余机制，但不能由节点数量推导出当前服务具备多条可用路径，
也不能声称任意网络故障下无感或跨 Provider 无损恢复。

2026-09-16 05:34:59 UTC 从本地经公网读取，使用
`deployments/ip-mesh-testnet-ca.crt` 校验 HTTPS 信任链和 IP 主机名：

| 节点 | 结果 | 对服务能力的含义 |
| --- | --- | --- |
| Bridge1、Bridge2 | HTTP 200；各发现 3 个 peer | 两个发现入口可用，不代表不同的 6 个 Provider |
| Bridge3 | 7 秒超时 | 本次未验证可用 |
| Relay1 | HTTP 200；结算就绪；0 Provider | 不能提供推理 |
| Relay2 | 7 秒超时 | 本次未验证可用 |
| Relay3 | HTTP 200；3 Provider；推理及结算就绪 | 当前实际推理集中于同一个 Relay |

成功的公网 health 调用本次约 3.1 秒；它受本机至节点路径影响，不是模型时延或 SLA。
这是一个时点的观察，不是长期在线率或外网所有位置的连通性结论。

## 已修复：一个坏 Bridge 不应中断全部注册

`gateway/client.py::join_provider_pools` 原来顺序调用 Bridge，并且仅捕获 `PoolError`。
真实 HTTP 响应头黑洞会直接抛出 `TimeoutError`，坏 JSON 会抛出 `JSONDecodeError`，
两者都可能中止注册回调，导致尚未尝试的健康 Bridge 也不可用。
对已转换成 `PoolError` 的普通网络错误，多 Bridge 超时还会逐个叠加。

修复包括：

- 最多 8 个并行网络调用，共享一个总体注册 deadline；排队调用不得获得新的完整超时预算。
- 对每个远端调用隔离失败；一个坏 JSON、断连或超时不取消其他 Bridge 的注册。
- 签名描述符仍在调用线程串行生成，避免 transport-key 轮换的并发混用。
- 同一个 Bridge URL 只注册一次；结果和错误回调保持配置顺序。
- 返回前等待已启动调用结束，不在 Relay 身份切换后留下旧注册后台任务。

同一真实 loopback HTTP 夹具中，3 个响应头黑洞加 1 个健康 Bridge，每个调用设置 0.4 秒：
逐个执行同样请求并逐个记录异常为 1207 ms，修复后的共享预算并行为 403 ms，均有 1 个健康响应。
这里的串行对照特意记录异常后继续；原函数遇到裸 `TimeoutError` 会更早直接失败。
这些数字只说明故障隔离和超时叠加，不说明模型吞吐或生产网络恢复时限。
底层系统 DNS 解析等非可中断操作仍可能超过 Python socket 的预算，不能将其宣传为硬实时保证。

## 真实故障注入覆盖

`tests/test_network_resilience_flow.py` 使用真实 loopback HTTP 监听和真实 Provider/Relay TCP 监听，
未替换连接、注册、发现或路由网络函数。7 项覆盖：

1. 3 个 Bridge 响应头黑洞时，健康 Bridge 仍能完成注册，整体预算不串行叠加。
2. 坏 JSON、接受连接后断开均隔离于该 Bridge。
3. 描述符串行生成、重复 URL 去重和结果顺序。
4. 超过 8 个注册时，排队工作也受同一 deadline 约束。
5. 非法预算在产生描述符或联网之前失败。
6. 黑洞和坏 JSON 的发现入口不丢掉健康入口的 peer。
7. 真正关闭主 Relay 的 Provider TCP 连接，原 Provider 身份连接备用 Relay，并成功处理新的 ping。
   清理旧注册回调发生在改变 Relay 签名/收款绑定之前；不重放原请求。

第 7 项使用 local 网络配置、非付费 ping 和测试身份，不等于远程 TLS、真实推理、
执行中断线恢复或黑洞检测全部通过。已有付款、回执和会话安全测试属于其他验收项。

复现：

```sh
python3 -m unittest tests.test_network_resilience_flow tests.test_pool tests.test_client tests.test_relay_robustness tests.test_relay_scheduler -q
```

该命令本轮 177 项全部通过（8.223 秒），`git diff --check` 通过。

## 尚存边界

- **发现不是开放的 gossip/DHT。** Bridge 的 `bootstrap_pools` 当前只作为配置和 health 元数据，
  未实现 Bridge 间反熵同步；Provider 需要向显式配置的 Bridge 多点注册。
- **控制面仍有可用性依赖。** 非 local Provider 要求至少一个 Bridge 注册租约有效；
  默认 TTL 30 秒。全部 Bridge 失联后，即使已有 Relay 连接仍在，也会拒绝新推理。
  本轮没有为了可用性放宽此安全门禁。
- **TCP 主动关闭不等于网络黑洞。** 现有空闲连接检测不能据一次主动断连试验推导出
  丢包、防火墙静默丢弃或半开连接的恢复时间；需要专门的心跳和黑洞测试。
- **会话不是随意切账号。** 原 Provider 离线时，其他 Provider 不持有其上游会话状态。
  后续请求仅能跟随同一个已验证 signer 改走 Relay；执行中且结果未知的请求不能安全自动重放。
- **当前容量集中。** 3 个 Provider 全在 Relay3，Relay1 虽可自动承接未来断连迁移，
  但此刻不能独立提供推理。该现状、共同上游和同一网络配置/证书信任域仍是相关故障风险。
- **没有生产长期压力验收。** 本轮不证明持续负载、真实流式首字延迟、丢包恢复或 P95/SLA 达标。

本轮修复尚未发布到远端。宽范围另跑 `tests.test_p2p` 时仍有一个既存错误文本断言失败：
`test_handle_infer_rejects_model_outside_provider_descriptor` 期望旧文本，而实现返回
`requested model is not supported by provider`；未修改拒绝行为或为变绿而放宽安全检查。
