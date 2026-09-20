# 2026-09-16 网络恢复记录

## 根因和处置范围

Relay1、Relay3 的进程均耗尽 `RLIMIT_NOFILE=8192`。Relay1 持有 4092 个
`relay-settlement.sqlite3` 句柄和 4092 个 WAL 句柄；Relay3 分别为 4093、4092 个。
`RelaySettlementOutbox._connect()` 每次返回新连接，调用方使用
`with sqlite3.Connection` 仅提交或回滚事务，没有显式关闭连接。
监听队列随后积压；现场 Python 3.14.4 的 `socketserver` 在 accept 抛出
`OSError` 后直接返回、不退避，与观察到的高 CPU 忙循环一致。

经批准，先 Relay3、后 Relay1，仅修复远程
`/opt/mycomesh-mesh/app/gateway/session_relayer.py`：增加所需导入，将 `_connect()`
改为上下文管理器，在事务退出后通过 `finally: db.close()` 关闭连接。
每台均检查原文件哈希、创建唯一备份、编译检查语法，并在重启前再次只读确认数据库完整、
没有待处理或广播状态不明的回执，然后重启 `mycomesh-ip-relay.service`。
**没有整包部署 V9，没有修改身份、密钥或经济配置，没有发送付费请求或资金交易。**

## 文件校验与备份

两台修改前后哈希相同：

- 修改前 SHA256：`a0115899a1693bec0dcce6e322d8358d3e7bd485bd84158045b047f1b632aa3e`
- 修改后 SHA256：`a6e38bc8b575d10c8b7ac7923c2b504300fcf187911b117cda59ff6a69735b66`
- Relay3 备份：`/opt/mycomesh-mesh/app/gateway/session_relayer.py.pre-fd-close-20260916T050850Z-e0bf99cb`
- Relay1 备份：`/opt/mycomesh-mesh/app/gateway/session_relayer.py.pre-fd-close-20260916T051038Z-dec02623`

## 恢复验证

| 节点 | 修复后 FD | 修复后 RSS | 3 秒 CPU 采样 | 数据库只读结果 |
| --- | ---: | ---: | ---: | --- |
| Relay1 | 5–6 | 约 78 MiB | 0.00% | `integrity_check=ok`；confirmed 9、failed 2 |
| Relay3 | 6–8 | 约 78 MiB | 0.33% | `integrity_check=ok`；confirmed 6 |

两台的回执状态计数在重启前后不变，均无 pending、submitted 或 broadcast_unknown。
修复前 RSS 约 700 MiB；修复后本机 health 请求约 3–12 ms，热循环消失。
这是短时恢复检查，不等于长期稳定性或负载测试。

随后从本地经公网、严格校验证书信任链的 health 检查结果：

| 节点 | 公网 health 结果 | 就绪情况 |
| --- | --- | --- |
| Bridge1 | HTTP 200，约 573 ms | health 可访问 |
| Bridge2 | HTTP 200，约 568 ms | health 可访问 |
| Bridge3 | 7 秒超时 | 尚未恢复确认 |
| Relay1 | HTTP 200，约 682 ms | settlement ready；0 Provider，inference false |
| Relay2 | 7 秒超时 | 尚未恢复确认 |
| Relay3 | HTTP 200，约 573 ms | 3 Provider；inference、settlement 均 ready |

以上均为 **health 检查耗时，不是模型推理性能测试**。本机 health 的 3–12 ms
也不能作为公网端到端响应时间。当前不能宣称所有节点或 Relay1 的推理服务已经恢复。

## 回滚注意

如确需回滚，应先核验当前文件仍为上述修改后哈希，并确认没有后续变更；
只使用该节点列出的原文件备份，还原这一个 `session_relayer.py`，随后受控重启并重新验证。
不要覆盖整个应用目录、回退数据库、删除 WAL/SHM，或修改身份和结算配置。
还原旧文件会重新引入连接泄漏；若出现新故障，应优先诊断，而非直接撤销修复。
