# IP mesh deployment — 2026-09-15

实际部署状态：3 个 Bridge、2 个 Relay 与 Provider2–4 已入网。Provider 签名授权、Relay gas 补充已完成；真实 Consumer Key + URL 请求已覆盖三个 Provider，并产生链上结算。Relay2 仍不可达，不能宣称全部六个网络节点部署完成。

## 节点与入口

地址来自工作区 `envirment.xlsx` 的 Sheet1。未把主机凭据写入部署脚本或本文。

| 节点 | 公网 IP | 当前状态 |
| --- | --- | --- |
| Bridge1 | 166.88.209.61 | 已运行，HTTPS 健康检查通过 |
| Bridge2 | 216.173.64.214 | 已运行，HTTPS 健康检查通过 |
| Bridge3 | 23.27.245.249 | 已运行；Bridge1、Provider2–4 可访问，本地网络直连超时 |
| Relay1 | 136.0.3.126 | 已运行；HTTPS 443、Provider TLS 9901 通过；连接 Provider2、3 |
| Relay2 | 23.27.22.74 | 无法连接 SSH，未部署；多个源主机均无法连接 |
| Relay3 | 166.88.96.60 | 已运行；HTTPS 443、Provider TLS 9901 通过；连接 Provider4 |
| Provider1 | 166.88.209.216 | 保留原部署，本次未迁移 |
| Provider2 | 156.235.89.90 | 已接入 Relay1、全部 3 个 Bridge；真实请求通过 |
| Provider3 | 23.27.163.225 | 已接入 Relay1、全部 3 个 Bridge；真实请求通过 |
| Provider4 | 156.236.76.153 | 已接入 Relay3、全部 3 个 Bridge；真实请求通过 |

各新节点提供 `https://IP/health` 和 `https://IP/.well-known/mycomesh-network.json`。Relay 另提供 `/relay/health` 和 `/v1`；Bridge 不是推理入口。

原 `https://bridge.mycomesh.xyz` 保留为兼容入口。当前 Bridge 之间不是自动 gossip；每个 Provider 的配置都包含 3 个 Bridge，由 Provider 分别签名注册、续期。部署配置只开放当前验证路径中的 `gpt-5.5`，不宣称其他模型已完成实测。

## IP 加密与信任

新节点使用 IP SAN 证书和专用测试网 CA，不需要新增域名或 DNS 记录。Python 的证书验证及 Node 的 TLS 验证均开启；未把 CA 安装到操作系统全局信任库。公共 CA 文件：[`deployments/ip-mesh-testnet-ca.crt`](../deployments/ip-mesh-testnet-ca.crt)。

CA SHA-256 指纹：

```text
D1:24:A1:9A:1F:01:C4:B1:0E:E6:9A:81:E8:12:C6:21:E0:B2:07:60:3D:19:03:FD:5E:A2:91:F9:00:4D:44:20
```

客户端需通过可信分发渠道取得并核对公共 CA。Node 客户端使用进程级 `NODE_EXTRA_CA_CERTS`；Python Provider 使用包含系统 CA 与专用 CA 的 `SSL_CERT_FILE`。浏览器直接访问 IP 不会自动信任此 CA；本地 Consumer 的服务端可负责这些 TLS 连接，不必要求钱包浏览器全局信任 CA。

```sh
curl --cacert deployments/ip-mesh-testnet-ca.crt https://136.0.3.126/health
curl --cacert deployments/ip-mesh-testnet-ca.crt https://166.88.209.61/.well-known/mycomesh-network.json
```

叶证书到期时间为 2026-12-14 04:07:26 UTC；需要在到期前续签并 reload edge，尚未配置自动续签。CA 有效期至 2027-09-15。CA 私钥仅保存在本机 `.codex-run/mesh/pki/ca.key`，未上传服务器；服务器只持有各自 TLS 私钥。应安全备份此目录，不得提交 CA 私钥到仓库。

这只消除了新 mesh 入口的域名依赖；Codex 上游、Sepolia 公共 RPC 和保留的旧入口仍使用各自域名。

## 隔离与运维

Bridge/Relay 使用 `/opt/mycomesh-mesh/app`、独立 Python venv、`/etc/mycomesh-mesh` 配置和 `/var/lib/mycomesh-mesh` 持久数据；没有覆盖原 `/opt/mycomesh`。

每台 Bridge：`mycomesh-ip-bridge.service` + `mycomesh-ip-edge.service`。
每台 Relay：`mycomesh-ip-relay.service` + `mycomesh-ip-edge.service`。
这些服务已配置开机启动，原生应用端口只监听 loopback，公网入口由独立 Nginx 配置承接。Role 进程以专用低权限用户运行，内存上限 768 MiB。

```sh
systemctl is-active mycomesh-ip-relay mycomesh-ip-edge
systemctl is-enabled mycomesh-ip-relay mycomesh-ip-edge
journalctl -u mycomesh-ip-relay --since '10 minutes ago' --no-pager
```

Bridge 节点将上面的 `relay` 换为 `bridge`。停止新部署可执行对应的 `systemctl disable --now mycomesh-ip-relay mycomesh-ip-edge`；这不会删除身份、数据或旧部署。不要运行针对全项目的清理命令。

Provider2–4 使用 `/opt/mycomesh-mesh/mesh.env`（0600）及 `mesh.override.json`。保留现有镜像和以下四个 external named volumes，源码、公开部署参数及 CA 只读覆盖：

```text
mycomesh_mycomesh-provider-data
mycomesh_mycomesh-provider-codex-data
mycomesh_mycomesh-provider-agent-data
mycomesh_mycomesh-provider-workspace
```

初始化会调整卷权限，并生成缺失的内部 agent key；侧车会更新托管的 Codex 配置，但没有重新登录、重置认证或替换既有 Codex auth。新 Provider EVM 身份与节点身份已持久保存，UID/GID 10001、文件 0600。侧车/Provider 内存上限分别为 1400 MiB/384 MiB。

部署入口脚本：[`ip_mesh_node.py`](../scripts/ip_mesh_node.py) 与 [`ip_mesh_provider.py`](../scripts/ip_mesh_provider.py)。前者 `init` 只准备角色配置、身份与 systemd unit；后者 `prepare` 只准备独立 Compose 配置。启动服务是另一个显式步骤。

## 已完成的链上步骤

只读查询已验证 chain ID 为 11155111。Settlement V8：`0x6b543a0ff6fae02172c6f205759b1b9de8a6d218`；收款钱包：`0x8d13f6c18ae30f223d985f39050cc8d9b00f90e1`。

| 节点 | Provider signer | providerSigners 查询 |
| --- | --- | --- |
| Provider2 | 0x6b21fd92347f055802434f83685f8089dfb943c8 | true |
| Provider3 | 0x4d5100e6b1b05994bd5ee8e17dc94255e7af1e5f | true |
| Provider4 | 0xf3217abadf55b970fd029cc17beabc1cc12b099b | true |

| 节点 | 独立 gas submitter | 本次补充 Sepolia ETH |
| --- | --- | --- |
| Relay1 | 0xa0121ad2dc2bb48f2c8b3435b5e491f0c3013ad3 | 0.002 |
| Relay3 | 0x7012be8d81b66f6a040e19e2f78103d663a767e6 | 0.002 |

Relay attestation signer 分别为 `0x44d183a73b1a87801bc18b060a2ce0a7f3aecaaf` 和 `0x420b2033a61491c268c2600c95d1b64ad9b962ca`，与 gas submitter 分离。V8 合约不要求 Relay 白名单，但需要 Provider signer 授权和可支付交易 gas 的提交账户。

用户确认后完成了上述 3 次授权及 2 次 gas 转账，五笔交易均成功并等待至少 6 个区块确认，随后启动 Provider。没有主网交易、USDC 铸币或充值，钱包私钥仅用于本机内存签名，未上传服务器或写入部署文件。

| 操作 | Sepolia 交易哈希 |
| --- | --- |
| Provider2 授权 | `0xc46d238328bd2e6087f420678196bb83a0f13859378dc1593f3bdc0b7c25060d` |
| Provider3 授权 | `0x6f521c90534db49df59c1bd6ce76409f1fca427262274d1a98e9e7c13345ee69` |
| Provider4 授权 | `0x6b512c79ed2b08b6159c8d8d5934d5d77084a7dcab6cf643a2d61e041c5312e6` |
| Relay1 gas | `0x4660dc83ff7610d6b209a11c8784bcbf334954aa246b8fd70a8e23d69bdc4bff` |
| Relay3 gas | `0x2626f6c04335af6f1d962c133754fd9e0699d1cf79074558f744e386255e8c2a` |

Provider 运维启动命令（授权已完成，不要重复发送交易）：

```sh
docker compose -p mycomesh \
  --env-file /opt/mycomesh-mesh/mesh.env \
  -f /opt/mycomesh-mesh/docker-compose.yml \
  -f /opt/mycomesh-mesh/mesh.override.json \
  --profile provider up -d --no-deps --no-build --pull never \
  --wait --wait-timeout 120 provider
```

Provider3 初次启动遭遇公共 RPC 可达性差异：Publicnode 返回 403、dRPC 返回 400，而 ethpandaops 和 Tenderly 均通过真实 chain ID 与授权查询。已为 Provider3 单独配置两个已验证端点，没有放宽鉴权或把所有 HTTP 400 视为可重试。重建配置必须保留：

```sh
--rpc-urls https://rpc.sepolia.ethpandaops.io,https://sepolia.gateway.tenderly.co
```

该参数由 `ip_mesh_provider.py prepare` 提供，同时更新本机 manifest 和 Provider 环境。原 `.env.deploy` 不变。

## Consumer 使用

原 `http://127.0.0.1:8111/v1` 保持运行且未重启，继续使用旧入口。新测试入口复用原支付 Key：

| API URL | Relay 优先顺序 |
| --- | --- |
| `http://127.0.0.1:8112/v1` | Relay1、Relay3 |
| `http://127.0.0.1:8113/v1` | Relay3、Relay1 |

新进程通过真实钱包 challenge/personal_sign/authenticate 解锁原有链上 grant，没有绕过钱包检查，也没有重复注册或充值。支付 Key 仅经本机私有管道进入子进程内存；没有再写一份 Key 文件或将 Key 放入启动参数/操作系统环境。

8112/8113 是本次启动的本地测试进程，不是开机自启服务，重启后需重新签名解锁。它们各自使用 `.codex-run/mesh/consumer-8112`、`consumer-8113` 存放非密钥运行记录。不要直接把 API URL 换成 Relay IP 并发送 Bearer Key：Relay 接受的是 Consumer 为请求生成的付款签名。

## 本次验证及边界

- Bridge1 及 Provider2–4 四个源主机均可通过严格 TLS 访问全部 5 个已部署节点；两条 Relay Provider 9901 端口协商 TLS 1.3，IP SAN 匹配。
- 已进一步在 Provider2–4 的实际侧车容器内验证相同连接：全部健康入口 HTTP 200，两个 9901 端口均为 TLS 1.3；5 台节点的角色及 edge 服务均为 active、enabled。
- 未信任专用 CA 的客户端按预期拒绝证书。没有使用 `-k` 或关闭 TLS 校验。
- 本地访问 4 个可达入口，健康请求约 570–590 ms；Bridge1 访问 5 个入口约 3–11 ms。每项仅 3 次样本，包含建连，不是压测结果、模型生成延迟或 SLA。
- Provider2–4 的 `/health`、`/ready` 及 Docker health 均通过。这里 `settlement_ready` 指侧车计量能力，不证明 Provider 链上授权或已产生可结算收入。
- Provider 上线后，两个 Relay 无付款签名均返回 402；本地 Consumer 缺 Key/无效 Key 均返回 401，无付款回执。两处模型目录均返回 200，并分别指向新 IP Relay。六项非收费检查通过。
- Relay1 的真实 Responses 请求由 Provider3 完成，HTTP 200、4.903 秒；Relay3 的真实 Chat Completions 请求由 Provider4 完成，HTTP 200、9.349 秒。这是短请求样本，不是模型延迟 SLA 或压测结论。
- 临时停止 Provider3 后，Relay1 仅剩 Provider2；真实请求由 Provider2 完成，HTTP 200、5.360 秒。Provider3 已恢复，未修改其登录或身份。
- 停止新 Relay1 的 edge 后，8112 使用同一个 Key 自动选择 Relay3，真实请求 HTTP 200、6.436 秒；随后恢复 edge，三个 Provider 重新出现在全部 Bridge 中。首次控制脚本的 30 秒超时短于 Nginx 的 35 秒长连接关闭窗口，未发送推理即自动恢复；调整等待窗口后完成了上述测试，没有重复付费请求。
- 部署新增单测 13 个、相关网络/Provider/Relay 单测 132 个，共 145 个通过。

四次真实推理总费用为 **0.008521 tUSDC**（8521 个最小单位）。两台 Relay 各有两条 confirmed outbox 记录，独立 RPC 核验了成功交易、正确 submitter、匹配 request ID/provider signer/费用的 `ReceiptSettled` 事件；最终检查四笔均至少 12 个区块确认，未发现重试或重复结算。

| 请求 | 真实路径 | tUSDC | 结算交易哈希 |
| --- | --- | --- | --- |
| Responses | 8112 → Relay1 → Provider3 | 0.002155 | `0x3cea66ea259ee802c8d295b30676e34f8ae786f0e08f0349fc300ab5173b25f4` |
| Chat Completions | 8113 → Relay3 → Provider4 | 0.002206 | `0xb21a16bef58094459d6262d39dd4c5c07042afacb169af12cb01708a931881a6` |
| Provider3 停机 | 8112 → Relay1 → Provider2 | 0.002160 | `0x723853aff3c7d7a75a4407381aa0f8b309208713a6148d45c0c053b57601c89c` |
| Relay1 入口停机 | 8112 → Relay3 → Provider4 | 0.002000 | `0x9803d4ae4d5f32762c73583d7a2e712d02e8484c8838781fc201e557d0ee8893` |

本轮没有做大并发压测、模型目录扩展、真正逐 token 流式输出或公网浏览器 IP 证书自动信任测试。

Relay2 复核：2026-09-15 12:33 北京时间，从本机、Bridge1、Relay1 对其 22/443/9901 共九项 TCP 检查全部超时。需要修复该主机的公网连通性或提供可用管理入口，现有 SSH 信息不足以完成部署。

本地审计证据位于 `.codex-run/mesh/`：`approved-transactions.json`、`chain-readiness.json`、`membership-three-providers.json`、`settlement-verification.json`、`results/`、`relay2-recheck.json`，以及此前 TLS 与服务检查。该目录同时包含敏感 CA/TLS 私钥，不能整体分享；公开报告应只导出必要的非敏感字段。
