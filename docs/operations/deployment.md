# 部署

本文说明当前仓库支持的两种部署方式：单机 Agent 和本地管理平台。测试专用的 VM、容器拓扑不属于生产部署，统一见测试指南。

## 部署选择

| 目标 | 入口 | 适用场景 |
|---|---|---|
| 单机 Agent | `make install-agent` | 无平台连接的主机采集、检测和本地调查 |
| GitHub 发行包 | Release 页面中的 `install.sh` | 可追溯的 standalone 候选版本或正式版本 |
| 本地管理平台 | `make deploy` | 端云链路、集中管理和开发验证 |

当前 Compose 配置面向单机开发和验证，默认凭据、无安全插件的 OpenSearch 以及宿主机暴露的基础设施端口不应直接用于生产环境。

## 前置条件

- Linux；安装 Agent 还要求 systemd 和 root 权限。
- Go、Docker Compose、`make`、OpenSSL 和 `curl`。
- 构建 release 或运行真实测试时，需要与主机架构匹配的 Tetragon 归档；可设置 `SYSARMOR_TETRAGON_ARCHIVE`，或将 `tetragon-v1.7.0-amd64.tar.gz` 放入仓库 `.cache/`。

真实测试环境使用独立的完整预检：

```bash
make test-doctor
```

## 安装单机 Agent

```bash
make install-agent
sudo sysarmorctl agent health
```

安装器构建 Agent 和 `sysarmorctl`，安装 Tetragon bundle，写入默认配置和策略，并启用 `sysarmor-agent.service`。Sensor installer 未收到本地 archive 时会使用 `deployments/sensors/tetragon/bundle.env` 中的版本与下载地址。

| 路径 | 内容 |
|---|---|
| `/opt/sysarmor/agent/bin/sysarmor-agent` | Agent 可执行文件 |
| `/opt/sysarmor/agent/bundles/tetragon/` | Tetragon 原始 bundle |
| `/opt/sysarmor/agent/sensors/` | 已安装的传感器版本 |
| `/etc/sysarmor/agent/agent.yaml` | Agent 运行配置 |
| `/etc/sysarmor/agent/policy.json` | 端侧策略 |
| `/var/lib/sysarmor/agent/` | 身份、本地事件、Signal 与有界状态 |
| `/run/sysarmor/agent/control.sock` | 本地控制面 Unix socket |
| `/usr/local/bin/sysarmorctl` | 管理命令行 |

默认配置运行 managed Tetragon、host scope 和 observe-only 模式，不连接平台。注册信息由 enrollment 写入本地状态，不应手工添加到 YAML。自定义安装路径和配置项见[配置参考](../reference/configuration.md)。

### 安装 GitHub 发行包

在 Forgejo Releases 页面选择目标版本，使用该版本说明中的固定 URL。候选版本标记为
Pre-release；正式版本不带该标记：

```bash
curl -fsSL https://github.com/PKU-ASAL/sysarmor/releases/download/<tag>/install.sh | sudo bash
```

公开发行包支持 Linux x86_64；默认 `linux-systemd` profile 安装主机服务，
`linux-container` profile 用于容器镜像。RC tag 采用 `vX.Y.Z-rc.N`，正式版本采用
`vX.Y.Z`。安装脚本下载同一 Release 的归档，校验固定 SHA-256，安装后等待 Agent 健康检查
通过。重复安装会更新程序和 systemd unit，但保留已有配置、策略和本地数据。

GitHub 公开归档只包含 SysArmor。安装时从 Tetragon 官方 Release 下载锁定版本并校验固定
SHA-256，从而避免在第三方许可证清单完成前重新分发其二进制。需要完全离线的一体包时，仍须先完成
第三方 LICENSE、NOTICE、SBOM 和源代码提供义务审查。

可使用 GitHub CLI 验证构建来源：

```bash
gh attestation verify sysarmor-agent-linux-amd64-<tag>.tar.gz --repo PKU-ASAL/sysarmor
```

### 安装到容器镜像

容器 profile 在 Docker build 阶段只安装文件并写入 `namespace/self` 配置，不启动 eBPF。
容器运行时由 `/usr/local/bin/sysarmor-container-entrypoint` 先启动 Agent，等待健康后再执行
Dockerfile 的业务命令：

```dockerfile
FROM ubuntu:22.04

ARG SYSARMOR_INSTALL_URL
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl util-linux \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "$SYSARMOR_INSTALL_URL" \
    | bash -s -- --profile linux-container

ENTRYPOINT ["/usr/local/bin/sysarmor-container-entrypoint"]
CMD ["sleep", "infinity"]
```

运行容器时必须提供 eBPF 所需权限与宿主机资源，并配置容器级恢复：

```bash
docker run -d --name sysarmor-endpoint \
  --privileged --cgroupns=host --restart unless-stopped \
  -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  <image>
```

入口脚本原样执行其参数。改造 Vulhub 等已有镜像时，必须把原 `ENTRYPOINT` 及参数作为
SysArmor 入口的业务命令显式保留，否则可能跳过配置展开、权限切换、数据库初始化或漏洞环境准备。
不同 Vulhub 镜像的入口语义并不统一，应逐镜像验证，不能假设通用 Dockerfile 自动兼容。

容器内 root 仍可 kill Agent；入口脚本会让容器异常退出，Docker restart policy 负责恢复，避免业务
在 Agent 消失后静默继续运行。这是故障可见与恢复机制，不是防篡改边界。需要抵抗容器内高权限攻击者时，
应由宿主机 Agent 与 eBPF LSM 提供外部保护。

## 启动本地平台

```bash
make deploy
make status
make doctor
```

`make deploy` 依次完成：构建服务二进制、生成签名 Agent release、初始化 PKI 和登录凭据、构建镜像并启动 Compose。标准数据流为：

```text
Agent -> Gateway -> Kafka -> Flink Normalize/Detection/Projection -> OpenSearch
Browser -> Manager Console BFF -> Manager
```

完整 Compose 平台包含 Kafka、Kafka topic 初始化、RustFS checkpoint 存储、Flink
JobManager、TaskManager、Normalize Job、Detection Job、Projection Job、PostgreSQL、Redis、
OpenSearch、Manager、Gateway 和 Manager UI。查看服务状态：

```bash
make status
```

默认宿主机入口：

| 服务 | 地址 | 用途 |
|---|---|---|
| Manager Console | `http://127.0.0.1:4173` | 登录、部署和查询界面 |
| Manager | `http://127.0.0.1:19443` | Operator HTTP API |
| Gateway | `127.0.0.1:19444` | Agent mTLS gRPC |
| Gateway health | `http://127.0.0.1:19445` | `/healthz` 和 `/metrics` |
| Package feed | `http://127.0.0.1:18080` | 已签名 Agent release |
| PostgreSQL | `127.0.0.1:15432` | 控制面状态 |
| Kafka | `127.0.0.1:19092` | 原始遥测交接 |
| Redis | `127.0.0.1:16379` | Gateway 热状态 |
| OpenSearch | `http://127.0.0.1:29200` | Event、Signal、Incident、Evidence 投影 |

端口均可通过 `SYSARMOR_*_PORT` 环境变量覆盖。例如：

```bash
SYSARMOR_OPENSEARCH_PORT=39200 make deploy
```

## 身份与信任

`make auth-init` 在 `deployments/pki/agent-plane-mtls/runtime/` 创建：

- Auth.js session 密钥和一次性 bootstrap 管理员凭据；
- BFF 签发 Manager JWT 所需的 RS256 密钥；
- Agent plane mTLS CA、Gateway 证书和 artifact 签名密钥。

已有完整凭据不会被覆盖。不要提交 `runtime/` 中的私钥或密码；非本地环境应使用外部密钥和机密管理系统。

浏览器只调用同源 BFF。BFF 校验 session 后签发短期 Manager JWT；浏览器不持有该 JWT，也不直接调用 Manager。Agent 证书使用以下 URI SAN 绑定 tenant 和 Agent：

```text
spiffe://sysarmor.local/tenant/<tenant_id>/agent/<agent_id>
```

Gateway 同时校验证书链、URI 身份和每个数据/控制帧中的 tenant、Agent ID。

## Release 与注册

```bash
make release RELEASE_VERSION=v1.0.0
```

产物写入 `dist/release/`。Package 服务提供不可变字节，Manager 管理 artifact 元数据、channel、一次性 enrollment 和安装脚本。

本地平台 Agent bundle 还包含 Tetragon、bpftool、gops 和 BPF 对象等第三方资产。仓库根目录的 MulanPSL-2.0 只覆盖 SysArmor，不改变第三方组件的许可证。在完成逐项许可证清单、LICENSE/NOTICE 携带和全部打包文件完整性校验前，该一体 bundle 只用于开发与评估，不能作为已经完成外部分发合规的制品发布。GitHub 发行包使用不携带 Tetragon 二进制的 thin 包，不属于该一体 bundle。

推荐从 Manager Console 的 Deploy 页面选择 artifact、channel 和安装 profile，然后在目标端执行生成的安装命令。完整流程为：

```text
构建并签名 artifact -> 绑定 channel -> 创建一次性 enrollment
-> 用一次性 bootstrap ticket 获取安装器 -> 下载并校验包
-> 端点生成私钥与 CSR
-> Manager 签发 tenant/Agent 绑定证书 -> Agent 连接 Gateway
```

安装 URL 中只包含一次性 bootstrap ticket。ticket 首次读取安装脚本后失效，Manager 同时轮换 enrollment token；安装器将 token 写入临时 `0600` 文件，并通过 Authorization header 下载受保护 artifact，避免凭据进入 URL、代理访问日志和进程参数。

Manager 只保存 token 哈希，并以 enrollment 中的 tenant、Agent ID、Gateway 和 TLS server name 为准。端点私钥不离开端点；同一 token 的重试绑定同一公钥和证书。默认只上传 enrollment 边界之后的数据；只有明确需要历史数据时才启用 `--upload-history`。

安装 profile：

- `linux-systemd`：安装并启用 systemd 服务，适用于主机或 VM。
- `linux-container`：不使用 systemd，scope 为 `namespace/self`；Manager 安装器在本次 enrollment 中启动 Agent，业务镜像仍需显式集成容器入口与原业务命令。

## 生命周期命令

```bash
make status                 # 查看平台服务
make down                   # 停止并保留数据卷
make up                     # 使用现有镜像和 release 启动
make reset                  # 删除数据卷并重建；保留 PKI
make clean                  # 停止平台并删除数据卷
sudo sysarmorctl unenroll   # Agent 返回 standalone
make uninstall-agent        # 保留配置和本地数据
make uninstall-agent PURGE=1
```

`reset`、`clean` 和 `PURGE=1` 会删除状态或数据，执行前先按[维护指南](maintenance.md)完成备份。
