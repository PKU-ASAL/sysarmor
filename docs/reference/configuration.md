# 配置参考

本文定义当前 Agent YAML、安装路径、平台端口和主要环境变量。代码中的解析器、部署脚本和 Compose 文件是最终事实来源；未知 Agent section 或 key 会直接报错。

## Agent 配置

默认文件为 `/etc/sysarmor/agent/agent.yaml`，参考配置为 `deployments/agent/standalone.yaml` 和 `configs/agent.example.yaml`。

必填项：`local.state_path`、`sensor.backend`、`sensor.mode`、`policy.path`。所有 duration 使用 Go duration（如 `500ms`、`10s`、`1m`）；字节数必须带 `B`、`KiB`、`MiB` 或 `GiB`。

### 本地状态与导出

| Key | 默认值 | 约束或含义 |
|---|---|---|
| `local.state_path` | `/var/lib/sysarmor/agent` | 身份和本地状态根目录 |
| `local.storage.max_bytes` | `10GiB` | 正数，本地总预算 |
| `local.storage.min_free_bytes` | `2GiB` | 正数，磁盘保留空间 |
| `local.storage.segment_size` | `64MiB` | 正数，事件段大小 |
| `local.storage.signal_max_count` | `100000` | 正数，Signal 数量上限 |
| `local.export.retry_initial` | `1s` | 正数且不大于 `retry_max` |
| `local.export.retry_max` | `30s` | 最大重试间隔 |
| `local.export.request_timeout` | `10s` | 单次请求超时 |
| `local.export.max_inflight` | `1` | 当前只接受 `1` |
| `local.export.wire_compression` | `none` | 线传压缩方式 |

### 身份、控制与运行时

| Key | 默认值 | 约束或含义 |
|---|---|---|
| `agent.label.<name>` | 无 | 任意非空 label 名；身份由 enrollment 管理 |
| `control.socket_path` | `/run/sysarmor/agent/control.sock` | 本地 gRPC Unix socket |
| `runtime.feature_flags.matcher_strategy` | `linear` | `linear` 或 `optimized` |
| `health.interval` | `10s` | 正 duration |
| `policy.path` | `/etc/sysarmor/agent/policy.json` | 统一策略文件 |
| `content.path` | `/var/lib/sysarmor/agent/content` | 已应用内容存储目录 |
| `content.trust_keys` | 空 | 逗号分隔的 `key_id=base64_ed25519_public_key` |
| `resource.max_active_cep_groups` | `4096` | 非负；CEP 活跃组上限 |
| `resource.max_event_refs_per_signal` | `128` | 非负；Signal 事件引用上限 |

### 平台连接

当前 YAML 不接受 `manager:`，也不接受 `agent.id`、`host_id`、`tenant_id` 或 token。设备身份、Gateway 地址和 mTLS 材料由 enrollment 流程写入受保护的本地状态。手工恢复旧版 `manager:` 配置会触发 unknown section 错误，而不是启用平台连接。

### Sensor

| Key | 默认值 | 约束或含义 |
|---|---|---|
| `sensor.backend` | `tetragon` | `tetragon` 或 `fake` |
| `sensor.mode` | `managed` | `managed` 或 `external` |
| `sensor.version` | 空 | 期望的 sensor 版本标签 |
| `sensor.bundle_dir` | 空 | managed bundle 根目录 |
| `sensor.install_dir` | 空 | 已安装 sensor 根目录 |
| `sensor.tetra_path` | 空 | `tetra` 路径 |
| `sensor.tetragon_path` | 空 | `tetragon` 路径 |
| `sensor.event_transport` | `grpc` | `grpc` 或 `tetra` |
| `sensor.server_address` | `unix:///var/run/tetragon/tetragon.sock` | Tetragon gRPC 地址 |
| `sensor.event_source` | 空 | 调试输入；`-` 表示 stdin JSONL |
| `sensor.scope.type` | `host` | `host`、`container`、`cgroup`、`namespace`、`pod` |
| `sensor.scope.selector` | 空 | 非 host scope 必填；namespace 仅支持 `self` |
| `sensor.observe_only` | `true` | 是否只观测 |
| `sensor.restart` | `always` | sensor 重启策略 |
| `sensor.max_restarts` | `5` | 非负 |
| `sensor.restart_window` | `1m` | 重启观察窗口 |
| `sensor.max_parse_errors` | `0` | 允许的解析错误阈值 |
| `sensor.max_dropped_events` | `0` | 允许的丢弃阈值 |

性能和底层路径参数还包括 `cgroup_rate`、`pprof_address`、`gops_address`、`process_cache_size`、`data_cache_size`、`event_queue_size`、`rb_queue_size`、`btf_path`、`bpffs_path`、`require_btf`、`require_bpffs` 和 `fake_startup_events`。只有基于测量结果调优或测试 fake backend 时才应覆盖它们。

### Telemetry

| Key | 默认值 | 有效范围 |
|---|---:|---:|
| `telemetry.max_batch_items` | `256` | `1..4096` |
| `telemetry.max_batch_bytes` | `256KiB` | `64KiB..16MiB` |
| `telemetry.flush_interval` | `1s` | `100ms..1m` |

统一 Policy 可在有效范围内覆盖这些基线值。

## Endpoint Policy

`policy.path` 指向的 JSON 是 Agent 实际应用的统一 Endpoint Policy，不是 Manager 保存的发布元数据。顶层必填 `policy_id`、正整数 `version`，以及 `collection`、`detection`、`telemetry`、`response` 四个对象。安装包使用的最小有效结构为：

```json
{
  "policy_id": "standalone-default",
  "version": 1,
  "collection": {
    "behaviors": ["process.exec", "file.write", "network.connect"],
    "observe_only": true
  },
  "detection": {},
  "telemetry": {
    "max_batch_items": 256,
    "max_batch_bytes": 262144,
    "flush_interval": "1s"
  },
  "response": {}
}
```

| Section | 主要字段 | 约束 |
|---|---|---|
| `collection` | `behaviors`、`binary_prefixes`、`file_prefixes`、`socket_families`、`socket_addrs`、`socket_ports`、`scope_type`、`scope_selector`、`observe_only` | `behaviors` 接受行为 ID 数组，也接受带 selector 的对象数组 |
| `detection` | `policy_id`、`version`、`mode`、`scope`、`rulesets`、`rule_overrides`、`context_refs`、`ioc_refs` | 空对象使用当前默认检测行为；未解析引用当前可能被跳过或降级 |
| `telemetry` | `max_batch_items`、`max_batch_bytes`、`flush_interval` | Agent 配置表中的有效范围同样适用 |
| `response` | `allowed_actions`、`allowed_modes`、`approval_required`、`approval_threshold`、`approval_roles`、`allow_destructive` | 空对象归一化为默认 `collect`/`noop` 与 `observe`；破坏性动作必须显式允许 |

Endpoint Policy 顶层以及 detection、telemetry、response 使用 strict decoding；Collection 子结构当前使用普通 JSON 解码，可能忽略未知字段。未知 ruleset 也可能得到零条有效规则，context 或 IOC 引用可能被跳过。不要把“解析未报错”当作字段或引用已经生效，必须检查 explain report 和实际有效规则。应用前执行：

```bash
sudo sysarmorctl policy explain --file /path/to/policy.json
sudo sysarmorctl policy apply --file /path/to/policy.json --dry-run
```

完整示例以 `deployments/agent/policy.json` 为准，四层策略的设计与变更方法见[策略指南](../guides/policy.md)。Manager Policy 另含 tenant、发布、分配和云侧收敛元数据，不应直接写入 Agent 的 `policy.path`。

## 安装路径覆盖

安装器支持通过环境变量覆盖目标路径，常用项如下：

| 变量 | 默认值 |
|---|---|
| `SYSARMOR_AGENT_HOME` | `/opt/sysarmor/agent` |
| `SYSARMOR_AGENT_DST` | `$SYSARMOR_AGENT_HOME/bin/sysarmor-agent` |
| `SYSARMOR_CTL_DST` | `/usr/local/bin/sysarmorctl` |
| `SYSARMOR_SERVICE_DST` | `/etc/systemd/system/sysarmor-agent.service` |
| `SYSARMOR_CONFIG_DST` | `/etc/sysarmor/agent/agent.yaml` |
| `SYSARMOR_POLICY_DST` | `/etc/sysarmor/agent/policy.json` |
| `SYSARMOR_TETRAGON_BUNDLE_DIR` | `$SYSARMOR_AGENT_HOME/bundles/tetragon` |
| `SYSARMOR_TETRAGON_INSTALL_DIR` | `$SYSARMOR_AGENT_HOME/sensors` |
| `SYSARMOR_ENABLE_SERVICE` | `1` |

## 平台端口

| 变量 | 宿主机默认端口 | 容器端口 |
|---|---:|---:|
| `SYSARMOR_MANAGER_UI_PORT` | `4173` | `4173` |
| `SYSARMOR_MANAGER_PORT` | `19443` | `9443` |
| `SYSARMOR_GATEWAY_PORT` | `19444` | `9444` |
| `SYSARMOR_GATEWAY_HEALTH_PORT` | `19445` | `9445` |
| `SYSARMOR_PACKAGE_PORT` | `18080` | `80` |
| `SYSARMOR_POSTGRES_PORT` | `15432` | `5432` |
| `SYSARMOR_KAFKA_PORT` | `19092` | `9092` |
| `SYSARMOR_REDIS_PORT` | `16379` | `6379` |
| `SYSARMOR_OPENSEARCH_PORT` | `29200` | `9200` |

## 服务环境变量

| 服务 | 核心变量 |
|---|---|
| Manager | `SYSARMOR_POSTGRES_DSN`、`SYSARMOR_OPENSEARCH_URL`、`SYSARMOR_ARTIFACT_DIR`、`SYSARMOR_AGENT_PACKAGE_INDEX_URL`、`SYSARMOR_ARTIFACT_PUBLIC_KEY`、`SYSARMOR_AGENT_CA_CERT`、`SYSARMOR_AGENT_CA_KEY`、`SYSARMOR_JWT_PUBLIC_KEY_FILE`、`SYSARMOR_JWT_ISSUER`、`SYSARMOR_JWT_AUDIENCE` |
| Gateway | `SYSARMOR_POSTGRES_DSN`、`SYSARMOR_KAFKA_BROKERS`、`SYSARMOR_REDIS_ADDR`、`SYSARMOR_GRPC_TLS_CERT`、`SYSARMOR_GRPC_TLS_KEY`、`SYSARMOR_GRPC_CLIENT_CA` |
| Worker | `SYSARMOR_POSTGRES_DSN`、`SYSARMOR_KAFKA_BROKERS`、`SYSARMOR_KAFKA_TOPIC`、`SYSARMOR_KAFKA_GROUP_ID`、`SYSARMOR_OPENSEARCH_URL` |
| Manager Console | `AUTH_SECRET_FILE`、`SYSARMOR_BOOTSTRAP_ADMIN_USERNAME_FILE`、`SYSARMOR_BOOTSTRAP_ADMIN_PASSWORD_FILE`、`SYSARMOR_BFF_JWT_PRIVATE_KEY_FILE`、`SYSARMOR_MANAGER_JWT_ISSUER`、`SYSARMOR_MANAGER_JWT_AUDIENCE`、`MANAGER_API_ORIGIN` |

示例值位于 `deployments/{manager,gateway,worker,manager-ui}/*.env.example`。示例中的数据库密码只适用于隔离的本地 Compose；生产环境必须从环境或机密管理系统注入。

Manager 与 Worker 的生产启动路径要求 PostgreSQL，`SYSARMOR_POSTGRES_DRIVER` 默认是
`postgres`，`SYSARMOR_POSTGRES_DSN` 必须非空；不存在 memory/file backend 配置或自动回退。
Worker 还要求非空 Kafka brokers/topic/group 与 OpenSearch URL。OpenSearch 基本认证可通过
`SYSARMOR_OPENSEARCH_USERNAME` 和 `SYSARMOR_OPENSEARCH_PASSWORD` 注入，禁止写入仓库配置。

## `configs/` 的边界

`configs/` 保存策略和规则元数据示例，运行时不会自动发现或加载该目录。Agent 默认值在 `deployments/agent/`，wire contract 在 `packages/contracts/proto/`，可执行测试内容在 `test/data/`。没有显式 loader 或 apply 流程时，不要把 `configs/` 中的文件视为已部署策略。
