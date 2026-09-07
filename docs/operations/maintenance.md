# 维护与故障处理

本文覆盖运行状态检查、备份、升级、Schema 演进和恢复。部署步骤见[部署指南](deployment.md)。

## 日常检查

平台部署后执行：

```bash
make status
make doctor
```

`make doctor` 会验证认证材料、核心容器、Manager 和 UI 健康端点、未登录访问拒绝，以及 bootstrap 用户通过 BFF 调用 Manager 的完整链路。

Agent 检查：

```bash
sudo systemctl status sysarmor-agent
sudo sysarmorctl agent health
sudo sysarmorctl agent capability
sudo sysarmorctl policy current
```

重点关注：传感器运行状态、事件丢弃、解析错误、重启次数、batch 队列、发送重试、CEP 降级和当前有效策略版本。

Gateway 健康：

```bash
curl -fsS http://127.0.0.1:19445/healthz
curl -fsS http://127.0.0.1:19445/metrics
```

## 日志定位

```bash
journalctl -u sysarmor-agent -n 200 --no-pager
docker compose -f deployments/compose.platform.yaml logs --tail=200 manager gateway flink-detection flink-projection
docker compose -f deployments/compose.platform.yaml ps
```

按链路由前向后排查：

1. Agent 是否收到传感器事件，是否出现 parse/drop/restart。
2. Agent batch 是否积压，Gateway mTLS 是否通过。
3. Gateway 是否向 Kafka 写入，Flink Job 是否消费或写入 DLQ。
4. PostgreSQL 控制状态与 OpenSearch 投影是否可用。
5. BFF session、JWT issuer/audience 与 Manager 公钥是否一致。

禁止把依赖错误转成空成功结果；命令、API 或脚本失败必须保留状态码和错误正文。

## 备份与恢复边界

必须分别保护四类状态：

| 状态 | 默认位置 | 恢复要求 |
|---|---|---|
| Agent 身份与本地历史 | `/var/lib/sysarmor/agent/` | 保留权限；身份私钥不得复制到另一 Agent |
| 平台控制状态 | Compose `postgres-data` | 与目标版本数据库结构兼容 |
| 搜索投影 | Compose `opensearch-data` | 可从保留的数据源重建时仍建议保留快照 |
| PKI 和登录机密 | `deployments/pki/agent-plane-mtls/runtime/` | 私密备份，恢复原权限 |

停止写入后再做一致性备份：先停止 Agent 上传或平台写入，再备份 PostgreSQL、OpenSearch 和 PKI，最后记录 release、镜像和 Schema 版本。不要把 Redis 当作权威存储。

恢复顺序：PKI 和基础设施、PostgreSQL、OpenSearch、Manager/Gateway/Flink，最后恢复 Agent 连接。恢复后执行 `make doctor` 并验证一条真实 Event/Signal 链路。

## 升级原则

1. 构建带明确版本的签名 release，禁止覆盖已发布 artifact。
2. 先升级能同时读取新旧契约的消费者，再升级生产者。
3. 通过 channel 小范围绑定，检查 Agent health、drop、retry 和资源指标。
4. 扩大范围前保留旧 artifact、旧索引和回滚 channel。
5. 只有 Kafka 保留窗口内不再出现旧 Schema 后，才移除旧兼容逻辑。

Agent 升级不得改变 tenant/Agent 身份；安装 profile 只改变生命周期和 sensor scope。

## OpenSearch Schema 演进

### Alias 与物理索引

应用不直接访问带版本的物理索引，而是通过稳定 alias 间接访问：

```text
Manager 查询、Flink 历史读取 -> read alias  -> 当前物理索引
Flink 写入安全投影           -> write alias -> 当前物理索引
```

三类名称承担不同职责：

- **物理索引**保存真实文档和 mapping，名称中的 `v1`、`v2` 表示 Schema 版本。
- **读 alias**是查询入口。Manager 和 Flink 无需知道当前物理版本。
- **写 alias**是写入入口，必须且只能有一个目标标记为 `is_write_index=true`。

初始关系如下：

| 数据 | 读 alias | 写 alias | 初始物理索引 |
|---|---|---|---|
| Event | `sysarmor-events-read` | `sysarmor-events-write` | `sysarmor-events-v1` |
| Signal | `sysarmor-signals-read` | `sysarmor-signals-write` | `sysarmor-signals-v1` |
| Incident | `sysarmor-incidents-read` | `sysarmor-incidents-write` | `sysarmor-incidents-v1` |
| Evidence | `sysarmor-evidence-read` | `sysarmor-evidence-write` | `sysarmor-evidence-v1` |

例如，初始状态下 `sysarmor-incidents-read` 和 `sysarmor-incidents-write` 都指向 `sysarmor-incidents-v1`。升级后两个 alias 改为指向 `sysarmor-incidents-v2`，但应用使用的名称不变，因此不需要随 Schema 版本修改代码或配置。

缺少 alias 是部署错误，应用不会回退到 `sysarmor-incidents` 之类的无版本索引。显式失败可以避免新旧数据被写入不同位置、写入成功但查询不可见，或者错误 mapping 被静默创建。

### 何时需要新版本

新增可选字段且不改变既有查询语义时，可以兼容更新 mapping 和模板；模板只影响以后创建的索引，当前物理索引需要使用对应的 mapping 更新。以下变化不能依赖原地修改，必须创建新物理索引：

- 改变字段类型，例如由 `keyword` 改为 `date`；
- 改变分词、聚合或精确匹配方式；
- 改变字段含义，需要重算历史文档；
- 新分析逻辑要求历史数据采用不同结构。

### 从 v1 迁移到 v2

以 Incident v1 升级到 v2 为例：

1. **创建 v2。** 使用已审查的 mapping 创建 `sysarmor-incidents-v2`。此时读写 alias 仍指向 v1，线上流量不受影响。
2. **复制历史数据。** 将 v1 reindex 到 v2。第一次复制用于搬迁大部分数据，但迁移期间 Flink Projection 仍可能向 v1 写入，因此此时不能切换。
3. **验证 v2。** 比较文档数，并验证 tenant、时间范围、精确 Incident ID 和关键聚合。只比较总数不足以发现字段类型或查询语义错误。
4. **收敛写入差异。** 当前最稳妥的方式是短暂停止 Flink Projection，再执行一次最终 reindex。只有具备经过验证的变更游标或双写能力时，才能用增量同步替代停写。
5. **原子切换。** 在同一个 `POST /_aliases` 请求中移除 v1 的两个 alias，并将它们添加到 v2。OpenSearch 要么应用全部动作，要么全部不应用，不会留下“读 v2、写 v1”的中间状态。
6. **恢复并观察。** 恢复 Flink Projection，确认 bulk 写入落到 v2，Manager 能通过 read alias 查到新数据，并持续检查 mapping、DLQ 和文档计数。

原子切换请求的结构是：

```json
{
  "actions": [
    {"remove": {"index": "sysarmor-incidents-v1", "alias": "sysarmor-incidents-read"}},
    {"remove": {"index": "sysarmor-incidents-v1", "alias": "sysarmor-incidents-write"}},
    {"add": {"index": "sysarmor-incidents-v2", "alias": "sysarmor-incidents-read"}},
    {"add": {"index": "sysarmor-incidents-v2", "alias": "sysarmor-incidents-write", "is_write_index": true}}
  ]
}
```

切换前后检查：

```text
GET /_alias/sysarmor-*-read
GET /_alias/sysarmor-*-write
GET /_cat/count/sysarmor-incidents-v2?v
GET /sysarmor-incidents-read/_search
```

### 回滚边界

保留 v1，直到 v2 通过约定的观察窗口。如果 v2 出现 mapping、查询或写入问题，应先暂停投影，再用一次 `POST /_aliases` 将两个 alias 原子移回 v1。切换到 v2 后产生的新文档不会自动出现在 v1；恢复写入前必须确认这些差异已经回放或明确接受丢弃。

调查完成前不要删除失败索引。删除 v1 是迁移完成后的独立操作，不应与 alias 切换放在同一个请求中。

## 常见故障

### Agent 无法启动

- 检查 `/etc/sysarmor/agent/agent.yaml` 是否包含必填的 `local.state_path`、`sensor.backend`、`sensor.mode`、`policy.path`。
- 检查 Tetragon 可执行文件、BTF、bpffs 和 systemd 日志。
- 使用 `sudo sysarmorctl agent capability` 确认实际支持的采集行为。

### Agent 无法连接 Gateway

- 使用 `sysarmorctl agent health` 检查 enrollment 和传输状态，必要时重新执行受支持的 enrollment 流程；不要在 YAML 中手工添加 `manager:`。
- 确认证书 URI SAN 中的 tenant/Agent 与 Agent 帧一致。
- 检查系统时间；证书和 enrollment token 都依赖有效时间窗口。

### Manager 或 UI 登录失败

- 执行 `make auth-init` 补齐机密集，但不要手工只生成其中一个文件。
- 检查 runtime 文件权限：私钥、密码和 session secret 应为 `0600`。
- 核对 BFF 和 Manager 的 JWT issuer、audience 与密钥对。

### 搜索无结果但上游正常

- 确认 OpenSearch read/write alias 存在并指向同一预期版本。
- 检查 Flink Job 日志、Kafka consumer group 和 DLQ。
- 区分“合法空结果”和依赖失败；后者应返回明确错误。

### VM 测试找不到 libvirt

先运行 `make test-doctor`。它会检查 Vagrant、`vagrant-libvirt`、libvirt URI 和 Tetragon archive，并给出针对性的修复建议。不要通过修改 `VAGRANT_HOME` 指向空目录来绕过检查。

## 卸载

```bash
make uninstall-agent
```

默认删除二进制、systemd unit 和运行目录，保留 `/etc/sysarmor/agent/` 与 `/var/lib/sysarmor/agent/`。确认不再需要身份、配置和本地历史后才执行：

```bash
make uninstall-agent PURGE=1
```
