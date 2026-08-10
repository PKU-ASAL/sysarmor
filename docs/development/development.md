# 开发指南

本文说明代码归属、构建入口和变更规则。测试方法独立维护在[测试指南](testing.md)。

## 开发入口

```bash
make help
make build-binary
make test-unit
```

前端依赖统一使用 pnpm：

```bash
make web-install
make web-build
```

后端为 Go，不在仓库中维护手工下载的生成代码或二进制；构建产物写入 `dist/`。

## 仓库边界

| 目录 | 负责内容 |
|---|---|
| `apps/*/cmd/` | 各产品的薄可执行入口和依赖组装 |
| `packages/contracts/proto/` | Agent 数据面与控制面 wire contract |
| `apps/agent/internal/` | 配置、本地状态、注册、Policy 和 daemon 生命周期 |
| `apps/agent/internal/endpoint/` | 事件规范化、匹配和端侧检测 |
| `apps/agent/internal/sensors/` | Sensor 运行时与平台适配器实现 |
| `apps/manager/internal/adapters/inbound/grpc/` | Agent-facing mTLS Data/Control gRPC adapters |
| `apps/manager/internal/ingest/` | 持久遥测消费和投影 |
| `apps/manager/internal/analytics/` | 云端关联、证据图和事件分析 |
| `apps/manager/internal/` | Operator API、鉴权和控制面流程 |
| `apps/manager/internal/store/` | PostgreSQL 控制面持久化 |
| `apps/manager/internal/platform/` | Kafka、Redis、OpenSearch adapter |
| `deployments/` | 安装器、镜像、Compose、PKI 和运行配置 |
| `apps/console/` | Manager Console 与认证 BFF |
| `configs/` | Policy/rule 元数据示例，不自动加载 |
| `test/` | Unit、Functional、Detection、Performance、Distribution 验证与 Release 门禁 |

边界规则：

- `apps/*/cmd/` 只组装服务，业务逻辑进入所属应用的 `internal/` package。
- Endpoint 不直接读取平台数据库；端云交互只经过已定义协议。
- 浏览器调用同源 BFF，不直接调用 Manager。
- protobuf 是 Agent wire contract 的事实来源。
- 应用白盒集成测试进入所属 `apps/*/integration/`，环境 E2E 留在 `test/`，正式运行资产留在 `deployments/`。
- `configs/` 文件只有通过明确 loader/apply 路径后才具有运行效果。

## 常用构建命令

| 命令 | 结果 |
|---|---|
| `make api` | 从 `packages/contracts/proto/*.proto` 生成 Go protobuf 和 gRPC 代码 |
| `make build-agent-binary` | 构建 `dist/bin/sysarmor-agent` |
| `make build-agent-tools` | 构建 Agent 和 `sysarmorctl` |
| `make build-binary` | 构建 Agent、Gateway、Manager、Worker、CLI |
| `make build SERVICE=manager` | 构建指定 Compose service image |
| `make release` | 创建签名 Agent release 与 index |
| `make deploy` | 构建二进制和镜像并启动本地平台 |
| `make clean-bin` | 删除 `dist/bin` |

`make build` 必须显式传 `SERVICE`。Package 服务使用 `nginx:alpine`，没有本地 image build。

### GitHub 发布

发布使用短生命周期 `release/vX.Y.Z` 分支。先将功能分支通过 PR 合入 `dev`，再从冻结的
`dev` 创建 release 分支；不要直接提交到 `dev` 或 `main`。首次引入或修改发布入口时，
对应 workflow 必须先存在于默认分支，否则 GitHub 不提供 `workflow_dispatch` 入口。

在仓库根目录发布 RC：

```bash
make release-rc VERSION=1.0.0 RC=1
```

该命令从 `release/v1.0.0` 触发 `.github/workflows/release-candidate.yml`，创建
`v1.0.0-rc.1` Pre-release。RC 使用 runner 临时生成的 RSA manifest key 和 Ed25519
content key。工作流从同一提交生成安装说明、容器示例、provenance 验证命令和变更链接，
并通过 `--notes-file` 创建 Release。也可以从 GitHub Actions 页面选择
`Release candidate`，在对应 release 分支输入相同的 RC 序号。

验收通过后，将 release 分支通过 PR 合入 `main`，再发布正式版：

```bash
make release-stable VERSION=1.0.0 RC=1
```

该命令从 `main` 触发 `.github/workflows/release-stable.yml`，自动传递
`accepted_rc_tag=v1.0.0-rc.1`。也可以从 GitHub Actions 页面手工填写相同参数。工作流
仅在 `main` 与 RC tag 的 Git tree 完全一致时继续，并使用同一 Release Notes 渲染器生成
正式版本说明。GitHub Releases 是发行变更记录的事实来源，不另行维护重复的 changelog。

两个 Make 命令只负责触发 Workflow，不创建或合并分支，也不等待发布完成。运行前需要
安装 GitHub CLI 并执行 `gh auth login`。

正式发布前，仓库必须配置受保护的 `production-release` Environment、审批人，以及：

- Secret `SYSARMOR_ARTIFACT_SIGNING_KEY_PEM`：RSA artifact manifest 私钥。
- Secret `SYSARMOR_CONTENT_SIGNING_KEY_PEM`：Ed25519 content 私钥。
- Variable `SYSARMOR_CONTENT_KEY_ID`：稳定且可审计的内容签名 key ID。

公共 `.github/workflows/release-build.yml` 对 RC 和 GA 执行相同测试、构建、SHA-256 自校验
和 provenance attestation。GitHub-hosted runner 不具备本项目要求的 libvirt/eBPF 环境，
因此公开 RC 的真实采集、检测和性能验收不能由构建工作流替代。

## 修改协议

1. 先确定变化属于 `schema_version`、`analysis_version` 还是 OpenSearch mapping。
2. 修改 `packages/contracts/proto/`；不得复用字段编号或名称。
3. 运行 `make api`，不要手工编辑 `*.pb.go`。
4. 同步 producer、consumer、兼容性检查和契约测试。
5. 按[API 参考](../reference/api.md)的 consumer-first 顺序规划发布。

Manager HTTP 字段变化还必须同步 `apps/manager/internal/api/` handler 测试与 `apps/console/lib/api/` typed client。页面组件不拼接 Manager URL 或授权 header。

## 修改 Agent 配置

Agent 配置解析器位于 `apps/agent/internal/config/`，采用严格 key 校验。新增字段需要同时完成：

1. 配置结构、默认值、解析和 Validate 规则。
2. 正常值、边界值、未知值和冲突值测试。
3. `deployments/agent/standalone.yaml` 或 `configs/agent.example.yaml` 示例。
4. [配置参考](../reference/configuration.md)的字段说明。

不要为尚无调用方的配置项预留抽象或开关。

## Manager Console

`apps/console` 是 Next.js + React 项目，包管理器为 pnpm。推荐从仓库根目录运行：

```bash
make web-install
make auth-init
make deploy
make doctor
```

Compose 在 `http://127.0.0.1:4173` 提供 Console。前台热更新：

```bash
make web-dev
```

默认地址为 `http://127.0.0.1:5173`。生产构建和前台预览：

```bash
make web-build
make web-preview
```

后台预览使用 `make web-up`、`make web-status`、`make web-stop`。开发服务器仍需要与 Compose 相同的 secret file 和 Manager origin 环境变量。

## 部署资产

| 路径 | 作用 |
|---|---|
| `deployments/agent/` | Agent installer、默认配置、Policy、systemd unit |
| `deployments/packages/` | release builder |
| `deployments/{gateway,manager,worker}/` | 服务镜像和环境示例 |
| `deployments/manager-ui/` | Console image 和运行入口 |
| `deployments/infra/` | Kafka、PostgreSQL、Redis、OpenSearch image |
| `deployments/opensearch/` | versioned mapping 和 alias 初始化 |
| `deployments/pki/` | 本地 PKI 工具和运行时材料目录 |
| `deployments/sensors/` | managed sensor bundle installer |

私钥、密码、运行结果和生成二进制不得提交。示例配置不得包含可用于非本地环境的真实密钥。

## 提交前验证

按改动范围选择最小但充分的验证：

```bash
make test-unit
make web-build                 # UI 变更
make test-doctor               # VM/真实链路测试前
git diff --check
```

涉及协议、共享存储、Agent 生命周期、发行包或用户主流程时，应进一步运行对应 Functional、Detection、Performance 或 Distribution suite。新增测试命令进入 `test/Makefile help`，测试方法进入 `docs/development/testing.md`，不要在 suite 子目录新增重复 README。

## 代码与文档规则

- 遵循现有风格、KISS、DRY、SOLID 和 YAGNI；单个函数超过 50 行或文件超过 500 行时评估拆分。
- 对外部输入执行校验，错误显式返回，不静默降级。
- 同一个契约只在 Reference 定义，Guide 通过链接引用。
- 当前能力、实验能力和规划能力必须清楚区分。
- Commit 使用 Conventional Commits，保持一个提交一个关注点；功能和修复分支从 `dev` 发起并通过 PR 合并。
