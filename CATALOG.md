# SysArmor 文档目录

本文定义 SysArmor 的正式文档结构、事实来源和治理边界。文档按用户任务组织，不按代码目录组织。

## 文档原则

1. 一个主题只有一个事实来源，其他页面使用链接，不复制定义。
2. 每份文档只承担一种职责：教程、操作指南、原理说明、参考或开发文档。
3. 当前能力、目标能力和研究设想必须明确区分。
4. 命令以 Makefile 和 CLI `--help` 为准，协议以 protobuf 为准，文档解释使用方式和稳定契约。
5. 实施计划、设计过程、生成结果和商业尽调材料不进入公开技术文档导航。
6. 单页超过 500 行、出现不同受众或独立版本周期时才拆分。

## 正式导航

| 类型 | 文档 | 回答的问题 |
|---|---|---|
| 导航 | [文档首页](docs/index.md) | 我应该从哪里开始？ |
| 教程 | [快速开始](docs/quickstart.md) | 如何从零运行 Agent 并看到第一个 Signal？ |
| 原理 | [设计原则](docs/design-principles.zh-CN.md) | 为什么采用动态博弈、效能平衡和端云协同？ |
| 原理 | [系统架构](docs/architecture.md) | Agent、控制平面、数据平面和云侧分析如何协作？ |
| 规划 | [技术路线图](docs/roadmap.md) | 当前优先解决什么问题，各阶段如何验收？ |
| 指南 | [策略](docs/guides/policy.md) | 如何理解和调整四层统一策略？ |
| 指南 | [Agent 管理](docs/guides/agent-management.md) | 如何安装、注册、管理和取消注册 Agent？ |
| 指南 | [调查](docs/guides/investigation.md) | 如何从 Event、Signal 和 Evidence 调查 Incident？ |
| 运维 | [部署](docs/operations/deployment.md) | 如何部署 standalone Agent 和管理平台？ |
| 运维 | [维护](docs/operations/maintenance.md) | 如何升级、诊断、恢复和维护系统？ |
| 参考 | [配置](docs/reference/configuration.md) | 配置、Policy、路径、端口和环境变量的精确约定是什么？ |
| 参考 | [API](docs/reference/api.md) | Manager、BFF、gRPC、protobuf 和版本规则是什么？ |
| 参考 | [CLI](docs/reference/cli.md) | `sysarmorctl` 的命令边界是什么？ |
| 开发 | [开发指南](docs/development/development.md) | 如何构建、修改和扩展项目？ |
| 开发 | [测试指南](docs/development/testing.md) | 如何运行和解释 Product、Effectiveness、Performance 测试？ |

## 仓库入口与局部索引

| 文档 | 职责 |
|---|---|
| `README.md` | 英文项目入口 |
| `README.zh-CN.md` | 中文项目入口 |
| `CATALOG.md` | 文档治理与导航 |
| `AGENTS.md` | 开发协作规则，不属于公开技术文档 |
| `test/README.md` | 测试目录的最短入口，只链接正式测试指南 |
| `test/data/README.md` | Policy、Workload、Scenario、Expected 和 Content 数据契约 |

## 非公开材料

商业材料、过程性设计和个人工作记录不进入仓库文档目录，也不作为工程事实来源。

## 事实来源

| 主题 | 唯一事实来源 |
|---|---|
| 三项设计原则 | `docs/design-principles.zh-CN.md` |
| 中长期建设重点与阶段退出标准 | `docs/roadmap.md` |
| Event、Signal、Evidence、Incident | `docs/architecture.md` |
| Agent 与平台运行边界 | `docs/architecture.md` |
| 代码分层、目录归属与扩展规则 | `docs/development/development.md` |
| 四层策略模型 | `docs/guides/policy.md` |
| 部署与 PKI | `docs/operations/deployment.md` |
| 运维与 OpenSearch 演进 | `docs/operations/maintenance.md` |
| 配置字段与运行路径 | `docs/reference/configuration.md` |
| API 与 Schema 演进 | `docs/reference/api.md` 和 `packages/contracts/proto/` |
| CLI | `docs/reference/cli.md` 和 `sysarmorctl --help` |
| 测试方法 | `docs/development/testing.md` |
| 测试数据格式 | `test/data/README.md` |

## 维护规则

- 新增页面前先更新本目录，说明其文档类型和唯一职责。
- 新字段只在 Reference 定义；Guide 通过链接使用。
- 新测试命令进入 `test/Makefile help`，测试方法进入 `docs/development/testing.md`。
- 新测试 fixture 格式进入 `test/data/README.md`。
- 图表必须同时维护 `.drawio` 源文件和 `.svg` 交付图。
- 性能数字和一次性测试输出留在 `.results/` 或发布材料，不写入长期指南。
- 路线图状态只依据退出标准和可重复验证证据更新，不使用完成百分比。
- 商业材料引用技术文档，不反向定义工程能力。
