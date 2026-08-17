# Documentation and Security Vocabulary Convergence Design

## 结论

SysArmor 将一次性收敛安全数据概念和公开文档体系。生产合同、生产代码、正式文档、正式测试与报告统一使用 canonical vocabulary，不保留旧术语映射、旧路径跳转、运行时双读或 fallback。

已完成的过程性设计、实施计划和商业材料从当前工作树删除，由 Git 历史归档。仍然有效的架构不变量在删除前提炼到正式文档。

## 目标

1. 为 Event、Signal、Stage、DetectorKind、Where、Evidence 和 Incident 建立唯一事实来源。
2. 让开源读者按“运行、理解、使用、查询、贡献”的顺序阅读项目。
3. 分离当前能力、目标能力、研究设想和历史过程材料。
4. 清除 Detection Terminal、Learning Signal、Model Signal 等歧义产品语言。
5. 清除正式构建、测试和文档对 `.scratchpad/` 的依赖。
6. 通过合同测试阻止概念和文档结构再次漂移。

## 非目标

- 本次不实现 NodLink、Steiner Tree 或 Graph Conclusion 生产生成器。
- 本次不重写与概念和文档体系无关的业务逻辑。
- 本次不翻译整套中英文文档。
- 本次不破坏性删除被 Git 忽略的用户本地研究资料。
- 本次不建立仓库内历史归档目录。

## 目标文档结构

```text
/
├── README.md
├── README.zh-CN.md
├── CONTRIBUTING.md
└── docs/
    ├── README.md
    ├── quickstart.md
    ├── design-principles.md
    ├── architecture.md
    ├── roadmap.md
    ├── concepts/
    │   └── security-data-model.md
    ├── guides/
    │   ├── agent-management.md
    │   ├── policy.md
    │   └── investigation.md
    ├── operations/
    │   ├── deployment.md
    │   └── maintenance.md
    ├── reference/
    │   ├── configuration.md
    │   ├── api.md
    │   └── cli.md
    └── development/
        └── testing.md
```

文档按职责分层：Quickstart 回答第一次怎样运行，Concepts 定义对象，Design Principles 解释取舍，Architecture 描述当前生产系统，Guide 指导任务，Reference 描述精确合同，Operations 负责部署维护，Development 负责贡献验证，Roadmap 只容纳未实现能力。

`docs/concepts/security-data-model.md` 是核心安全概念的唯一正式定义。其他文档引用该定义，只解释所在场景，不复制另一套定义。

## 目录归并

- 将 `docs/index.md` 和 `CATALOG.md` 合并为 `docs/README.md`。
- 将 `docs/design-principles.zh-CN.md` 迁移为 `docs/design-principles.md`，全仓更新引用，不保留旧路径跳转页。
- 将通用贡献内容迁入根目录 `CONTRIBUTING.md`，协议、配置和测试细节分别归入对应 Reference 或 Testing。
- 将 `docs/development/debug.md` 中仍有效的限制归入 Testing，删除一次性问题记录。
- 删除 `docs/superpowers/`、`docs/business/` 和 `CATALOG.md`，由 Git 历史保留原内容。
- 不新增 `archive/`、旧路径兼容页或旧术语对照页。
- 实验运行报告继续位于 `test/.results/`，不进入长期文档。

## 统一安全数据模型

### Event

Event 是系统实际观察到的一次规范化行为事实。它不表达恶意判断，可能因为采集能力、策略或丢失而不完整，后续分析不能修改 Event 来迎合结论。

### Signal

Signal 是从 Event、既有 Signal、运行状态或关系中提炼出的检测发现。每个生产 Signal 必须通过三个正交维度说明发现方法、成熟度和产生位置：

```text
detector_kind：谁发现的
stage：发现成熟到哪一步
where：在哪里发现的
```

### Stage

`Candidate` 是仍需关联或验证的候选发现，不能单独参与 Incident 收敛。`Conclusion` 是满足明确检测条件、可以参与 Incident 收敛的结论性发现。

Candidate 和 Conclusion 是 Signal 的阶段，不是独立数据对象。提升 Candidate 时产生新的 Conclusion Signal，并通过 `signal_refs` 引用上游 Candidate，不原地修改既有 Signal。

### DetectorKind

| 值 | 含义 | 当前能力 |
|---|---|---|
| Rule | 确定性规则或关联规则 | 已实现 |
| Model | Learning Model 异常检测 | 已实现 Candidate |
| Graph | 图结构或路径算法检测 | 合同已定义，生产生成器尚未实现 |
| System | Agent 健康、自保护和篡改检测 | 已实现 |

### Where

`Endpoint` 表示 Agent 端侧产生，`Cloud` 表示 Worker 云侧产生。Where 只表示产生位置，不推导 Stage 或 DetectorKind。

### 规范组合

正式文档和报告使用 `<DetectorKind> <Stage>`：

```text
Rule Candidate
Rule Conclusion
Model Candidate
Graph Conclusion
System Conclusion
```

Model Candidate 的对象类型仍然是 Signal，当前完整语义是 `detector_kind=Model`、`stage=Candidate`、`where=Endpoint`。正式范围不再交替使用 Learning Signal、Model Signal 或 Terminal Signal。

### Evidence

Evidence 是支持 Signal 或 Incident 的可复核依据，而不是独立的检测阶段。当前具体形态包括 Signal Evidence Bundle、Incident Evidence Subgraph 和 Evidence Pullback Result。Evidence 不能脱离来源变成新的事实或结论。

### Incident

Incident 是由相关 Conclusion Signal 和 Evidence 在明确 tenant、作用域、时间窗口及分析版本内收敛出的可重复安全分析报告。它不是人工案件管理对象，不包含负责人、评论、SLA 或关闭状态。

统一表述为：

```text
Event 是事实
Signal 是发现
Evidence 是依据
Incident 是安全分析报告
```

## Terminal 边界

Detection 产品语义中不再存在 Terminal。仅允许以下情况保留该单词：

- Protobuf 对旧字段号和 `terminal` 名称的 `reserved` 声明；
- 一次性 OpenSearch 迁移测试中的最小旧数据输入；
- 控制命令、协议拒绝等普通生命周期的 terminal 状态；
- 未来 Steiner Tree 算法内部的 `SteinerTerminal`。

Terminal 不得进入 Signal、Incident、Policy、CLI、实验报告或公开产品术语。

## 生产不变量

- 生产 Signal 的 `stage`、`detector_kind` 和 `where` 必须明确，可信边界拒绝 `UNSPECIFIED`。
- Model 当前只能产生 Endpoint Candidate。
- Model Candidate 必须包含完整模型 provenance 和有效 Event 引用。
- Model Candidate 不能携带 Rule provenance、Response Intent 或 Global Rarity。
- Incident 至少需要一个合法 Conclusion。
- Graph Conclusion 在真实生产生成器完成前必须标注为目标能力。
- Candidate 提升产生新 Signal，不修改旧 Signal 的语义身份。

## 历史材料提炼规则

删除 84 份已完成 specs/plans 前，只提炼同时满足以下条件的内容：

1. 当前生产代码仍遵守；
2. 属于安全或可靠性不变量；
3. 对部署、升级、扩展或测试仍有长期价值；
4. 在正式文档中尚无唯一事实来源。

过程步骤、临时输出、旧目录结构和被当前实现取代的方案不迁移。

## 生产语言和实验语言迁移

- 为 Proto 枚举和关键字段补充稳定语义注释。
- 将只处理模型候选的生产符号收敛为 Model Candidate 语义。
- 保留策略应用上下文中的 Candidate，因为它表示待应用策略对象，不属于 Detection Stage。
- 保留控制生命周期和终端图标中的非 Detection terminal 语义。
- 清除正式测试覆盖表和攻击样例中的 terminal signal/state。
- Learning 报告内部使用 `model_candidates`，展示统一使用 Rule Signal、Model Candidate 和 Conclusion。
- 报告样本显式展示 `stage`、`detectorKind` 和 `where`。

## Scratchpad 边界

- 删除 Makefile、测试和正式文档中的 `.scratchpad/.cache` fallback。
- 正式项目只接受显式环境变量或正式 `.cache/`。
- `.scratchpad/third_party` 和 `nodlink.md` 保持被 Git 忽略，不作为工程事实来源。
- NodLink 的有效结论只进入 Concepts 或 Roadmap，并明确标为目标能力。
- 本任务不删除用户本地 `.scratchpad` 数据。

## 一次性 OpenSearch 迁移

- 新生产路径只读写 v2 的 `stage` 和 `detectorKind`。
- 不允许运行时双读、字段 alias 或 terminal fallback。
- 迁移 fixture 只保留最小 v1 输入，用于验证一次转换。
- Protobuf 永久保留旧字段号和名称的 `reserved` 声明，防止误复用；这不是向后兼容。
- 业务 fixture、查询、报告和正式文档不得再产生旧字段。

## 实施顺序

1. 用失败的合同测试锁定目标目录、canonical vocabulary、例外和链接完整性。
2. 建立文档骨架和唯一概念事实来源。
3. 提炼历史材料中的有效不变量并归入正式文档。
4. 迁移生产符号、正式测试和实验报告语言。
5. 删除历史过程材料、商业材料和 scratchpad fallback。
6. 运行全量质量门禁并人工验证三条阅读路径。

## 提交边界

```text
test(docs): lock canonical documentation contracts
docs: establish canonical security data model
docs: reorganize public documentation
refactor: align detection terminology
test: align learning and detection reports
chore: remove historical process documentation
```

实现时可以将历史提炼和删除拆成两个提交，确保删除前后的信息去向可审查。

## 验收

自动验收包括：

- 文档目录和内部链接合同；
- 概念及 Detection Terminal 泄漏扫描；
- Python 全量测试；
- Go 全量测试；
- `go vet ./...`；
- `git diff --check`。

人工验收以下阅读路径：

```text
新用户：README -> Quickstart -> Concepts
使用者：Concepts -> Architecture -> Guide -> Reference
贡献者：CONTRIBUTING -> Architecture -> Testing
```

最终状态必须满足：一个概念只有一个正式定义；当前能力与目标能力不混写；Model Candidate 不被描述为独立对象；Detection Terminal 不进入产品语言；公开文档树不包含过程材料和商业材料；正式构建不依赖个人 scratchpad；删除旧结构后所有测试、链接和示例仍有效。
