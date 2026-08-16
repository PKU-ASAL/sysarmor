# Endpoint 性能实验人类可读报告设计

## 目的

Endpoint performance suite 在实验结束后自动生成一份运行级 `report.md`，让工程师可以直接阅读一次实验的环境、条件、策略、检测效果、样本、性能和健康状态，而不必手工拼接 JSON、CSV 和 NDJSON 产物。

## 范围与约束

- 报告粒度为一次运行级报告；一次运行内的多个 policy 在同一份报告中分章节，并提供横向性能对比。
- 保留现有 `report.py` 生成 `matrix.csv` 的职责，不改变已有矩阵格式。
- 新增独立报告生成器，使用 Python 标准库，不引入模板引擎或额外依赖。
- 报告默认宽松：缺失文件、无效 JSON 或损坏 JSONL 不阻断实验；在报告中记录 warning，并在 stderr 输出 warning。
- 生成器预留 `--strict` 模式；严格模式下报告数据问题返回非零，用于未来质量门禁。
- 默认每个 policy 展示 5 条 Event sample；Signal 默认全部展示，超过 20 条时截断并注明；展示 Event behavior Top 10。

## 架构

新增 `test/suites/performance/endpoint/human_report.py`，只负责读取一个 endpoint performance run directory 并渲染 Markdown。脚本内部按“加载与诊断、聚合、渲染”三个边界组织，避免把格式化逻辑混入现有矩阵生成器。

`test/suites/performance/endpoint/report.py` 继续负责从每个 policy 目录生成 `matrix.csv`。`run.sh` 在调用该脚本后调用 `human_report.py`，将输出写入 `$OUT_DIR/report.md`。报告失败只打印 warning，不覆盖性能测试的退出状态。

## 数据流

每个 policy 目录读取以下已有产物：

- `manifest.json`：系统环境、profile、workload、scenario、VM、Agent/tenant 和 phase 条件。
- `collection-apply.json`、`detection-apply.json`、content apply JSON：策略版本、生成 hash、resolved refs、coverage 和 selector 位置。
- `summary.json`、`matrix.csv`：阶段和总体事件、Signal、CPU、RSS、EPS、drop、parse error 指标。
- `events.scope.ndjson`（回退 `events.ndjson`）：Event 样本和 behavior 统计。
- `signals.scope.ndjson`（回退 `signals.ndjson`）：Signal、stage、detector、rule、confidence、Evidence 和关联 Event ID。
- `raw/*.health.json`：最后一个有效 health 快照，以及状态变化和关键 telemetry/sensor/detection 字段。
- `artifacts.json`：产物说明和索引。

运行级报告先加载所有 policy，生成横向对比表，再渲染每个 policy 的详细章节。单个 policy 的错误隔离在该章节内，不影响其他 policy。

## 报告内容

1. **结论摘要**：运行 ID、policy 数、实验状态、整体事件/Signal 数、总体 EPS、Agent/EDR 资源和 warning 数。
2. **Policy 横向对比**：每个 policy 的 workload、事件、Signal、EPS、Agent CPU/RSS、EDR CPU/RSS、Sensor drop、parse error、health。
3. **系统环境与实验条件**：profile、VM 环境、Agent/tenant、policy 文件、workload/scenario、phase durations、profiling、feature flags、复现命令。
4. **Policy 详细章节**：应用结果、coverage、resolved refs、selector 下推/Agent-side/unsupported、Event 统计与 5 条样本、Signal 和 Evidence、阶段性能表、最终 health 与诊断。
5. **产物索引**：报告使用的文件、缺失文件、损坏行计数和原始目录链接。

## Signal 与 Evidence 展示规则

Signal 读取 envelope 内的 `signal` 对象。报告展示名称、ID、stage、detector kind、rule/version、severity、confidence、时间、实体摘要、eventRefs 和 labels。若存在 `evidence.summary`，优先展示该摘要；否则展示 Evidence ID 和可序列化的简短 JSON。关联 Event 只展示 ID 映射，不复制完整事件正文。

## 错误处理

- 文件不存在：记录 `missing artifact` warning，并使用 `N/A`。
- JSON 无效：记录文件级 warning，跳过该文件。
- JSONL 单行无效：跳过该行，累计 `invalid JSONL lines`，继续处理。
- 关键输出目录不存在或命令参数错误：脚本返回非零。
- 默认模式下 `run.sh` 不因报告脚本非零而失败；严格模式由调用方显式选择。

## 验证

- 单元测试覆盖：多 policy 横向表、数字格式化、Event/Signal 解析、Evidence 展示、health 诊断、缺失 artifact、损坏 JSONL、Signal 截断和 strict 模式。
- 合同测试验证 `run.sh` 在矩阵生成后调用报告脚本，并把报告放在 `$OUT_DIR/report.md`。
- 使用现有 medium 结果离线生成报告，检查报告可读、无未替换占位符，并保留原有 `matrix.csv` 内容不变。
