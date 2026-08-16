# Endpoint 性能实验人类可读报告实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use TDD to implement this plan task-by-task.

**目标：** 为 Endpoint performance suite 自动生成运行级、可归档的 Markdown 实验报告。

**架构：** 保留 `report.py` 的 CSV 矩阵职责，新增独立 `human_report.py` 负责加载已有 artifacts、聚合诊断数据并渲染 `report.md`。`run.sh` 在矩阵生成后以宽松模式调用报告生成器。

**技术栈：** Python 3 标准库、Bash、现有 NDJSON/JSON/CSV artifacts。

## 全局约束

- 不引入 Python 第三方依赖。
- 默认报告生成问题只产生 warning，不改变性能测试退出码。
- Event sample 上限为 5；Signal 默认最多展示 20 条；Event behavior 展示 Top 10。
- 保持现有 `matrix.csv` 字段和内容不变。

### Task 1: 报告生成器核心模型与渲染

**文件：**
- 创建：`test/suites/performance/endpoint/human_report.py`
- 创建：`test/suites/performance/endpoint/test_human_report.py`

**接口：**
- `generate_report(run_dir: Path, output: Path, strict: bool = False) -> ReportResult`
- CLI：`python3 human_report.py <run-dir> [--output <path>] [--strict]`

- [ ] 写测试：使用临时目录构造两个 policy，验证报告包含运行摘要、横向性能表、环境条件、policy 章节、Event/Signal/Evidence 和 artifacts。
- [ ] 运行测试确认因模块不存在或接口不存在而失败。
- [ ] 实现标准库加载器：容错读取 JSON、JSONL、CSV；累计 missing/invalid warnings；解析 manifest、apply、summary、health、events、signals。
- [ ] 实现 Markdown 渲染：固定章节、表格转义、数字格式化、样本截断和 health 诊断。
- [ ] 实现宽松/strict 返回语义。
- [ ] 运行测试确认全部通过。

### Task 2: 接入 Endpoint 性能运行流程

**文件：**
- 修改：`test/suites/performance/endpoint/run.sh:808` 附近
- 修改：`test/suites/performance/endpoint/test_run_contract.py`

- [ ] 写合同测试：验证脚本在生成 `matrix.csv` 后调用 `human_report.py`，输出路径为 `$OUT_DIR/report.md`，且报告失败使用 warning 语义。
- [ ] 运行合同测试确认当前脚本未满足调用契约。
- [ ] 在 `run.sh` 中调用 `python3 "$HERE/human_report.py" "$OUT_DIR" --output "$OUT_DIR/report.md"`，失败只输出 warning。
- [ ] 运行合同测试确认接入通过。

### Task 3: 离线生成现有 medium 报告并验收

**文件：**
- 生成但不提交：`test/.results/performance-endpoint/<run-id>/report.md`

- [ ] 使用现有 `20260816T145855Z` 结果运行生成器。
- [ ] 检查报告无未替换字段，包含性能/效果/健康诊断和所有 policy 章节。
- [ ] 检查 `matrix.csv` 生成前后内容一致。
- [ ] 运行相关 Python 测试和静态语法检查。
- [ ] 提交实现为原子 commit。
