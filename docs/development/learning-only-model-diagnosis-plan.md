# Learning-only Model Diagnosis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use test-driven development to implement this plan task-by-task.

**Goal:** 为 managed learning-only 报告增加逐 attack profile 的候选归因，并据此实施一个可证实的最小修复。

**Architecture:** 在 `managed_analysis.py` 内基于现有 Event/Profile/Candidate 数据计算纯函数诊断；`report.py` 只组装结果，renderer 只展示摘要。诊断不参与既有 gate 判定，避免改变验收语义。

**Tech Stack:** Python 3.10、`unittest`、现有 NDJSON/JSON 报告 artifact。

## Global Constraints

- 不修改 FeatureSchemaV2、模型包或阈值，直到 profile 链路根因得到证明。
- 新字段缺失时显式返回 unavailable/unknown，不静默推断。
- 保持 Python 3.10 兼容。

---

### Task 1: Attack profile 归因纯函数

**Files:**
- Modify: `test/suites/performance/learning/managed_analysis.py`
- Test: `test/suites/performance/learning/test_managed_analysis.py`

**Interfaces:**
- Produces: `attack_profile_diagnostics(events, truth_event_ids, profile_campaign_ids, truth_campaign_ids, endpoint_candidates, projected_candidates) -> dict[str, object]`

- [ ] 编写覆盖五种状态及 unavailable 输入的失败测试。
- [ ] 运行 `python3 -m unittest test/suites/performance/learning/test_managed_analysis.py`，确认因函数缺失失败。
- [ ] 实现最小纯函数，状态优先级遵循设计文档。
- [ ] 重跑单测，确认通过。

### Task 2: 报告组装与结构化输出

**Files:**
- Modify: `test/suites/performance/learning/report.py`
- Modify: `test/suites/performance/learning/managed_analysis.py`
- Test: `test/suites/performance/learning/test_report.py`

**Interfaces:**
- Consumes: Task 1 的 `attack_profile_diagnostics`。
- Produces: mode metrics 中的 `attack_profile_diagnostics` 字段。

- [ ] 编写失败测试，要求 managed learning-only mode 输出状态计数和逐 profile 记录。
- [ ] 从现有 artifacts 传入 endpoint Candidate 与 projected Candidate，不创建新采集格式。
- [ ] 运行 learning report 单测并确认通过。

### Task 3: 既有失败产物归因

**Files:**
- Modify only if evidence proves a report parsing defect.

- [ ] 对 `test/.results/performance-endpoint/20260831T104939Z-learning-only` 运行诊断。
- [ ] 记录每个 truth profile 的状态、Candidate score/ref 和运行级缺口。
- [ ] 形成单一根因假设：端侧攻击 Candidate 已产生，但 Candidate 洪泛导致 Stream cohort 未收敛。

### Task 4: 数据窗口与 calibration 下限

**Files:**
- Modify: `tools/learning_detector/pipeline.py`
- Modify: `tools/learning_detector/prepare_model.py`
- Test: `tools/learning_detector/test_pipeline.py`
- Test: `tools/learning_detector/test_prepare_model.py`

- [ ] 先写 marker window 与 calibration 最小规模的失败测试。
- [ ] 支持按 `normal_activity_start`/`normal_activity_done` 截取正常数据。
- [ ] 拒绝 profile 数少于 `ceil(1 / target_rate)` 的 calibration 数据。
- [ ] 运行工具测试和全部 learning report 测试。

### Task 5: 验证

- [ ] 运行 `python3 -m unittest discover -s test/suites/performance/learning -p 'test_*.py'`。
- [ ] 用现有失败产物确认诊断结果稳定、可解释。
- [ ] 运行 `git diff --check` 并进行代码审查。
- [ ] 完整 managed VM E2E 留到模型或运行时行为实际改变后执行。

### Task 6: Agent 增量分析上下文

**Files:**
- Modify: `apps/streaming/src/streaming/detectors/contracts.py`
- Modify: `apps/streaming/src/streaming/engine/detection_state.py`
- Modify: `apps/streaming/src/streaming/engine/analysis.py`
- Modify: `apps/streaming/src/streaming/jobs/detection.py`
- Test: `streaming/tests/test_detector_contracts.py`
- Test: `streaming/tests/test_detection_state.py`
- Test: `streaming/tests/test_detection_function.py`

- [x] 增加 `DetectorDelta` 并按 `required_inputs` 调度受影响 Detector。
- [x] 增量维护 ProvenanceGraph，输出 changed node/edge。
- [x] 将核心 key 收敛为 `tenant + agent`，业务标签不切割状态。
- [x] 落地 versioned Detector keyed state 的 checkpoint/restore。
- [x] Detector 使用有界全量快照与增量 Delta，并验证增量/全量结果一致。
- [x] 修复跨租户、timer、乱序、重复 ID 和 Event Detector fast-path 边界。
