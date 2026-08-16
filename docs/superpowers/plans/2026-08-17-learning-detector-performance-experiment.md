# Learning Detector Performance Experiment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一套可重复的 Learning Detector disabled/enabled medium A/B 实验，从显式正常数据训练、校准、签名模型，到 fresh VM 串行运行、自动门禁和横向 `report.md`。

**Architecture:** 新增 Learning 实验编排器，复用现有 Endpoint 单次 runner；Endpoint runner 只增加模型注入和 serial activity 通用能力，不知道 A/B。Python 复用既有 `tools/learning_detector/pipeline.py` 做特征、float32 打分和 Bundle digest；Go 测试命令复用 Agent 正式 `SignModelBundle` 契约完成签名。

**Tech Stack:** Bash、Python 3 标准库、Go、Ed25519、现有 Vagrant VM/recorder、现有 NDJSON Event/Signal 和 YAML truth fixtures。

## Global Constraints

- 训练和校准数据必须显式传入，Event ID 非空、文件内唯一、两个文件交集为空。
- 校准目标为 `normal Candidate rate <= 0.5%`，正式 A/B 期间不得动态调阈值。
- A/B 固定同一 commit、`vm-endpoint`、`medium`、`collection-balanced`、Detection policy 和串行活动；每侧 fresh VM。
- Agent 端只输出 Model Candidate；Worker 图检测不纳入本实验。
- disabled 不配置模型；enabled 必须验证签名 Bundle 并显示 `loaded`，禁止默认模型或 fallback。
- final health、Sensor/Batcher drop、parse errors 必须分别显式检查；Stream eviction 只报告。
- CPU 使用 normal marker 窗口 `agent_cpu_pct` 平均值；RSS 使用 `agent_rss_mb` 最大值；EPS 使用窗口 Event 增量/窗口秒数。
- 性能门槛：CPU `<= max(disabled + 1pp, disabled * 1.15)`，RSS `<= max(disabled + 32MiB, disabled * 1.15)`，EPS `>= disabled * 0.90`。
- 攻击召回只作为 `needs-improvement` 基线，不阻断实验；Rule truth Event 关联在 A/B 两侧必须满足。
- private key 仅签名期间以 `0600` 保存，验证后删除；不进入仓库或 Agent 配置。
- 每个函数不超过 50 行，新增文件保持单一职责，不保留旧参数或兼容路径。

---

### Task 1: Add Deterministic Dataset Validation and Threshold Calibration

**Files:**
- Modify: `tools/learning_detector/pipeline.py`
- Create: `tools/learning_detector/prepare_model.py`
- Modify: `tools/learning_detector/test_pipeline.py`
- Create: `tools/learning_detector/test_prepare_model.py`

**Interfaces:**
- `prepare_model.validate_dataset(path: Path) -> DatasetMetadata`
- `prepare_model.validate_pair(training: Path, calibration: Path) -> PairMetadata`
- `prepare_model.prepare(training: Path, calibration: Path, output: Path, target_rate: float = 0.005) -> dict[str, Any]`
- `pipeline.next_float32(value: float) -> float`
- `pipeline.calibrate_threshold(scores: list[float], target_rate: float) -> tuple[float, int]`

- [ ] **Step 1: Write failing tests for input contracts and threshold ties**

```python
def test_rejects_duplicate_and_empty_event_ids(tmp_path):
    path = write_events(tmp_path / "events.ndjson", [{"id": ""}, {"id": "e1"}, {"id": "e1"}])
    with pytest.raises(ValueError, match="event id"):
        validate_dataset(path)

def test_rejects_training_calibration_overlap(tmp_path):
    training = write_events(tmp_path / "training.ndjson", [{"id": "e1"}])
    calibration = write_events(tmp_path / "calibration.ndjson", [{"id": "e1"}])
    with pytest.raises(ValueError, match="overlap"):
        validate_pair(training, calibration)

def test_threshold_excludes_ties_and_respects_rate():
    threshold, allowed = calibrate_threshold([5.0, 5.0, 4.0, 2.0], 0.5)
    assert allowed == 2
    assert sum(score >= threshold for score in [5.0, 5.0, 4.0, 2.0]) <= allowed
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python3 -m pytest tools/learning_detector/test_prepare_model.py tools/learning_detector/test_pipeline.py -q`

Expected: FAIL because dataset metadata, float32 successor, and calibration functions do not exist.

- [ ] **Step 3: Implement the minimal deterministic helpers**

Use the existing `read_events`, `feature_vector`, `train`, `score`, `validate_bundle`, and `float32` functions. Implement `next_float32` by incrementing the IEEE-754 positive finite bit pattern, and choose the smallest successor above the first excluded descending score. `prepare` must write a Bundle through the existing `train` path, replay calibration, and return counts, SHA-256 digests, threshold, and score quantiles.

- [ ] **Step 4: Add determinism and calibration replay assertions**

```python
def test_prepare_is_reproducible(tmp_path):
    first = prepare(training, calibration, tmp_path / "a.json")
    second = prepare(training, calibration, tmp_path / "b.json")
    assert first == second
    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()
    assert first["calibration_candidate_rate"] <= 0.005
```

- [ ] **Step 5: Run tests and commit**

Run: `python3 -m pytest tools/learning_detector/test_prepare_model.py tools/learning_detector/test_pipeline.py -q`

Expected: all focused Python tests pass.

Commit: `feat: calibrate learning detector experiment models`

### Task 2: Add Test Model Signing Command and VM Learning Injection

**Files:**
- Create: `apps/agent/cmd/sysarmor-model-sign/main.go`
- Create: `apps/agent/cmd/sysarmor-model-sign/main_test.go`
- Modify: `Makefile`
- Modify: `test/shared/vm/sync-agent.sh`
- Modify: `test/suites/performance/endpoint/run.sh`
- Modify: `test/suites/performance/endpoint/test_runtime_contract.py`

**Interfaces:**
- Command: `sysarmor-model-sign --input /tmp/model-bundle.json --output /tmp/signed-model-bundle.json --key-id experiment --private-key /tmp/model-signing.key`
- Sync inputs: `SYSARMOR_LEARNING_MODEL`, `SYSARMOR_LEARNING_TRUST_KEYS`
- Endpoint inputs: `SYSARMOR_BENCH_LEARNING_MODEL`, `SYSARMOR_BENCH_LEARNING_TRUST_KEYS`, `SYSARMOR_BENCH_LEARNING_VARIANT`

- [ ] **Step 1: Write failing Go and shell contract tests**

```go
func TestModelSignWritesBundleAcceptedByLoadModelBundle(t *testing.T) {
    // Generate an Ed25519 key, sign test/data/learning/model-bundle.json,
    // load the result with the public key, and require no error.
}
```

Contract assertions must require: disabled has no learning inputs; enabled requires both inputs; sync uploads the model before install; Endpoint manifest records variant and model digest.

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./apps/agent/cmd/sysarmor-model-sign ./apps/agent/internal/adapters/detection -run Model -count=1` and `python3 -m pytest test/suites/performance/endpoint/test_runtime_contract.py -q`.

Expected: command package is missing and shell contracts fail.

- [ ] **Step 3: Implement the signer by reusing the formal Agent adapter**

Read the private key as raw Ed25519 bytes, call exported `detectionadapter.SignModelBundle`, write atomically with mode `0600` during creation, and verify the resulting JSON can be loaded with the supplied public key. Reject missing files, malformed keys, mismatched input/output, and empty key IDs explicitly.

- [ ] **Step 4: Implement strict VM injection**

In `sync-agent.sh`, validate the enabled/disabled pair before VM mutation. Upload enabled Bundle to `/etc/sysarmor/agent/learning/model-bundle.json`, add `learning.model_path` and `learning.trust_keys` to generated YAML, and reject half-configured values. Keep disabled YAML free of a `learning:` section.

- [ ] **Step 5: Pass model inputs and provenance through Endpoint manifests**

Add environment initialization before VM lifecycle, pass the values to `sync-agent.sh`, and write only public model digest/ref/version/schema/threshold to manifests. Never write private key material.

- [ ] **Step 6: Run focused tests and commit**

Run: `go test ./apps/agent/cmd/sysarmor-model-sign ./apps/agent/internal/adapters/detection -count=1` and `python3 -m pytest test/suites/performance/endpoint/test_runtime_contract.py -q`.

Expected: signer, disabled/enabled injection, and manifest contract tests pass.

Commit: `feat: inject signed learning models into endpoint benchmarks`

### Task 3: Add Serial Normal/Scenario Activity to Endpoint Runner

**Files:**
- Modify: `test/suites/performance/endpoint/run.sh`
- Modify: `test/suites/performance/endpoint/report.py`
- Modify: `test/suites/performance/endpoint/test_run_contract.py`
- Modify: `test/suites/performance/endpoint/test_human_report.py`

**Interfaces:**
- Input: `SYSARMOR_BENCH_ACTIVITY_MODE=parallel|serial`
- Serial markers: `normal_activity_start`, `normal_activity_done`, `scenario_start`, `scenario_done`, `scenario_observe_start`, `scenario_observe_done`
- Report phase keys: `normal_activity`, `scenario`

- [ ] **Step 1: Add failing runner contract tests**

```python
def test_serial_mode_finishes_normal_before_starting_scenario():
    script = RUN_SCRIPT.read_text()
    normal_done = script.index('normal_activity_done')
    scenario_start = script.index('scenario_start')
    assert normal_done < scenario_start
```

Also assert the new mode is recorded in both manifests and that existing parallel mode remains explicit rather than implicit.

- [ ] **Step 2: Run contract tests and verify failure**

Run: `python3 -m pytest test/suites/performance/endpoint/test_run_contract.py -q`

Expected: FAIL because serial markers and mode do not exist.

- [ ] **Step 3: Implement serial activity with marker-aligned windows**

Add a serial branch in `run_case_activity`: run the normal workload synchronously, emit normal start/done markers, then emit scenario markers and run the scenario. Keep the existing parallel branch unchanged for other Endpoint tests. Require both workload and scenario in serial mode; fail early if either is missing.

- [ ] **Step 4: Expose normal activity phase metrics**

Update `report.py` to derive `normal_activity` from the marker half-open window and to preserve raw marker errors as invalid input. Calculate Event delta, EPS, Agent CPU average, and Agent RSS maximum from timeline samples in that window.

- [ ] **Step 5: Run tests and commit**

Run: `python3 -m pytest test/suites/performance/endpoint/test_run_contract.py test/suites/performance/endpoint/test_human_report.py -q`

Expected: all Endpoint contract and report tests pass.

Commit: `feat: add serial activity phases to endpoint benchmarks`

### Task 4: Build Strict Learning A/B Report

**Files:**
- Create: `test/suites/performance/learning/report.py`
- Create: `test/suites/performance/learning/test_report.py`
- Create: `test/suites/performance/learning/__init__.py`

**Interfaces:**
- `report.generate_report(run_dir: Path, output: Path | None = None, strict: bool = True) -> ReportResult`
- `report.evaluate_ab(disabled: dict, enabled: dict, gates: dict) -> dict`
- `report.load_endpoint_run(path: Path, phase: str) -> dict`

- [ ] **Step 1: Write fixture-driven failing tests**

Fixtures must cover: loaded/disabled status, model provenance, rule truth links, unresolved event refs, zero drops, stream eviction, marker phase metrics, CPU/RSS/EPS pass and fail boundaries, and partial/not-run/unavailable states.

```python
def test_report_marks_cpu_overhead_as_failed(tmp_path):
    result = evaluate_ab(disabled_metrics, enabled_metrics_with_high_cpu, DEFAULT_GATES)
    assert result["gates"]["performance_cpu"]["status"] == "failed"

def test_stream_eviction_is_reported_without_being_a_drop_failure(tmp_path):
    result = evaluate_ab(metrics_with_stream_evictions, metrics_with_stream_evictions, DEFAULT_GATES)
    assert result["gates"]["reliability"]["status"] == "passed"
    assert result["observations"]["stream_evictions"] > 0
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python3 -m pytest test/suites/performance/learning/test_report.py -q`

Expected: FAIL because the Learning report package does not exist.

- [ ] **Step 3: Implement structured loading and strict gate evaluation**

Load only `manifest.json`, `summary.json`, `signals.scope.ndjson`, `events.scope.ndjson`, and marker/timeline artifacts. Reject missing markers, malformed JSON, unknown status, and unresolved refs. Keep missing values as `unavailable`; never coerce them to zero.

- [ ] **Step 4: Render the report sections and bounded samples**

Render environment/provenance, calibration, A/B metric deltas, health/reliability, normal Candidate rate and score quantiles, attack truth matrix, Rule regression, bounded samples, and final verdict. Write identical gate values to `summary.json` and `report.md`.

- [ ] **Step 5: Run tests and commit**

Run: `python3 -m pytest test/suites/performance/learning/test_report.py -q`

Expected: all report fixtures pass.

Commit: `feat: add learning detector ab report`

### Task 5: Add Learning A/B Orchestrator

**Files:**
- Create: `test/suites/performance/learning/run.sh`
- Create: `test/suites/performance/learning/test_run_contract.py`
- Modify: `test/Makefile`
- Modify: `Makefile`

**Interfaces:**
- Command: `make -C test performance-learning TRAINING_DATA=test/.results/performance-endpoint/20260816T145855Z/collection-balanced/events.scope.ndjson CALIBRATION_DATA=test/.results/performance-endpoint/20260816T161359Z/collection-balanced/events.scope.ndjson PROFILE=medium`
- Environment: `SYSARMOR_LEARNING_TRAINING_DATA`, `SYSARMOR_LEARNING_CALIBRATION_DATA`, `SYSARMOR_LEARNING_RUN_ID`
- Output: `.results/learning-detector/$SYSARMOR_LEARNING_RUN_ID/manifest.json`, `summary.json`, `report.md`

- [ ] **Step 1: Write failing shell contract tests**

```python
def test_orchestrator_prepares_model_before_first_endpoint_run():
    script = RUN_SCRIPT.read_text()
    assert script.index("prepare_model.py") < script.index("performance/endpoint/run.sh")

def test_orchestrator_runs_disabled_before_enabled_and_uses_one_policy():
    script = RUN_SCRIPT.read_text()
    assert script.index('VARIANT=disabled') < script.index('VARIANT=enabled')
    assert 'collection-balanced.json' in script
```

Also assert that a disabled failure exits before enabled, every run uses `SYSARMOR_BENCH_VM_FRESH=1`, serial mode, and the strict report is the final command.

- [ ] **Step 2: Run tests and verify failure**

Run: `python3 -m pytest test/suites/performance/learning/test_run_contract.py -q`

Expected: FAIL because the orchestrator and Make target do not exist.

- [ ] **Step 3: Implement prepare/sign lifecycle and manifest**

Create a unique UTC run directory, validate explicit datasets, call `prepare_model.py`, generate an ephemeral key pair, invoke `sysarmor-model-sign`, verify the public key, and delete the private key. Write immutable gate constants, commit, VM, policy, input digests, model provenance, and child run IDs to the top-level manifest.

- [ ] **Step 4: Invoke the two Endpoint runs with strict failure handling**

Run disabled and enabled sequentially with `SYSARMOR_BENCH_POLICIES=test/data/policies/collection-balanced.json`, `SYSARMOR_BENCH_ACTIVITY_MODE=serial`, `SYSARMOR_BENCH_WORKLOAD=business-normal`, `SYSARMOR_BENCH_SCENARIO=apt-fileless-c2-local`, `SYSARMOR_BENCH_VM_FRESH=1`, and `SYSARMOR_BENCH_PROFILE=medium`. On a child failure record `failed`/`not-run`, invoke partial report, and return nonzero.

- [ ] **Step 5: Add Make targets and local contract tests**

Expose `performance-learning` from `test/Makefile` and the root Makefile help/dispatch without changing existing Endpoint targets. Require both dataset variables and fail with an actionable message when absent.

- [ ] **Step 6: Run tests and commit**

Run: `python3 -m pytest test/suites/performance/learning/test_run_contract.py -q` and `make -C test -n performance-learning TRAINING_DATA=/tmp/train CALIBRATION_DATA=/tmp/calibration`.

Expected: contract tests pass and dry-run shows preparation, disabled, enabled, and strict report ordering.

Commit: `feat: add learning detector ab benchmark`

### Task 6: Full Verification and Real Medium Acceptance

**Files:**
- Read: source and test files changed by Tasks 1-5; no new source file is expected in this verification task.
- Create: `test/.results/learning-detector/$SYSARMOR_LEARNING_RUN_ID/` generated artifacts (ignored; never commit).

- [ ] **Step 1: Run focused Python and Go tests**

Run: `python3 -m pytest tools/learning_detector test/suites/performance/endpoint/test_run_contract.py test/suites/performance/endpoint/test_runtime_contract.py test/suites/performance/learning -q` and `go test ./apps/agent/... ./apps/agent/cmd/sysarmor-model-sign/...`.

Expected: all focused tests pass.

- [ ] **Step 2: Run repository quality gates**

Run: `go test ./...` and `git diff --check`.

Expected: Go tests pass and diff check is clean.

- [ ] **Step 3: Run the real Learning medium A/B**

Run with the two previously selected independent normal datasets:

```bash
make -C test performance-learning \
  TRAINING_DATA=test/.results/performance-endpoint/20260816T145855Z/collection-balanced/events.scope.ndjson \
  CALIBRATION_DATA=test/.results/performance-endpoint/20260816T161359Z/collection-balanced/events.scope.ndjson \
  PROFILE=medium
```

Expected: `report.md` and `summary.json` are generated; all hard gates pass or the report explicitly identifies the failing gate; attack recall is reported as baseline.

- [ ] **Step 4: Review generated report and clean worktree**

Check model private key is absent, disabled contains no learning config, enabled health is loaded, all Candidate refs resolve, normal metrics use serial markers, and generated results are ignored. Run `git status --short` and ensure only intentional source changes remain.

- [ ] **Step 5: Commit verification fixes atomically**

Commit any test-only or report correctness fixes separately with the applicable `fix:` or `test:` Conventional Commit. Do not commit `.results` or private key material.
