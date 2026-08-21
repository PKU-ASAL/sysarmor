# Candidate Lifecycle Cohort Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 managed Learning 验收按同一组 Signal 身份证明 created、spooled、accepted、correlated、projected 和 rejected 生命周期，消除累计计数补数误判。

**Architecture:** Candidate 仍是 `stage=CANDIDATE` 的 Signal，不新增实体或 ID。Agent 使用一次性冻结快照确定计数和 Event sequence cutoff；Worker 使用 PostgreSQL `worker_signal_processing` 按现有 Signal ID 持久化 correlated/projected/rejected 状态；报告按 cutoff 和正式 Worker Signal 结果计算 cohort。

**Tech Stack:** Go、PostgreSQL/lib/pq、Python unittest、Bash、Vagrant managed VM。

## Global Constraints

- PostgreSQL 是 Manager/Worker 唯一生产路径，不增加 SQLite 或方言兼容生产实现。
- 不改变 Learning 模型、特征、阈值和 Candidate 生成算法。
- 不向生产 Signal 增加 benchmark run ID 或测试窗口字段。
- `Signal.id` 是唯一 Signal 身份；Candidate 只是 Signal 阶段。
- Worker projection 的业务原子性保持不变。
- 缺失必需生命周期产物必须 unavailable/failed，禁止静默解释为零。

---

### Task 1: PostgreSQL Worker Signal Processing State

**Files:**
- Modify: `apps/manager/internal/ports/worker.go`
- Modify: `apps/manager/internal/adapters/inbound/kafka/batch_decoder.go`
- Modify: `apps/manager/internal/adapters/inbound/kafka/batch_decoder_test.go`
- Modify: `apps/manager/internal/adapters/outbound/postgres/migrations/postgres.go`
- Modify: `apps/manager/internal/adapters/outbound/postgres/migrations/postgres_test.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/worker/signal_processing.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/worker/signal_processing_test.go`
- Modify: `apps/manager/internal/adapters/outbound/postgres/worker/telemetry_batches_postgres_test.go`

**Interfaces:**
- Produces: `ports.SignalProcessingRecord` with tenant, Signal, batch, subject, trigger Event and sequence identity.
- Produces: `TelemetryBatches.CorrelateSignals(context.Context, ports.SignalProcessingBatch) error`.
- Extends: `ports.TelemetryBatchDelta.ProjectedSignals []ports.SignalProcessingRecord`.

- [ ] **Step 1: Write failing migration and repository tests**

```go
func TestSignalProcessingCorrelateIsIdempotent(t *testing.T) {
    repo, db := newSignalProcessingRepository(t)
    batch := ports.SignalProcessingBatch{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: claim(t, repo), Signals: []ports.SignalProcessingRecord{{SignalID: "signal-a", SubjectID: "process-a", TriggerEventID: "event-a", EventSequence: 7}}}
    requireNoError(t, repo.CorrelateSignals(context.Background(), batch))
    requireNoError(t, repo.CorrelateSignals(context.Background(), batch))
    assertSignalState(t, db, "signal-a", "correlated")
    assertMetric(t, db, "model_candidates_correlated", 1)
}
```

- [ ] **Step 2: Run tests and verify RED**

Run: `go test ./apps/manager/internal/adapters/outbound/postgres/migrations ./apps/manager/internal/adapters/outbound/postgres/worker`

Expected: FAIL because migration 9 and `CorrelateSignals` do not exist.

- [ ] **Step 3: Add migration 9 and type-safe port**

```sql
CREATE TABLE IF NOT EXISTS worker_signal_processing (
  tenant_id TEXT NOT NULL,
  signal_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  subject_id TEXT NOT NULL DEFAULT '',
  trigger_event_id TEXT NOT NULL DEFAULT '',
  event_sequence BIGINT NOT NULL CHECK (event_sequence >= 0),
  status TEXT NOT NULL CHECK (status IN ('correlated','projected','reference_rejected')),
  failure_class TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, signal_id),
  CHECK (status = 'reference_rejected' OR (subject_id <> '' AND trigger_event_id <> ''))
);
CREATE INDEX IF NOT EXISTS idx_worker_signal_processing_batch
  ON worker_signal_processing (tenant_id, batch_id);
```

```go
type SignalProcessingRecord struct {
    SignalID, BatchID, SubjectID, TriggerEventID string
    EventSequence uint64
}

type SignalProcessingBatch struct {
    TenantID, BatchID, ClaimToken string
    Signals []SignalProcessingRecord
}
```

- [ ] **Step 4: Implement fenced, idempotent correlated insert**

Use a PostgreSQL transaction, lock the processing batch with tenant/batch/claim token, insert each Signal with `ON CONFLICT DO NOTHING`, and increment `model_candidates_correlated` only by inserted rows.

Extend `ports.CandidateRejection` with the existing Model Candidate Signal IDs collected from the rejected DataBatch. `RecordCandidateRejection` writes those IDs to `worker_signal_processing` with `reference_rejected` and the violation code, increments rejection metrics only for newly inserted rows, and removes the old aggregate rejection table in migration 9.

- [ ] **Step 5: Run tests and verify GREEN**

Run: `go test ./apps/manager/internal/adapters/outbound/postgres/migrations ./apps/manager/internal/adapters/outbound/postgres/worker`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/manager/internal/ports/worker.go apps/manager/internal/adapters/inbound/kafka apps/manager/internal/adapters/outbound/postgres/migrations apps/manager/internal/adapters/outbound/postgres/worker
git commit -m "feat(worker): persist Signal processing lifecycle"
```

### Task 2: Worker Correlated and Projected Transitions

**Files:**
- Modify: `apps/manager/internal/application/worker/process_batch.go`
- Modify: `apps/manager/internal/application/worker/process_metrics.go`
- Modify: `apps/manager/internal/application/worker/process_batch_test.go`
- Modify: `apps/manager/internal/adapters/outbound/postgres/worker/telemetry_batches.go`
- Modify: `apps/manager/internal/adapters/outbound/postgres/worker/telemetry_batches_test.go`

**Interfaces:**
- Consumes: `TelemetryBatches.CorrelateSignals` and `SignalProcessingBatch` from Task 1.
- Produces: projected transition inside `TelemetryBatches.Commit`.

- [ ] **Step 1: Write failing service tests**

```go
func TestProjectionFailureLeavesSignalCorrelated(t *testing.T) {
    fixture := newProcessFixtureWithModelCandidate()
    fixture.projector.err = errors.New("opensearch unavailable")
    _, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)
    if err == nil || fixture.batches.correlated != 1 || fixture.batches.projected != 0 {
        t.Fatalf("err=%v correlated=%d projected=%d", err, fixture.batches.correlated, fixture.batches.projected)
    }
}
```

- [ ] **Step 2: Run test and verify RED**

Run: `go test ./apps/manager/internal/application/worker -run 'TestProjectionFailureLeavesSignalCorrelated|TestProcessBatchProjectsDomainModelsAndMetrics'`

Expected: FAIL because both metrics are currently assigned together after projection.

- [ ] **Step 3: Build Signal processing records from the formal DataBatch**

Add a focused helper that selects endpoint Model Candidate Signals, resolves their single subject and current Event, and returns `[]ports.SignalProcessingRecord`. It must return an error when the already-validated identity cannot be represented.

- [ ] **Step 4: Record correlated before projection and projected during commit**

Call `CorrelateSignals` after analysis/reference resolution and before `BatchProjector.Project`. Remove `ModelCandidatesCorrelated` and `ModelCandidatesProjected` from the shared `telemetryBatchDelta` assignment. Attach Signal records to the commit delta; PostgreSQL advances only correlated rows for the owned batch to projected and increments the projected metric by changed rows.

- [ ] **Step 5: Verify retry idempotency**

Run: `go test ./apps/manager/internal/application/worker ./apps/manager/internal/adapters/outbound/postgres/worker`

Expected: PASS; projection failure exposes correlated without projected, and retry does not duplicate either metric.

- [ ] **Step 6: Commit**

```bash
git add apps/manager/internal/application/worker apps/manager/internal/adapters/outbound/postgres/worker apps/manager/internal/ports/worker.go
git commit -m "refactor(worker): separate Signal correlation from projection"
```

### Task 3: Exact Experiment Cohort

**Files:**
- Modify: `test/suites/performance/endpoint/run.sh`
- Modify: `test/suites/performance/endpoint/test_runtime_contract.py`
- Modify: `test/suites/performance/learning/managed_analysis.py`
- Modify: `test/suites/performance/learning/report.py`
- Modify: `test/suites/performance/learning/test_report.py`

**Interfaces:**
- Produces: one-shot `candidate-lifecycle-final.json` with `experimentCreated` and `eventSequenceCutoff`.
- Produces: strict Worker lifecycle artifact derived from Manager results.

- [ ] **Step 1: Write failing cohort pollution tests**

```python
def test_worker_candidates_after_event_cutoff_do_not_fill_backlog(self):
    candidates = [candidate("signal-a", "agent-0007"), candidate("probe", "agent-0010")]
    cohort = MANAGED.worker_candidate_cohort(candidates, event_sequence_cutoff=7)
    self.assertEqual([item["id"] for item in cohort], ["signal-a"])
```

Also add tests proving missing `manager-metrics.json` and missing required fields return unavailable rather than zero.

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest test/suites/performance/learning/test_report.py test/suites/performance/endpoint/test_runtime_contract.py`

Expected: FAIL because the runner polls Agent health and the parser does not filter by Event sequence.

- [ ] **Step 3: Replace Agent polling with one-shot freeze**

`capture_final_candidate_lifecycle` performs one health request, writes the snapshot atomically, and annotates both:

```json
{
  "detection": {"learning": {"candidates": {"experimentCreated": 9}}},
  "localStore": {"eventSequenceCutoff": 1200}
}
```

The cutoff value comes from the existing `localStore.latestEventSequence`; no new production field is added. Timeout handling retains this frozen artifact and never falls back to current `created`.

- [ ] **Step 4: Filter formal Worker Signals by triggering Event sequence**

Parse the numeric sequence suffix from the required current `eventRefs` identity, reject malformed/missing refs, keep only sequence `<= eventSequenceCutoff`, and require unique Signal IDs. Compute Worker cohort counts from the filtered formal Manager Signal result; tenant-level metrics remain diagnostics, not cohort membership proof.

- [ ] **Step 5: Run tests and verify GREEN**

Run: `python3 -m unittest discover -s test/suites/performance -p 'test_*.py' && bash -n test/suites/performance/endpoint/run.sh`

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add test/suites/performance/endpoint test/suites/performance/learning
git commit -m "test(learning): enforce exact Candidate Signal cohort"
```

### Task 4: Hard Gate Missing Data and Endpoint Storage Loss

**Files:**
- Modify: `test/suites/performance/learning/learning_effect.py`
- Modify: `test/suites/performance/learning/learning_report_renderer.py`
- Modify: `test/suites/performance/learning/test_report.py`

**Interfaces:**
- Consumes: strict lifecycle and cohort values from Task 3.
- Produces: blocking lifecycle gate with explicit failure reason.

- [ ] **Step 1: Write failing gate tests**

```python
def test_endpoint_storage_drop_fails_candidate_lifecycle(self):
    metrics = complete_lifecycle_metrics()
    metrics["reference_gaps"]["endpoint_storage_drop"] = 1
    self.assertEqual(EFFECT.candidate_lifecycle_gate(metrics)["status"], "failed")

def test_observation_gap_does_not_fail_candidate_lifecycle(self):
    metrics = complete_lifecycle_metrics()
    metrics["reference_gaps"]["observation_gap"] = 99
    self.assertEqual(EFFECT.candidate_lifecycle_gate(metrics)["status"], "passed")
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest test/suites/performance/learning/test_report.py`

Expected: endpoint storage drop test FAILS.

- [ ] **Step 3: Add storage loss and strict availability to the gate**

Require `endpoint_storage_drop`, Agent rejection/backlog, Gateway rejection/backlog, Worker rejection/backlog, correlated and projected. Any missing value yields unavailable/failed; any nonzero loss/rejection/backlog fails. Observation gap remains an informational report row.

- [ ] **Step 4: Run all report tests and verify GREEN**

Run: `python3 -m unittest discover -s test/suites/performance -p 'test_*.py'`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add test/suites/performance/learning
git commit -m "test(learning): harden Signal lifecycle quality gate"
```

### Task 5: Integration and Managed VM Acceptance

**Files:**
- Modify: `docs/development/testing.md`
- Modify: `docs/concepts/security-data-model.md`
- Delete after completion: `docs/superpowers/specs/2026-08-21-candidate-lifecycle-cohort-design.md`
- Delete after completion: `docs/superpowers/plans/2026-08-21-candidate-lifecycle-cohort.md`

**Interfaces:**
- Consumes all previous tasks.
- Produces final managed report and formal documentation.

- [ ] **Step 1: Run focused and full quality checks**

```bash
go test ./apps/manager/internal/application/worker ./apps/manager/internal/adapters/outbound/postgres/migrations ./apps/manager/internal/adapters/outbound/postgres/worker
python3 -m unittest discover -s test/suites/performance -p 'test_*.py'
bash -n test/suites/performance/endpoint/run.sh
git diff --check
```

- [ ] **Step 2: Run PostgreSQL integration tests**

Run: `make test-postgres-integration`

Expected: the real PostgreSQL worker concurrency script passes, including correlated/projected transitions, claim fencing and retry idempotency against lib/pq.

- [ ] **Step 3: Run managed quick VM matrix**

```bash
SYSARMOR_LEARNING_RUN_ID=20260821T-managed-quick-cohort \
make test-performance DOMAIN=learning PROFILE=quick \
  TRAINING_DATA=test/data/learning/observed-events.ndjson \
  CALIBRATION_DATA=test/data/learning/normal-events.ndjson
```

Expected lifecycle acceptance:

- learning-only and hybrid lifecycle gates pass;
- Model Candidate sample count equals cohort projected count;
- no contract/Gateway/Worker rejection or pending backlog;
- hybrid graph recall and conclusion recall are both at least `0.90`.

Learning-only normal Candidate rate and RSS remain separate gates and may still fail without invalidating this lifecycle implementation assessment.

- [ ] **Step 4: Update formal docs and archive working documents in Git history**

Document that Candidate is a Signal stage, Signal ID is the lifecycle identity, and Worker persistence records processing state rather than a Candidate entity. Remove the completed spec and plan from the working tree as required by the repository documentation policy.

- [ ] **Step 5: Request final read-only code review and commit docs cleanup**

```bash
git add docs/development/testing.md docs/concepts/security-data-model.md docs/superpowers
git commit -m "docs: document Signal lifecycle verification"
```
