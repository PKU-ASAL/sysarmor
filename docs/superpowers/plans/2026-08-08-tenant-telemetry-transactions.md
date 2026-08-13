# Tenant Telemetry Transactions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace tenant telemetry snapshot overwrites with batch-idempotent PostgreSQL transactions that remain correct across retries, restarts, and concurrent Workers.

**Architecture:** Processor claims a tenant batch before side effects, then commits Metrics delta, Rarity delta, and completed status in one transaction. PostgreSQL is the production source of truth; memory/file adapters implement the same port for development without retaining global compatibility state.

**Tech Stack:** Go 1.26, PostgreSQL, `database/sql`, Protocol Buffers, existing fake SQL driver, Go tests.

## Global Constraints

- Duplicate `(tenant_id, batch_id)` completed batches return success without analysis, indexing, or counters.
- PostgreSQL tenant telemetry cannot be written through `Store.Save()` snapshots or `SaveMetrics()`.
- Metrics, Rarity, and completed status commit atomically.
- Database and adapter errors are returned explicitly.
- No global/default Metrics or Rarity compatibility path remains.
- Production code changes follow test-first RED/GREEN cycles.

---

### Task 1: Define Batch Transaction Contract And Migration

**Files:**
- Modify: `apps/manager/internal/store/backend.go`
- Modify: `apps/manager/internal/store/migrations/postgres.go`
- Modify: `apps/manager/internal/store/migrations/postgres_test.go`
- Modify: `apps/manager/internal/store/postgres/migrate_test.go`

**Interfaces:**
- Produces: `TelemetryBatchDelta`, `BatchClaim`, `TelemetryBatchBackend.ClaimTelemetryBatch`, `TelemetryBatchBackend.CommitTelemetryBatch`.

- [ ] **Step 1: Write failing migration and contract tests**

Assert migration version 3 and schema containing:

```sql
CREATE TABLE IF NOT EXISTS telemetry_batches (
  tenant_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  status TEXT NOT NULL,
  lease_until TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, batch_id),
  CHECK (status IN ('processing', 'completed'))
);
```

- [ ] **Step 2: Run RED**

Run: `GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/store/migrations ./apps/manager/internal/store/postgres -run 'Migration|Migrations' -count=1`

Expected: FAIL because version 3 and `telemetry_batches` do not exist.

- [ ] **Step 3: Add types and migration**

```go
type TelemetryBatchDelta struct {
    TenantID string
    BatchID string
    Metrics Metrics
    Rarity rarity.Baseline
}

type BatchClaim int
const (
    BatchClaimed BatchClaim = iota
    BatchDuplicate
    BatchBusy
)

type TelemetryBatchBackend interface {
    ClaimTelemetryBatch(context.Context, string, string, time.Time) (BatchClaim, error)
    CommitTelemetryBatch(context.Context, TelemetryBatchDelta) error
}
```

Add migration 3 without modifying migration 1 or 2 SQL.

- [ ] **Step 4: Run GREEN and commit**

Run the Task 1 test command; expect PASS.

Commit: `feat(store): add telemetry batch transaction contract`

### Task 2: Implement PostgreSQL Claim And Atomic Commit

**Files:**
- Create: `apps/manager/internal/store/postgres/telemetry_batch.go`
- Create: `apps/manager/internal/store/postgres/telemetry_batch_test.go`
- Modify: `apps/manager/internal/store/postgres/fake_driver_test.go`
- Modify: `apps/manager/internal/store/postgres/telemetry.go`

**Interfaces:**
- Consumes: Task 1 `TelemetryBatchBackend` contract.
- Produces: PostgreSQL implementation with row locking and atomic increments.

- [ ] **Step 1: Write failing adapter tests**

Cover:

```go
func TestClaimTelemetryBatchReturnsDuplicateForCompleted(t *testing.T)
func TestClaimTelemetryBatchReturnsBusyForLiveLease(t *testing.T)
func TestCommitTelemetryBatchCommitsMetricsRarityAndCompletion(t *testing.T)
func TestCommitTelemetryBatchRollsBackOnRarityFailure(t *testing.T)
func TestLoadRarityForTenantPreservesGlobalFallback(t *testing.T)
```

The commit test must assert one transaction and SQL containing `FOR UPDATE`, additive rarity upsert, and completed update.

- [ ] **Step 2: Run RED**

Run: `GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/store/postgres -run 'TelemetryBatch|GlobalFallback' -count=1`

Expected: FAIL with missing methods or incorrect transaction counts.

- [ ] **Step 3: Implement claim**

Use one short transaction. Lock an existing batch row. Return duplicate for completed, busy for an unexpired lease, and update expired processing leases. Insert missing rows as processing. Reject blank tenant or batch IDs.

- [ ] **Step 4: Implement atomic commit**

Within one `sql.Tx`:

```text
SELECT status FROM telemetry_batches ... FOR UPDATE
INSERT metrics zero row ON CONFLICT DO NOTHING
SELECT metrics.data ... FOR UPDATE
merge existing metrics + delta
UPDATE metrics
INSERT rarity rows ... DO UPDATE signal_count = rarity_baseline.signal_count + EXCLUDED.signal_count
UPDATE telemetry_batches SET status='completed', completed_at=now()
COMMIT
```

Reject commits without a claimed processing row. Preserve `global` exactly when loading Rarity.

- [ ] **Step 5: Run GREEN and commit**

Run all PostgreSQL tests; expect PASS.

Commit: `feat(postgres): commit tenant telemetry atomically`

### Task 3: Move Store To The Transaction Port

**Files:**
- Create: `apps/manager/internal/store/telemetry_batch.go`
- Create: `apps/manager/internal/store/telemetry_batch_test.go`
- Modify: `apps/manager/internal/store/store.go`
- Modify: `apps/manager/internal/store/models.go`
- Modify: `apps/manager/internal/store/persistence.go`
- Modify: `apps/manager/internal/store/telemetry.go`
- Modify: `apps/manager/internal/store/telemetry_tenant.go`
- Modify: `apps/manager/internal/store/postgres/snapshot.go`

**Interfaces:**
- Produces: `Store.ClaimTelemetryBatch`, `Store.CommitTelemetryBatch`, tenant-only query methods.

- [ ] **Step 1: Write failing Store contract tests**

Cover memory/file duplicate success, expired lease reclaim, atomic file round-trip, and tenant isolation. Add a reload test proving Signal updates use tenant/key identity instead of pointer identity.

- [ ] **Step 2: Run RED**

Run: `GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/store -run 'TelemetryBatch|Signal.*Reload' -count=1`

Expected: FAIL because batch APIs and durable batch ledger are absent.

- [ ] **Step 3: Implement Store adapter**

Delegate to `TelemetryBatchBackend` when attached. For memory/file, guard ledger and tenant state with the Store mutex, persist one State containing batch ledger, Metrics and Rarity, and return explicit errors.

- [ ] **Step 4: Delete compatibility paths**

Remove `Metrics`, `RarityBaseline`, `MetricsBackend`, global getters/setters, `SaveMetrics`, and PostgreSQL snapshot projection of telemetry. Keep only `MetricsByTenant`, `RarityByTenant`, and `TenantSignals`. Replace pointer matching in Signal compatibility synchronization with tenant plus stable signal key, then remove the global Signal view when no consumer remains.

- [ ] **Step 5: Run GREEN and commit**

Run Store and PostgreSQL tests; expect PASS.

Commit: `refactor(store): make tenant telemetry transactional`

### Task 4: Switch Processor To Claim/Commit

**Files:**
- Modify: `apps/manager/internal/ingest/processor.go`
- Modify: `apps/manager/internal/ingest/worker_test.go`
- Modify: `apps/manager/internal/ingest/history_test.go`
- Modify: `apps/manager/internal/store/backend/backend_test.go`

**Interfaces:**
- Consumes: `Store.ClaimTelemetryBatch`, `Store.CommitTelemetryBatch`.
- Produces: duplicate-safe Processor flow.

- [ ] **Step 1: Write failing Processor tests**

```go
func TestProcessorDuplicateBatchSkipsProjectionAndMetrics(t *testing.T)
func TestProcessorRestartContinuesTenantMetricsAndRarity(t *testing.T)
func TestTwoProcessorsDoNotLoseTenantUpdates(t *testing.T)
func TestProcessorCommitFailureLeavesBatchRetryable(t *testing.T)
```

- [ ] **Step 2: Run RED**

Run: `GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/ingest ./apps/manager/internal/store/backend -run 'DuplicateBatch|RestartContinues|DoNotLose|CommitFailure' -count=1`

Expected: FAIL because Processor performs side effects before idempotency and uses snapshot methods.

- [ ] **Step 3: Implement claim-first flow**

Validate identity, claim with a bounded lease, return a successful duplicate `Result` before `AddAgent`, analysis, or projection, and return a retryable error for busy claims.

- [ ] **Step 4: Implement one commit**

Build Metrics and Rarity deltas from the accepted batch and analysis result. Call `CommitTelemetryBatch` exactly once after successful OpenSearch projection. Remove `RecordDataBatchIngestForTenant`, `ObserveRaritySignalsForTenant`, `SaveMetrics`, and telemetry snapshot writes from this path.

- [ ] **Step 5: Run GREEN and commit**

Run ingest and backend tests; expect PASS.

Commit: `fix(ingest): make telemetry batches idempotent`

### Task 5: Verify And Review The Checkpoint

**Files:**
- Modify only files required by test or review findings.

- [ ] **Step 1: Run focused verification**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/store/... ./apps/manager/internal/ingest/... -race -count=1
```

- [ ] **Step 2: Run complete verification**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/... -count=1
GOCACHE=/tmp/sysarmor-layered-go-cache make -C test test-unit
```

- [ ] **Step 3: Confirm removed paths**

Run `rg -n 'SaveMetrics|MetricsBackend|RarityBaseline[^S]|RecordDataBatchIngestForTenant' apps/manager` and expect no production call sites.

- [ ] **Step 4: Independent checkpoint review**

Review from `60731c29` through HEAD for restart safety, concurrent accumulation, duplicate side effects, rollback, tenant isolation, and prohibited compatibility paths. Required result: `Critical 0 / Important 0 / Ready Yes`.
