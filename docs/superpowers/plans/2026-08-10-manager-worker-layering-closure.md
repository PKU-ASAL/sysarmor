# Manager and Worker Layering Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Task 6 and Task 8 by moving all Manager and Worker production paths to Domain/Application/Ports/Adapters/Bootstrap, retaining only PostgreSQL production storage and deleting every legacy Store, Ingest, Analytics, and compatibility path.

**Architecture:** Manager HTTP routes call narrow application services backed by PostgreSQL repositories and units of work. Worker Kafka adapters decode wire messages into worker boundary models, application services enforce claim/retry/projection semantics, and pure detection/investigation domains perform deterministic analysis. Production commands call Bootstrap only; no legacy facade or fallback remains.

**Tech Stack:** Go 1.26, PostgreSQL, OpenSearch, Kafka, Redis, Protocol Buffers, HTTP/JWT, gRPC/mTLS, Python architecture contracts.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-10-manager-worker-layering-closure-design.md` exactly.
- Preserve published HTTP, JSON, and Protobuf semantics.
- Retain only PostgreSQL production storage; delete memory and file product backends.
- Domain must not import Protobuf, HTTP, gRPC, SQL, Kafka, Redis, or OpenSearch.
- Application may import only Domain, Application, Ports, and allowed standard library packages.
- Every tenant-scoped Port requires a validated non-empty `tenant.ID`.
- Do not retain forwarding packages, compatibility constructors, fallback routes, or dual writes.
- Write a failing test before each production change.
- Keep changed functions below 50 lines and non-generated files below 500 lines.
- Use `GOCACHE=/tmp/sysarmor-layered-go-cache` for repository-wide Go verification.

---

## Progress Summary

| Task | Scope | Status |
|---:|---|---|
| 1 | Executable closure contracts | Complete |
| 2 | Enrollment and unenrollment slice | Complete |
| 3 | Control and evidence pullback slice | Complete |
| 4 | Response approval slice | Complete |
| 5 | Artifact, channel, and deployment material slice | Complete |
| 6 | Manager query and telemetry Store removal | Complete |
| 7 | PostgreSQL-only Manager Bootstrap | Complete |
| 8 | Pure analytics Domain packages | Complete |
| 9 | `ProcessBatch` Worker Application Service | Complete |
| 10 | PostgreSQL-only `bootstrap.NewWorker` | Complete |
| 11 | Legacy roots and compatibility deletion | Complete |
| 12 | Repository-wide verification and documentation | Complete |

Current closure result: production commands use Bootstrap, the shared database opener rejects every non-PostgreSQL driver,
Worker orchestration lives in Application, wire/document mapping lives in Adapters, and no Store,
Ingest, or Analytics compatibility facade remains. Tasks 1-12 are implemented and verified by the
architecture contracts and repository-wide Go checks below; the table above is the authoritative
status summary for those historical slices.

---

### Task 1: Make Closure Requirements Executable

**Files:**
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- Produces explicit absence checks for Task 6/8 legacy roots and symbols.
- Leaves Agent legacy exemptions intact for Task 9/10.

- [ ] **Step 1: Add failing absence and command-boundary assertions**

```python
RETIRED_MANAGER_ROOTS = {
    "apps/manager/internal/store",
    "apps/manager/internal/ingest",
    "apps/manager/internal/analytics",
    "apps/manager/internal/platform",
}

RETIRED_SYMBOLS = ("store.Store", "ManagerStore", "SaveState", "ingest.Processor")

def test_manager_commands_depend_on_bootstrap_only(self):
    for command in ("sysarmor-manager", "sysarmor-worker", "sysarmor-gateway"):
        text = (self.repo / "apps/manager/cmd" / command / "main.go").read_text()
        self.assertNotIn("/internal/store", text)
        self.assertNotIn("/internal/ingest", text)
        self.assertNotIn("/internal/api", text)
```

- [ ] **Step 2: Run `python3 -m unittest test.contracts.test_layered_architecture -v`**

Expected: FAIL because legacy roots and command imports still exist. Do not skip or weaken these checks while slices migrate.

- [ ] **Step 3: Commit with `test(architecture): define manager worker closure`**

### Task 2: Migrate Enrollment and Unenrollment

**Files:**
- Create: `apps/manager/internal/domain/enrollment/{model.go,model_test.go}`
- Create: `apps/manager/internal/application/manager/enrollment/{service.go,service_test.go}`
- Create: `apps/manager/internal/ports/enrollment.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/enrollment/{repository.go,unit_of_work.go,repository_test.go}`
- Create: `apps/manager/internal/adapters/inbound/http/enrollment/{handler.go,handler_test.go,dto.go,mapper.go}`
- Create: `apps/manager/internal/bootstrap/manager_enrollment.go`
- Delete after route switch: legacy enrollment handlers and Store methods.

**Interfaces:**
- Produces `enrollment.Service` operations `Create`, `FetchArtifact`, `IssueCertificate`, `AuthorizeUnenrollment`, `CompleteUnenrollment`, and `List`.
- Produces `ports.EnrollmentUnitOfWork` and `ports.EnrollmentTransaction` using Domain models.

- [ ] **Step 1: Write failing token and identity state tests**

```go
func TestEnrollmentConsumesTokenOnce(t *testing.T) {
    enrollment := activeEnrollment(t)
    used, err := enrollment.Consume(fixedNow)
    if err != nil { t.Fatal(err) }
    if _, err := used.Consume(fixedNow); failure.KindOf(err) != failure.Conflict {
        t.Fatalf("second consume kind = %v", failure.KindOf(err))
    }
}

func TestUnenrollmentRejectsIdentityMismatch(t *testing.T) {
    record := pendingUnenrollment(t)
    _, err := record.Complete(Completion{AgentID: "other"}, fixedNow)
    if failure.KindOf(err) != failure.Conflict { t.Fatalf("kind = %v", failure.KindOf(err)) }
}
```

- [ ] **Step 2: Run `go test ./apps/manager/internal/domain/enrollment -count=1` and verify RED because the package does not exist.**
- [ ] **Step 3: Implement immutable Domain transitions, then write Fake UoW tests proving token consumption, certificate persistence, and audit share one transaction.**
- [ ] **Step 4: Move enrollment/certificate/unenrollment SQL into the PostgreSQL adapter without wrapping Store.**
- [ ] **Step 5: Switch `/enrollments`, `/enrollment-artifact`, `/enrollment-certificate`, and `/unenrollment-completions`; remove their `ManagerStore` methods immediately.**
- [ ] **Step 6: Run focused Domain/Application/Adapter/HTTP tests and commit `refactor(manager): migrate enrollment application slice`.**

### Task 3: Migrate Control and Evidence Pullback

**Files:**
- Create: `apps/manager/internal/domain/control/{model.go,model_test.go}`
- Create: `apps/manager/internal/application/manager/control/{service.go,service_test.go}`
- Create: `apps/manager/internal/ports/control.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/control/{command_repository.go,unit_of_work.go}`
- Create: `apps/manager/internal/adapters/inbound/http/control/{handler.go,handler_test.go,dto.go,mapper.go}`
- Modify: Gateway control handlers to call the same application service.
- Delete after switch: legacy control and evidence Store methods.

**Interfaces:**
- Produces create, list, ack, retry, cancel, expire, pullback create/list/get/complete operations.
- `ports.ControlTransaction` exposes only command, pullback, and audit repositories.

- [ ] **Step 1: Write the failing transition test**

```go
func TestSentCommandAcknowledgementIsIdempotent(t *testing.T) {
    command := sentCommand(t)
    first, err := command.Acknowledge(Ack{Status: StatusSucceeded}, fixedNow)
    if err != nil { t.Fatal(err) }
    second, err := first.Acknowledge(Ack{Status: StatusSucceeded}, fixedNow)
    if err != nil || second != first { t.Fatalf("idempotent ack failed: %v", err) }
}
```

- [ ] **Step 2: Verify RED, implement Domain/Application with Fake UoW, and verify GREEN.**
- [ ] **Step 3: Move SQL with optimistic status predicates into the adapter; Contract DTOs remain in mappers only.**
- [ ] **Step 4: Switch HTTP and Gateway callers, delete old methods, run focused tests, and commit `refactor(manager): migrate control application slice`.**

### Task 4: Migrate Response Approval

**Files:**
- Create: `apps/manager/internal/domain/response/{model.go,model_test.go}`
- Create: `apps/manager/internal/application/manager/response/{service.go,service_test.go}`
- Create: `apps/manager/internal/ports/response.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/response/{repository.go,unit_of_work.go}`
- Create: `apps/manager/internal/adapters/inbound/http/response/{handler.go,handler_test.go,dto.go,mapper.go}`
- Delete after switch: legacy response handlers and Store methods.

**Interfaces:**
- Produces `Create`, `Decide`, `Approve`, `Acknowledge`, `List`, and `Pending`.
- Approval writes Decision, Command, and Audit atomically.

- [ ] **Step 1: Write failing multi-approval test**

```go
func TestApprovalCreatesCommandOnlyAtThreshold(t *testing.T) {
    service, tx := newServiceFixture(t, requiredApprovals(2))
    first, err := service.Approve(ctx, operatorA, approvalCommand())
    if err != nil || first.CommandCreated { t.Fatalf("first = %#v, %v", first, err) }
    second, err := service.Approve(ctx, operatorB, approvalCommand())
    if err != nil || !second.CommandCreated || tx.CommitCount != 2 {
        t.Fatalf("second = %#v, %v", second, err)
    }
}
```

- [ ] **Step 2: Add role, denial, duplicate decision, and idempotent ack tests; verify RED.**
- [ ] **Step 3: Implement Domain/Application, PostgreSQL adapter, and HTTP mapper.**
- [ ] **Step 4: Switch routes, delete legacy response code, run focused tests, and commit `refactor(manager): migrate response application slice`.**

### Task 5: Migrate Artifact, Channel, and Deployment Material

**Files:**
- Create: `apps/manager/internal/domain/artifact/{model.go,model_test.go}`
- Create: `apps/manager/internal/application/manager/artifact/{service.go,service_test.go}`
- Create: `apps/manager/internal/ports/artifact.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/artifact/{repository.go,repository_test.go}`
- Create: `apps/manager/internal/adapters/inbound/http/artifact/{handler.go,handler_test.go,dto.go,mapper.go}`
- Create: `apps/manager/internal/adapters/outbound/archive/artifact.go`
- Delete after switch: legacy artifact/channel/deploy handlers and Store methods.

**Interfaces:**
- Produces artifact/channel application operations and `ports.ArtifactArchive` for filesystem access.

- [ ] **Step 1: Write failing active-artifact test**

```go
func TestChannelRejectsInactiveArtifact(t *testing.T) {
    service := newArtifactService(t, artifactWithStatus(StatusRetired))
    _, err := service.SetChannel(ctx, operator, SetChannelCommand{Channel: "stable", ArtifactID: "agent-1"})
    if failure.KindOf(err) != failure.FailedPrecondition { t.Fatalf("kind = %v", failure.KindOf(err)) }
}
```

- [ ] **Step 2: Verify RED, implement Domain/Application, then add PostgreSQL contract tests.**
- [ ] **Step 3: Move archive parsing and install/deploy material generation into adapters and switch unchanged HTTP DTOs.**
- [ ] **Step 4: Delete legacy path, run focused tests, and commit `refactor(manager): migrate artifact application slice`.**

### Task 6: Replace Remaining Manager Query and Telemetry Store Access

**Files:**
- Create: `apps/manager/internal/application/manager/telemetry/{query.go,query_test.go}`
- Create: `apps/manager/internal/ports/telemetry.go`
- Create: `apps/manager/internal/adapters/outbound/opensearch/telemetry_query.go`
- Create: `apps/manager/internal/adapters/inbound/http/telemetry/{handler.go,handler_test.go}`
- Create: `apps/manager/internal/adapters/inbound/http/search/{handler.go,handler_test.go}`
- Modify: Identity query service for health/overview/metrics ownership.
- Delete after switch: telemetry, incident, search, overview, recompute, rules, and store-status legacy handlers.

**Interfaces:**
- Produces tenant-scoped Event, Signal, Incident, Search, Metrics, and Rarity queries.
- No query accepts blank tenant as an all-tenant shortcut.

- [ ] **Step 1: Write failing tenant test**

```go
func TestTelemetryQueryRequiresTenant(t *testing.T) {
    service := NewQueryService(fakeTelemetryReader{})
    _, err := service.Events(ctx, manager.RequestContext{}, EventQuery{})
    if failure.KindOf(err) != failure.InvalidArgument { t.Fatalf("kind = %v", failure.KindOf(err)) }
}
```

- [ ] **Step 2: Add two-tenant HTTP contract cases and verify RED.**
- [ ] **Step 3: Implement query Ports/OpenSearch adapter, switch routes, and delete operational `Save`, `Info`, and reset-style capabilities.**
- [ ] **Step 4: Run focused tests and commit `refactor(manager): remove remaining store-backed queries`.**

### Task 7: Introduce PostgreSQL-Only Manager Bootstrap

**Files:**
- Create: `apps/manager/internal/bootstrap/manager.go`
- Create: `apps/manager/internal/bootstrap/manager_test.go`
- Modify: `apps/manager/cmd/sysarmor-manager/{main.go,main_test.go}`
- Modify: `apps/manager/cmd/sysarmor-gateway/main.go`
- Create: shared PostgreSQL opener below `apps/manager/internal/adapters/outbound/postgres`.

**Interfaces:**
- Produces `bootstrap.NewManager(Config) (*http.Server, io.Closer, error)`.
- Removes store backend selection and file/memory fallback.

- [ ] **Step 1: Write failing required-DSN test**

```go
func TestNewManagerRejectsMissingPostgresDSN(t *testing.T) {
    _, _, err := NewManager(ManagerConfig{})
    if err == nil || !strings.Contains(err.Error(), "postgres dsn is required") {
        t.Fatalf("err = %v", err)
    }
}
```

- [ ] **Step 2: Verify RED and implement validation/composition.**
- [ ] **Step 3: Reduce Manager command to flag parsing, Bootstrap call, serve, and close; assert it imports no API, Store, SQL repository, or OpenSearch package.**
- [ ] **Step 4: Run Bootstrap/command/Gateway tests and commit `refactor(manager): use postgres-only bootstrap`.**

### Task 8: Move Analytics into Pure Domain Packages

**Files:**
- Create: `apps/manager/internal/domain/detection/{correlation,convergence,rarity}/`
- Create: `apps/manager/internal/domain/investigation/{entity,graph,evidence,incident}/`
- Create: `apps/manager/internal/domain/telemetry/model.go`
- Move and adapt tests from `apps/manager/internal/analytics/*`.
- Create: `apps/manager/internal/adapters/contracts/{telemetry_mapper.go,telemetry_mapper_test.go}`

**Interfaces:**
- Produces Protobuf-free Event, Signal, Evidence, Incident, Analysis, and Rarity models.
- Produces round-trip mappers between wire contracts and Domain models.

- [ ] **Step 1: Port algorithm tests before implementation, including stable Incident identity**

```go
func TestStableIncidentIDIgnoresInputOrder(t *testing.T) {
    first := Build(candidateSignals("a", "b"))
    second := Build(candidateSignals("b", "a"))
    if first.ID != second.ID { t.Fatalf("IDs differ: %q != %q", first.ID, second.ID) }
}
```

- [ ] **Step 2: Run new Domain tests and verify RED because implementations are absent.**
- [ ] **Step 3: Move algorithms to Domain types and implement boundary mappers; retain only analysis-relevant fields.**
- [ ] **Step 4: Run Domain tests/benchmarks and commit `refactor(worker): isolate analytics domain`.**

### Task 9: Replace Ingest Processor with Worker Application

**Files:**
- Create: `apps/manager/internal/application/worker/{process_batch.go,process_batch_test.go,process_metrics.go,recompute_scope.go}`
- Create: `apps/manager/internal/ports/worker_batch.go`
- Create: `apps/manager/internal/adapters/inbound/kafka/{batch_decoder.go,batch_decoder_test.go}`
- Create: `apps/manager/internal/adapters/outbound/opensearch/worker/{history.go,documents.go,projector.go,projector_test.go}`
- Reuse: `apps/manager/internal/adapters/outbound/postgres/worker/telemetry_batches.go`

**Interfaces:**
- Produces `ProcessBatch.Execute(context.Context, ports.DataBatch) (ProcessBatchResult, error)`.
- Kafka Adapter owns Protobuf decode/schema validation and returns permanent errors only for invalid wire input.

- [x] **Step 1: Write processing failure matrix, beginning with projection failure**

```go
func TestProjectionFailureAbandonsClaim(t *testing.T) {
    fixture := newProcessFixture(t)
    fixture.projector.err = errors.New("opensearch unavailable")
    _, err := fixture.service.Execute(ctx, fixture.batch)
    if err == nil { t.Fatal("expected projection error") }
    if fixture.batches.abandoned != 1 || fixture.batches.committed != 0 {
        t.Fatalf("abandon=%d commit=%d", fixture.batches.abandoned, fixture.batches.committed)
    }
}
```

- [x] **Step 2: Add duplicate, busy, history, policy, commit, abandon, and success cases; verify RED.**
- [x] **Step 3: Implement the use case using Domain analysis and move document mapping/stable IDs to adapters.**
- [x] **Step 4: Run Worker/Application/Adapter tests.**

### Task 10: Introduce PostgreSQL-Only Worker Bootstrap

**Files:**
- Create: `apps/manager/internal/bootstrap/{worker.go,worker_test.go}`
- Modify: `apps/manager/cmd/sysarmor-worker/{main.go,main_test.go}`

**Interfaces:**
- Produces `bootstrap.NewWorker(context.Context, WorkerConfig) (*worker.Worker, io.Closer, error)`.
- Requires PostgreSQL DSN, Kafka brokers/topic/group, and OpenSearch URL.

- [x] **Step 1: Write failing configuration test**

```go
func TestNewWorkerRejectsMissingDependencies(t *testing.T) {
    _, _, err := NewWorker(WorkerConfig{})
    if err == nil { t.Fatal("empty worker config accepted") }
}
```

- [x] **Step 2: Verify RED and implement Bootstrap composition/cleanup.**
- [x] **Step 3: Reduce Worker command below 100 lines and remove Protobuf, Kafka, OpenSearch, PostgreSQL, Ingest, and Store imports.**
- [x] **Step 4: Run Bootstrap/command tests.**

### Task 11: Delete Legacy Roots and Compatibility Paths

**Files:**
- Delete: `apps/manager/internal/store`
- Delete: `apps/manager/internal/ingest`
- Delete: `apps/manager/internal/analytics`
- Delete: `apps/manager/internal/platform`
- Delete or reduce: `apps/manager/internal/api` after all handlers move.
- Modify: tests/fixtures that instantiate `store.Store`.
- Modify: architecture and monorepo contracts.

**Interfaces:**
- Produces no compatibility surface; all callers compile against new layers.

- [x] **Step 1: Run `rg -n 'internal/(store|ingest|analytics|platform)|store\.Store|ManagerStore|SaveState|ingest\.Processor' apps/manager packages --glob '*.go'`.** Production Manager/Worker code has no matches; the remaining match is an intentional command-level absence assertion.

Expected: only files scheduled for deletion or tests scheduled for migration.

- [x] **Step 2: Migrate remaining tests to narrow Fake Ports/PostgreSQL adapters; do not recreate an in-memory aggregate.**
- [x] **Step 3: Delete legacy roots and remove only Manager Task 6/8 exemptions.**
- [x] **Step 4: Run the architecture contract and symbol scan; expect PASS and no production matches.**
- [x] **Step 5: Commit `refactor(architecture): remove manager worker legacy paths`.** Legacy path removal was preserved in the preceding atomic refactor commits.

### Task 12: Final Verification and Documentation

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/development/{development.md,testing.md}`
- Modify: `docs/reference/configuration.md`
- Modify: `CATALOG.md` only if navigation changes.

**Interfaces:**
- Documentation describes implemented PostgreSQL-only Manager/Worker architecture.

- [x] **Step 1: Run formatting, static, and architecture gates**

```bash
test -z "$(gofmt -l apps packages)"
git diff --check
python3 -m unittest discover -s test/contracts -p 'test_*.py' -v
GOCACHE=/tmp/sysarmor-layered-go-cache go vet ./...
```

- [x] **Step 2: Run unit and race suites**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./...
GOCACHE=/tmp/sysarmor-layered-go-cache go test -race ./apps/manager/...
```

- [x] **Step 3: Run `make test-functional DOMAIN=platform`, `make test-functional DOMAIN=topology`, and `make test-detection`.** Platform functional passed against PostgreSQL, and topology functional completed with `[e2e-agent-systemd-vm] ok`. Managed dual-policy smoke run `20260811T153118Z` verified enrollment and online balanced/deep rollout without snapshot ACK errors. Full managed Detection run `20260811T172402Z` passed in one matrix with `[assert-detection] ok`: `apt-fileless-c2` scored `0.9813`, `apt-staged-drop` scored `0.9833`, and `benign-ci-noise` scored `1.0` for both alert and evidence under both policies. The score threshold remained `0.9`; Manager timestamps, contributing signal refs, exact published-policy version reads for backlog isolation, paginated history, lease heartbeat/CAS, condition-tree evidence matching, and required entity matching were exercised by focused and staged tests.
- [x] **Step 4: Update docs with actual slices, PostgreSQL startup, transactions, and retry/DLQ behavior.**
- [x] **Step 5: Run final legacy and size scans; require no Manager/Worker legacy matches and no newly introduced non-generated Go file over 500 lines.** Existing Agent files above 500 lines remain outside this refactor scope.
- [x] **Step 6: Commit `docs: document manager worker layered architecture`.** Final architecture and verification documentation is committed with the closure series.
