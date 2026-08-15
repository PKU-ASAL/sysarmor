# Signal Stage Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Detection Signal `Terminal` with required `SignalStage` and `DetectorKind`, migrate persisted OpenSearch signals once, and leave no runtime compatibility path.

**Architecture:** Domain and wire contracts use explicit enums. Producers assign stage and detector kind; Incident convergence consumes only Conclusion signals. OpenSearch init performs a fail-closed v1-to-v2 reindex and atomic alias cutover before the new application starts serving traffic.

**Tech Stack:** Go 1.26, Protobuf, OpenSearch, Bash, Python architecture contracts.

## Global Constraints

- Reserve old Protobuf field numbers and names; never reinterpret field 11.
- Reject unspecified Stage or DetectorKind at trusted production boundaries.
- Do not retain `Terminal`, `GetTerminal`, `--terminal`, JSON `terminal`, dual reads, aliases, or fallback.
- Rename Incident detection `terminals` to `conclusion_entities`; unrelated command terminal-state terminology is out of scope.
- Use TDD for every production change and keep each intermediate commit buildable.
- Keep changed functions below 50 lines and production files below 500 lines.

---

### Task 1: Lock the Breaking Contract

**Files:**
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`
- Test: `test/contracts/test_layered_architecture.py`

**Interfaces:**
- Produces an architecture rule that rejects Detection Signal `Terminal` fields, accessors, query flags, and JSON keys outside historical plans and the future Worker Steiner implementation.
- Requires `SignalStage` and `DetectorKind` in Domain and Protobuf contracts.

- [ ] **Step 1: Add failing assertions for removed and required symbols**

Assert that `signal.proto` reserves field/name 11/`terminal`, defines `stage` and `detector_kind`, and that production Detection paths contain no `GetTerminal`, `.Terminal`, `json:"terminal"`, or `--terminal`.

- [ ] **Step 2: Run the focused contract and observe RED**

```bash
python3 -m unittest test.contracts.test_layered_architecture -v
```

Expected: FAIL because current Signal contracts still expose `terminal`.

- [ ] **Step 3: Keep the test RED and continue into Task 2**

### Task 2: Replace Wire and Domain Signal Types

**Files:**
- Modify: `packages/contracts/proto/signal/v1/signal.proto`
- Modify: `packages/contracts/proto/incident/v1/incident.proto`
- Generate: `packages/contracts/proto/{signal,incident}/v1/*.pb.go`
- Modify: `apps/agent/internal/domain/detection/signal.go`
- Modify: `apps/manager/internal/domain/telemetry/model.go`
- Modify: `apps/agent/internal/adapters/contracts/detection.go`
- Modify: `apps/manager/internal/adapters/contracts/signal_mapper.go`

**Interfaces:**
- Produces `SignalStage{Unspecified,Candidate,Conclusion}`.
- Produces `DetectorKind{Unspecified,Rule,Model,Graph,System}`.
- Produces `Incident.ConclusionEntities`.

- [ ] **Step 1: Add mapper tests for every enum and invalid unspecified values**
- [ ] **Step 2: Run mapper tests and observe compile-time RED**

```bash
go test ./apps/agent/internal/adapters/contracts ./apps/manager/internal/adapters/contracts -count=1
```

- [ ] **Step 3: Change proto/domain types and regenerate contracts**

```bash
make proto
```

- [ ] **Step 4: Implement explicit mappers and run focused tests GREEN**
- [ ] **Step 5: Commit `refactor(contracts): replace signal terminal with stage`**

### Task 3: Migrate Agent Producers and Policy Content

**Files:**
- Modify: `apps/agent/internal/domain/detection/runtime/*.go`
- Modify: `apps/agent/internal/domain/health/tamper.go`
- Modify: `apps/agent/internal/domain/content/model.go`
- Modify: `apps/agent/internal/adapters/content/{document.go,domain_mapper.go,store.go}`
- Modify: `apps/agent/internal/bootstrap/runtime/detection_runtime.go`
- Modify corresponding tests and policy fixtures under `test/data/`.

**Interfaces:**
- Rule runtime emits Rule Candidate or Rule Conclusion explicitly.
- Health/tamper emits System Conclusion.
- Policy output requires `stage: candidate|conclusion`; missing or unknown stage is rejected.

- [ ] **Step 1: Convert Agent tests and policy fixtures to the desired Stage API, then observe RED**
- [ ] **Step 2: Replace `RuleSpec.Terminal` with `RuleSpec.Stage` and remove boolean default helpers**
- [ ] **Step 3: Validate every policy output stage and detector assignment**
- [ ] **Step 4: Run Agent detection/content/health tests GREEN**

```bash
go test ./apps/agent/internal/domain/... ./apps/agent/internal/adapters/content ./apps/agent/internal/adapters/contracts ./apps/agent/internal/bootstrap/runtime -count=1
```

- [ ] **Step 5: Commit `refactor(agent): emit staged detection signals`**

### Task 4: Migrate Manager Queries, Convergence, and Incident

**Files:**
- Modify: `apps/manager/internal/domain/{telemetry,detection,investigation}/`
- Modify: `apps/manager/internal/application/manager/telemetry/query.go`
- Modify: `apps/manager/internal/ports/telemetry.go`
- Modify: `apps/manager/internal/adapters/inbound/http/telemetry/handler.go`
- Modify: `apps/manager/internal/adapters/outbound/opensearch/telemetry_query.go`
- Modify: `apps/cli/cmd/sysarmorctl/manager_telemetry.go`
- Modify corresponding tests.

**Interfaces:**
- Query filter is `Stage *SignalStage` and CLI is `--stage candidate|conclusion`.
- Correlation and Incident builders treat only Conclusion as final.
- Incident exposes `ConclusionEntities`.

- [ ] **Step 1: Write Stage query and Conclusion-only convergence tests; observe RED**
- [ ] **Step 2: Implement typed Stage query parsing and OpenSearch exact filtering**
- [ ] **Step 3: Replace boolean convergence and incident logic**
- [ ] **Step 4: Run Manager and CLI focused tests GREEN**

```bash
go test ./apps/manager/internal/domain/... ./apps/manager/internal/application/manager/telemetry ./apps/manager/internal/adapters/inbound/http/telemetry ./apps/manager/internal/adapters/outbound/opensearch ./apps/cli/cmd/sysarmorctl -count=1
```

- [ ] **Step 5: Commit `refactor(manager): consume staged detection signals`**

### Task 5: Add the One-Time OpenSearch Migration

**Files:**
- Create: `deployments/opensearch/mappings/signals-v2.json`
- Modify: `deployments/opensearch/init.sh`
- Modify: `test/suites/functional/platform/opensearch-alias-lifecycle.sh`
- Modify: `packages/contracts/schema/agent_test_assets_test.go`

**Interfaces:**
- Fresh installs create `sysarmor-signals-v2`.
- Existing v1 installs reindex `terminal` to `stage`, infer existing producer kind, remove `terminal`, verify counts, and atomically move aliases.
- Reruns validate the v2 aliases without rewriting documents.

- [ ] **Step 1: Extend the lifecycle test with v1 Signal fixtures and expected v2 fields; observe RED**
- [ ] **Step 2: Add the v2 mapping and fail-closed migration function**
- [ ] **Step 3: Verify migration, rerun idempotence, and rollback safety against real OpenSearch**

```bash
bash test/suites/functional/platform/opensearch-alias-lifecycle.sh
```

- [ ] **Step 4: Commit `feat(opensearch): migrate signal stage documents`**

### Task 6: Remove Old Product Language and Close the Migration

**Files:**
- Modify: `docs/{architecture.md,development/testing.md,guides/investigation.md,guides/policy.md}`
- Modify: Detection functional assertions and reports under `test/`.
- Modify: `test/contracts/test_layered_architecture.py`.

**Interfaces:**
- Public docs and tests use Candidate/Conclusion and DetectorKind only.
- Detection `Terminal` survives only in NODLINK/Steiner research text or future Worker internal algorithm identifiers.

- [ ] **Step 1: Convert functional expected data, reports, and CLI assertions to Stage**
- [ ] **Step 2: Run architecture contracts GREEN**

```bash
python3 -m unittest test.contracts.test_layered_architecture test.contracts.test_monorepo_layout -v
```

- [ ] **Step 3: Run repository quality gates**

```bash
test -z "$(gofmt -l apps packages)"
git diff --check
go vet ./...
go test ./... -count=1
go test -race ./apps/agent/... ./apps/manager/... -count=1
```

- [ ] **Step 4: Request final review and fix every Critical/Important finding**
- [ ] **Step 5: Commit `docs: define staged signal semantics` and require a clean worktree**
