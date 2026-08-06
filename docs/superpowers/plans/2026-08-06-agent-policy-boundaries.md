# Agent Policy Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move standalone collection, detection, telemetry, and CurrentPolicy use cases from `daemon` into `control` without changing API contracts, persistence order, authority rules, or runtime behavior.

**Architecture:** `control.PolicyController` owns validation, use-case sequencing, result construction, and policy projection. A daemon-owned runtime adapter exposes only atomic config, Store, Sensor, detection-engine, telemetry-batcher, and state operations; `localapi` and `remoteapi` continue depending only on the existing `control.PolicyController` interface.

**Tech Stack:** Go, protobuf boundary adapters, SQLite-backed `localstore`, Sensor SDK, Go race detector, Python architecture contracts.

## Global Constraints

- Preserve all protobuf, local socket, remote manager, and CLI interfaces.
- Preserve standalone authority checks and managed endpoint routing.
- Preserve Sensor-before-Store ordering and Sensor rollback for standalone collection updates.
- Preserve detection rejection/degraded reporting and telemetry batcher behavior.
- Keep production files below 500 lines and functions at or below 50 lines where practical.
- Add tests before production changes and observe RED before GREEN.
- Create one Conventional Commit per task.

---

### Task 1: Move telemetry policy use case into control

**Files:**
- Create: `apps/agent/internal/control/telemetry_policy.go`
- Create: `apps/agent/internal/control/telemetry_policy_test.go`
- Modify: `apps/agent/internal/control/policy_result.go`
- Modify: `apps/agent/internal/daemon/policy_controller.go`
- Modify: `apps/agent/internal/daemon/policy_controller_runtime.go`
- Create or modify: `apps/agent/internal/daemon/policy_runtime.go`

**Interfaces:**
- Consumes: `PolicyCommand`, `Result`, `config.ResolveTelemetry`, `policymodel.TelemetryPolicy`.
- Produces: `TelemetryPolicyRuntime` and `(*TelemetryPolicyController).Apply(context.Context, PolicyCommand) Result`.

- [x] **Step 1: Write failing control tests**

Cover nested and direct JSON, structured telemetry fields, missing policy, invalid limits, dry-run without mutation, persistence failure, and successful persist-before-activate-before-batcher ordering.

- [x] **Step 2: Verify RED**

Run: `GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control -run TestTelemetryPolicy -count=1`

Expected: FAIL because `NewTelemetryPolicyController` is undefined.

- [x] **Step 3: Implement the minimal controller and daemon runtime adapter**

Use this boundary:

```go
type TelemetryPolicyRuntime interface {
    PolicyIdentity() PolicyIdentity
    ValidatePolicyContext(RequestContext) error
    BeginLocalPolicyMutation(context.Context, bool) (func(), error)
    PersistTelemetryPolicy(context.Context, policymodel.TelemetryPolicy) (config.EffectiveTelemetry, error)
    ActivateTelemetryPolicy(policymodel.TelemetryPolicy, config.EffectiveTelemetry)
}
```

The controller must parse and validate first, return immediately on dry-run, persist before activation, and construct `Result` without protobuf dependencies.

- [x] **Step 4: Verify GREEN and compatibility**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control ./apps/agent/internal/daemon -run 'TestTelemetryPolicy|TestLocalControlApplyTelemetryPolicyContract' -count=1
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git commit -m "refactor(agent): move telemetry policy use case into control"
```

### Task 2: Move detection policy use case into control

**Files:**
- Create: `apps/agent/internal/control/detection_policy.go`
- Create: `apps/agent/internal/control/detection_policy_test.go`
- Modify: `apps/agent/internal/control/policy_result.go`
- Modify: `apps/agent/internal/daemon/policy_controller.go`
- Modify: `apps/agent/internal/daemon/policy_controller_runtime.go`
- Modify: `apps/agent/internal/daemon/policy_runtime.go`

**Interfaces:**
- Consumes: active runtime policy, collection intent, detection content, limits, standalone endpoint persistence.
- Produces: `DetectionPolicyRuntime` and `(*DetectionPolicyController).Apply(context.Context, PolicyCommand) Result`.

- [x] **Step 1: Write failing control tests**

Cover nested/direct JSON, dry-run, rejected detection status projection, persistence failure without in-memory activation, and successful durable-before-memory activation.

- [x] **Step 2: Verify RED**

Run: `GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control -run TestDetectionPolicy -count=1`

Expected: FAIL because `NewDetectionPolicyController` is undefined.

- [x] **Step 3: Implement the minimal controller and adapter**

Keep the detection update transaction around prepare, persistence, and activation. Build the engine in control, but expose Store and in-memory activation as separate runtime operations so failure remains fail-closed.

- [x] **Step 4: Verify GREEN and compatibility**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control ./apps/agent/internal/daemon -run 'TestDetectionPolicy|TestLocalControlDetectionPolicy' -count=1
```

Expected: PASS.

- [x] **Step 5: Commit**

```bash
git commit -m "refactor(agent): move detection policy use case into control"
```

### Task 3: Move collection policy use case into control

**Files:**
- Create: `apps/agent/internal/control/collection_policy.go`
- Create: `apps/agent/internal/control/collection_policy_prepare.go`
- Create: `apps/agent/internal/control/collection_policy_test.go`
- Modify: `apps/agent/internal/control/policy_result.go`
- Modify: `apps/agent/internal/daemon/policy_controller.go`
- Modify: `apps/agent/internal/daemon/policy_controller_runtime.go`
- Modify: `apps/agent/internal/daemon/policy_runtime.go`

**Interfaces:**
- Consumes: runtime scope, content snapshot, Sensor capabilities/runtime, active detection policy, endpoint Store, and in-memory state.
- Produces: `CollectionPolicyRuntime` and `(*CollectionPolicyController).Apply(context.Context, PolicyCommand) Result`.

- [ ] **Step 1: Write failing control tests**

Cover scope precedence, content ref expansion, unsupported selectors, degraded detection coverage, dry-run, Sensor failure, Store failure with Sensor rollback, rollback failure reporting, and successful activation.

- [ ] **Step 2: Verify RED**

Run: `GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control -run TestCollectionPolicy -count=1`

Expected: FAIL because `NewCollectionPolicyController` is undefined.

- [ ] **Step 3: Implement prepare and transactional apply**

The non-dry-run order must remain:

```text
prepare -> Sensor apply -> standalone endpoint persist -> in-memory collection/detection activate
                       \-> on persist failure: restore previous Sensor intent
```

Do not introduce a generic transaction framework; use one explicit controller method and atomic runtime operations.

- [ ] **Step 4: Verify GREEN and compatibility**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control ./apps/agent/internal/daemon -run 'TestCollectionPolicy|TestLocalControl.*Collection|TestLocalControlExplainCollection' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor(agent): move collection policy use case into control"
```

### Task 4: Move routing and CurrentPolicy projection into control

**Files:**
- Create: `apps/agent/internal/control/policy_controller.go`
- Create: `apps/agent/internal/control/policy_controller_test.go`
- Create: `apps/agent/internal/control/policy_projection.go`
- Create: `apps/agent/internal/control/policy_projection_test.go`
- Modify: `apps/agent/internal/daemon/local_control.go`
- Modify: `apps/agent/internal/daemon/transport_runtime.go`
- Modify: `apps/agent/internal/daemon/policy_observation.go`
- Delete: `apps/agent/internal/daemon/policy_controller.go`
- Delete: `apps/agent/internal/daemon/policy_controller_runtime.go`
- Delete or narrow: `apps/agent/internal/daemon/policy_controller_codec.go`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- Consumes: endpoint, collection, detection, and telemetry controllers plus projection snapshots from the daemon runtime.
- Produces: a concrete control controller satisfying the existing `PolicyController` interface.

- [ ] **Step 1: Write failing routing and projection tests**

Verify empty type routes to endpoint, managed always routes to endpoint, standalone types route to their dedicated controllers, unsupported types reject, endpoint JSON wins over legacy runtime JSON, and pending Store state is projected exactly.

- [ ] **Step 2: Verify RED**

Run: `GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control -run 'TestPolicyController|TestCurrentPolicy' -count=1`

Expected: FAIL because the concrete control policy controller is not implemented.

- [ ] **Step 3: Implement control routing/projection and direct assembly**

Keep `localapi` and `remoteapi` unchanged. Replace daemon `newPolicyController` construction with the concrete control controller and daemon runtime adapters. Keep protobuf conversion only in API boundary packages or a narrowly scoped daemon adapter still required by legacy tests.

- [ ] **Step 4: Add architecture contract**

Require the concrete controller under `apps/agent/internal/control` and reject production `apps/agent/internal/daemon/policy_controller.go` and `policy_controller_runtime.go`.

- [ ] **Step 5: Run full verification**

Run:

```bash
python3 test/contracts/test_monorepo_layout.py
GOCACHE=/tmp/sysarmor-core-go-cache go test -race ./apps/agent/... -count=1
git diff --check
```

Expected: all PASS; socket tests must run outside the restricted sandbox.

- [ ] **Step 6: Request independent review and commit**

Fix every Critical and Important finding, then commit:

```bash
git commit -m "refactor(agent): move policy orchestration into control"
```
