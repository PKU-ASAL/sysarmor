# Agent Management Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 standalone、enrolling、managed、unenrolling 在身份、网络和策略写权限上使用同一份管理语义，并修复 enrolling 首份 Manager 策略因身份错配而无法激活的问题。

**Architecture:** 新增无外部依赖的 Agent 内部 `management` 领域包，将持久化 lifecycle 纯函数投影为 authority、identity source 和 transport mode。`localstore` 保持持久化职责并通过类型别名兼容现有调用；`daemon` 统一 reconcile 投影；`control` 只编排持久化和运行时副作用。

**Tech Stack:** Go、SQLite、现有 Agent control/localstore/daemon 测试体系、libvirt/Vagrant topology E2E。

## Global Constraints

- 不修改外部 API、protobuf、SQLite schema 或 Sensor 接口。
- `enrolling`、`managed`、`unenrolling` 均由 Manager 独占策略写权限。
- `enrolling` 使用 Enrollment identity 和 managed transport，但允许当前 standalone policy 继续执行。
- Manager 连接状态不进入 lifecycle state。
- 非法状态和 Store 读取失败必须 fail closed。
- 不引入通用状态机、事件总线、Strategy 层或跨产品 `packages/` 抽象。
- 单文件不超过 500 行，单函数不超过 50 行。

---

## File Map

- Create `apps/agent/internal/management/model.go`: lifecycle、投影值和授权规则。
- Create `apps/agent/internal/management/model_test.go`: 状态、授权、转换完整矩阵。
- Modify `apps/agent/internal/localstore/enrollment.go`: 将原状态类型和常量改为 management 别名，不改变存储格式。
- Create `apps/agent/internal/daemon/management_context.go`: 唯一运行时 reconcile 和 identity 投影。
- Modify `apps/agent/internal/daemon/runtime_identity.go`: 删除按状态自行解释 identity 的逻辑。
- Modify `apps/agent/internal/daemon/network_supervisor.go`: 消费已解析的 transport，不自行推导 managed 状态。
- Modify `apps/agent/internal/daemon/daemon.go`: 启动时调用统一 reconcile。
- Modify `apps/agent/internal/daemon/endpoint_policy_runtime.go`: managed 晋升和本地策略授权使用 management Context。
- Modify `apps/agent/internal/control/enrollment.go`: EnrollmentRuntime 暴露单一 reconcile 端口。
- Modify `apps/agent/internal/control/enrollment_flow.go`: 注册提交和失败恢复调用 reconcile。
- Modify `apps/agent/internal/control/unenrollment_flow.go`: 退管提交后调用 reconcile。
- Modify `apps/agent/internal/daemon/enrollment_runtime.go`: 实现 Coordinator 的 reconcile adapter。
- Modify `apps/agent/internal/daemon/local_control_status.go`: 使用 Resolve 校验并输出 lifecycle mode。
- Modify related tests under `apps/agent/internal/{management,control,daemon}`.

---

### Task 1: Management Domain Model

**Files:**
- Create: `apps/agent/internal/management/model_test.go`
- Create: `apps/agent/internal/management/model.go`
- Modify: `apps/agent/internal/localstore/enrollment.go:13-20`

**Interfaces:**
- Produces: `Resolve(State) (Context, error)`
- Produces: `(Context).Authorize(PolicyWriteOrigin) error`
- Produces: `ValidateTransition(State, State) error`
- Produces: backward-compatible `localstore.EnrollmentState` alias and `State*` constants.

- [ ] **Step 1: Write the failing state and authority matrix tests**

```go
func TestResolveProjectsManagementContext(t *testing.T) {
    tests := []struct {
        state State
        want  Context
    }{
        {StateStandalone, Context{State: StateStandalone, Authority: AuthorityLocal, IdentitySource: IdentityStandalone, Transport: TransportStandalone}},
        {StateEnrolling, Context{State: StateEnrolling, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
        {StateManaged, Context{State: StateManaged, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
        {StateUnenrolling, Context{State: StateUnenrolling, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}},
    }
    for _, test := range tests {
        got, err := Resolve(test.state)
        if err != nil || got != test.want {
            t.Fatalf("Resolve(%q) = %+v, %v; want %+v", test.state, got, err, test.want)
        }
    }
}

func TestResolveRejectsUnknownState(t *testing.T) {
    if _, err := Resolve(State("corrupt")); err == nil {
        t.Fatal("Resolve accepted an unknown state")
    }
}

func TestContextAuthorizesOnlyItsPolicyAuthority(t *testing.T) {
    local, _ := Resolve(StateStandalone)
    managed, _ := Resolve(StateEnrolling)
    if err := local.Authorize(PolicyWriteLocal); err != nil {
        t.Fatalf("standalone local write rejected: %v", err)
    }
    if err := local.Authorize(PolicyWriteManager); err == nil {
        t.Fatal("standalone accepted manager write")
    }
    if err := managed.Authorize(PolicyWriteLocal); err == nil {
        t.Fatal("enrolling accepted local write")
    }
    if err := managed.Authorize(PolicyWriteManager); err != nil {
        t.Fatalf("enrolling manager write rejected: %v", err)
    }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/management
```

Expected: compile failure because `State`, `Context`, and `Resolve` do not exist.

- [ ] **Step 3: Implement the minimal model**

```go
package management

import "fmt"

type State string
type Authority string
type IdentitySource string
type TransportMode string
type PolicyWriteOrigin string

const (
    StateStandalone State = "standalone"
    StateEnrolling State = "enrolling"
    StateManaged State = "managed"
    StateUnenrolling State = "unenrolling"
    AuthorityLocal Authority = "local"
    AuthorityManager Authority = "manager"
    IdentityStandalone IdentitySource = "standalone"
    IdentityEnrollment IdentitySource = "enrollment"
    TransportStandalone TransportMode = "standalone"
    TransportManaged TransportMode = "managed"
    PolicyWriteLocal PolicyWriteOrigin = "local"
    PolicyWriteManager PolicyWriteOrigin = "manager"
)

type Context struct {
    State State
    Authority Authority
    IdentitySource IdentitySource
    Transport TransportMode
}

func Resolve(state State) (Context, error) {
    switch state {
    case StateStandalone:
        return Context{State: state, Authority: AuthorityLocal, IdentitySource: IdentityStandalone, Transport: TransportStandalone}, nil
    case StateEnrolling, StateManaged, StateUnenrolling:
        return Context{State: state, Authority: AuthorityManager, IdentitySource: IdentityEnrollment, Transport: TransportManaged}, nil
    default:
        return Context{}, fmt.Errorf("unsupported management state %q", state)
    }
}

func (c Context) Authorize(origin PolicyWriteOrigin) error {
    if (c.Authority == AuthorityLocal && origin == PolicyWriteLocal) ||
        (c.Authority == AuthorityManager && origin == PolicyWriteManager) {
        return nil
    }
    return fmt.Errorf("%s policy authority is active; %s policy mutation is not allowed", c.Authority, origin)
}
```

Add the four legal transitions to `ValidateTransition`; reject all others, including self transitions and unknown states:

```go
func ValidateTransition(from, to State) error {
    valid := false
    switch from {
    case StateStandalone:
        valid = to == StateEnrolling
    case StateEnrolling:
        valid = to == StateManaged
    case StateManaged:
        valid = to == StateUnenrolling
    case StateUnenrolling:
        valid = to == StateStandalone
    default:
        return fmt.Errorf("unsupported management state %q", from)
    }
    if !valid {
        return fmt.Errorf("invalid management transition %s -> %s", from, to)
    }
    return nil
}
```

- [ ] **Step 4: Alias localstore lifecycle types**

```go
type EnrollmentState = management.State

const (
    StateStandalone = management.StateStandalone
    StateEnrolling = management.StateEnrolling
    StateManaged = management.StateManaged
    StateUnenrolling = management.StateUnenrolling
)
```

- [ ] **Step 5: Run focused and localstore tests**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/management ./apps/agent/internal/localstore
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/agent/internal/management apps/agent/internal/localstore/enrollment.go
git commit -m "refactor(agent): define management context"
```

---

### Task 2: Runtime Identity and Network Reconcile

**Files:**
- Create: `apps/agent/internal/daemon/management_context.go`
- Create or modify: `apps/agent/internal/daemon/management_context_test.go`
- Modify: `apps/agent/internal/daemon/runtime_identity.go`
- Modify: `apps/agent/internal/daemon/network_supervisor.go`
- Modify: `apps/agent/internal/daemon/network_supervisor_test.go`
- Modify: `apps/agent/internal/daemon/daemon.go:211-235`

**Interfaces:**
- Consumes: `management.Resolve` and `management.Context` from Task 1.
- Produces: `(*AgentRuntime).reconcileManagementContext(localstore.Enrollment) error`.
- Produces: `networkSupervisor.ApplyEnrollment(localstore.Enrollment, management.Context)`.

- [ ] **Step 1: Add the P0 reproduction test**

```go
func TestReconcileManagementContextUsesEnrollmentIdentityWhileEnrolling(t *testing.T) {
    runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", HostID: "host-a", TenantID: "local"}}}
    runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})

    err := runner.reconcileManagementContext(localstore.Enrollment{
        State: localstore.StateEnrolling, AgentID: "agent-a", TenantID: "tenant-a",
    })

    identity := runner.currentIdentity()
    if err != nil || identity.AgentID != "agent-a" || identity.TenantID != "tenant-a" {
        t.Fatalf("identity=%+v error=%v", identity, err)
    }
}
```

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/daemon -run TestReconcileManagementContextUsesEnrollmentIdentityWhileEnrolling
```

Expected: compile failure because `reconcileManagementContext` does not exist.

- [ ] **Step 3: Implement identity projection and validation**

Implement `identityForManagementContext` so `IdentityEnrollment` requires non-empty tenant and agent IDs and preserves the standalone HostID. Unknown state or incomplete enrollment identity returns an explicit error before network startup.

```go
func (r *AgentRuntime) reconcileManagementContext(enrollment localstore.Enrollment) error {
    mode, err := management.Resolve(enrollment.State)
    if err != nil {
        return err
    }
    identity, err := r.identityForManagementContext(enrollment, mode)
    if err != nil {
        return err
    }
    r.setProjectedIdentity(identity)
    if r.network != nil {
        r.network.ApplyEnrollment(enrollment, mode)
    }
    return nil
}
```

- [ ] **Step 4: Make network supervisor consume transport projection**

Change `ApplyEnrollment` and `run` to receive `management.Context`. Choose standalone or managed flow only from `mode.Transport`; `Managed()` checks stored transport rather than lifecycle states.

```go
func (s *networkSupervisor) ApplyEnrollment(enrollment localstore.Enrollment, mode management.Context) {
    s.transitionMu.Lock()
    defer s.transitionMu.Unlock()
    s.mu.Lock()
    if s.cancel != nil && reflect.DeepEqual(s.enrollment, enrollment) && s.mode == mode {
        s.mu.Unlock()
        return
    }
    cancel, done := s.detachLocked()
    s.mu.Unlock()
    stopNetworkFlow(cancel, done)
    ctx, cancel := context.WithCancel(s.parent)
    done = make(chan struct{})
    s.mu.Lock()
    s.cancel = cancel
    s.done = done
    s.enrollment = enrollment
    s.mode = mode
    s.mu.Unlock()
    go s.run(ctx, enrollment, mode, done)
}

func (s *networkSupervisor) run(ctx context.Context, enrollment localstore.Enrollment, mode management.Context, done chan struct{}) {
    defer close(done)
    if mode.Transport == management.TransportStandalone {
        s.startStandalone(ctx)
        return
    }
    s.startManaged(ctx, enrollment)
}

func (s *networkSupervisor) Managed() bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.cancel != nil && s.mode.Transport == management.TransportManaged
}
```

Keep managed `enrolling -> managed` promotion connection-preserving with this explicit contract:

```go
func (s *networkSupervisor) PromoteEnrollment(enrollment localstore.Enrollment, mode management.Context) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.cancel == nil || s.mode.State != management.StateEnrolling || mode.State != management.StateManaged ||
        s.mode.Transport != management.TransportManaged || mode.Transport != management.TransportManaged {
        return false
    }
    s.enrollment = enrollment
    s.mode = mode
    return true
}
```

`reconcileManagementContext` first tries `PromoteEnrollment`; only a false result calls `ApplyEnrollment`, so first managed policy activation does not reconnect.

- [ ] **Step 5: Replace startup state checks with reconcile**

Replace:

```go
r.applyEnrollmentIdentity(enrollment)
r.network.ApplyEnrollment(enrollment)
```

with:

```go
if err := r.reconcileManagementContext(enrollment); err != nil {
    return failStartup("management_context", err)
}
```

- [ ] **Step 6: Run daemon tests**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/daemon
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add apps/agent/internal/daemon
git commit -m "fix(agent): reconcile enrolling management identity"
```

---

### Task 3: Enrollment Coordinator Runtime Boundary

**Files:**
- Modify: `apps/agent/internal/control/enrollment.go:49-62`
- Modify: `apps/agent/internal/control/enrollment_flow.go:32-57`
- Modify: `apps/agent/internal/control/unenrollment_flow.go:71-88`
- Modify: `apps/agent/internal/control/enrollment_test.go`
- Modify: `apps/agent/internal/daemon/enrollment_runtime.go:104-124`
- Modify: `apps/agent/internal/daemon/enrollment_coordinator_test.go`

**Interfaces:**
- Consumes: `AgentRuntime.reconcileManagementContext` from Task 2.
- Produces: `EnrollmentRuntime.ReconcileEnrollment(localstore.Enrollment) error`.
- Removes: `ApplyEnrollmentNetwork` and `ApplyEnrollmentIdentity` from the control runtime port.

- [ ] **Step 1: Update the recording runtime and write failing coordinator tests**

Add a single `reconcileStates []localstore.EnrollmentState` recorder and `reconcileErr error`.

```go
func (r *recordingEnrollmentRuntime) ReconcileEnrollment(enrollment localstore.Enrollment) error {
    r.reconcileStates = append(r.reconcileStates, enrollment.State)
    return r.reconcileErr
}
```

Add assertions that successful enrollment reconciles exactly `enrolling`, failed Store commit reconciles exactly `standalone`, and successful退管 reconciles exactly `standalone`.

Add a test proving that reconcile failure after `SetEnrolling` keeps Store state `enrolling`, keeps credentials finalized, and returns `pending` rather than rolling credentials back.

- [ ] **Step 2: Run control tests and verify RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control -run EnrollmentCoordinator
```

Expected: compile or assertion failure because the Coordinator still calls separate network and identity methods.

- [ ] **Step 3: Replace the runtime port**

```go
type EnrollmentRuntime interface {
    EnrollmentIdentity() EnrollmentIdentity
    PrepareEnrollment(context.Context, string, string) (EnrollmentPreparation, error)
    RollbackEnrollment(EnrollmentPreparation, error) error
    FinalizeEnrollment(EnrollmentPreparation)
    StopEnrollmentNetwork()
    ReconcileEnrollment(localstore.Enrollment) error
    WithPolicyAuthority(func() error) error
    RevokeEnrollment(context.Context, localstore.Enrollment, string) (string, time.Time, error)
    RestoreStandalonePolicy(context.Context, func(context.Context) error) error
    RemoveEnrollmentCredentials(localstore.Enrollment) error
    ReportUnenrollmentCompletion(context.Context) (bool, error)
}
```

- [ ] **Step 4: Apply persistence-first failure semantics**

Before `SetEnrolling` succeeds, failures restore standalone runtime and roll back prepared credentials. After `SetEnrolling` succeeds, call `FinalizeEnrollment` even if reconcile fails, keep state and credentials, and return:

```text
status=pending
message=enrollment committed; runtime reconciliation is pending: <error>
```

On退管, call `ReconcileEnrollment(standalone)` only after the Store transaction has switched the active policy and lifecycle.

- [ ] **Step 5: Implement daemon adapter**

```go
func (r *enrollmentRuntime) ReconcileEnrollment(enrollment localstore.Enrollment) error {
    return r.runner.reconcileManagementContext(enrollment)
}
```

- [ ] **Step 6: Run control and daemon tests**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/control ./apps/agent/internal/daemon
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add apps/agent/internal/control apps/agent/internal/daemon/enrollment_runtime.go apps/agent/internal/daemon/*enrollment*_test.go
git commit -m "refactor(agent): centralize enrollment runtime reconcile"
```

---

### Task 4: Policy Authority Fail-Closed Enforcement

**Files:**
- Modify: `apps/agent/internal/daemon/endpoint_policy_runtime.go:129-179`
- Modify: `apps/agent/internal/daemon/local_control_policy_test.go`
- Modify: `apps/agent/internal/daemon/endpoint_policy_control_test.go`

**Interfaces:**
- Consumes: `management.Resolve` and `(Context).Authorize` from Task 1.
- Consumes: `AgentRuntime.reconcileManagementContext` from Task 2.

- [ ] **Step 1: Add failing authorization tests**

The management package matrix covers all four lifecycle states. Add these daemon boundary regressions for the previously missing `enrolling` case and Store fail-closed behavior; retain `mutation=false` as an allowed read/dry-run path:

```go
func TestEnrollingAgentRejectsLocalPolicyMutation(t *testing.T) {
    store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
    if err != nil {
        t.Fatal(err)
    }
    defer store.Close()
    if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
        t.Fatal(err)
    }
    runner := &AgentRuntime{localStore: store}
    if release, err := runner.beginLocalPolicyMutation(t.Context(), true); err == nil || release != nil {
        t.Fatalf("release=%v error=%v", release, err)
    }
}

func TestLocalPolicyMutationFailsClosedWithoutStore(t *testing.T) {
    runner := &AgentRuntime{}
    if release, err := runner.beginLocalPolicyMutation(t.Context(), true); err == nil || release != nil {
        t.Fatalf("release=%v error=%v", release, err)
    }
    release, err := runner.beginLocalPolicyMutation(t.Context(), false)
    if err != nil || release == nil {
        t.Fatalf("read-only release=%v error=%v", release, err)
    }
    release()
}
```

Update `TestManagedTransitionWaitsForLocalPolicyMutation` to open a real standalone local Store before acquiring the read lock; it must no longer rely on a nil Store to represent standalone.

- [ ] **Step 2: Run tests and verify RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/daemon -run 'LocalPolicyMutation|ManagedAuthority'
```

Expected: the nil Store mutation test fails because current behavior allows it.

- [ ] **Step 3: Route authorization through management Context**

```go
func (r *AgentRuntime) beginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
    if !mutation {
        return func() {}, nil
    }
    r.policyAuthorityMu.RLock()
    if r.localStore == nil {
        r.policyAuthorityMu.RUnlock()
        return nil, fmt.Errorf("local store is unavailable")
    }
    enrollment, err := r.localStore.Enrollment(ctx)
    if err != nil {
        r.policyAuthorityMu.RUnlock()
        return nil, fmt.Errorf("read enrollment state: %w", err)
    }
    mode, err := management.Resolve(enrollment.State)
    if err == nil {
        err = mode.Authorize(management.PolicyWriteLocal)
    }
    if err != nil {
        r.policyAuthorityMu.RUnlock()
        return nil, err
    }
    return r.policyAuthorityMu.RUnlock, nil
}
```

- [ ] **Step 4: Reconcile managed promotion through the same path**

After durable managed policy activation, `PromoteManagedAuthority` reads the committed Enrollment and calls `reconcileManagementContext`. It must reject an unexpected non-managed state instead of silently returning success.

- [ ] **Step 5: Run focused and race tests**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/daemon
GOCACHE=/tmp/sysarmor-core-go-cache go test -race ./apps/agent/internal/control ./apps/agent/internal/daemon
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/agent/internal/daemon
git commit -m "fix(agent): enforce projected policy authority"
```

---

### Task 5: Lifecycle Observability and End-to-End Verification

**Files:**
- Modify: `apps/agent/internal/daemon/local_control_status.go:78-105`
- Modify: `apps/agent/internal/daemon/local_control_status_test.go`

**Interfaces:**
- Consumes: `management.Resolve` from Task 1.
- Does not change protobuf fields or JSON shape.

- [ ] **Step 1: Add failing invalid-state Health test**

Persist or inject an unsupported lifecycle state and assert `managementLifecycleStatus` returns an explicit `unsupported management state` error instead of presenting it as a valid mode.

Retain existing assertions for pending policy, transition phase, revocation confirmation and completion status.

- [ ] **Step 2: Run test and verify RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./apps/agent/internal/daemon -run ManagementLifecycle
```

Expected: invalid state is currently returned as a normal mode, so the new assertion fails.

- [ ] **Step 3: Validate Health through the domain projection**

```go
mode, err := management.Resolve(enrollment.State)
if err != nil {
    return nil, err
}
status := &controlplanev1.ManagementLifecycleStatus{
    Mode: string(mode.State),
    TransitionPhase: enrollment.TransitionPhase,
    RevocationConfirmed: enrollment.RevocationConfirmed,
    LastTransitionError: enrollment.LastTransitionError,
    UpdatedAt: timestampString(enrollment.UpdatedAt),
}
```

- [ ] **Step 4: Run repository unit tests**

Run:

```bash
GOCACHE=/tmp/sysarmor-core-go-cache go test ./...
```

Expected: PASS.

- [ ] **Step 5: Run real managed topology regression**

Run:

```bash
make test-functional DOMAIN=topology
```

Expected: Agent enters enrolling using the Manager tenant/agent identity, accepts the Manager default endpoint policy, promotes to managed, and the suite passes.

- [ ] **Step 6: Run dependent detection topology**

Run:

```bash
make test-detection
```

Expected: PASS, with managed events/signals attributed to the enrollment identity.

- [ ] **Step 7: Run release-relevant regression subset**

Run:

```bash
make test-unit
make test-functional DOMAIN=endpoint
make test-functional DOMAIN=platform
```

Expected: PASS. Do not run unrelated known-failing release packaging, platform-full JWT, or endpoint performance gates as part of this commit.

- [ ] **Step 8: Commit**

```bash
git add apps/agent/internal/daemon/local_control_status.go apps/agent/internal/daemon/local_control_status_test.go
git commit -m "test(agent): cover management lifecycle recovery"
```

---

## Completion Review

- Confirm no production code directly maps lifecycle state to authority, identity source or transport outside `management.Resolve`.
- Confirm current effective policy still comes from `policy_activation`, not `management.Context`.
- Confirm `enrolling` can survive Manager disconnect and process restart without restoring local mutation authority.
- Confirm no protobuf, SQLite migration, Sensor API or top-level `packages/` change exists.
- Run `git diff --check`, inspect per-commit scope, and leave the worktree free of generated `bin/` or topology staging artifacts.
