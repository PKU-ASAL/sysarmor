# Manager Identity Read Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate tenant-scoped Agent, Health, Session, Metrics, Rarity, and agent-overview reads from `store.Store` to the approved Manager Domain/Application/Ports/PostgreSQL/HTTP architecture without changing public JSON.

**Architecture:** Identity Domain owns query-relevant values plus immutable JSON documents for large health and rarity payloads. Application query services require a validated actor tenant. PostgreSQL and HTTP adapters own persistence and JSON mapping; bootstrap wires the production routes before legacy read handlers are deleted.

**Tech Stack:** Go 1.26, `database/sql`, PostgreSQL, SQLite adapter tests, `net/http`, existing JWT request-context resolver.

## Global Constraints

- Preserve all existing HTTP paths, JSON fields, status codes, filter semantics, and tenant isolation.
- Domain imports only Domain and approved standard-library packages; Application imports only Domain, Ports, and standard library.
- Every Repository method requires validated non-empty `tenant.ID`; no system-wide list method is exposed.
- Health and rarity JSON documents are cloned at boundaries and canonicalized to the requested tenant.
- This slice is read-only. Gateway/session writes and telemetry projection remain on their current paths until their planned slices.
- No changed function exceeds 50 lines and no non-generated file exceeds 500 lines.
- Use `GOCACHE=/tmp/sysarmor-layered-go-cache` for verification.

---

### Task 1: Add Identity Domain and Query Application

**Files:**
- Create: `apps/manager/internal/domain/identity/model.go`
- Create: `apps/manager/internal/domain/identity/model_test.go`
- Create: `apps/manager/internal/application/manager/identity/query.go`
- Create: `apps/manager/internal/application/manager/identity/query_test.go`
- Create: `apps/manager/internal/ports/identity.go`

**Interfaces:**
- Produces `identity.Agent`, `identity.Health`, `identity.Session`, `identity.Metrics`, `identity.RarityBaseline`, filters, repositories, and `identity.QueryService`.
- Consumes `manager.RequestContext` and validated `tenant.ID`.

- [ ] **Step 1: Write failing Domain tests**

Add tests proving `Health.Document` and `RarityBaseline.Document` are cloned, `RarityBaseline.Count` checks workload before global fallback, and agent filters match scope and health status without mutating inputs.

```go
func TestRarityCountFallsBackToGlobal(t *testing.T) {
    baseline := RarityBaseline{WorkloadCounts: map[string]map[string]uint64{
        "global": {"signal-a": 3},
    }}
    if got := baseline.Count("host:a", "signal-a"); got != 3 {
        t.Fatalf("Count() = %d, want 3", got)
    }
}
```

- [ ] **Step 2: Verify Domain RED**

Run:

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/domain/identity -count=1
```

Expected: FAIL because the package and types do not exist.

- [ ] **Step 3: Implement the minimal Domain model**

Define these stable values without contract, SQL, HTTP, or Protobuf imports:

```go
type AgentID string
type Agent struct {
    TenantID tenant.ID
    ID AgentID
    HostID, Version, AuthType, CertificateIdentity string
}
type Scope struct { Type, Selector string }
type Health struct {
    TenantID tenant.ID
    AgentID AgentID
    HostID, Status string
    Scope Scope
    ObservedAt time.Time
    Document []byte
}
type Session struct {
    TenantID tenant.ID
    ID string
    AgentID AgentID
    StartedAt, LastSeenAt, LastDataSeenAt, LastControlSeenAt, ClosedAt time.Time
    LastAckCursor, DataTransport, ControlTransport, Status string
}
type Metrics struct {
    DataBatchesAppended, EventsIngested, EndpointSignalsIngested uint64
    CloudSignalsEmitted, SignalsEmitted, IncidentsCreated uint64
    DroppedEvents, DuplicateEvents uint64
    LastConvergenceLatencyMs, MaxConvergenceLatencyMs, TotalConvergenceLatencyMs uint64
    AverageConvergenceLatency float64
}
type RarityBaseline struct {
    WorkloadCounts map[string]map[string]uint64
    Document []byte
}
```

- [ ] **Step 4: Write failing Application tests**

Use fakes to prove every repository receives `request.Actor.TenantID`, Agent listing joins health within the same tenant, filters scope/status, missing health produces an offline item, session resume uses the first ordered session, and repository errors are explicit.

```go
func TestListAgentsUsesActorTenant(t *testing.T) {
    tenantID, request := identityRequestContext(t, "tenant-a")
    repositories := newFakeIdentityRepositories(tenantID)
    service := NewQueryService(repositories)
    result, err := service.ListAgents(context.Background(), request, ListAgentsQuery{})
    if err != nil { t.Fatal(err) }
    if repositories.observedTenant != tenantID || len(result.Agents) != 1 {
        t.Fatalf("result=%+v tenant=%q", result, repositories.observedTenant)
    }
}
```

- [ ] **Step 5: Define Ports and implement QueryService**

```go
type AgentRepository interface {
    List(context.Context, tenant.ID, identity.AgentFilter) ([]identity.Agent, error)
}
type AgentHealthRepository interface {
    Get(context.Context, tenant.ID, identity.AgentID) (identity.Health, error)
    List(context.Context, tenant.ID, identity.HealthFilter) ([]identity.Health, error)
}
type AgentSessionRepository interface {
    List(context.Context, tenant.ID, identity.SessionFilter) ([]identity.Session, error)
}
type IdentitySnapshotRepository interface {
    Metrics(context.Context, tenant.ID) (identity.Metrics, error)
    Rarity(context.Context, tenant.ID) (identity.RarityBaseline, error)
}
type IdentityRepositories interface {
    Agents() AgentRepository
    Health() AgentHealthRepository
    Sessions() AgentSessionRepository
    Snapshots() IdentitySnapshotRepository
}
```

Implement `ListAgents`, `GetHealth`, `ListHealth`, `ListSessions`, `Resume`, `Metrics`, `Rarity`, and `AgentOverview`. Each method first requires `tenant.RoleViewer` and never accepts a tenant from its query.

- [ ] **Step 6: Verify Domain/Application GREEN**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/domain/identity ./apps/manager/internal/application/manager/identity -count=1
python3 -m unittest test.contracts.test_layered_architecture -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add apps/manager/internal/domain/identity apps/manager/internal/application/manager/identity apps/manager/internal/ports/identity.go
git commit -m "feat(manager): add identity query application slice"
```

### Task 2: Add PostgreSQL Identity Read Adapter

**Files:**
- Create: `apps/manager/internal/adapters/outbound/postgres/identity/repository.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/identity/mapper.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/identity/repository_test.go`

**Interfaces:**
- Consumes repositories from `apps/manager/internal/ports/identity.go`.
- Produces `identitypostgres.NewRepositories(*sql.DB) ports.IdentityRepositories`.

- [ ] **Step 1: Write failing adapter contract tests**

Create SQLite tables matching production columns. Insert tenant A and B rows and assert Agent, Health, Session, Metrics, and Rarity methods return only tenant A. Assert blank tenant returns `failure.InvalidArgument`, missing health returns `failure.NotFound`, and health JSON identity is canonicalized from SQL keys rather than trusted document fields.

- [ ] **Step 2: Verify adapter RED**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/adapters/outbound/postgres/identity -count=1
```

Expected: FAIL because `NewRepositories` does not exist.

- [ ] **Step 3: Implement SQL repositories and mappers**

Use tenant predicates in SQL, not post-query filtering:

```sql
SELECT agent_id, host_id, version, data
FROM agents WHERE tenant_id = $1 ORDER BY agent_id ASC
```

```sql
SELECT agent_id, host_id, scope_type, scope_selector, observed_at, data
FROM agent_health
WHERE tenant_id = $1 AND ($2 = '' OR agent_id = $2)
ORDER BY agent_id ASC
```

```sql
SELECT session_id, agent_id, started_at, last_seen_at, last_data_seen_at,
       last_control_seen_at, closed_at, last_ack_cursor, data_transport,
       control_transport, status, data
FROM agent_sessions
WHERE tenant_id = $1 AND ($2 = '' OR agent_id = $2)
ORDER BY last_seen_at DESC, session_id ASC
```

Read metrics from `tenant_metrics` and rarity from `rarity_baseline`, preserving the existing zero-value behavior when no snapshot exists. Clone all returned byte slices and maps.

- [ ] **Step 4: Verify adapter GREEN and compatibility**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/adapters/outbound/postgres/identity ./apps/manager/internal/store/postgres -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/manager/internal/adapters/outbound/postgres/identity
git commit -m "feat(postgres): add identity query repositories"
```

### Task 3: Route Identity HTTP Reads Through Application

**Files:**
- Create: `apps/manager/internal/adapters/inbound/http/identity/handler.go`
- Create: `apps/manager/internal/adapters/inbound/http/identity/dto.go`
- Create: `apps/manager/internal/adapters/inbound/http/identity/mapper.go`
- Create: `apps/manager/internal/adapters/inbound/http/identity/handler_test.go`
- Create: `apps/manager/internal/bootstrap/manager_identity.go`
- Create: `apps/manager/internal/bootstrap/manager_identity_test.go`
- Modify: `apps/manager/internal/api/http.go`
- Modify: `apps/manager/cmd/sysarmor-manager/main.go`

**Interfaces:**
- Consumes `identity.QueryService` and the existing Policy `RequestContextResolver` shape.
- Produces handlers for `/agents`, GET `/agent-health`, `/agent-sessions`, `/data-resume`, `/metrics`, and `/rarity-baseline`, plus an injected agent-summary query used by the existing `/ui/overview` orchestrator.

- [ ] **Step 1: Write failing HTTP contract tests**

For each route, authenticate tenant A while the fake service contains A and B data. Assert no B identifier/count occurs. Assert query `tenant_id=tenant-b` cannot override the actor tenant. Preserve `{"sessions":[]}`, `DataResume`, metrics JSON, rarity `baseline/count`, filters, 404 for missing health, and 405 behavior.

- [ ] **Step 2: Verify HTTP RED**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/adapters/inbound/http/identity -count=1
```

Expected: FAIL because the handler package does not exist.

- [ ] **Step 3: Implement handler and DTO mappers**

The handler resolves `manager.RequestContext` once per request. It maps domain failure kinds to the same HTTP status mapping as Policy. Health responses write canonical `Health.Document`; agent list DTO contains existing `agent_id`, `host_id`, `tenant_id`, version/auth/cert fields and joined health fields.

- [ ] **Step 4: Wire bootstrap and production routes**

Add `identityRoutes` and `SetIdentityRoutes` to `managerapi.Server`. Besides HTTP methods, the interface exposes `AgentOverview(context.Context, manager.RequestContext) (identity.AgentOverview, error)` and `MetricsQuery(context.Context, manager.RequestContext) (identity.Metrics, error)` so the existing mixed-slice `/ui/overview` handler stops reading identity state from Store without moving incident search or Store status into this slice. Production bootstrap requires non-nil DB and resolver, creates PostgreSQL repositories and QueryService, and `sysarmor-manager` injects the routes immediately after Policy routes.

- [ ] **Step 5: Verify route compatibility**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/internal/adapters/inbound/http/identity ./apps/manager/internal/bootstrap ./apps/manager/internal/api ./apps/manager/cmd/sysarmor-manager -count=1
```

Expected: PASS; existing API contract tests remain green.

- [ ] **Step 6: Commit**

```bash
git add apps/manager/internal/adapters/inbound/http/identity apps/manager/internal/bootstrap/manager_identity.go apps/manager/internal/bootstrap/manager_identity_test.go apps/manager/internal/api/http.go apps/manager/cmd/sysarmor-manager/main.go
git commit -m "refactor(manager): route identity reads through application"
```

### Task 4: Remove Migrated Legacy Identity Reads

**Files:**
- Modify: `apps/manager/internal/api/http_identity.go`
- Modify: `apps/manager/internal/api/http_ui_overview.go`
- Modify: `apps/manager/internal/api/store_capabilities.go`
- Modify: `apps/manager/internal/store/agent.go`
- Modify: `apps/manager/internal/store/postgres/identity.go`
- Modify: affected tests under `apps/manager/internal/api` and `apps/manager/internal/store`

**Interfaces:**
- Keeps health POST and session write methods for their later slices.
- Deletes only read methods and HTTP handlers whose production routes have moved.

- [ ] **Step 1: Add architecture absence assertions**

Assert production Identity GET routes cannot fall back to legacy handlers, `/ui/overview` obtains its agent and metric summaries through `identityRoutes`, and new layered packages never import `store`, `api`, `packages/contracts/health`, or `analytics/rarity`.

- [ ] **Step 2: Delete migrated reads**

Remove legacy GET branches and Store methods only after `rg` proves no non-test caller remains. Keep `UpsertAgentHealth`, session lifecycle writes, `Info`, health POST, incident search, and telemetry projection until their owning slices migrate.

- [ ] **Step 3: Run full validation**

```bash
test -z "$(gofmt -l apps/manager)"
git diff --check
python3 -m unittest test.contracts.test_layered_architecture -v
GOCACHE=/tmp/sysarmor-layered-go-cache go vet ./apps/manager/...
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./apps/manager/... -count=1
```

Expected: PASS, with socket-requiring tests run outside the sandbox when necessary.

- [ ] **Step 4: Review and commit**

Review target: Critical 0, Important 0, no dual production Identity read path, public JSON unchanged.

```bash
git add apps/manager test/contracts
git commit -m "refactor(manager): remove legacy identity reads"
```
