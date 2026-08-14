# SysArmor Layered Architecture Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate Agent, Manager, Gateway, and Worker to the approved Domain, Application, Ports, Adapters architecture while fixing tenant isolation and production transport security, preserving published contracts and runtime reliability.

**Architecture:** Each vertical slice introduces pure domain types, an explicit application use case, consumer-owned ports, concrete adapters, and bootstrap wiring before deleting the corresponding legacy write path. Manager Policy is the reference slice; later slices repeat its dependency and transaction pattern without retaining `store.Store`, `ManagerStore`, `gateway.Backend`, or `daemon.AgentRuntime` as compatibility containers.

**Tech Stack:** Go 1.26, Protocol Buffers, PostgreSQL, OpenSearch, Kafka, Redis, SQLite, gRPC/mTLS, HTTP/JWT, Tetragon, Python contract tests, Shell/VM functional tests.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-08-domain-application-ports-adapters-architecture-design.md` exactly.
- Keep one Go module and the existing `apps/*` and `packages/*` product boundaries.
- Do not change public Protobuf semantics during structural migration.
- Keep every intermediate commit buildable and independently reviewable.
- Separate `fix` commits from `refactor` commits.
- Do not maintain two writable implementations of the same use case after a slice is migrated.
- Domain packages must not import Protobuf, HTTP, gRPC, SQL, OS, or adapter packages.
- Application packages may import only their product Domain, Ports, and standard library.
- Tenant-scoped ports require a validated non-empty `tenant.ID`.
- Production Gateway requires server TLS and verified client certificates; insecure operation requires explicit development bootstrap.
- Non-generated files must remain below 500 lines and changed functions should remain below 50 lines.
- Use `GOCACHE=/tmp/sysarmor-layered-go-cache` for repository-wide Go verification.

---

## Delivery Waves

| Wave | Tasks | Independently shippable result |
|---|---|---|
| Foundation | 1-2 | Enforced dependency rules and shared error/time/tenant primitives |
| Security | 3-4 | Tenant-safe Manager reads and fail-closed Gateway startup |
| Manager reference | 5 | Policy publish/assign runs through Domain/Application/Ports/PostgreSQL |
| Manager control plane | 6 | Identity, enrollment, control, response, artifact use cases migrated |
| Gateway | 7 | Data/control gRPC adapters call Gateway application use cases |
| Worker | 8 | Kafka adapter calls batch-processing application and pure analytics domain |
| Agent domain | 9 | Management, policy, content, detection models isolated from wire DTOs |
| Agent runtime | 10 | Agent lifecycle assembled from application services and adapters |
| Closure | 11-12 | Shared legacy models and global containers removed; full validation complete |

## Implementation Status

| Task | Scope | Status | Completion evidence |
|---|---|---|---|
| 1 | Architecture contracts | Complete | Layer and monorepo contracts are mandatory gates |
| 2 | Foundation Domain and Ports | Complete | Shared tenant, time, and failure primitives are layered |
| 3 | Tenant isolation | Complete | Manager reads and writes require validated tenant scope |
| 4 | Gateway bootstrap | Complete | Production startup is mTLS-only and fails closed |
| 5 | Manager Policy reference slice | Complete | Policy publish and assignment use Application/Ports/PostgreSQL |
| 6 | Manager control plane | Complete | Identity, enrollment, control, response, and artifact paths are layered |
| 7 | Gateway | Complete | Data and control gRPC adapters call Application services |
| 8 | Worker | Complete | Kafka calls `ProcessBatch`; production persistence is PostgreSQL-only |
| 9 | Agent Domain | Complete | Management, event, policy, content, and detection rules are isolated |
| 10 | Agent runtime | Complete | Commands call Bootstrap; Application and Adapters own runtime behavior |
| 11 | Legacy retirement | Complete | Agent-owned shared models, legacy roots, facades, and exemptions are removed |
| 12 | Reliability and documentation | Complete | Full gates, functional matrices, performance quick profiles, and final review passed |

The detailed Agent closure plan expands this plan's Tasks 9-12 into twelve smaller execution tasks in
`docs/superpowers/plans/2026-08-13-agent-layered-architecture-closure.md`. Its Tasks 1-5 implement the
Agent Domain task, Tasks 6-10 implement the Agent runtime task, Task 11 retires legacy models and
exemptions, and Task 12 performs final validation and documentation closure.

### Task 1: Add Architecture Contract Enforcement

**Files:**
- Create: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`
- Modify: `test/Makefile`
- Create: `.github/workflows/architecture.yml`

**Interfaces:**
- Produces a repository contract that classifies paths as `domain`, `application`, `ports`, `adapters`, `bootstrap`, or `contracts` and rejects forbidden imports.
- Consumes only repository source text and `go list`; it does not mutate generated code.

- [ ] **Step 1: Write the failing layer contract**

Add tests with this allow matrix and explicit legacy exemptions:

```python
ALLOWED = {
    "domain": {"domain"},
    "application": {"domain", "application", "ports"},
    "ports": {"domain", "ports"},
    "adapters": {"domain", "application", "ports", "adapters", "contracts"},
    "bootstrap": {"domain", "application", "ports", "adapters", "bootstrap", "contracts"},
}

LEGACY_ROOTS = {
    "apps/agent/internal/daemon",
    "apps/manager/internal/store",
    "apps/manager/internal/api",
    "apps/manager/internal/gateway",
    "apps/manager/internal/ingest",
}
```

Assert that new layered packages obey the matrix, Agent never imports Manager internals, Manager never imports Agent internals, and Domain never imports `packages/contracts/proto`.

- [ ] **Step 2: Run the contract and verify the missing-layer failure**

Run:

```bash
python3 -m unittest test.contracts.test_layered_architecture -v
```

Expected: FAIL because the required layer roots and governance allowlist do not exist.

- [ ] **Step 3: Add empty layer roots through governance files**

Create `README.md` files under both product `internal/{domain,application,ports,adapters,bootstrap}` roots. Each file states its allowed imports and points to the approved spec. Do not create empty Go packages.

- [ ] **Step 4: Wire the contract into test entrypoints**

Add `test-layered-architecture` to `test/Makefile` and CI, then run:

```bash
python3 -m unittest test.contracts.test_layered_architecture -v
make -C test test-unit
```

Expected: architecture contract PASS; existing unit suite remains green where socket permissions permit.

- [ ] **Step 5: Commit**

```bash
git add test apps/agent/internal/{domain,application,ports,adapters,bootstrap}/README.md apps/manager/internal/{domain,application,ports,adapters,bootstrap}/README.md .github/workflows/architecture.yml
git commit -m "test(architecture): enforce layered dependencies"
```

### Task 2: Introduce Foundation Domain and Port Types

**Files:**
- Create: `apps/manager/internal/domain/tenant/tenant.go`
- Create: `apps/manager/internal/domain/tenant/tenant_test.go`
- Create: `apps/manager/internal/domain/failure/failure.go`
- Create: `apps/manager/internal/domain/failure/failure_test.go`
- Create: `apps/manager/internal/ports/system.go`
- Create: `apps/agent/internal/domain/failure/failure.go`
- Create: `apps/agent/internal/ports/system.go`

**Interfaces:**
- Produces `tenant.ID`, `tenant.Actor`, `tenant.RoleSet`, `failure.Kind`, `Clock`, and `IDGenerator`.
- Later tasks must use these exact types rather than defining local tenant strings or clocks.

- [ ] **Step 1: Write tenant and failure tests**

```go
func TestNewIDRejectsBlank(t *testing.T) {
    if _, err := NewID("  "); err == nil { t.Fatal("blank tenant accepted") }
}

func TestActorRequireAcceptsAdmin(t *testing.T) {
    tenantID, err := NewID("tenant-a")
    if err != nil { t.Fatal(err) }
    actor := Actor{TenantID: tenantID, Roles: NewRoleSet(RoleAdmin)}
    if err := actor.Require(RoleOperator); err != nil { t.Fatal(err) }
}
```

Test stable failure kinds: `InvalidArgument`, `Unauthenticated`, `PermissionDenied`, `NotFound`, `Conflict`, `FailedPrecondition`, `ResourceExhausted`, `RetryableDependency`, and `Internal`.

- [ ] **Step 2: Verify tests fail before implementation**

```bash
go test ./apps/manager/internal/domain/tenant ./apps/manager/internal/domain/failure ./apps/agent/internal/domain/failure
```

Expected: FAIL with undefined constructors and kinds.

- [ ] **Step 3: Implement minimal immutable values and ports**

```go
type Clock interface { Now() time.Time }
type IDGenerator interface { New() string }

type ID string
func NewID(raw string) (ID, error) {
    value := strings.TrimSpace(raw)
    if value == "" { return "", failure.New(failure.InvalidArgument, "tenant is required") }
    return ID(value), nil
}
```

Keep `failure.Error` free of HTTP/gRPC status codes.

- [ ] **Step 4: Run foundation and architecture tests**

```bash
go test ./apps/manager/internal/domain/... ./apps/agent/internal/domain/...
python3 -m unittest test.contracts.test_layered_architecture -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/manager/internal/domain apps/manager/internal/ports apps/agent/internal/domain apps/agent/internal/ports
git commit -m "feat(architecture): add domain foundation types"
```

### Task 3: Fix Tenant Isolation Before Structural Migration

**Files:**
- Modify: `apps/manager/internal/api/http_auth_test.go`
- Modify: `apps/manager/internal/api/http_search_test.go`
- Modify: `apps/manager/internal/api/http_identity_test.go`
- Modify: `apps/manager/internal/api/http_ui_overview_test.go`
- Modify: `apps/manager/internal/api/http_telemetry.go`
- Modify: `apps/manager/internal/api/http_search.go`
- Modify: `apps/manager/internal/api/http_identity.go`
- Modify: `apps/manager/internal/api/http_ui_overview.go`
- Modify: `apps/manager/internal/store/agent.go`
- Modify: `apps/manager/internal/store/postgres/identity.go`

**Interfaces:**
- All authenticated Manager reads are constrained to the principal tenant.
- `ListAgentHealthWithError(tenantID string)` and overview helpers require a tenant.
- `/api/v1/reset` is removed from production routing; test-only reset uses a non-production helper.

- [ ] **Step 1: Add two-tenant failing tests**

For each endpoint `/events`, `/signals`, `/search`, `/search/histogram`, `/agent-health`, `/ui/overview`, `/metrics`, and `/rarity-baseline`, create tenant A and tenant B records, authenticate as tenant A, and assert no tenant B identifier or count appears.

- [ ] **Step 2: Run focused tests and verify cross-tenant failures**

```bash
go test ./apps/manager/internal/api -run 'Tenant|Overview|Search|Health|Metrics|Rarity' -count=1
```

Expected: FAIL on the previously unscoped handlers.

- [ ] **Step 3: Inject tenant filters at the last trusted boundary**

Ensure OpenSearch requests include top-level or label tenant filters according to index mapping. Change store list methods to require tenant and reject blank tenant. Do not rely only on request-body rewriting.

- [ ] **Step 4: Remove production reset semantics**

Remove `/api/v1/reset` from `Server.Handler`; replace internal test setup with direct fixture construction. Assert authenticated requests receive `404` and cannot mutate another tenant.

- [ ] **Step 5: Verify focused and package tests**

```bash
go test ./apps/manager/internal/api ./apps/manager/internal/store ./apps/manager/internal/store/postgres -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/manager/internal/api apps/manager/internal/store
git commit -m "fix(manager): enforce tenant-scoped operations"
```

### Task 4: Make Gateway Production Bootstrap Fail Closed

**Files:**
- Create: `apps/manager/internal/bootstrap/gateway.go`
- Create: `apps/manager/internal/bootstrap/gateway_test.go`
- Create: `apps/manager/internal/adapters/inbound/grpc/security.go`
- Modify: `apps/manager/cmd/sysarmor-gateway/main.go`
- Modify: `packages/tlsconfig/mtls.go`
- Modify: `packages/tlsconfig/mtls_test.go`
- Modify: `deployments/gateway/gateway.env.example`

**Interfaces:**
- Produces `bootstrap.NewProductionGateway(Config)` and `bootstrap.NewDevelopmentGateway(Config)`.
- Production requires TLS certificate, key, Client CA, and verified client certificates.

- [ ] **Step 1: Write the security-mode matrix tests**

```go
func TestProductionGatewayRejectsMissingMTLS(t *testing.T) {
    _, err := NewProductionGateway(Config{})
    if err == nil { t.Fatal("production gateway accepted missing mTLS") }
}

func TestDevelopmentGatewayRejectsNonLoopbackInsecureListen(t *testing.T) {
    _, err := NewDevelopmentGateway(Config{Listen: "0.0.0.0:9444", Insecure: true})
    if err == nil { t.Fatal("insecure gateway exposed non-loopback") }
}
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./apps/manager/internal/bootstrap ./packages/tlsconfig -count=1
```

- [ ] **Step 3: Implement explicit constructors and thin main wiring**

Move security-mode selection out of implicit flag combinations. `main` selects production unless `--development` is explicitly present; production constructor returns an error before opening any listener.

- [ ] **Step 4: Run Gateway tests and build**

```bash
go test ./apps/manager/cmd/sysarmor-gateway ./apps/manager/internal/bootstrap ./apps/manager/internal/gateway ./packages/tlsconfig
go build ./apps/manager/cmd/sysarmor-gateway
```

- [ ] **Step 5: Commit**

```bash
git add apps/manager/cmd/sysarmor-gateway apps/manager/internal/bootstrap apps/manager/internal/adapters packages/tlsconfig deployments/gateway
git commit -m "fix(gateway): require production mTLS"
```

### Task 5: Build Manager Policy as the Reference Vertical Slice

**Files:**
- Create: `apps/manager/internal/domain/policy/{model.go,publication.go,assignment.go}`
- Create: `apps/manager/internal/domain/policy/*_test.go`
- Create: `apps/manager/internal/domain/audit/model.go`
- Create: `apps/manager/internal/application/manager/policy/{publish.go,assign.go,query.go}`
- Create: `apps/manager/internal/application/manager/policy/*_test.go`
- Create: `apps/manager/internal/ports/policy.go`
- Create: `apps/manager/internal/adapters/outbound/postgres/policy/{repository.go,unit_of_work.go,mapper.go}`
- Create: `apps/manager/internal/adapters/inbound/http/policy/{handler.go,dto.go,mapper.go}`
- Modify: `apps/manager/internal/api/http.go`
- Modify: `apps/manager/internal/store/postgres/policy.go`

**Interfaces:**

```go
type PublishPolicy interface {
    Execute(context.Context, RequestContext, PublishPolicyCommand) (PublishPolicyResult, error)
}
type PolicyUnitOfWork interface {
    Execute(context.Context, func(context.Context, PolicyTransaction) error) error
}
```

- [ ] **Step 1: Write pure Domain tests**

Test stale version rejection, tenant mismatch, immutable publication audit, assignment target validation, and deterministic behavior with supplied time.

- [ ] **Step 2: Write Application transaction tests with fakes**

Assert publish writes Policy and Audit in one callback; assignment writes Assignment, Audit, and optional Control Command; any fake failure rolls back the captured transaction.

- [ ] **Step 3: Run tests and verify undefined-type failures**

```bash
go test ./apps/manager/internal/domain/policy ./apps/manager/internal/application/manager/policy
```

- [ ] **Step 4: Implement Domain, Ports, and use cases**

Use validated `tenant.ID`, injected `Clock`, and domain failure kinds. Do not import legacy `store` or `packages/policy` from Domain/Application.

- [ ] **Step 5: Implement PostgreSQL adapter contract tests**

Run the same repository behavior suite against memory fakes and PostgreSQL fake driver: tenant isolation, conflict behavior, atomic publication, and rollback.

- [ ] **Step 6: Switch HTTP policy routes to the new inbound Adapter**

Preserve existing JSON and status contract. Remove policy methods from `managerapi.ManagerStore` once no route uses them.

- [ ] **Step 7: Run reference-slice verification**

```bash
go test ./apps/manager/internal/domain/policy/... ./apps/manager/internal/application/manager/policy/... ./apps/manager/internal/adapters/... ./apps/manager/internal/api/...
python3 -m unittest test.contracts.test_layered_architecture -v
```

- [ ] **Step 8: Commit in two atomic changes**

```bash
git add apps/manager/internal/domain/policy apps/manager/internal/domain/audit apps/manager/internal/application/manager/policy apps/manager/internal/ports/policy.go apps/manager/internal/adapters/outbound/postgres/policy
git commit -m "feat(manager): add policy application slice"
git add apps/manager/internal/adapters/inbound/http/policy apps/manager/internal/api
git commit -m "refactor(manager): route policy API through application"
```

### Task 6: Migrate Remaining Manager Control-Plane Slices

**Files:**
- Create: `apps/manager/internal/domain/{identity,enrollment,control,response,artifact,audit}/`
- Create: `apps/manager/internal/application/manager/{identity,enrollment,control,response,artifact}/`
- Create: `apps/manager/internal/ports/{identity,enrollment,control,response,artifact}.go`
- Create: matching `apps/manager/internal/adapters/outbound/postgres/*/`
- Create: matching `apps/manager/internal/adapters/inbound/http/*/`
- Modify: `apps/manager/internal/api/http.go`
- Delete after route migration: corresponding legacy files under `apps/manager/internal/api/` and `apps/manager/internal/store/`

**Interfaces:**
- Produces the exact Repository and UnitOfWork families specified in the design.
- Each slice follows Task 5 and has no direct dependency on another slice's adapter.

- [ ] **Step 1: Migrate Identity read use cases**

Implement tenant-scoped Agent, Health, Session, Overview, Metrics, and Rarity queries. Run two-tenant tests before deleting legacy identity handlers.

- [ ] **Step 2: Migrate Enrollment and certificate issuance**

Test token single use, CSR identity binding, idempotent issuance, commit failure behavior, certificate revocation, and unenrollment completion.

- [ ] **Step 3: Migrate Control commands**

Test create, pending, sent, ack, retry, cancel, expire, replay, and optimistic conflicts through `ControlUnitOfWork`.

- [ ] **Step 4: Migrate Response approval**

Test role requirements, multi-approval, denial, command creation, ack, and audit in `ResponseUnitOfWork`.

- [ ] **Step 5: Migrate Artifact and channel operations**

Keep archive parsing in outbound Adapter; keep artifact state transitions in Domain/Application.

- [ ] **Step 6: Remove migrated legacy methods and run Manager tests**

```bash
go test ./apps/manager/internal/domain/... ./apps/manager/internal/application/manager/... ./apps/manager/internal/adapters/... ./apps/manager/internal/api/...
```

- [ ] **Step 7: Commit one slice at a time**

Use `feat(manager): add <slice> application slice` followed by `refactor(manager): remove legacy <slice> path`.

### Task 7: Migrate Gateway Data and Control Planes

**Files:**
- Create: `apps/manager/internal/application/gateway/{accept_batch.go,open_session.go,dispatcher.go,revoke.go}`
- Create: `apps/manager/internal/application/gateway/handlers/*.go`
- Create: `apps/manager/internal/ports/{batch.go,session.go,message.go}.go`
- Create: `apps/manager/internal/adapters/inbound/grpc/{auth,dataplane,control}/`
- Create: `apps/manager/internal/adapters/outbound/{kafka,redis}/`
- Modify: `apps/manager/internal/bootstrap/gateway.go`
- Delete: `apps/manager/internal/gateway/backend.go`
- Delete after migration: `apps/manager/internal/gateway/{grpc.go,control_grpc.go,runtime.go,identity.go,resume.go,server.go}`

**Interfaces:**
- Data acceptance returns accepted only after reliable publish or proven duplicate.
- Control dispatcher delegates each command type to a handler below 50 lines.

- [ ] **Step 1: Add application tests for batch reliability**

Cover identity mismatch, revoked certificate, duplicate batch, publisher failure, session failure after publish, and accepted cursor.

- [ ] **Step 2: Add dispatcher tests**

Cover hello, health, policy ack, response ack, evidence result, command ack, replay, sequence gap, and unknown frame.

- [ ] **Step 3: Implement application use cases using Manager Ports**

Pass request context through all calls; remove `context.Background()` from request paths.

- [ ] **Step 4: Implement gRPC mappers and stream adapters**

Protobuf remains confined to `adapters/inbound/grpc` and `packages/contracts`.

- [ ] **Step 5: Switch bootstrap and delete the old Gateway package**

```bash
go test ./apps/manager/internal/application/gateway/... ./apps/manager/internal/adapters/inbound/grpc/... ./apps/manager/cmd/sysarmor-gateway
```

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(gateway): add data and control application services"
git commit -m "refactor(gateway): remove legacy runtime backend"
```

### Task 8: Migrate Worker and Analytics

**Files:**
- Create: `apps/manager/internal/domain/detection/{correlation,convergence,rarity}/`
- Create: `apps/manager/internal/domain/investigation/{entity,graph,evidence,incident}/`
- Create: `apps/manager/internal/application/worker/{process_batch.go,recompute_scope.go}`
- Create: `apps/manager/internal/ports/{history.go,projection.go,deadletter.go}.go`
- Create: `apps/manager/internal/adapters/inbound/kafka/consumer.go`
- Create: `apps/manager/internal/adapters/outbound/opensearch/{history.go,projection.go}`
- Modify: `apps/manager/internal/bootstrap/worker.go`
- Modify: `apps/manager/cmd/sysarmor-worker/main.go`
- Delete after migration: `apps/manager/internal/{analytics,ingest,platform/opensearch}`

**Interfaces:**
- Pure analysis Domain accepts Domain Event/Signal and returns Domain Analysis.
- `ProcessDataBatchResult` exposes `accepted`, `retryable`, or `rejected` disposition.

- [ ] **Step 1: Port analytics tests to Protobuf-free Domain models**

Retain correlation, graph, rarity, convergence, stable Incident ID, and evidence assertions.

- [ ] **Step 2: Add Worker failure matrix tests**

Cover invalid contract, history timeout, policy lookup failure, partial projection, DLQ failure, and successful offset eligibility.

- [ ] **Step 3: Implement Contract mappers and use cases**

Map Protobuf only in Kafka Adapter. Require tenant on history and projection Ports.

- [ ] **Step 4: Switch Worker bootstrap and remove old Processor**

```bash
go test ./apps/manager/internal/domain/detection/... ./apps/manager/internal/domain/investigation/... ./apps/manager/internal/application/worker/... ./apps/manager/internal/adapters/inbound/kafka/...
```

- [ ] **Step 5: Run benchmarks and commit**

```bash
go test -bench=. ./apps/manager/internal/domain/detection/... ./apps/manager/internal/domain/investigation/...
git commit -m "refactor(worker): isolate analytics and message adapters"
```

### Task 9: Migrate Agent Domain Models

**Files:**
- Move and adapt: `apps/agent/internal/management` -> `apps/agent/internal/domain/management`
- Move and adapt: `apps/agent/internal/detection/matcher` -> `apps/agent/internal/domain/detection/matcher`
- Create: `apps/agent/internal/domain/{policy,content,event,telemetry,health,response}/`
- Create: `apps/agent/internal/domain/detection/{compiler,runtime}/`
- Create: `apps/agent/internal/adapters/contracts/mapper.go`
- Modify tests from current `control`, `detection`, `content`, `policy`, and `event` packages

**Interfaces:**
- Domain uses no Protobuf or sensor contract types.
- Detection `Program` is immutable; only bounded `RuntimeState` mutates.

- [ ] **Step 1: Move management and matcher with unchanged tests**
- [ ] **Step 2: Introduce Domain Event, Signal, Policy, Content, and Telemetry models**
- [ ] **Step 3: Port detection compiler and runtime tests before implementation moves**
- [ ] **Step 4: Add Protobuf mapper round-trip tests in Adapter package**
- [ ] **Step 5: Run Domain tests and benchmarks**

```bash
go test ./apps/agent/internal/domain/... ./apps/agent/internal/adapters/contracts/...
go test -bench=. ./apps/agent/internal/domain/detection/...
```

- [ ] **Step 6: Commit by Domain context**

Use atomic `refactor(agent): isolate <context> domain` commits.

### Task 10: Replace AgentRuntime with Application Services and Adapters

**Files:**
- Create: `apps/agent/internal/application/{lifecycle,enrollment,policy,content,detection,pipeline,telemetry,health,diagnostics}/`
- Create: `apps/agent/internal/ports/{sensor,state,spool,content,data,control}.go`
- Create: `apps/agent/internal/adapters/{config,sqlite,segments,filesystem,sensor/tetragon,sensor/fake,inbound/unix,inbound/grpc,outbound/grpc,outbound/jsonl,system}/`
- Create: `apps/agent/internal/bootstrap/agent.go`
- Modify: `apps/agent/cmd/sysarmor-agent/main.go`
- Delete after migration: legacy `daemon`, `control`, `localapi`, `remoteapi`, `localstore`, `sensors`, `telemetry`, `config`, and `content` packages

**Interfaces:**
- Policy/content activation follows Prepare -> persist -> runtime swap -> report.
- Checkpoint advances only for accepted/duplicate acknowledgements.
- Bootstrap owns lifecycle; no replacement global runtime container is allowed.

- [ ] **Step 1: Implement State, Spool, Sensor, DataAppender, and ControlChannel contract suites**
- [ ] **Step 2: Migrate policy/content activation use cases and failure-point tests**
- [ ] **Step 3: Migrate event pipeline and telemetry use cases with Fake Ports**
- [ ] **Step 4: Migrate enrollment, unenrollment, health, and diagnostics use cases**
- [ ] **Step 5: Implement SQLite, segment, Tetragon, Unix, and gRPC adapters**
- [ ] **Step 6: Wire `bootstrap.NewAgent` and reduce main to command dispatch**
- [ ] **Step 7: Delete each legacy package immediately after its last caller moves**
- [ ] **Step 8: Run Agent verification**

```bash
go test -race ./apps/agent/... ./packages/...
make test-functional DOMAIN=endpoint
```

- [ ] **Step 9: Commit one use case and adapter family at a time**

### Task 11: Retire Shared Business Models and Legacy Containers

**Files:**
- Modify: `packages/README.md`
- Keep: `packages/contracts/proto`, `packages/contracts/schema`
- Split or delete: `packages/{policy,response,eventmodel,tlsconfig}` and `packages/contracts/{controlmodel,health}`
- Delete remaining: `apps/manager/internal/store`, old Manager API/Gateway/Ingest packages, old Agent runtime packages
- Modify: `test/contracts/test_monorepo_layout.py`
- Modify: `test/contracts/test_layered_architecture.py`

**Interfaces:**
- `packages` contains stable wire/plugin contracts only.
- No old global Store, Runtime, Backend, Processor, or shared mutable business model remains.

- [ ] **Step 1: Add failing absence/import assertions for every retired package**
- [ ] **Step 2: Move remaining contract DTOs under `packages/contracts` without changing wire semantics**
- [ ] **Step 3: Remove legacy packages and all exemptions from the architecture contract**
- [ ] **Step 4: Verify no forbidden names remain**

```bash
rg -n 'store\.Store|ManagerStore|ControlStore|SaveState|AgentRuntime|gateway\.Backend|ingest\.Processor' apps packages --glob '*.go'
```

Expected: no product implementation matches; historical docs may retain names.

- [ ] **Step 5: Commit**

```bash
git commit -m "refactor(architecture): remove legacy application containers"
```

### Task 12: Final Architecture, Reliability, and Documentation Closure

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/reference/configuration.md`
- Modify: `docs/development/development.md`
- Modify: `docs/development/testing.md`
- Modify: `CATALOG.md`
- Modify only defects found by final review elsewhere

**Interfaces:**
- Documentation describes implemented state only.
- Architecture tests have no legacy exemptions.

- [ ] **Step 1: Run formatting, static, and architecture checks**

```bash
test -z "$(gofmt -l apps packages)"
git diff --check
python3 -m unittest discover -s test/contracts -p 'test_*.py' -v
GOCACHE=/tmp/sysarmor-layered-go-cache go vet ./...
```

- [ ] **Step 2: Run unit and race suites**

```bash
GOCACHE=/tmp/sysarmor-layered-go-cache go test ./...
GOCACHE=/tmp/sysarmor-layered-go-cache go test -race ./apps/agent/... ./apps/manager/...
```

- [ ] **Step 3: Run product integration suites**

```bash
make build-binary
make test-functional DOMAIN=platform
make test-functional DOMAIN=topology
make test-detection
make test-performance DOMAIN=endpoint PROFILE=quick
make test-performance DOMAIN=platform PROFILE=quick
```

- [ ] **Step 4: Check file and function governance**

Run the repository governance contract and confirm no non-generated Go file exceeds 500 lines and no newly changed function exceeds 50 lines without an approved exception.

- [ ] **Step 5: Update current architecture documentation**

Document layer ownership, dependency direction, transaction boundaries, production/development bootstrap, and test commands. Remove descriptions of deleted Store/Runtime paths.

- [ ] **Step 6: Perform final review and commit**

```bash
git add docs CATALOG.md test apps packages
git commit -m "docs: document layered product architecture"
```

Expected final state: clean worktree, all available validation green, no legacy architecture exemptions, and public contracts unchanged unless separately approved.
