# Agent Layered Architecture Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Agent Tasks 9-12 by moving every production path to Domain, Application, Ports, Adapters, and Bootstrap, then deleting all Agent legacy roots and retired shared business models.

**Architecture:** Migrate one vertical behavior at a time from inner rules to outer adapters. Each task introduces the target test/API, observes RED, switches every caller, deletes the old implementation in the same task, and ends with a buildable atomic commit. Standalone and managed authority remain separate and fail closed throughout.

**Tech Stack:** Go 1.26, SQLite, Tetragon, gRPC/Protobuf, Unix sockets, JSONL, Python architecture contracts, Bash functional suites.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-13-agent-layered-architecture-closure-design.md`.
- Preserve public CLI, configuration, Protobuf, local API, SQLite migration, segment, enrollment, and telemetry behavior.
- Domain must not import Protobuf, SQLite, Tetragon, gRPC, JSON, YAML, filesystem, or operating-system implementations.
- Application may import only Domain, Application, Ports, and approved standard-library packages.
- Do not retain forwarding packages, type aliases at old roots, dual production paths, or a replacement aggregate `AgentRuntime`.
- Preserve released SQLite schemas and `legacy_mtls` compatibility only inside Adapter boundaries.
- Write and observe a failing test before every production change.
- Keep changed functions below 50 lines and new non-generated files below 500 lines.
- Every task ends with focused tests, architecture contracts, race coverage for touched packages, and an atomic Conventional Commit.
- Do not run PostgreSQL concurrency tests unless Manager or Worker PostgreSQL code changes.

---

### Task 1: Make Agent Closure Executable

**Files:**
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- Produces `AGENT_LEGACY_ROOTS`, the ordered burn-down set used by later tasks.
- Produces command, layered-to-legacy import, retired-symbol, and file-size checks.

- [ ] **Step 1: Add the first failing management-root assertion**

```python
def test_agent_management_domain_is_layered(self):
    self.assertTrue((self.repo / "apps/agent/internal/domain/management").is_dir())
    self.assertFalse((self.repo / "apps/agent/internal/management").exists())
```

- [ ] **Step 2: Run the focused contract and verify RED**

Run: `python3 -m unittest test.contracts.test_layered_architecture.LayeredArchitectureContractTest.test_agent_management_domain_is_layered -v`

Expected: FAIL because `internal/management` still exists and `domain/management` does not.

- [ ] **Step 3: Add migration-safe governance**

Keep the current explicit legacy set, but add checks that layered Agent packages never import a legacy root and `cmd/sysarmor-agent` may only import Bootstrap after Task 9. Each later task removes one or more entries rather than weakening assertions.

- [ ] **Step 4: Continue directly into Task 2; commit the contract with the first green slice**

### Task 2: Isolate Management Domain

**Files:**
- Create: `apps/agent/internal/domain/management/model.go`
- Create: `apps/agent/internal/domain/management/model_test.go`
- Modify callers under: `apps/agent/internal/{daemon,localstore}`
- Delete: `apps/agent/internal/management/`
- Modify: `test/contracts/test_layered_architecture.py`

**Interfaces:**
- Produces `management.Resolve(State) (Context, error)`.
- Produces `management.ValidateTransition(State, State) error`.
- Produces `(Context).Authorize(PolicyWriteOrigin) error`.

- [ ] **Step 1: Move the existing behavioral tests to the target package while the target implementation is absent**
- [ ] **Step 2: Run `go test ./apps/agent/internal/domain/management -count=1` and verify RED because the implementation is missing**
- [ ] **Step 3: Move the pure model, switch all callers, and delete the old package**
- [ ] **Step 4: Remove only `apps/agent/internal/management` from `AGENT_LEGACY_ROOTS`**
- [ ] **Step 5: Run management, localstore, daemon, architecture, and Agent race tests**
- [ ] **Step 6: Commit `refactor(agent): isolate management domain`**

### Task 3: Isolate Event Domain and Contract Mapper

**Files:**
- Create: `apps/agent/internal/domain/event/{model.go,process_table.go,identity.go}`
- Create: `apps/agent/internal/domain/event/{process_table_test.go,identity_test.go}`
- Create: `apps/agent/internal/adapters/contracts/event.go`
- Create: `apps/agent/internal/adapters/contracts/event_test.go`
- Create: `apps/agent/internal/adapters/sensor/tetragon/event_mapper.go`
- Modify: event pipeline callers
- Delete: `apps/agent/internal/event/`

**Interfaces:**
- Produces Domain `Event`, `Process`, `Object`, `RuntimeScope`, and concurrency-safe `ProcessTable`.
- Produces deterministic `StableProcessID`, `SensorProcessID`, and `EventID` functions.
- Adapter maps `sensorv1.SensorEvent -> domain/event.Event` and `domain/event.Event -> eventv1.CanonicalEvent`.

- [ ] **Step 1: Write Domain identity and parent-lineage tests without Protobuf fixtures**
- [ ] **Step 2: Verify RED for missing Domain APIs**
- [ ] **Step 3: Implement pure Domain identity/table rules**
- [ ] **Step 4: Write failing Adapter round-trip and sensor mapping tests**
- [ ] **Step 5: Implement mappers, switch pipeline callers, and delete legacy event packages**
- [ ] **Step 6: Run Domain, Adapter, daemon, telemetry, architecture, and race tests**
- [ ] **Step 7: Commit `refactor(agent): isolate event domain`**

### Task 4: Isolate Policy Domain

**Files:**
- Create: `apps/agent/internal/domain/policy/{model.go,collection.go,endpoint.go}`
- Move and adapt tests from: `apps/agent/internal/policy/*_test.go`
- Create: `apps/agent/internal/adapters/contracts/policy.go`
- Modify: `apps/agent/internal/control`, detection and sensor callers
- Delete: `apps/agent/internal/policy/`

**Interfaces:**
- Produces Domain policy identity, collection intent, endpoint sections, activation candidate, authority validation, and version validation.
- Contract mapper owns `packages/policy` conversion until Task 11 removes the shared business model.

- [ ] **Step 1: Write target Domain validation tests and observe RED**
- [ ] **Step 2: Implement pure policy values and collection compilation inputs**
- [ ] **Step 3: Add failing shared-contract mapper round-trip tests**
- [ ] **Step 4: Implement mapper, switch callers, and delete legacy policy root**
- [ ] **Step 5: Run policy/control/sensor tests, architecture contracts, and race tests**
- [ ] **Step 6: Commit `refactor(agent): isolate policy domain`**

### Task 5: Isolate Detection Domain

**Files:**
- Create: `apps/agent/internal/domain/detection/{model.go,compiler,runtime,matcher}/`
- Move behavioral and benchmark tests from: `apps/agent/internal/detection/`
- Create: `apps/agent/internal/adapters/contracts/detection.go`
- Modify: control, content, pipeline, telemetry, and Tetragon callers
- Delete: `apps/agent/internal/detection/`

**Interfaces:**
- Produces immutable `Program`, bounded `RuntimeState`, Domain `Signal`, `Evidence`, compile report, and evaluation result.
- Contract mapper owns Protobuf signal/evidence conversion.

- [ ] **Step 1: Move matcher tests to target package and verify RED**
- [ ] **Step 2: Move matcher implementation and benchmark without behavior changes**
- [ ] **Step 3: Split engine tests into compiler, runtime, correlation, and evidence behaviors; verify each target RED**
- [ ] **Step 4: Implement the minimal pure Domain packages and remove generated-contract imports**
- [ ] **Step 5: Add mapper tests, switch callers, delete legacy detection root**
- [ ] **Step 6: Run Domain benchmarks, focused tests, architecture contracts, and Agent race**
- [ ] **Step 7: Commit by coherent contexts: matcher, compiler, runtime/evidence**

### Task 6: Move Content Activation Behind Application Ports

**Files:**
- Create: `apps/agent/internal/domain/content/{manifest.go,layers.go,model.go}`
- Create: `apps/agent/internal/application/content/{activate.go,activate_test.go}`
- Create: `apps/agent/internal/ports/content.go`
- Create: `apps/agent/internal/adapters/filesystem/content/`
- Modify: daemon/control/bootstrap callers
- Delete: `apps/agent/internal/content/` and migrated control content files

**Interfaces:**
- `ContentRepository.Current/Replace` uses Domain snapshots.
- `Activate.Execute` enforces verify -> resolve -> persist -> runtime swap -> result.

- [ ] **Step 1: Write failure-order Application tests and observe RED**
- [ ] **Step 2: Move pure manifest/layer rules into Domain**
- [ ] **Step 3: Implement narrow Ports and filesystem Adapter contract tests**
- [ ] **Step 4: Switch control/daemon callers and delete old content path**
- [ ] **Step 5: Run content, control, daemon, architecture, and race tests**
- [ ] **Step 6: Commit `refactor(agent): move content activation to application`**

### Task 7: Move Policy Activation Behind Application Ports

**Files:**
- Create: `apps/agent/internal/application/policy/{activate.go,service.go,projection.go}`
- Create: `apps/agent/internal/ports/{policy.go,sensor.go,state.go}`
- Modify: legacy control and daemon runtime files
- Delete migrated policy controllers from: `apps/agent/internal/control`, `apps/agent/internal/daemon`

**Interfaces:**
- `Activate.Prepare` validates authority and builds an immutable candidate.
- `Activate.Commit` persists, applies sensor/runtime state, and returns an explicit report.

- [ ] **Step 1: Port existing failure-matrix tests to Application fakes and observe RED**
- [ ] **Step 2: Implement minimal orchestration using Domain and narrow Ports**
- [ ] **Step 3: Switch local and remote API handlers to the Application interface**
- [ ] **Step 4: Delete migrated control/daemon policy orchestration**
- [ ] **Step 5: Run standalone/managed policy tests, architecture, and race**
- [ ] **Step 6: Commit `refactor(agent): move policy activation to application`**

### Task 8: Move Event Pipeline and Telemetry Delivery

**Files:**
- Create: `apps/agent/internal/domain/telemetry/`
- Create: `apps/agent/internal/application/{pipeline,telemetry}/`
- Create: `apps/agent/internal/ports/{data.go,spool.go,telemetry.go}`
- Create: `apps/agent/internal/adapters/{sqlite,segments,outbound/grpc,outbound/jsonl}/`
- Modify: daemon/bootstrap callers
- Delete: `apps/agent/internal/telemetry/` and migrated localstore event/segment code

**Interfaces:**
- Pipeline processes Domain sensor events and emits Domain events/signals.
- Telemetry delivery advances checkpoints only for accepted/duplicate acknowledgments.
- Capacity and eviction decisions are pure Domain rules.

- [ ] **Step 1: Write acknowledgment/checkpoint and retry failure tests; observe RED**
- [ ] **Step 2: Implement Domain telemetry decisions and Application services**
- [ ] **Step 3: Add SQLite segment and gRPC/JSONL Adapter contract tests**
- [ ] **Step 4: Switch callers and delete legacy telemetry root**
- [ ] **Step 5: Run pipeline, storage recovery, transport, architecture, race, and endpoint functional tests**
- [ ] **Step 6: Commit pipeline and delivery as separate atomic commits**

### Task 9: Move Enrollment, Health, Response, and Diagnostics

**Files:**
- Create: `apps/agent/internal/domain/{health,response}/`
- Create: `apps/agent/internal/application/{lifecycle,enrollment,health,response,diagnostics}/`
- Create: `apps/agent/internal/ports/{control.go,enrollment.go,health.go,response.go}`
- Create: `apps/agent/internal/adapters/{inbound/unix,inbound/grpc,outbound/grpc}/`
- Modify: local/remote API and daemon callers
- Delete: `apps/agent/internal/{control,localapi,remoteapi}` after last caller moves

**Interfaces:**
- Enrollment transitions and completion outbox are durable Application workflows.
- Health aggregates narrow component snapshots without owning components.
- Response validates Domain authorization before invoking a response Port.

- [ ] **Step 1: Port enrollment/unenrollment failure and recovery tests; observe RED**
- [ ] **Step 2: Implement lifecycle and enrollment services over narrow Ports**
- [ ] **Step 3: Port health, response, and diagnostics tests and implementations**
- [ ] **Step 4: Implement Unix/gRPC boundary mappers and switch API servers**
- [ ] **Step 5: Delete control/localapi/remoteapi roots and their exemptions**
- [ ] **Step 6: Run focused, topology contract, architecture, and race tests**
- [ ] **Step 7: Commit one use-case family at a time**

### Task 10: Move Remaining Infrastructure Adapters and Wire Bootstrap

**Files:**
- Create: `apps/agent/internal/adapters/{config,sqlite,sensor/tetragon,sensor/fake,system}/`
- Create: `apps/agent/internal/bootstrap/{agent.go,runner.go,resources.go}`
- Modify: `apps/agent/cmd/sysarmor-agent/main.go`
- Modify: `apps/agent/cmd/sysarmor-content-sign/main.go`
- Delete: `apps/agent/internal/{config,daemon,localstore,sensors,tamper}` after caller switch

**Interfaces:**
- `bootstrap.NewAgent(Config) (*Runner, io.Closer, error)` owns composition only.
- Runner starts, coordinates, and stops Application services without business decisions.
- Commands import Bootstrap only.

- [ ] **Step 1: Add failing command-boundary and Bootstrap validation tests**
- [ ] **Step 2: Move concrete infrastructure behind existing Ports**
- [ ] **Step 3: Implement Bootstrap resource construction and deterministic close ordering**
- [ ] **Step 4: Switch commands and verify CLI/config compatibility**
- [ ] **Step 5: Delete daemon and remaining infrastructure legacy roots**
- [ ] **Step 6: Run all Agent tests, race, endpoint functional, and managed topology smoke**
- [ ] **Step 7: Commit Adapter families separately, then `refactor(agent): wire layered bootstrap`**

### Task 11: Retire Shared Business Models and All Exemptions

**Files:**
- Modify: `packages/README.md`
- Inspect and split/delete: `packages/{policy,response,eventmodel}`
- Inspect and split/delete: `packages/contracts/{controlmodel,health}`
- Keep if still genuinely shared: `packages/tlsconfig`, generated Protobuf/schema, sensor SDK
- Modify: `test/contracts/test_layered_architecture.py`
- Modify: `test/contracts/test_monorepo_layout.py`

**Interfaces:**
- `packages` contains only stable cross-process, plugin, schema, or technical contracts.
- Architecture contract has no Agent legacy exemptions.

- [ ] **Step 1: Add failing absence/import tests for each proven-retired package**
- [ ] **Step 2: Move remaining product-owned types and switch callers**
- [ ] **Step 3: Delete retired shared packages and all Agent legacy exemptions**
- [ ] **Step 4: Run forbidden-symbol/import and file-size scans**
- [ ] **Step 5: Run full Go, architecture, and race suites**
- [ ] **Step 6: Commit `refactor(architecture): remove agent legacy roots`**

### Task 12: Final Reliability and Documentation Closure

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/development/{development.md,testing.md}`
- Modify: `docs/reference/configuration.md`
- Modify: `CATALOG.md`
- Modify: the implementation plan status table

**Interfaces:**
- Documentation describes only implemented paths.
- Final repository has no compatibility facade or architecture exemption.

- [ ] **Step 1: Run formatting, diff, architecture, vet, unit, and race gates**
- [ ] **Step 2: Run standalone endpoint functional tests**
- [ ] **Step 3: Run managed topology functional and Detection tests**
- [ ] **Step 4: Run quick endpoint and platform performance profiles**
- [ ] **Step 5: Verify no non-generated production Go file exceeds 500 lines and no changed function exceeds 50 lines without explicit justification**
- [ ] **Step 6: Update documentation and mark Tasks 9-12 complete with exact run evidence**
- [ ] **Step 7: Request final code review, fix all Critical/Important findings, and rerun affected gates**
- [ ] **Step 8: Commit `docs: close layered product architecture` and require a clean worktree**
