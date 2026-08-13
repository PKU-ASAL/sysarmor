# Agent Layered Architecture Closure Design

## 1. Conclusion

Agent Tasks 9-12 will be implemented as vertical domain slices. Each slice moves one coherent behavior through Domain, Application, Ports, Adapters, and Bootstrap, switches every caller, and then deletes the corresponding legacy package or exemption. The migration must not introduce forwarding facades, parallel production paths, or a replacement global `AgentRuntime` container.

The implementation order is:

1. architecture contracts and migration baseline;
2. management and event domains;
3. policy and detection domains;
4. content domain and activation application service;
5. sensor event pipeline and telemetry application services;
6. enrollment, health, response, and diagnostics services;
7. SQLite, filesystem, segment, Tetragon, Unix, and gRPC adapters;
8. `bootstrap.NewAgent` and command closure;
9. shared business model and legacy root deletion;
10. repository-wide verification and documentation.

This order follows the dependency graph from inner rules to outer composition. It keeps standalone and managed modes operational after every accepted slice.

## 2. Scope

### 2.1 Included

- Complete Tasks 9-12 from `2026-08-08-layered-architecture-migration.md`.
- Move Agent business rules into `internal/domain` without Protobuf, SQLite, Tetragon, HTTP, gRPC, filesystem, or operating-system dependencies.
- Move orchestration into explicit Application services that depend only on Domain and Ports.
- Implement infrastructure under `internal/adapters` and composition under `internal/bootstrap`.
- Reduce `cmd/sysarmor-agent` and `cmd/sysarmor-content-sign` to command parsing and Bootstrap calls.
- Remove all Agent entries from `LEGACY_ROOTS` in the architecture contract.
- Remove shared mutable business models from `packages`; retain stable wire, schema, plugin, and genuinely shared technical contracts.
- Preserve public CLI, configuration, Protobuf, local API, storage migration, enrollment, and telemetry behavior.

### 2.2 Excluded

- New detection features, new response actions, new configuration options, or new protocols.
- PostgreSQL changes on Manager or Worker.
- Replacing SQLite, Tetragon, Kafka, gRPC, JSONL, or the segment format.
- Removing upgrade compatibility for released Agent database schemas or `legacy_mtls` unenrollment.
- Large performance tuning not required to preserve current acceptance thresholds.

## 3. Architectural Rules

The stable dependency direction is:

```text
cmd -> bootstrap -> adapters -> application -> domain
                              -> ports <- adapters
```

- Domain imports only approved standard-library packages and other Agent Domain packages.
- Application imports only Agent Domain, Application, Ports, and approved standard-library packages.
- Ports use Domain or Port-owned boundary types and never import Application or Adapter packages.
- Adapters own Protobuf, JSON, YAML, SQLite, Tetragon, filesystem, network, and operating-system mapping.
- Bootstrap is the only layer allowed to construct concrete Adapter graphs.
- Commands import Bootstrap only, except the Go standard library.
- No package exposes a general service locator, aggregate Store, or runtime object that grants unrelated capabilities.

Architecture contracts must enforce these rules before production callers are switched. Legacy exemptions may only decrease.

## 4. Vertical Slices

### 4.1 Foundation Contracts

Add executable absence and dependency assertions for the target Agent layout. Record the existing 14 legacy roots as an ordered burn-down list. Each later slice removes its own root only after all non-test callers move.

The contract also rejects:

- commands importing legacy Agent packages;
- new imports from layered packages back into legacy roots;
- Domain imports of generated contracts or infrastructure;
- Application imports of Adapter implementations;
- new non-generated Go files above 500 lines.

### 4.2 Management and Event

Move management state, authority, lifecycle transition, event context, and normalization rules into Domain. Preserve the distinction between:

- `standalone`: local policy authority and no Manager identity requirement;
- `managed`: Manager policy authority and enrolled network identity;
- transitional or degraded states: explicit, durable, and fail-closed.

Wire and sensor inputs are converted into Domain events by Adapter mappers. Domain event identity and timestamps must not depend on Tetragon-generated types.

### 4.3 Policy and Detection

Create Domain policy values for collection, detection, telemetry, response, and endpoint policy identity. Move the matcher, compiler, correlation state, and evaluation engine under Domain detection subpackages.

The Domain detection program is immutable after compilation. Mutable CEP state is isolated in a bounded runtime state object. Compilation and evaluation accept Domain events and return Domain signals and evidence; Protobuf mapping remains in adapters.

Policy activation is an Application use case with this invariant:

```text
validate authority -> prepare candidate -> persist durable policy
-> apply sensor/runtime state -> publish result
```

Failures are explicit. A managed Agent cannot silently fall back to a standalone policy. Runtime and durable state cannot report success if either side failed.

### 4.4 Content

Move content signature verification, layer resolution, snapshot identity, and compatibility validation into Domain. Filesystem reads, archive decoding, and key loading remain adapters.

Content activation follows prepare, persist, runtime swap, and result reporting. Detection compilation consumes an immutable content snapshot through a narrow Port rather than importing the legacy content store.

### 4.5 Pipeline and Telemetry

Separate sensor subscription, event normalization, detection evaluation, local publication, spooling, batching, upload, acknowledgment, and checkpoint advancement into Application services.

Required reliability invariants:

- accepted and duplicate acknowledgments may advance a checkpoint;
- retryable or rejected transport outcomes never discard an uncommitted batch;
- local storage capacity enforcement remains deterministic and observable;
- standalone output remains local and managed output retains enrollment identity and policy version;
- shutdown drains only within the configured bound and reports incomplete work explicitly.

SQLite segments, JSONL, gRPC data appenders, ring buffers, and Tetragon subscriptions are Adapter implementations of narrow Ports.

### 4.6 Enrollment, Health, Response, and Diagnostics

Move enrollment and unenrollment state transitions, completion outbox rules, health aggregation, response authorization, and diagnostic snapshot orchestration into Application and Domain packages.

Released SQLite schemas and `legacy_mtls` behavior remain supported through Adapter migrations. Compatibility code is allowed only at persisted-data and wire boundaries; it must not reintroduce legacy business packages or dual runtime paths.

Health reads are projections over narrow status Ports. They must expose degraded sensor, policy, storage, transport, and management states without allowing a failed component to terminate unrelated Agent capabilities.

### 4.7 Adapters and Bootstrap

Concrete implementations are grouped by external technology:

```text
internal/adapters/
  config/
  contracts/
  inbound/unix/
  inbound/grpc/
  outbound/grpc/
  outbound/jsonl/
  sqlite/
  segments/
  filesystem/
  sensor/tetragon/
  sensor/fake/
  system/
```

`bootstrap.NewAgent` constructs small Application services and owns lifecycle ordering. It may own a resource closer and a top-level runner, but the runner must only start, coordinate, and stop services. It must not contain policy, detection, enrollment, or persistence decisions.

Commands must not construct SQLite stores, sensors, data appenders, API servers, or policy controllers directly.

## 5. Shared Package Closure

After all Agent callers move, inspect the remaining shared packages by ownership:

- keep generated Protobuf and schema contracts;
- keep sensor SDK contracts intended for external sensor plugins;
- keep `tlsconfig` only if both products consume it as a pure technical helper;
- move Agent-only business types into Agent Domain;
- move Manager-only business types into Manager Domain;
- delete `packages/policy`, `packages/response`, `packages/eventmodel`, `contracts/controlmodel`, or `contracts/health` only after import scans prove no legitimate cross-process contract remains.

Deletion is evidence-driven. Package names alone are not sufficient reason to remove stable external contracts.

## 6. Migration Mechanics

Every vertical slice follows the same TDD sequence:

1. add or move a behavioral test against the desired Domain/Application API;
2. run it and confirm the expected RED failure;
3. implement the smallest new Domain/Application boundary;
4. add the Adapter mapper or repository implementation;
5. switch all production callers in the slice;
6. run focused tests and Agent race tests;
7. delete the old implementation and its architecture exemption;
8. run the architecture contract and relevant functional gate;
9. commit the independently working slice.

Temporary forwarding packages are prohibited. A short-lived type conversion inside an Adapter is acceptable while callers move within the same slice, but it must not survive the slice commit.

## 7. Testing Strategy

### 7.1 Per Slice

- Domain unit tests for deterministic rules and invalid transitions.
- Application tests with narrow fakes for ordering, rollback, and error propagation.
- Adapter contract tests for SQLite migrations, Protobuf round trips, filesystem behavior, sensor application, and network acknowledgments.
- Architecture contracts proving dependency direction and legacy-root removal.
- `go test -race` for touched Agent packages.

### 7.2 Mode Coverage

Standalone acceptance verifies local policy authority, offline operation, local output, storage recovery, and sensor degradation.

Managed acceptance verifies enrollment identity, published policy authority, policy-version propagation, control reconnect, durable telemetry upload, unenrollment, and restart recovery.

Neither mode is allowed to borrow the other mode's policy or credentials as a fallback.

### 7.3 Final Gates

- formatting, `git diff --check`, architecture contracts, and `go vet`;
- `go test ./...`;
- `go test -race ./apps/agent/... ./apps/manager/...`;
- endpoint functional tests for standalone;
- topology functional and Detection tests for managed;
- quick endpoint and platform performance profiles;
- no Agent legacy architecture exemptions;
- no product implementation references to `AgentRuntime`, aggregate Store facades, or retired shared business models;
- no non-generated production Go file above 500 lines.

PostgreSQL concurrency is outside this Agent-only phase and is not repeated unless Manager or Worker PostgreSQL code changes.

## 8. Commit and Branch Strategy

All work remains on `refactor/agent-layered-architecture`, created from merge commit `ee76264b` on `dev`.

Commits are organized by independently reviewable behavior, not directory operations. Expected categories include:

```text
test(architecture): define agent layering closure
refactor(agent): isolate management domain
refactor(agent): isolate event domain
refactor(agent): isolate policy domain
refactor(agent): isolate detection domain
refactor(agent): move content activation to application
refactor(agent): move event pipeline to application
refactor(agent): move telemetry delivery to application
refactor(agent): move enrollment lifecycle to application
refactor(agent): wire layered bootstrap
refactor(architecture): remove agent legacy roots
docs: close layered product architecture
```

Each commit must build and pass its focused tests. The final pull request targets `dev` through `origin` on `git.pku.edu.cn`.

## 9. Completion Criteria

Tasks 9-12 are complete only when all of the following are true:

1. Agent production code lives under Domain, Application, Ports, Adapters, Bootstrap, and commands.
2. The architecture contract contains no Agent `LEGACY_ROOTS` exemptions.
3. Agent commands depend on Bootstrap only.
4. Standalone and managed acceptance suites both pass without compatibility fallback between modes.
5. Released storage and wire upgrades remain supported at Adapter boundaries.
6. Shared packages contain only stable cross-process, plugin, schema, or technical contracts.
7. No replacement aggregate Store or `AgentRuntime` container exists.
8. All final quality gates pass and the worktree is clean.
