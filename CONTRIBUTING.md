# Contributing to SysArmor

SysArmor welcomes focused issues and pull requests. Report security vulnerabilities through the private process in [SECURITY.md](SECURITY.md), not through a public issue.

## Workflow

Create feature and fix branches from `dev`, then open pull requests back to `dev`. Release branches are short-lived and merge into `main` only after release-candidate acceptance. Do not commit directly to `dev` or `main`.

Use Conventional Commits such as `feat:`, `fix:`, `refactor:`, `docs:`, and `test:`. Keep each commit focused on one concern.

## Repository Boundaries

| Path | Responsibility |
|---|---|
| `apps/*/cmd/` | Flag parsing, process lifecycle, and top-level exit codes |
| `apps/agent/internal/domain/` | Pure Agent models, state transitions, and deterministic algorithms |
| `apps/agent/internal/application/` | Agent use cases and orchestration |
| `apps/agent/internal/ports/` | Narrow interfaces consumed by Agent application code |
| `apps/agent/internal/adapters/` | Config, SQLite, filesystem, Unix/gRPC, sensor, and system adapters |
| `apps/agent/internal/bootstrap/` | Technical resource creation and Agent assembly |
| `apps/manager/internal/domain/` | Pure Manager and Worker models and algorithms |
| `apps/manager/internal/application/` | Manager and Worker use cases and transaction intent |
| `apps/manager/internal/ports/` | Tenant-scoped interfaces consumed by application code |
| `apps/manager/internal/adapters/` | HTTP, gRPC, Kafka, PostgreSQL, OpenSearch, and Redis adapters |
| `apps/manager/internal/bootstrap/` | Manager, Gateway, and Worker assembly |
| `packages/contracts/proto/` | Agent data-plane and control-plane wire contracts |
| `packages/` | Stable capabilities genuinely shared by products |
| `deployments/` | Installers, images, Compose, PKI, and production configuration |
| `apps/console/` | Manager Console and authentication BFF |
| `configs/` | Examples loaded only through an explicit apply path |
| `test/` | Functional, Detection, Performance, Distribution, and release gates |

## Dependency Rules

- Domain depends only on its own domain and the Go standard library.
- Application depends on Domain and consumer-owned Ports, never concrete infrastructure.
- Ports define narrow needs; Adapters implement them and own wire, SQL, and document mapping.
- Bootstrap creates resources and assembles use cases; it does not implement business rules.
- Product internals never import another product's `internal/` packages.
- Commands call Bootstrap rather than constructing Adapters directly.
- Manager and Worker production persistence uses PostgreSQL; there is no memory or file Store fallback.
- Endpoint code does not read platform databases; endpoint-cloud interaction uses defined protocols.
- Browser code calls the same-origin BFF, not Manager directly.
- Protobuf is the wire-contract source of truth.
- Application white-box integration tests live under the owning `apps/*/integration/`; environment E2E stays under `test/`.

Layer-specific README files state the allowed dependencies at each boundary. Architecture contracts enforce these rules.

## Build

Common commands:

```bash
make help
make api
make build-binary
make test-unit
make web-install
make web-build
```

The backend is Go. Frontend dependencies use pnpm. Generated binaries and runtime output belong under ignored output directories such as `dist/`.

## Changing Protocols

1. Decide whether the change belongs to `schema_version`, `analysis_version`, or an OpenSearch mapping.
2. Change `packages/contracts/proto/`; never reuse reserved field numbers or names.
3. Run `make api`; do not edit generated `*.pb.go` manually.
4. Update producers, consumers, boundary validation, and contract tests together.
5. Follow the consumer-first versioning rules in the [API reference](docs/reference/api.md).

Manager HTTP changes must also update handler tests and the Console typed client.

## Changing Agent Configuration

Update all of the following together:

1. Config type, defaults, strict parsing, and validation.
2. Valid, boundary, unknown, and conflicting-value tests.
3. Packaged or example configuration.
4. The [configuration reference](docs/reference/configuration.md).

Do not add switches or abstractions without a production caller.

## Release Changes

Release candidates originate from a frozen `dev` through a short-lived `release/vX.Y.Z` branch. Stable releases require the accepted RC tree to match `main`.

```bash
make release-rc VERSION=1.0.0 RC=1
make release-stable VERSION=1.0.0 RC=1
```

These commands trigger workflows; they do not create or merge branches. GitHub Releases are the release-notes source of truth. Real eBPF collection, Detection, and Performance acceptance requires the supported VM environment and is not replaced by hosted build runners.

## Console Changes

`apps/console` is Next.js and React. Use the root commands:

```bash
make web-install
make auth-init
make deploy
make web-dev
make web-build
```

The browser must not construct Manager URLs or authorization headers.

## Verification

Choose the smallest suite that fully covers the change:

```bash
make test-unit
git diff --check
```

Run the applicable Functional, Detection, Performance, Distribution, or release gate for shared contracts and user workflows. The [testing guide](docs/development/testing.md) explains the scope and interpretation of each suite.

Before requesting review:

- keep functions below 50 lines and production files below 500 lines;
- handle external input errors explicitly;
- keep one contract in one Reference source;
- distinguish current, experimental, and target capabilities;
- document tests that could not run and the remaining risk.
