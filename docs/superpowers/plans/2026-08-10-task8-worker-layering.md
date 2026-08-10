# Task 8 Worker Layering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use test-driven development to implement each slice and verify it before continuing.

**Goal:** Move the production Manager worker from `internal/ingest` into layered application, ports, adapters, and bootstrap boundaries without changing claim, retry, projection, or DLQ behavior.

**Architecture:** The application worker owns raw-batch validation, processing retries, and terminal/permanent failure decisions. Ports describe Kafka messages, batch processing, telemetry claims, projection, and history/rarity reads. Inbound Kafka and outbound PostgreSQL/OpenSearch adapters implement those contracts; `cmd/sysarmor-worker` only composes them.

**Tech Stack:** Go, `database/sql`, `segmentio/kafka-go`, existing OpenSearch HTTP client, protobuf JSON contracts, PostgreSQL.

## Global Constraints

- Application imports only domain, ports, application packages, and allowed standard library packages.
- Adapters may depend on technical libraries and contracts but must not wrap `internal/ingest` or `internal/store` as runtime services.
- Preserve telemetry claim idempotency, three processing attempts, permanent failure DLQ behavior, and Kafka commit ordering.
- Keep functions under 50 lines and non-generated files under 500 lines.

### Task 1: Worker Application Contract

Create failing tests for message validation, schema rejection, retry count, permanent failure DLQ, and commit-after-process ordering. Add `ports.RawMessage`, `ports.RawConsumer`, `ports.RawProducer`, and `ports.BatchProcessor`; implement `application/worker.Run` with context cancellation and explicit errors.

### Task 2: Persistence and Projection Adapters

Add outbound ports for telemetry claim/commit/abandon, event projection, history, and rarity. Implement direct PostgreSQL/OpenSearch adapters using existing SQL/HTTP behavior. Move processor behavior behind application services and add SQLite/fake adapter tests for tenant identity and duplicate claims.

### Task 3: Worker Bootstrap

Add `bootstrap.NewWorker`, compose Kafka readers/writers, PostgreSQL store adapters, and OpenSearch projector. Update `cmd/sysarmor-worker/main.go` to use only bootstrap and ports. Preserve flags, retry configuration, signal shutdown, and resource cleanup.

### Task 4: Legacy Removal and Gates

Migrate remaining tests to layered packages, remove `internal/ingest`, update architecture and layout contracts, scan for legacy imports, then run formatting, vet, full tests, race, and contract tests.
