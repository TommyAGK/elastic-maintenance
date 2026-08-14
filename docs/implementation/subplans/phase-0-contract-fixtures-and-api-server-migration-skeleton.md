# Phase 0 — contract fixtures and API-server migration skeleton

## Objective

Preserve the verified Kibana contract baseline while replacing the prototype CLI foundation with a side-effect-free web/API server skeleton.

## Existing evidence

- `docs/implementation/phase-0-baseline.md`
- `docs/kibana-api-contracts.md`
- `testdata/contracts/kibana/v9.2.0/`
- `testdata/contracts/kibana/v9.4.2/`
- `docs/implementation/phase-0-retirement-inventory.md`

## Substeps

### 0.1 Record the architecture pivot

1. Remove CLI-first, loopback-only, Job-based, and no-daemon assumptions from active documentation.
2. Record the selected single-replica API architecture, OIDC, PVC JSON state, RBAC, mounted-source authority, and Kubernetes Secret upload model.
3. Keep the previous commits as fallback evidence; do not rewrite history.
4. Mark the old prototype and any Cobra work as superseded rather than partially integrating it.

### 0.2 Preserve and validate Kibana contracts

1. Keep pinned 9.2.0/9.4.2 source URLs and hashes.
2. Validate successful JSON fixtures against their pinned OpenAPI response schemas.
3. Retain the 9.2-compatible installed-package endpoint correction.
4. Keep missing privilege claims as live-matrix gaps.
5. Scan fixtures for credential-like values.

### 0.3 Define server startup configuration

1. Create strict startup types for config path, listen address, state directory, public URL, trusted proxy settings, OIDC metadata, role mappings, Kubernetes Secret policy, and mount roots.
2. Define environment overrides suitable for Kubernetes without accepting target credentials.
3. Add development defaults only where safe.
4. Add `--version`; do not add operator subcommands.
5. Validate startup configuration before opening the listener.

### 0.4 Create the server entry point

1. Replace `cmd/elastic-maintenance` with `cmd/elastic-maintainer`.
2. Keep `main.go` as wiring for build metadata, signal context, startup config, and server lifecycle.
3. Implement graceful shutdown with bounded timeout.
4. Return deterministic process errors without logging configuration/secret bodies.
5. Add development and linker-injected version output.

### 0.5 Build HTTP server and routing skeleton

1. Use `net/http` with explicit middleware ordering and dependency injection.
2. Add `/health/live`, `/health/ready`, `/api/v1/openapi.json`, auth route placeholders, and protected `/api/v1` route groups.
3. Configure read/header/write/idle timeouts and body limits.
4. Add request IDs, safe structured access logs, panic recovery, and JSON error envelopes.
5. Keep health probes narrow and side-effect free.
6. Do not contact Kibana, Kubernetes, OIDC, mounted sources, or PVC state yet.

### 0.6 Define auth/RBAC interfaces

1. Define actor, session, token validator, role, permission, and authorization interfaces.
2. Define viewer/planner/applier/administrator permissions centrally.
3. Add a test-only authenticator; production OIDC lands in Phase 2.
4. Deny protected routes by default.
5. Define audit-event inputs without implementing durable audit storage yet.

### 0.7 Define asynchronous job contracts

1. Define validation, plan, and apply job types/statuses.
2. Define enqueue/read/list/cancel-capability interfaces without execution.
3. Define idempotency-key and request/response contracts.
4. Return honest not-implemented responses for unfinished mutation endpoints.
5. Keep job IDs and timestamps injectable/deterministic in tests.

### 0.8 Publish an initial OpenAPI contract

1. Describe health, session, sources, targets, credentials, validations, plans, jobs, reports, and audit routes.
2. Mark unfinished operations clearly.
3. Define versioned error/job/actor schemas.
4. Test path/method registration against the OpenAPI document.
5. Exclude secret values from every response schema and example.

### 0.9 Normalize module/build tooling

1. Normalize the module path and retained imports.
2. Pin server/OIDC/OpenAPI dependencies only when selected and needed.
3. Add build, test, vet, clean, and version targets.
4. Build `bin/elastic-maintainer` directly as the server.
5. Update README with the architecture pivot and unfinished status.

### 0.10 Retire stale executable behavior

1. Remove the old review/apply command and JSON CLI flags after the server builds/tests.
2. Keep old internal packages only until replacements own their behavior.
3. Inventory Docker/Kubernetes/README references for later phases.
4. Keep `start-web.sh` untracked until its server dependencies exist.

## Verification

```bash
go test ./... -count=1
go test -race ./internal/server/... ./internal/api/... ./internal/auth/...
go vet ./...
make build
bin/elastic-maintainer --version
bin/elastic-maintainer --config testdata/server-minimal.yaml
git diff --check
```

Use an in-memory/test listener for endpoint tests. The skeleton must not create state, call Kubernetes, resolve OIDC, or contact Kibana.

## Phase gate

The binary starts a safe API skeleton, health/readiness/OpenAPI/authz boundaries test, public Kibana fixtures remain valid, the old operator CLI is gone, and unfinished domain endpoints are explicit and side-effect free.

## Completion evidence

The Phase 0 gate passed on the implementation branch with full tests, server/API/auth race tests, vet, linker-injected build/version verification, all 62 Kibana contract fixtures, production dependency checks, graceful local startup/shutdown, health/readiness/OpenAPI/authentication smoke checks, no state-directory creation, and stale executable/delivery artifact checks.
