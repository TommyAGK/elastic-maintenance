# Phase 5 — web interface

## Objective

Provide a loopback-only operator interface over the exact same validation, planning, state, and apply services used by the CLI.

## Prerequisites

- Phase 4 gate passes.
- Shared application services have no CLI-specific output or process-exit dependencies.
- Plans and apply reports have stable versioned schemas.

## Substeps

### 5.1 Extract shared application services

1. Define request/result boundaries for validate, inventory, plan, saved-plan read, apply, and report read.
2. Keep reconciliation and safety decisions below both CLI and HTTP layers.
3. Use contexts for cancellation and deadlines.
4. Return typed safe errors suitable for CLI and web mapping.
5. Add parity tests proving both interfaces receive equivalent results.

### 5.2 Define the loopback HTTP API

1. Version API routes.
2. Add read-only routes for health, validation, targets/resources, saved plans, plan details, and reports.
3. Add JSON mutation routes for plan generation and apply initiation.
4. Keep GET/HEAD routes side-effect free.
5. Define stable status-code/error envelopes.
6. Bound request bodies and reject unknown JSON fields.

### 5.3 Enforce listener and host safety

1. Parse and resolve the configured listener before binding.
2. Accept only literal loopback addresses; reject wildcard and non-loopback binds.
3. Build an allowlist of expected Host values for the bound address/port.
4. Reject malformed or unexpected Host headers before routing.
5. Do not add Service/Ingress assumptions.
6. Test IPv4, IPv6, localhost, wildcard, and DNS-rebinding cases.

### 5.4 Enforce browser mutation safety

1. Require `application/json` for mutations.
2. Validate same-origin `Origin` when present.
3. Enforce compatible Fetch Metadata headers.
4. Generate a per-process CSRF token and require it on mutations.
5. Set restrictive CSP, no-sniff, frame, referrer, and no-store headers.
6. Avoid inline scripts/styles unless covered by explicit nonces/hashes.
7. Ensure credentials and unrestricted environment data never enter responses.

### 5.5 Serialize mutation jobs

1. Permit only one plan/apply mutation per state directory.
2. Return visible conflict/busy responses rather than queueing invisibly.
3. Expose job state and final report safely.
4. Propagate cancellation where it cannot leave state ambiguous.
5. Rely on existing target locks as the final cross-process guard.

### 5.6 Build the embedded operator UI

1. Use embedded static assets with no runtime CDN dependency.
2. Show validation diagnostics and source locations.
3. Show target/resource inventory and selection.
4. Show saved-plan operations, observations, dependencies, ownership conflicts, and drift.
5. Require explicit confirmation before apply.
6. Show per-target outcomes, skipped dependencies, rejection reasons, and new-plan guidance.
7. Never display API keys, raw environment data, or unsafe remote bodies.

### 5.7 Connect `serve`

1. Replace the placeholder command with config/manifests/plans/state initialization.
2. Validate loopback listener before any remote access.
3. Resolve API keys only inside shared operations that need them.
4. Start `http.Server` with bounded header/read/write/idle settings.
5. Handle shutdown and in-flight work without claiming daemon semantics.
6. Log the exact loopback URL and safe runtime mode.

### 5.8 Test API, browser security, and parity

1. Test every route and method.
2. Test Host, Origin, Fetch Metadata, content type, CSRF, body limits, and headers.
3. Test mutation serialization and state-lock conflicts.
4. Test plans/reports with partial failures and ownership conflicts.
5. Test that web and CLI summaries derive from identical domain results.
6. Scan HTML, JSON, logs, and errors for sentinel secrets.
7. Run browser-level tests for primary workflows and severe layout/accessibility failures.

## Verification

```bash
go test ./internal/web/... -count=1
go test -race ./internal/web/...
go test ./... -count=1
go vet ./...
```

Manually exercise the loopback UI against fixtures or an explicitly approved disposable stack.

## Phase gate

Every operator-relevant CLI outcome has equivalent web visibility, all mutations use shared safety services, loopback/browser protections pass, mutation concurrency is controlled, and no credential or internal-only data reaches the browser.
