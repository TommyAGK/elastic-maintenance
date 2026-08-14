# Phase 2 — API client and read adapters

## Objective

Implement safe, version-aware, space-aware Kibana reads and canonical live-resource projections for every supported kind.

## Prerequisites

- Phase 1 gate passes.
- Pinned contract manifests and fixtures exist for both supported versions.
- Target configuration can produce normalized URL, space, CA, and API-key environment references.

## Substeps

### 2.1 Build the HTTP client boundary

1. Define an injectable HTTP transport/client interface.
2. Construct TLS roots from system roots plus optional target CA contents.
3. Set bounded connect, TLS, header, request, and idle timeouts.
4. Limit response sizes and always close bodies.
5. Reject redirects that could carry authorization to another host.
6. Add `Authorization: ApiKey` and required `kbn-xsrf` headers without logging them.
7. Build default and `/s/{space}` paths with correct escaping.

### 2.2 Discover and enforce compatibility

1. Read Kibana status/version through a documented stable endpoint.
2. Parse stable release versions strictly.
3. Accept `>=9.2.0,<10.0.0`; reject snapshots/prereleases unless explicitly supported later.
4. Cache version only within one operation context.
5. Return typed unsupported-version errors before mutable-resource reads.
6. Include target and discovered version in safe diagnostics.

### 2.3 Classify remote errors

1. Model authentication, authorization, validation, not-found, conflict, throttling, timeout, unsupported-version, malformed-response, and remote-failure categories.
2. Bound and sanitize response excerpts.
3. Preserve status code and request ID where safe.
4. Retry only idempotent reads for narrowly classified transient failures.
5. Use bounded exponential backoff with context cancellation.
6. Never automatically retry mutations.

### 2.4 Implement pagination primitives

1. Implement EPM `searchAfter` cursor pagination.
2. Implement Fleet `page`/`perPage` pagination.
3. Implement detection `_find` `page`/`per_page` request and `perPage` response handling.
4. Detect repeated cursors/pages, inconsistent totals, empty nonterminal pages, and configured safety limits.
5. Preserve deterministic result ordering after complete retrieval.
6. Test every boundary using two-page and malformed fixtures.

### 2.5 Implement integration-package reads

1. List installed packages through the common 9.2/9.4 endpoint.
2. Read exact-version detail where needed.
3. Project package name, version, and installed status only.
4. Distinguish missing, installed desired, older, newer, and malformed versions.
5. Do not use the 9.4-only unversioned package endpoint.

### 2.6 Implement agent-policy reads

1. List all policies with pagination.
2. Read by caller-defined ID.
3. Project managed fields, stable ID, description marker, and fields needed for update safety.
4. Exclude revisions, timestamps, users, counts, and unrelated server additions from desired drift.
5. Retain revision/baseline fields separately when required for conflict detection.

### 2.7 Implement package-policy reads

1. List and read by caller-defined ID.
2. Project stable identity, package/version, policy assignments, namespace, description marker, enabled state, inputs, and managed variables.
3. Normalize semantically unordered policy assignments and variable maps.
4. Preserve meaningful input/stream ordering where required by the API.
5. Keep generated and unrelated fields outside the canonical desired comparison.

### 2.8 Implement custom detection-rule reads

1. Read by `rule_id` and list with complete pagination.
2. Parse supported custom rule variants through typed projections.
3. Preserve all fields required to construct a complete replacement update.
4. Separate custom (`immutable=false`) from prebuilt/immutable rules.
5. Normalize tags and other semantic sets.
6. Exclude revision, timestamps, execution summaries, and generated IDs from desired drift while retaining baseline safety data.

### 2.9 Implement collective prebuilt status

1. Read the prepackaged status endpoint.
2. Project only documented installed/not-installed/not-updated counts.
3. Treat the result as one collective resource.
4. Do not enumerate individual prebuilt rules for reconciliation.

### 2.10 Add contract and redaction tests

1. Run every adapter against versioned `httptest` fixtures.
2. Assert default/non-default space paths and escaping.
3. Assert auth/XSRF headers server-side without printing values.
4. Cover pagination, status classes, malformed/oversized bodies, redirects, timeouts, and cancellation.
5. Scan logs/errors for sentinel credentials.

## Verification

```bash
go test ./internal/kibana/... -count=1
go test -race ./internal/kibana/...
go vet ./...
```

Run read-only live smoke tests against 9.2.0 and the selected current 9.x patch when environments are available.

## Phase gate

Every supported resource can be read completely through documented public APIs in default and non-default spaces, canonical projections are deterministic, version enforcement works, and no single-page or secret-redaction assumption remains untested.
