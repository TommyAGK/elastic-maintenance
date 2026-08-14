# Phase 5 — web-first operator experience and API hardening

## Objective

Complete the browser-first product and harden the shared API for both interactive operators and external automation.

## Prerequisites

- Phases 1–4 expose stable authenticated APIs for validation, credentials, inventory, plans, jobs, apply, reports, and audit.
- OpenAPI schemas and domain result types are versioned.

## Substeps

### 5.1 Establish a coherent embedded UI

1. Build static assets embedded in the Go binary with no runtime CDN dependency.
2. Use `/api/v1` exclusively; no UI-only reconciliation routes.
3. Provide navigation for sources, targets, credentials, validations, plans, jobs, reports, audit, and API docs.
4. Display active actor/roles/session expiry.
5. Make authoritative source/resource views visibly read-only.

### 5.2 Complete source and validation workflow

1. Show resource-set mount identity, optional branch/revision metadata, canonical digest, and assigned targets.
2. Start validation jobs and show progress/history.
3. Present source-located diagnostics and resource/DAG inventory.
4. Explain that GitOps/orchestration owns changes and refresh is explicit.
5. Never imply the UI edits branches/files.

### 5.3 Complete credential administration

1. Restrict upload/rotation/deletion UI to administrators.
2. Use password-style/API-key input and PEM CA input without retaining values after submission.
3. Show only status, rotation time/actor, Secret reference, and certificate metadata/fingerprint.
4. Require explicit confirmation for rotation/deletion.
5. Clear client form state immediately and prohibit browser storage/autocomplete where practical.
6. Render safe target-unready states.

### 5.4 Complete plan/apply workflow

1. Select targets/resource sets and start planning jobs.
2. Show plan creator/source revision/digests/versions/operations/dependencies/conflicts/observations.
3. Gate apply control by role and require explicit confirmation.
4. Follow asynchronous job progress without relying solely on SSE.
5. Show reports, partial outcomes, skipped dependencies, rejection reasons, and replan guidance.
6. Prevent plan upload/edit/resume.

### 5.5 Complete audit and automation experience

1. Add paginated/filterable audit view according to role policy.
2. Link request/job/plan/report identifiers.
3. Publish authorized interactive OpenAPI docs and downloadable schema.
4. Include bearer-token automation examples without real tokens.
5. Document idempotency, pagination, error, job polling/SSE, and rate-limit contracts.

### 5.6 Harden browser/session security

1. Complete PKCE/state/nonce/session-expiry/logout tests.
2. Enforce Secure/HttpOnly/SameSite cookies.
3. Require CSRF and same-origin validation for cookie mutations.
4. Apply strict CSP, no-sniff, frame, referrer, permissions, HSTS-at-ingress, and no-store policies.
5. Keep tokens/credentials out of local/session storage and URLs.
6. Protect login/callback against open redirects.

### 5.7 Harden reverse-proxy and API behavior

1. Trust forwarded host/proto/client IP only from configured proxy ranges.
2. Validate public URL/Host/scheme and reject spoofed forwarding headers.
3. Keep CORS disabled unless explicit allowlist configured.
4. Bound JSON, headers, SSE clients, pagination, concurrency, and job queue.
5. Add rate limits for login, credential mutation, plan, apply, and expensive reads.
6. Ensure safe consistent error envelopes and request IDs.
7. Verify OpenAPI-handler parity in CI.

### 5.8 Accessibility and resilience

1. Meet keyboard navigation, focus, labels, contrast, status announcements, and reduced-motion requirements.
2. Handle refresh/reconnect/job restart without losing durable state.
3. Provide polling fallback for SSE.
4. Handle large inventories/plans with pagination/virtualization without hiding safety details.
5. Test narrow/desktop layouts and browser failure paths.

### 5.9 Parity and security tests

1. Prove UI uses the same API/services as automation.
2. Test every role’s visible controls and server denial.
3. Test CSRF/CORS/proxy/Host/session/cache/CSP/body/rate-limit controls.
4. Test credential form clearing and no-secret browser persistence.
5. Test operator-relevant drift/ownership/dependency/partial outcomes.
6. Run browser accessibility and severe layout checks.

## Phase gate

All workflows are complete through the embedded web UI, external clients can use the same versioned documented API, authorization remains server-enforced, mounted sources remain read-only, and browser/API/proxy/security/accessibility tests pass without credential leakage.
