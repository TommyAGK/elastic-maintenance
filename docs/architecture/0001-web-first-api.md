# ADR 0001 — Web-first API service

- Status: Accepted
- Date: 2026-08-14
- Supersedes: CLI-first and loopback-only assumptions in the original v1 plan

## Context

The prototype is a command-line utility that directly reads one JSON desired-state file and calls one Kibana target. The required product must instead be exposed as a web-first service in Kubernetes, support authenticated operators and external automation, preserve mounted Git/YAML as the desired-state authority, and manage credentials without placing them in application state.

## Decision

### Runtime and exposure

Build one long-running Go server and embedded web UI. Production runs as a single-replica Kubernetes Deployment behind a ClusterIP Service and TLS Ingress. The binary has startup configuration/version flags but no operator reconciliation CLI.

### API and user experience

Expose a versioned `/api/v1` REST API with an OpenAPI description. The embedded UI consumes the same API as external automation clients. Validation, planning, and apply are durable asynchronous jobs.

### Authentication and authorization

Use application-level OIDC:

- Authorization Code with PKCE and protected cookies for browser users.
- Bearer-token validation for automation.
- Viewer, planner, applier, and administrator roles.
- One explicitly configured local break-glass administrator for complete IdP outages. Its canonical non-secret username is mounted in application configuration, its pinned Argon2id verifier and opaque generation are mounted from a Kubernetes Secret, and the sole recoverable high-entropy username/password pair remains in an external audited password vault. Its browser session is explicitly marked `break-glass`, expires absolutely after 15 minutes without renewal, rechecks an internal revision of the live username/verifier/generation/enabled state on every use, requires no MFA, has no bearer-token equivalent, is rate-limited and audited, and is never selected as an automatic fallback. A tested runbook provisions it offline and rotates the vault credential and verifier generation after every use.
- An actor with apply permission may apply their own plan.
- Security and operational actions produce non-secret audit events.

### Desired-state authority

Mounted Git/YAML remains authoritative and read-only. Mounted configuration defines resource sets and assigns each Kibana target to one resource set. External GitOps/orchestration may mount separate branches or revisions at separate paths. The service does not perform Git operations or edit mounted content.

### Credentials

Administrators upload a Kibana API key and optional CA trust bundle through the protected API/UI. The service creates or rotates the exact configured, application-owned Kubernetes Secret. It stores only non-secret Secret/certificate metadata on the PVC and never provides a credential read-back operation. V1 supports CA trust only, not client-certificate/mTLS authentication.

### Persistence and scaling

Persist non-secret plans, jobs, reports, inventory, journals, source snapshots, idempotency records, and audit segments as versioned JSON files on a ReadWriteOnce PVC. V1 has one replica and one writer. Multi-replica/HA operation requires a later database/queue architecture.

### Reconciliation safety

Plans are internal server-managed artifacts and cannot be uploaded or edited through the API. Apply rechecks mounted desired inputs, target Secret availability, Kibana version, inventory authority, ownership markers, and live baselines. Independent targets continue after failures; rollback and resume are not provided; a new plan is required after apply outcomes.

## Consequences

### Positive

- Operators receive a web-first workflow and automation API.
- OIDC/RBAC/audit provide the primary authorization boundary, with a narrowly bounded and independently operable emergency recovery path.
- Git branch/revision orchestration remains outside the service and can evolve independently.
- Kubernetes Secrets keep Kibana credentials out of PVC application state.
- One reconciliation and safety implementation serves browser and API clients.

### Negative and constraints

- The service becomes a persistent, externally exposed security boundary.
- OIDC, break-glass credential/session controls, ingress/proxy trust, CSRF/CORS, rate limiting, and API compatibility require first-class testing.
- Creating Kubernetes Secrets requires namespaced ServiceAccount permissions that Kubernetes RBAC cannot restrict by creation-name prefix; a dedicated namespace plus application ownership checks is required.
- JSON/PVC persistence prevents safe multi-replica operation.
- Credential upload requests contain sensitive values in server memory and must be excluded from logging, tracing, caching, and state.
- Operators must update mounted sources externally; the UI cannot fix desired-state validation errors directly.

## Rejected alternatives

- Retaining the CLI as the primary interface.
- A thin CLI API client in v1.
- Loopback-only web serving.
- Kubernetes planner/applier Jobs.
- API-managed desired resources.
- Git operations or automatic polling inside the service.
- PostgreSQL or SQLite in v1.
- Equal permissions for all authenticated users.
- Storing uploaded credentials encrypted on the PVC.
- Client-certificate/mTLS Kibana authentication in v1.

## Follow-up

Implementation phases and acceptance gates are in `plan.md`. Detailed Phase 0 work is in `docs/implementation/subplans/phase-0-contract-fixtures-and-api-server-migration-skeleton.md`.
