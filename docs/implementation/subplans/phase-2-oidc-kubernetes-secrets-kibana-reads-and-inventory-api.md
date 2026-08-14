# Phase 2 — OIDC, Kubernetes Secrets, Kibana reads, and inventory API

## Objective

Complete production authentication/authorization, safely provision target credentials into owned Kubernetes Secrets, and expose canonical live Kibana inventory.

## Prerequisites

- Phase 1 mounted target/resource inventory is stable.
- Pinned Kibana fixtures exist for both supported versions.
- Deployment namespace and Secret prefix policy are defined.

## Substeps

### 2.1 Implement browser OIDC

1. Discover/pin issuer metadata and JWKS safely.
2. Implement Authorization Code with PKCE, state, and nonce.
3. Validate issuer, audience, signature, expiry, and callback URL.
4. Store only protected HttpOnly/Secure/SameSite session cookies.
5. Store session key in a mounted Kubernetes Secret.
6. Implement login, callback, logout, session inspection, expiry, and key rotation behavior.
7. Never put tokens in browser storage or logs.

### 2.2 Implement bearer authentication

1. Accept `Authorization: Bearer` for external API clients.
2. Validate the same issuer/audience/signature/expiry rules.
3. Reject ambiguous cookie-plus-bearer identity.
4. Map subject and claims into the common actor model.
5. Bound JWKS caching/refresh and fail closed.

### 2.3 Implement RBAC and audit hooks

1. Map configured OIDC groups/claims to viewer/planner/applier/administrator.
2. Enforce route and service-layer permissions.
3. Deny unknown/no-role users.
4. Add actor/action/result hooks for durable Phase 3 audit storage.
5. Test every endpoint/role combination.

### 2.4 Define Kubernetes Secret client boundary

1. Wrap only required namespaced Secret operations.
2. Use in-cluster configuration in production and injectable fakes in tests.
3. Enforce configured namespace and `elastic-maintainer-target-` prefix before any client call.
4. Require ownership labels/annotations for update/delete.
5. Refuse unrelated/preexisting Secrets.
6. Avoid serializing Secret objects into generic errors/logs.

### 2.5 Implement credential upload/rotation

1. Add administrator-only bounded JSON request with API key and optional PEM CA bundle.
2. Validate sizes, non-empty API key, PEM decoding, certificate parse, and CA suitability.
3. Require idempotency key and TLS public-origin checks.
4. Create/update the exact configured owned Secret.
5. Return status, resource version, rotation timestamp, and certificate fingerprint/expiry metadata—never values.
6. Mark responses `no-store` and redact request bodies globally.
7. Add deletion with in-use checks and exact ownership requirements.

### 2.6 Build target TLS/API-key clients

1. Fetch the target Secret only for an authorized server job/read.
2. Build system-plus-uploaded-CA trust roots.
3. Keep key/certificate bytes in memory only for job lifetime.
4. Send Kibana API key only in the authorization header.
5. Reject malformed/missing Secrets as target-unready without failing server liveness.
6. Zero/release buffers where practical without overstating guarantees.

### 2.7 Implement Kibana HTTP core

1. Add space-aware public paths, timeouts, limits, redirect rejection, and context cancellation.
2. Discover/enforce Kibana `>=9.2.0,<10.0.0`.
3. Classify safe remote errors.
4. Retry only narrowly classified idempotent reads.
5. Implement EPM cursor, Fleet page/perPage, and rule page/per_page pagination completely.
6. Test default/non-default spaces and every contract error fixture.

### 2.8 Implement read adapters

1. Integration installed/exact-version reads using common 9.2/9.4 endpoints.
2. Agent-policy list/read by caller ID.
3. Package-policy list/read by caller ID.
4. Custom-rule list/read by `rule_id`, preserving complete-update fields separately.
5. Collective prebuilt status.
6. Adapter-specific canonical projections and fingerprints.
7. Exclude generated drift fields without losing baseline safety data.

### 2.9 Expose credential and live inventory APIs

1. Implement credential status/upload/delete endpoints.
2. Implement target readiness/version/live inventory endpoints/jobs.
3. Require viewer for status/inventory and administrator for credential mutation.
4. Paginate resources and return typed safe errors.
5. Update OpenAPI/UI with credential-status and upload flows.
6. Ensure values cannot be retrieved after upload.

### 2.10 Security and contract tests

1. OIDC callback/session/bearer negative cases.
2. Full RBAC matrix.
3. CSRF/origin/cache/log redaction on credential endpoints.
4. Secret namespace/prefix/ownership/no-overwrite/delete behavior.
5. PEM/API-key malformed/oversized requests.
6. Kibana fixtures, TLS CA trust, spaces, pagination, errors, redirects, timeouts.
7. Sentinel scans across responses/logs/errors and test state.

## Phase gate

OIDC and roles fail closed; administrators can provision only configured owned Secrets; no credential can be read back or reach PVC/logs/audit/browser storage; and all supported live-resource kinds read canonically through public APIs.
