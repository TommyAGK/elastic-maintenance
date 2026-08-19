# Phase 2 — OIDC, Kubernetes Secrets, Kibana reads, and inventory API

## Objective

Complete production authentication/authorization, safely provision target credentials into owned Kubernetes Secrets, and expose canonical live Kibana inventory.

## Prerequisites

- Phase 1 mounted target/resource inventory is stable.
- Pinned Kibana fixtures exist for both supported versions.
- Deployment namespace and Secret prefix policy are defined.

## Current status

Substep 2.1 is implemented. Browser authentication now uses lazy, explicitly origin-pinned OIDC discovery, Authorization Code with PKCE/state/nonce, strict callback-origin and token validation, bounded redirect-free provider/JWKS HTTP, configured claim-to-role mapping, and stateless protected sessions. Session and transaction cookies are purpose-separated AES-GCM envelopes backed by a live mounted key ring; current plus at most two previous keys provide bounded rotation overlap. Existing sessions authenticate without contacting the IdP, while login/callback fail closed during provider outages. Linux reads projected Secret keys descriptor-relatively with `openat2` beneath the configured mount; the non-Linux test fallback requires an immutable administrator-controlled root. Substep 2.2 is also implemented: explicit audited emergency login, pinned Argon2id verification, bounded throttling and lockout, fixed 15-minute administrator sessions, live credential-set/session-key revocation, IdP-outage operation, UI warnings, and the mandatory provisioning/rotation runbook are complete. Bearer authentication begins in substep 2.3.

## Substeps

### 2.1 Implement browser OIDC

1. Discover/pin issuer metadata and JWKS safely.
2. Implement Authorization Code with PKCE, state, and nonce.
3. Validate issuer, audience, signature, expiry, and callback URL.
4. Store only protected HttpOnly/Secure/SameSite session cookies.
5. Store session key in a mounted Kubernetes Secret.
6. Implement login, callback, logout, session inspection, expiry, and key rotation behavior.
7. Never put tokens in browser storage or logs.

Implementation note: enabled OIDC requires an explicit `endpointOrigins` allowlist. Secret refs resolve beneath `oidc.secretMountRoot` as `<namespace>/<secret-name>/<key>`. The session-key value is a strict `elastic-maintainer-session-keyring/v1` text document with one `current <id> <base64url-32-byte-key>` line and up to two `previous` lines. Login transactions expire after 10 minutes; application sessions expire after at most eight hours or the ID token expiry, whichever is earlier. Rotating away a previous key invalidates its sessions and in-flight transactions.

### 2.2 Implement break-glass local administrator access

1. Add a distinct emergency login flow that remains functional when OIDC discovery, token exchange, and JWKS endpoints are completely unavailable.
2. Support exactly one configured local break-glass administrator. Store its non-secret canonical username in mounted application configuration and its pinned-format Argon2id verifier plus opaque credential generation in a dedicated mounted Kubernetes Secret; keep the recoverable username/password pair exclusively in an externally audited password vault. Neither Kubernetes nor application/PVC state may contain the plaintext password.
3. Do not require MFA for this account, and do not provide password creation, reset, retrieval, or management through the application API or UI.
4. Issue a visibly identified administrator session through the single application-session cookie, with authentication source `break-glass`, an internal credential-set revision, issue time, and a fixed 15-minute absolute expiry. It uses the same Secure, HttpOnly, SameSite and CSRF protections as OIDC sessions, has no rolling renewal, and never has a bearer form.
5. Keep the submitted password out of logs, errors, metrics, audit payloads, browser storage, PVC state, and process arguments; compare bounded verifier inputs in constant time where applicable.
6. Apply generic authentication errors, strict request/body limits, global and source-aware rate limits, progressive backoff, and bounded temporary lockout without revealing whether the configured username matched.
7. Extend the actor/session contract with a non-secret authentication source (`oidc`, `bearer`, or `break-glass`). Expose that source through session inspection for the emergency banner and audit distinction; reject duplicate session cookies, login/callback attempts while another identity is active, and session-plus-bearer ambiguity.
8. Derive an internal credential-set revision from the canonical username, exact verifier bytes, opaque generation, and enabled state, and recheck it against live mounted configuration/Secret state before accepting every emergency session. Any configuration, verifier, generation, enabled-state, or session-key change immediately rejects already-issued emergency sessions; the revision is never exposed or logged.
9. Add an operational provisioning and post-use rotation runbook: generate a high-entropy password with audited external tooling, store the recoverable username/password in the password vault, derive the pinned Argon2id verifier offline, atomically mount the verifier with a new opaque generation, verify access, and after every use rotate the vault entry and mounted verifier/generation so prior passwords and sessions stop working. This is operational tooling/documentation, not a product CLI or password-management API.
10. Test successful emergency access with the IdP fully unreachable, wrong-password and throttling behavior, Secret absence/malformed verifier failure, the exact actor/session source contract, 15-minute absolute expiry, invalidation after every effective configuration/verifier/generation change, ambiguous identities, CSRF/origin enforcement, audit hooks, and credential sentinel scans.

Implementation note: break-glass is an explicit local exception to OIDC, not an automatic fallback. It always maps to `administrator`, cannot authenticate automation, and must fail closed when its dedicated Secret is absent or invalid. Elastic Maintainer stores no recoverable break-glass password; only the external audited vault does.

### 2.3 Implement bearer authentication

1. Accept `Authorization: Bearer` for external API clients.
2. Validate the same issuer/audience/signature/expiry rules.
3. Reject ambiguous cookie-plus-bearer identity.
4. Map subject and claims into the common actor model.
5. Bound JWKS caching/refresh and fail closed.

### 2.4 Implement RBAC and audit hooks

1. Map configured OIDC groups/claims to viewer/planner/applier/administrator.
2. Enforce route and service-layer permissions.
3. Deny unknown/no-role users.
4. Add actor/action/result hooks for durable Phase 3 audit storage.
5. Test every endpoint/role combination.

### 2.5 Define Kubernetes Secret client boundary

1. Wrap only required namespaced Secret operations.
2. Use in-cluster configuration in production and injectable fakes in tests.
3. Enforce configured namespace and `elastic-maintainer-target-` prefix before any client call.
4. Require ownership labels/annotations for update/delete.
5. Refuse unrelated/preexisting Secrets.
6. Avoid serializing Secret objects into generic errors/logs.

### 2.6 Implement credential upload/rotation

1. Add administrator-only bounded JSON request with API key and optional PEM CA bundle.
2. Validate sizes, non-empty API key, PEM decoding, certificate parse, and CA suitability.
3. Require idempotency key and TLS public-origin checks.
4. Create/update the exact configured owned Secret.
5. Return status, resource version, rotation timestamp, and certificate fingerprint/expiry metadata—never values.
6. Mark responses `no-store` and redact request bodies globally.
7. Add deletion with in-use checks and exact ownership requirements.

### 2.7 Build target TLS/API-key clients

1. Fetch the target Secret only for an authorized server job/read.
2. Build system-plus-uploaded-CA trust roots.
3. Keep key/certificate bytes in memory only for job lifetime.
4. Send Kibana API key only in the authorization header.
5. Reject malformed/missing Secrets as target-unready without failing server liveness.
6. Zero/release buffers where practical without overstating guarantees.

### 2.8 Implement Kibana HTTP core

1. Add space-aware public paths, timeouts, limits, redirect rejection, and context cancellation.
2. Discover/enforce Kibana `>=9.2.0,<10.0.0`.
3. Classify safe remote errors.
4. Retry only narrowly classified idempotent reads.
5. Implement EPM cursor, Fleet page/perPage, and rule page/per_page pagination completely.
6. Test default/non-default spaces and every contract error fixture.

### 2.9 Implement read adapters

1. Integration installed/exact-version reads using common 9.2/9.4 endpoints.
2. Agent-policy list/read by caller ID.
3. Package-policy list/read by caller ID.
4. Custom-rule list/read by `rule_id`, preserving complete-update fields separately.
5. Collective prebuilt status.
6. Adapter-specific canonical projections and fingerprints.
7. Exclude generated drift fields without losing baseline safety data.

### 2.10 Expose credential and live inventory APIs

1. Implement credential status/upload/delete endpoints.
2. Implement target readiness/version/live inventory endpoints/jobs.
3. Require viewer for status/inventory and administrator for credential mutation.
4. Paginate resources and return typed safe errors.
5. Update OpenAPI/UI with credential-status and upload flows.
6. Ensure values cannot be retrieved after upload.

### 2.11 Security and contract tests

1. OIDC callback/session/bearer negative cases.
2. Break-glass IdP-outage, canonical username/config, pinned verifier, provisioning/rotation, throttling, actor source, absolute expiry, effective credential-set revision invalidation, ambiguity, audit, and redaction cases.
3. Full RBAC matrix.
4. CSRF/origin/cache/log redaction on credential endpoints.
5. Secret namespace/prefix/ownership/no-overwrite/delete behavior.
6. PEM/API-key malformed/oversized requests.
7. Kibana fixtures, TLS CA trust, spaces, pagination, errors, redirects, timeouts.
8. Sentinel scans across responses/logs/errors and test state.

## Phase gate

OIDC and roles fail closed; independently tested break-glass administrator access works during a complete IdP outage, exposes a distinct actor source, expires absolutely within 15 minutes, and is invalidated by any live effective credential-set change; a tested provisioning/post-use rotation runbook keeps the only recoverable break-glass username/password in the audited external vault; administrators can provision only configured owned Secrets; no credential can be read back or reach PVC/logs/audit/browser storage; and all supported live-resource kinds read canonically through public APIs.
