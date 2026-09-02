# elastic-maintainer v1 web-first API plan

## 1. Decision record

This plan supersedes the earlier CLI-first design.

- Build a long-running, web-first API service with an embedded browser UI.
- Deploy production as a single-replica Kubernetes Deployment exposed through a TLS Ingress.
- Remove the operator CLI. The binary starts the server directly and accepts only startup configuration/version flags.
- Authenticate users and automation clients with application-level OIDC.
- Authorize viewer, planner, applier, and administrator roles. A planner who also has apply permission may approve and apply their own plan.
- Publish a versioned REST API and OpenAPI description for the embedded UI and external automation.
- Persist non-secret application state as versioned JSON files on a PVC. V1 is deliberately single-replica and has no database.
- Keep mounted Git/YAML files as the desired-state source of truth. The API/UI never edits authoritative resources.
- Assign each Kibana target to one mounted resource set. External GitOps/orchestration may mount different branches or revisions as separate resource sets.
- Let administrators upload Kibana API keys and CA trust certificates through the protected API/UI. The server writes them to owned Kubernetes Secrets and never stores them on the PVC.
- Support CA trust certificates only in v1; do not support client-certificate/mTLS authentication to Kibana.
- Keep Docker packaging for production and `start-web.sh` for local testing only.
- After partial apply, require a new plan explicitly. Plans are not resumable.
- Plans are trusted server-managed artifacts and are not signed. Clients cannot upload or edit plan files.
- Preserve the existing Git remote and history. Do not push, publish, deploy, or merge without explicit approval.

## 2. Product goal and workflow

Build a Go service that reconciles mounted, Git-defined Elastic configuration against multiple Kibana 9.x targets and spaces through a web-first operator workflow.

1. An external orchestrator mounts one or more read-only resource sets, optionally from separate Git branches/revisions.
2. Mounted server configuration assigns each named Kibana target to exactly one resource set and one Kubernetes Secret name.
3. An administrator uploads or rotates the target API key and optional CA certificate. The service stores them in an owned Kubernetes Secret.
4. The service validates mounted inputs and displays target/resource inventory.
5. A planner requests an asynchronous plan through the API/UI.
6. The service snapshots desired inputs, reads Kibana, and saves a reviewable non-secret plan on the PVC.
7. An applier reviews and applies that saved plan through the API/UI.
8. Before mutation, the service rechecks mounted desired inputs, credentials, version, inventory authority, and live baselines.
9. Targets execute independently; reports preserve partial success without rollback.
10. Any partial/rejected apply requires an explicit new plan.

## 3. Scope and non-goals

### In scope

- Kibana stable releases `>=9.2.0,<10.0.0`.
- Multiple targets, spaces, mounted resource sets, and branch/revision separation managed outside the service.
- Integration packages, Fleet agent policies, Fleet package policies, custom detection rules, and collective Elastic prebuilt rules.
- OIDC browser login and OAuth2/OIDC bearer-token API access.
- Role-based authorization and durable audit events.
- API-driven validation, inventory, planning, apply, reports, target credential upload/rotation, and credential status.
- Embedded web UI over the same versioned API exposed to automation clients.
- Kubernetes Secret storage for Kibana API keys and CA trust bundles.
- JSON/PVC storage for plans, reports, inventory, jobs, source snapshots, and audit records.
- Production Docker image, Kubernetes Deployment/Service/Ingress/PVC/RBAC examples, and local Docker test tooling.

### Out of scope

- An operator reconciliation CLI or Kubernetes planner/applier Jobs.
- Editing target configuration or desired resources through the API/UI.
- Git clone, fetch, checkout, polling, webhooks, commits, or branch orchestration by the service.
- Multiple server replicas, HA, leader election, or a database in v1.
- Elastic 8.x or 10.x.
- Internal or undocumented Kibana endpoints.
- Automatic reconciliation, scheduled apply, rollback, cross-target transactions, or plan resume.
- Individual installation/update/pruning of prebuilt rules.
- Uploading plans or application state through the API.
- Storing Kibana credentials or certificate contents on the PVC, in plans/reports/logs, or in browser storage.
- Client-certificate/mTLS authentication to Kibana.
- Protection against a malicious cluster administrator, container runtime, or process with equivalent pod/Secret/PVC access.

## 4. Runtime architecture

### Components

- `cmd/elastic-maintainer`: server entry point.
- `internal/server`: HTTP server, routing, middleware, lifecycle, and health/readiness.
- `internal/auth`: OIDC login/callback/session handling, bearer-token validation, role mapping, and authorization.
- `internal/api`: `/api/v1` handlers, request/response types, OpenAPI contract, and safe errors.
- `internal/config`: strict mounted server/target/resource-set configuration.
- `internal/manifest`: strict resource envelopes, schemas, selectors, references, source snapshots, and digests.
- `internal/secrets`: Kubernetes Secret provisioning and retrieval through a narrow interface.
- `internal/kibana`: version-aware public API client and adapters.
- `internal/reconcile`: inventory, ownership, diff, DAG, plan, and apply logic.
- `internal/state`: PVC file formats, locking, atomic writes, journals, jobs, reports, and audit storage.
- `internal/web`: embedded UI assets consuming `/api/v1` only.

### Process model

- One long-running process and one Kubernetes replica.
- The server reads mounted configuration at startup and revalidates it before validation/plan operations.
- Source content is never edited. No filesystem watcher or automatic polling is required; operators explicitly request refresh/validation/plan.
- Validation, plan, and apply run as durable asynchronous jobs.
- At most one mutation job runs per state directory. Target locks remain the final operation guard.
- Read-only API requests may run concurrently within configured limits.

### Startup interface

```text
elastic-maintainer --config <server.yaml> [--listen <address>] [--state-dir <dir>] [--version]
```

- Defaults may come from environment variables suitable for Kubernetes.
- There are no `validate`, `plan`, `apply`, or `serve` subcommands.
- `--version` prints build identity and exits.
- Production listen defaults to `:8080`; exposure and TLS are controlled by Kubernetes Service/Ingress.
- Local testing may bind loopback directly.

## 5. Mounted configuration and branch-separated resource sets

Use strict mounted YAML:

```yaml
apiVersion: elastic-maintainer/v1alpha1
stateID: security-platform
publicURL: https://elastic-maintainer.example.test

resourceSets:
  production:
    path: /var/lib/elastic-maintainer/sources/production
    revisionFile: .source-revision
  staging:
    path: /var/lib/elastic-maintainer/sources/staging
    revisionFile: .source-revision

targets:
  production-default:
    url: https://kibana.example.test
    space: default
    labels:
      environment: production
    resourceSet: production
    credentialSecret:
      namespace: elastic-maintainer
      name: elastic-maintainer-target-production-default
```

Rules:

- Mounted configuration and resource sets are authoritative and read-only to the application.
- Each target references exactly one resource set. Multiple targets may share one set.
- Different Git branches/revisions are mounted as distinct paths by GitOps, CSI, init-container, or other external orchestration.
- `revisionFile` is optional display/provenance metadata. Eligibility is based on canonical content digest, not a claimed branch name/revision alone.
- A changed mount is detected on explicit validation/plan and before apply through source digests.
- `stateID` is required and stable.
- Target identity is `(stateID, target name, normalized URL, space)`.
- Renaming a target or changing URL/space creates a new identity and never transfers pruning authority automatically.
- Reject unknown fields, duplicate YAML keys, duplicate names, invalid URLs/labels, missing resource sets, unsafe paths, and unapproved Secret namespace/name patterns.
- Require HTTPS for Kibana except explicit loopback development targets.
- The API never changes this file or the mounted resource content.

## 6. Manifest format and identity

Read `.yaml` and `.yml` recursively in lexical relative-path order. Reject symlinks, traversal, special files, duplicate keys, unknown envelope fields, empty documents, and unsupported versions/kinds. Files may contain multiple YAML documents.

```yaml
apiVersion: elastic-maintainer/v1alpha1
kind: AgentPolicy
metadata:
  id: endpoint-agents
  name: Endpoint agents
  targetSelector:
    matchLabels:
      environment: production
  dependsOn: []
spec: {}
```

- `metadata.id` is required and stable.
- `(kind, metadata.id)` is unique within a resource set.
- `metadata.name` is display text, not identity.
- `targetSelector.matchLabels` is an exact-match conjunction evaluated against targets assigned to that resource set.
- An explicit selector that currently matches no assigned target is retained as a dormant resource rather than treated as invalid.
- `dependsOn` uses `<Kind>/<metadata.id>`.
- Reject dangling, cross-selector, self, duplicate, and cyclic references across the complete resource set, including dormant resources.
- Dependency edges are recorded as dependent-to-prerequisite; per-target DAG nodes are emitted in deterministic prerequisite-first order.
- `PackagePolicy.spec.agentPolicyRef` and `.integrationRef` resolve logical desired IDs and add automatic dependency edges.
- Strict kind schemas reject unknown fields and credential-bearing fields.

The `v1alpha1` kind schemas are intentionally narrow:

| Kind | Supported `spec` fields |
| --- | --- |
| `IntegrationPackage` | required `name` and exact SemVer `version` |
| `AgentPolicy` | optional `namespace`, defaulting to `default` |
| `PackagePolicy` | required `integrationRef` and `agentPolicyRef`; optional `namespace`, defaulting to `default` |
| `DetectionRule` | required `type: query`, `enabled`, `query`, `severity`, `interval`, `language`, and non-empty `index` |
| `PrebuiltRules` | empty object, meaning reconcile the collective prebuilt-rules operation |

Package-policy input variables, rule actions/exceptions, non-query rule variants, descriptions supplied by sources, Kibana response fields, and arbitrary payload passthrough are unsupported until explicitly designed. Managed descriptions and tags are generated by adapters rather than accepted from mounted sources.

Stable remote mapping:

| Kind | Stable identity |
| --- | --- |
| `IntegrationPackage` | `metadata.id`; `spec.name` is unique per target |
| `AgentPolicy` | `metadata.id`, sent as Fleet caller-defined `id` |
| `PackagePolicy` | `metadata.id`, sent as Fleet caller-defined `id` |
| `DetectionRule` | `metadata.id`, sent as `rule_id` |
| `PrebuiltRules` | `metadata.id`; at most one applies to a target |

Source snapshots are metadata-only. Versioned RFC 8785/SHA-256 desired digests cover canonical typed resources; target digests additionally cover only normalized assigned target configuration and applicable resources. Credential Secret references, unrelated targets/resource sets, source paths, raw formatting hashes, and external revision text are excluded. Raw file hashes and revision values remain provenance for diagnostics, so formatting-only or revision-only changes do not alter desired digests. Any canonical projection change requires a new digest version, and snapshots never become a writable replacement for mounted authority.

## 7. Authentication, sessions, and authorization

### OIDC

- Use Authorization Code flow with PKCE for browser login.
- Validate issuer, audience/client ID, signature, expiry, nonce, and state.
- Use secure, HttpOnly, SameSite cookies protected by a Kubernetes Secret-backed session key.
- Do not store access/ID tokens in browser local/session storage.
- Validate external automation bearer tokens against the same configured issuer and audience.
- Provide one explicitly configured local break-glass administrator that remains usable during a complete IdP outage. Store the canonical non-secret username in mounted configuration and only a pinned Argon2id verifier plus opaque generation in a mounted Kubernetes Secret; keep the sole recoverable high-entropy username/password pair in an external audited password vault. Its browser session is marked `break-glass`, expires absolutely after 15 minutes without renewal, rechecks an internal revision of the live username/verifier/generation/enabled state on every use, has no MFA requirement or bearer-token form, is rate-limited and audited, and is never an automatic fallback. A tested runbook provisions the verifier offline and rotates both vault credential and verifier generation after every use.
- Disable arbitrary CORS by default; use a strict configured origin allowlist only when external browser origins are required.

### Roles

| Role | Capabilities |
| --- | --- |
| `viewer` | View validation, source/target inventory, credential status (never values), plans, jobs, reports, and audit events permitted by policy |
| `planner` | Viewer capabilities plus request validation/refresh and generate plans |
| `applier` | Viewer capabilities plus approve/apply saved plans; may apply own plan |
| `administrator` | All capabilities plus upload/rotate/delete target credentials and manage operational settings allowed by mounted configuration |

- Map OIDC groups/claims to roles through mounted configuration.
- Deny by default and enforce authorization in middleware plus service-layer checks.
- Record actor subject, roles, request ID, action, target/plan/job IDs, result, and timestamp in audit events.
- Never place tokens, API keys, certificates, or sensitive request bodies in audit records.

## 8. Kubernetes Secret provisioning

### Credential API

Administrators may upload:

- one Kibana API key; and
- an optional PEM CA trust bundle.

The server writes an `Opaque` Secret at the exact namespace/name declared for the mounted target:

- `api-key`: Kibana API-key value;
- `ca.crt`: optional CA bundle.

### Safety model

- Require TLS on the public ingress before enabling credential upload.
- Accept credentials only in bounded JSON requests; never via query strings, headers used for logging, or multipart temporary files.
- Mark credential responses and endpoints `Cache-Control: no-store`.
- Never echo values after submission.
- Redact request bodies from access/error/audit logs and tracing.
- Validate API key non-empty/size and parse PEM CA certificates before writing.
- The server never writes credential contents to PVC state.
- Store only Secret namespace/name, resource version, last-rotated timestamp, actor, and non-secret certificate metadata/fingerprint.
- Read credentials from the Kubernetes API only when validating/planning/applying the target; keep them in memory for the request/job lifetime.
- Never send API keys or CA contents to the browser after upload.
- Restrict Secret operations to the deployment namespace and configured `elastic-maintainer-target-` name prefix.
- Require exact application ownership labels/annotations before update/delete.
- Refuse to overwrite or delete unrelated Secrets.
- Use a dedicated namespace because Kubernetes RBAC cannot enforce the application’s name-prefix ownership policy for Secret creation by itself.
- Grant the ServiceAccount only required Secret get/create/update/patch/delete verbs in that namespace plus no unrelated cluster permissions.
- Deleting a credential Secret is blocked while a mutation job uses it and leaves target configuration intact but target status unready.
- CA support is trust-bundle only; no client private key/certificate fields exist in v1.

## 9. Versioned API and job model

Base path: `/api/v1`. Publish `/api/v1/openapi.json` and render API documentation for authorized users.

### Core endpoints

- `GET /health/live` and `GET /health/ready`: narrow unauthenticated probes.
- `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`.
- `GET /api/v1/session`.
- `GET /api/v1/sources` and `GET /api/v1/sources/{id}`.
- `POST /api/v1/validations`; `GET /api/v1/validations/{jobID}`.
- `GET /api/v1/targets` and `GET /api/v1/targets/{id}`.
- `PUT /api/v1/targets/{id}/credentials`; `DELETE /api/v1/targets/{id}/credentials`; `GET .../credential-status`.
- `POST /api/v1/plans`; `GET /api/v1/plans`; `GET /api/v1/plans/{id}`.
- `POST /api/v1/plans/{id}/apply`.
- `GET /api/v1/jobs`; `GET /api/v1/jobs/{id}`; optional `GET /api/v1/jobs/{id}/events` using SSE.
- `GET /api/v1/reports`; `GET /api/v1/reports/{id}`.
- `GET /api/v1/audit` for authorized roles.

### API rules

- JSON request/response bodies only, except SSE and static UI assets.
- Strict decoding, unknown-field rejection, bounded bodies, pagination, request IDs, and versioned safe error envelopes.
- Idempotency keys are required for credential upload/rotation, plan creation, and apply initiation.
- Cookie-authenticated mutations require CSRF tokens and same-origin checks. Valid bearer-token clients do not use cookies and are not subject to CSRF, but remain subject to CORS and authorization.
- GET/HEAD routes are side-effect free.
- Plan/apply endpoints enqueue durable jobs and return `202 Accepted` with job IDs.
- Clients poll jobs or use bounded authenticated SSE; job execution does not depend on a connected browser.
- The OpenAPI document is tested against handlers and published examples.

## 10. Resource adapters and public Kibana APIs

### IntegrationPackage

- Require exact pinned semantic versions; reject `latest` and ranges.
- Read through common endpoints:
  - `GET /api/fleet/epm/packages/installed`
  - `GET /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
- Install with `POST /api/fleet/epm/packages/{pkgName}/{pkgVersion}`.
- Do not depend on unversioned package GET absent from 9.2.0.
- Never uninstall or automatically downgrade.

### AgentPolicy

- Use public Fleet agent-policy read/create/update/delete APIs.
- Use caller-defined ID.
- Reconcile `[managed-by:elastic-maintainer]` in description.
- Prune only with inventory plus matching marker.

### PackagePolicy

- Resolve desired integration/agent references.
- Use caller-defined ID and public Fleet package-policy APIs.
- Reconcile the managed description marker.
- Prune only with inventory plus matching marker.

### DetectionRule

- Manage custom rules only through public detection-rule APIs.
- Use `rule_id` and `elastic-maintainer:managed` tag.
- Build complete replacement PUT bodies.
- Reject immutable/prebuilt collisions.
- Prune only with inventory plus matching marker.

### PrebuiltRules

- Read `GET /api/detection_engine/rules/prepackaged/_status`.
- Install/update collectively with `PUT /api/detection_engine/rules/prepackaged`.
- Never mutate or prune individual prebuilt rules.

References:

- EPM: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-elastic-package-manager-epm
- Agent policies: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-elastic-agent-policies
- Package policies: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-fleet-package-policies
- Detection/prebuilt rules: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-security-detections-api

## 11. Kibana client and canonicalization

- Discover Kibana version before planning and recheck before apply.
- Build per-target TLS clients from system roots plus uploaded CA Secret contents.
- Use bounded timeouts, response limits, context cancellation, and cross-host redirect rejection.
- Send credentials only in `Authorization: ApiKey`.
- Implement all documented pagination styles completely.
- Classify authentication, authorization, compatibility, validation, conflict, not-found, throttling, timeout, and remote errors safely.
- Retry only idempotent reads for narrowly classified transient failures. Never retry mutations automatically.
- Canonicalize typed desired/live projections, excluding generated IDs, revisions, timestamps, execution summaries, and unrelated defaults.
- Normalize semantic sets and preserve meaningful ordering.
- Fingerprint RFC 8785 canonical JSON with SHA-256 and explicit format versions.

## 12. Dependency planning and ownership

Build a per-target DAG:

- Automatic edges from package policies to referenced integration/agent policies.
- Explicit `dependsOn` edges.
- Stable phase preference only as a tie-breaker among ready nodes.
- A failed operation skips only transitive dependants; unrelated target/resources continue.

Ownership markers are necessary but insufficient for deletion. Durable target inventory is also required.

- Marker-only resources are never adopted automatically.
- Missing/altered markers, changed IDs, ambiguous lookups, or missing inventory are conflicts/safe orphans, never deletes.
- Integration packages and prebuilt rules are never pruned.

## 13. PVC state and single-replica constraints

Store versioned non-secret files under the state directory:

```text
config-snapshots/
sources/
inventories/
journals/
plans/
jobs/
reports/
audit/
idempotency/
locks/
```

- Use owner-only permissions, symlink/path defenses, per-target/process locks, atomic same-directory writes, and fsync where supported.
- Never store API keys, CA contents, OIDC tokens, session keys, authorization headers, or credential request bodies.
- Store plans server-side only; no plan upload endpoint exists.
- Keep durable job state so status survives browser disconnect and server restart.
- Recover pending operation journals by comparing baseline/current/expected post-state.
- Record append-oriented audit segments safely; rotate without deleting required evidence automatically.
- V1 requires exactly one replica, a ReadWriteOnce PVC, and a deployment strategy that prevents simultaneous writers.
- Readiness fails when required mounted config/state is unsafe; target credential absence affects target readiness/status, not process liveness.
- Future multi-replica support requires a transactional shared database/queue and is explicitly a later architecture version.

## 14. Source snapshots and saved-plan safety

A plan records:

- format/tool versions, plan ID, creator, creation time, source/resource-set identity, and displayed external revision metadata;
- selected target identities and Kibana versions;
- canonical mounted config/resource digests and source-file diagnostics;
- canonical operations/dependencies, desired fingerprints, baseline fingerprints, and expected post-state;
- inventory generation/fingerprint for deletes;
- unchanged observations and ownership conflicts.

Before apply:

1. Acquire locks and recover journals.
2. Re-read mounted configuration/resource set and recompute target-specific desired digests.
3. Read the target Secret and build TLS/API-key client in memory.
4. Recheck Kibana version.
5. Re-fetch every affected resource and compare baseline fingerprints.
6. Recheck inventory and live markers for deletes.
7. Reject the target before first mutation if any precondition changed.

Plans are trusted internal artifacts, strict-decoded, and inaccessible for client editing. The service does not claim cryptographic integrity against a process/PVC administrator.

## 15. Apply and partial failure

- Verify source/desired/credential presence/version/live baselines before each target starts.
- Write a journal before each remote mutation.
- Verify expected post-state before committing inventory and clearing journal.
- Continue independent targets/resources; skip only transitive dependants.
- Never roll back.
- Persist per-operation/target reports: created, updated, deleted, unchanged, skipped, conflicted, rejected, failed.
- Once any mutation succeeds, the plan is operationally consumed.
- Any result requires a new plan before another attempt; no resume/force/implicit replan.

## 16. Web interface

The embedded UI is the primary operator experience and consumes `/api/v1` only.

It provides:

- OIDC login/session/role display;
- mounted source/revision and validation status;
- target/resource inventory and target-to-resource-set assignment;
- credential status, upload, rotation, certificate metadata, and deletion for administrators—never values;
- asynchronous validation/plan/apply job progress;
- saved-plan operation/dependency/ownership/drift review;
- explicit apply confirmation;
- partial failure/rejection reports and new-plan guidance;
- authorized audit-event review;
- OpenAPI documentation links for automation users.

Security:

- Require TLS public URL and validate expected Host/forwarded-host/proto only from configured trusted proxies.
- Enforce OIDC, RBAC, CSRF for cookie mutations, strict origins, JSON content types, body limits, secure headers, CSP, no-store where sensitive, and safe error responses.
- Do not use browser local storage for tokens or credentials.
- Do not ship runtime CDN dependencies.

## 17. Container and Kubernetes delivery

### Container

- Pinned builder/runtime images, reproducible binary, non-root user, CA certificates, read-only root filesystem, and no embedded secrets.
- Read-only mounts for config/resource sets; writable PVC mount for non-secret state.

### Kubernetes

Provide:

- single-replica Deployment with Recreate strategy;
- ClusterIP Service and TLS Ingress examples;
- ReadWriteOnce PVC;
- mounted config and one or more externally orchestrated resource-set volumes;
- OIDC/session configuration using ConfigMaps/Secrets;
- dedicated ServiceAccount/Role/RoleBinding for namespaced Secret operations;
- pod security context, resource limits, probes, disruption constraints consistent with one replica, and NetworkPolicy examples;
- no planner/applier Jobs, controller, CronJob, or automatic reconcile loop.

### Local testing

`start-web.sh` may run the server against configured mounts or owned disposable Docker Elasticsearch/Kibana containers. It must ownership-label objects, bind ports to loopback, avoid printing secrets, and remain clearly non-production tooling.

## 18. Logging, audit, and redaction

- Use `slog` with request/job/actor/target/resource/operation/outcome fields.
- Never log authorization headers, OIDC tokens, cookies, API keys, certificate bodies, Secret objects, credential request bodies, or unbounded remote responses.
- Centralize redaction before logs/API/audit/state serialization.
- Record durable security/operation audit events without secret data.
- Add sentinel scans across logs, audit, plans, reports, jobs, state, HTTP responses, and container output.

## 19. Implementation phases

### Incremental execution rule

The authoritative phase subplans are living plans. Remaining work must be split into small, independently implementable, verifiable, reviewable, and committable increments with explicit dependencies and worker ownership. Before starting an increment, refine it further when discoveries reveal multiple behaviors, unrelated file ownership, distinct safety evidence, or an unclear commit boundary. After verification, update its status and evidence and adjust only the affected remaining increments; preserve completed history and all architecture and safety constraints. Workers may proceed in parallel only on non-overlapping boundaries, while the primary implementation thread owns sequencing and integration.

### Phase 0 — contract fixtures and API-server migration skeleton

Detailed sub-plan: `docs/implementation/subplans/phase-0-contract-fixtures-and-api-server-migration-skeleton.md`

- Preserve existing pinned Kibana contracts/fixtures.
- Replace CLI-first migration assumptions with server startup, routing, health, OpenAPI, OIDC/RBAC interfaces, and asynchronous-job skeletons.
- Remove the old CLI command and Cobra-oriented sub-plan.

Gate: the renamed binary starts a side-effect-free authenticated API skeleton, health/readiness and OpenAPI contracts test, and public Kibana contracts remain documented.

### Phase 1 — mounted inputs, resource sets, and validation API

Detailed sub-plan: `docs/implementation/subplans/phase-1-mounted-inputs-resource-sets-and-validation-api.md`

- Implement mounted server config, target/resource-set assignment, strict manifests, selectors/references, source snapshots/digests, and validation jobs/API/UI.

Gate: invalid mounted inputs fail with actionable diagnostics; valid assigned resource sets produce deterministic target inventories/digests without Kibana credentials.

### Phase 2 — OIDC, Kubernetes Secrets, Kibana reads, and inventory API

**Status: passed.**

Detailed sub-plan: `docs/implementation/subplans/phase-2-oidc-kubernetes-secrets-kibana-reads-and-inventory-api.md`

- Complete OIDC/RBAC, independently operable audited break-glass administrator access, credential upload/rotation to owned Secrets, Kibana TLS/version/pagination/read adapters, and target/resource inventory APIs.

Gate: authenticated roles and Secret ownership controls pass; break-glass administrator access works without the IdP, expires absolutely, rechecks and invalidates on every effective credential-set change, and has a tested post-use vault/verifier rotation runbook; every kind reads through public APIs in both spaces/versions without secret leakage.

### Phase 3 — PVC state, diff, plans, and planning API

**Status: Phase 3.1, 3.2, 3.3.1, 3.3.2a, 3.3.2b, 3.3.3, 3.3.4a, 3.3.4b, 3.3.5, and 3.3.6a complete; Phase 3 not passed.**

Detailed sub-plan: `docs/implementation/subplans/phase-3-pvc-state-diff-plans-and-planning-api.md`

- Implement file state, jobs, audit, inventory/journals, ownership, DAG/diff, saved plans, planning API, and plan-review UI.
- **3.3.2b complete:** `internal/jobrecord.FileRepository.Recover` performs one bounded coherent jobs snapshot, validates/classifies all records before CAS interruption, preserves terminal bytes, and returns identifier-free counts; `internal/server` runs it once at `time.Now().UTC()` after `statefs.Open` and before listening, with safe failure cleanup. Focused recovery and restart tests cover matrix/statuses, malformed and concurrent state, reruns, bounds, and listener/lock behavior.
- **3.3.3 complete:** `internal/idempotencyrecord.FileRepository` persists strict scoped idempotency records under the fixed `idempotency` statefs directory. Its actor/action/key hash excludes request digest, validates deterministic filename/body IDs, accepts an explicit canonical UTC `at` and requires it to equal a new or replacement candidate's `CreatedAt`, atomically creates or replays with explicit `Record.Replay`, returns digest conflicts, safely reclaims only ETag-matching expired records at capacity, supports caller-time expiry/replacement and pending-to-terminal typed-result CAS, preserves restart-stable SHA-256 ETags, and bounds coherent validation scans to 10,000 records/32 MiB. Focused tests cover scope separation, restart/replay, conflicts, independent scopes, terminal completion, direct terminal results, multi-repository CAS races, expiry, nil-expiry retention, capacity reclamation, malformed/unsafe state, context cancellation, strict bytes, and sentinel-safe errors. No existing service/route, scheduler, HTTP/SSE, or audit integration was added.
- **3.3.4a complete:** `internal/jobscheduler` implements standalone durable admission and execution over the minimal `jobrecord.Repository` transition surface. It reserves `QueueCapacity+Workers` slots before durable create, applies bounded scheduler-owned persistence contexts, validates returned records and ETags, survives submitting-context disconnects after acceptance, bounds worker concurrency, CAS-claims queued records, preserves metadata and type-valid result links, maps invalid results/panics to fixed safe codes, linearizes shutdown cancellation under admission, closes safely on persistence or ownership ambiguity, and cooperatively cancels accepted queued/running work on shutdown. No runtime/service/route adapter, restart resumption, idempotency, cancellation API, SSE, planning, or audit was added. Verification timestamp: 2026-08-31T12:39:45Z.
- **3.3.4b complete:** `internal/server` now owns the minimal scheduler lifecycle, creating the default `jobscheduler` with fixed `Workers=1` and `QueueCapacity=32` (delegating persistence timeout to the scheduler core) only after successful durable job recovery and before listener/other-service construction. It retains the scheduler and recovered repository, performs no submissions or record enumeration, gates readiness on scheduler health, and uses a test factory seam for ordering/failure injection. Constructor cleanup bounds scheduler shutdown before listener/state cleanup; normal shutdown orders HTTP/current services, scheduler, then conditional state close; scheduler failure/timeout returns a fixed safe lifecycle error and retains state descriptors/process lock; unexpected Serve exits force-close current services, bounded-shut down the scheduler, and retain state. Existing route/service adapters, job reads, SSE, cancellation, idempotency, audit, planning, and HTTP API work remain outside this increment. Verification timestamp: 2026-09-01T09:49:54Z.
- **3.3.5 complete:** `internal/server` now exposes authenticated GET/HEAD `/api/v1/jobs` and `/api/v1/jobs/{jobId}` over a minimal read-only `Get`/`List` durable-repository contract. The recovered production `*jobrecord.FileRepository` is wired into `HandlerOptions`; handlers project only the existing public `jobs.Job` JSON fields, use fixed safe errors, preserve API versioning/non-nil empty arrays, and perform no queue submission, scheduling, cancellation, SSE, audit, or writes. List query parsing is strict for one bounded page size/token and repeatable exact type/status filters; repository page tokens pass through opaquely, filter-scoped snapshots return `job_page_changed` on mutation, and backend/corruption/scan failures return generic `jobs_unavailable`. OpenAPI and route contract tests cover the actual 200/400/401/403/404/409/503 surface. Focused server tests cover authentication and all inherited roles, all current job types/statuses, safe projection/sentinel absence, strict queries, opaque tokens, real statefs/jobrecord pagination, combined type/status filtering, unchanged bytes, mutation conflicts, restart polling, and a production-runtime recovery/authentication/read path. Verification timestamp: 2026-09-01T11:05:23Z.
- **3.3.6a complete:** durable cooperative cancellation mutation core is implemented with narrow repository CAS/replay semantics, one-write queued terminal cancellation, admission-serialized scheduler cancellation, pending removal/slot release, active executor cancellation, exact owned terminal derivation across replay/race/finish windows, claim-registration race closure, exact cancellation-only finish precedence, safe projections, and fail-closed persistence/ownership handling. No HTTP route, SSE, OpenAPI, audit, UI, or service adapter was added. Verification timestamp: 2026-09-02T12:07:12Z.
- **Next:** 3.3.6b — authenticated HTTP cancellation + bounded SSE projection. Audit, diffing, and saved plans remain future work.

Gate: deterministic non-secret plans are source/target scoped and cannot authorize prune without inventory plus marker.

### Phase 4 — apply engine and apply API

Detailed sub-plan: `docs/implementation/subplans/phase-4-apply-engine-and-apply-api.md`

- Implement preflight, mutation adapters, post-verification, dependency/target isolation, reports, idempotent initiation, and explicit replan semantics.

Gate: safety/fault/partial-failure tests pass and reports/audit remain accurate and non-secret.

### Phase 5 — web-first operator experience and API hardening

Detailed sub-plan: `docs/implementation/subplans/phase-5-web-first-operator-experience-and-api-hardening.md`

- Complete embedded UI workflows, external API usability/OpenAPI parity, OIDC sessions, CSRF/CORS/proxy/security headers, accessibility, concurrency, and audit views.

Gate: all operator workflows are web-complete and external automation can use the same secured versioned API.

### Phase 6 — container, Kubernetes exposure, and live matrix

Detailed sub-plan: `docs/implementation/subplans/phase-6-container-kubernetes-exposure-and-live-matrix.md`

- Finalize image, Deployment/Service/Ingress/PVC/RBAC/NetworkPolicy, branch-separated mount examples, local Docker launcher, and live 9.2.0/current-9.x matrix.

Gate: the one-replica web/API deployment and both live versions pass the full security/reconciliation acceptance matrix.

Implement incrementally on local branches. Require captain approval before guarded integration into `main`. Do not push, publish, deploy, or contact third parties without explicit approval.

## 20. Test strategy

### Unit/property tests

- Mounted config/manifests, duplicate keys, traversal/symlinks, selectors, references, DAGs, canonicalization, digests.
- OIDC claims/roles/session/CSRF, API schemas/errors/pagination/idempotency.
- Kubernetes Secret ownership, PEM/API-key validation, no-overwrite/delete, and redaction.
- Kibana adapters, pagination, canonicalization, version handling, ownership, pruning, plans, locks, journals, audit, reports.

### HTTP/API tests

- Authentication/authorization matrix for every endpoint.
- Browser cookie/CSRF/origin and bearer-token behavior.
- Proxy/Host/proto handling, body/response limits, safe errors, OpenAPI-handler parity.
- Credential upload never echoed/cached/logged/persisted to PVC.
- Asynchronous jobs survive disconnect/restart and enforce mutation serialization.

### Reconciliation tests

- Second plan after successful apply has zero operations.
- Mounted source/config/CA Secret/inventory/version/live drift rejects affected target.
- Unrelated resource sets/targets continue independently.
- Unmanaged and marker-only resources are never changed/deleted.
- Dependency failures skip only transitive dependants.
- Partial apply persists report/audit and requires new plan.
- Prebuilt rules remain collective.

### Live matrix

- Exact Kibana 9.2.0 and selected current stable 9.x patch, initially 9.4.2.
- Default/non-default spaces, caller IDs, pagination, privileges, conflicts, API-key behavior, collective prebuilt operations, and TLS CA trust.
- Record exact image versions/digests and sanitized evidence.

## 21. Acceptance criteria

- Production runs as a single-replica OIDC-protected Kubernetes web/API Deployment, not an operator CLI or Job workflow.
- Mounted Git/YAML resource sets remain authoritative and are never edited by the service.
- Every target is visibly assigned to one resource set; branch/revision provenance and canonical digest are displayed.
- Administrators can upload/rotate API keys and CA trust bundles into owned Kubernetes Secrets without values entering PVC state, logs, audit, responses, or browser storage.
- Viewer/planner/applier/administrator authorization is enforced and audited.
- Embedded UI and external clients use the same `/api/v1` OpenAPI-described API.
- All five resource kinds work through documented APIs in default/non-default spaces.
- Source, credential presence, CA, inventory, version, or live-baseline drift blocks affected-target mutation.
- No prune occurs without exact inventory plus live marker.
- Independent targets/resources continue after failures; no rollback/resume occurs.
- New plans are required after apply outcomes.
- JSON/PVC state is atomic, non-secret, recoverable, and explicitly single-writer/single-replica.
- Container/Kubernetes security, OIDC/API security, secret provisioning, reconciliation, web, and live-version tests pass.
