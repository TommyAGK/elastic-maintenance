# Phase 6 — container, Kubernetes exposure, and live matrix

**Status: Planned.** Phase 6 has not passed, and no increment in this document is complete. This document is the authoritative, living plan for the phase. Future workers must record evidence and update the relevant status only after its focused verification passes; a draft, manifest, local test, or approval request is not completion.

## Objective

Package and expose the single-replica web/API service securely, support externally mounted branch-separated sources, and prove the complete product against Kibana 9.2.0 and current stable 9.x.

## Prerequisites

- Phases 0–5 gates pass, including the durable single-writer state, apply/replan behavior, web/API security, and OpenAPI contracts.
- API, UI, state formats, mounted-input contracts, credential Secret boundary, and public Kibana adapters are stable for v1.
- The exact namespace, PVC storage class, ingress controller, public DNS/TLS name, trusted proxy ranges, OIDC provider, Kubernetes API access, and test targets are identified and authorized for the work window.
- The live matrix has an approved target list, license/test-data policy, cleanup owner, and sanitized evidence location before any live environment is contacted.
- Pulling images, creating or changing Kubernetes resources, creating or changing Kibana resources or credentials, deploying, publishing, and release promotion remain approval-gated. No prerequisite is implied by this plan.

## Preserved architecture and release constraints

These constraints are invariant across every increment. No worker may solve a problem by changing them or by marking a later architecture version complete.

- Production remains one long-running Go server in exactly one Kubernetes replica. The Deployment uses `Recreate`; v1 does not add HA, leader election, a database, a controller, a CronJob, or planner/applier Jobs.
- The state directory remains the sole non-secret durable application state and is mounted on one `ReadWriteOnce` PVC. There must never be simultaneous writers. Future multi-replica support requires a separate architecture decision.
- Mounted server configuration and Git/YAML resource sets remain authoritative, externally orchestrated, branch/revision-separated, and read-only. The service does not clone, fetch, poll, edit, commit, or execute Git.
- Config and resource-set volumes are read-only; only the explicitly designated state and temporary mounts are writable. The container root filesystem is read-only.
- Production exposure is through a ClusterIP Service and TLS Ingress with the expected HTTPS public URL. Direct unintended pod/service exposure is not an alternative.
- The pod remains non-root with dropped capabilities, `seccompProfile: RuntimeDefault`, bounded resources, correct probes, and a narrowly scoped namespaced ServiceAccount for only the Kubernetes Secret operations required by the application.
- NetworkPolicy must allow required DNS, OIDC issuer/JWKS, Kubernetes API, and configured Kibana destinations while restricting unnecessary ingress/egress and documenting hostname-policy limitations.
- Credentials and CA contents remain in owned Kubernetes Secrets only; they never enter PVC state, plans, reports, logs, audit, HTTP responses after submission, image layers, or browser storage. v1 supports CA trust bundles, not client-certificate/mTLS authentication.
- The supported Kibana range remains `>=9.2.0,<10.0.0`. The matrix must include exact 9.2.0 and the selected current stable 9.x patch, initially 9.4.2, with exact image digests and sanitized evidence. No automatic downgrade or unsupported endpoint is introduced.
- Mounted resource assignment, target identity, inventory-plus-marker pruning authority, dependency isolation, partial-failure reporting, explicit replan, and collective-only prebuilt-rule behavior remain unchanged.
- `start-web.sh` remains test/demo-only local tooling. It is not a production deployment mechanism and must not weaken production configuration or release controls.
- A release candidate is not a published release. No image, chart/manifests, SBOM, documentation bundle, or test result is published without the appropriate approval below.

## Execution, worker, and living-plan rules

- Each numbered increment is a small independently implementable, independently verifiable, and independently committable unit. A future worker may make one reviewable local commit for its increment after verification; this task creates no such commit.
- The **Worker boundary** in each increment is exclusive. The worker may add the tests, fixtures, configuration examples, or narrowly scoped documentation needed to verify its own deliverable, but must not implement a downstream increment or rewrite architecture. The plan maintainer owns status/evidence updates in this file unless that update is explicitly delegated.
- Dependencies are hard gates: do not start an increment until its listed prerequisites and increment dependencies have accepted evidence. A dependency being drafted or locally runnable is insufficient.
- Every increment must return: files changed, exact verification commands/results, evidence paths, external actions not taken, and any blocker. A failed verification leaves the increment Planned or Blocked; it is never silently bundled into the next increment.
- Before starting an increment, update this plan if its scope, dependency, worker boundary, or approval target has changed. Afterward, record status, evidence, and residual work here. If implementation reveals a larger unit, split it into new numbered increments rather than expanding an existing one.
- Preserve stable increment IDs once work begins. New work gets a suffix or a new increment; do not renumber completed evidence. Do not mark an increment or the phase gate complete based on another increment's evidence.
- All verification should be local, static, mocked, disposable, or explicitly approved live verification. Workers must not push, publish, deploy, contact a live provider/cluster, use live credentials, or mutate a live target merely because a command is available.

## External-effect approval gates

Approval is specific to the named target, action, environment, and time window. It must be recorded before the corresponding worker acts; silence, an existing credential, a dry-run, or a dependency does not count.

| Gate | Explicit approval required before | Default permitted evidence without the gate |
| --- | --- | --- |
| **AG-LOCAL** | Pulling/creating/removing Docker resources or using local test credentials beyond isolated fixtures | Static checks, unit tests, image inspection, and non-network fixture tests |
| **AG-DEPLOY** | Applying or merging Kubernetes namespace, Deployment, Service, Ingress, PVC, RBAC, ConfigMap/Secret mount, or NetworkPolicy changes; exposing any endpoint; changing a shared cluster | Manifest/schema validation, client-side dry-run, rendered-diff review, and mocked Kubernetes tests |
| **AG-PUBLISH** | Pushing an image, chart, manifest, SBOM, documentation bundle, release metadata, or matrix evidence to a registry, repository, artifact store, or public location; promoting a release | Local image digest, checksum, SBOM, signature/provenance, and sentinel outputs retained locally |
| **AG-LIVE** | Contacting an external OIDC provider or live Kibana/Kubernetes target; provisioning live test spaces/resources/API keys; uploading or rotating credentials; running any live mutation, cleanup, or destructive reconciliation | Mock servers, versioned fixtures, local disposable environments, and static contract checks |

AG-DEPLOY does not grant AG-LIVE or AG-PUBLISH. AG-LIVE for read-only probes does not grant approval for mutation, cleanup, or credential rotation; the live approval must name those actions separately. Every worker preserves the no-deploy/no-publish/no-live default when its gate is absent.

## Numbered increments

### 6.1 — Freeze the Phase 6 delivery contract and evidence register

- **Dependencies:** Phase 0–5 prerequisites; no Phase 6 increment.
- **Worker boundary:** Plan/evidence documentation only. Do not implement manifests, image changes, local tooling, or live setup.
- **Done when:** The exact supported versions (`9.2.0` and current stable 9.x, initially `9.4.2`), target/environment identities, required Kubernetes inputs, release constraints, approval owners, evidence retention location, and cleanup owner are recorded without inventing unavailable values.
- **Verification:** Review this subplan against `plan.md`, the architecture decision, state-directory contract, and deployment status; confirm every external action has an approval gate and every later increment has a dependency.
- **Status:** Planned.

### 6.2 — Pin image build inputs and reproducible build metadata

- **Dependencies:** 6.1; stable repository build entry points from Phases 0–5.
- **Worker boundary:** Dockerfile/build configuration and build reproducibility checks only. Do not add Kubernetes resources or publish an artifact.
- **Done when:** Go, builder image, and runtime image inputs are pinned by immutable digests; the binary uses `-trimpath` and deterministic version/commit/date metadata; the build records exactly how the digest and metadata were selected.
- **Verification:** Build twice from the same checkout in an isolated local environment, compare reproducibility evidence and embedded build identity, and inspect that no floating image tag controls the release build.
- **External-effect gate:** No gate for local builds; AG-PUBLISH is required before any push or release artifact upload.
- **Status:** Planned.

### 6.3 — Harden the runtime image identity and trust surface

- **Dependencies:** 6.2.
- **Worker boundary:** Runtime image contents, user/group definition, CA roots, and executable entrypoint only. Do not change Kubernetes pod security settings or application behavior outside startup/runtime requirements.
- **Done when:** The image runs as a dedicated non-root UID/GID, contains required CA roots, omits unnecessary shells/tools and build material, and has no credentials or credential-bearing examples in its layers.
- **Verification:** Inspect layers/filesystem and run the image locally as the dedicated user with a minimal configuration; prove required HTTPS trust works and forbidden image contents/secret patterns are absent.
- **Status:** Planned.

### 6.4 — Enforce container filesystem policy and local artifact evidence

- **Dependencies:** 6.2–6.3.
- **Worker boundary:** Read-only-root behavior, explicit writable state/temp paths, OCI labels, local checksums, SBOM/provenance, and image-layer scanning only. Do not publish evidence.
- **Done when:** The image supports a read-only root filesystem and documents only the state and temporary paths that may be writable; OCI metadata, checksums, and locally retained SBOM/provenance identify the exact build; secret scanning covers all layers and generated artifacts.
- **Verification:** Run with a read-only root and only the documented writable mounts, exercise startup/state/temp behavior, compare recorded digest/labels, and scan image layers, config, examples, and build output for secrets.
- **External-effect gate:** AG-PUBLISH is required to upload any image, SBOM, provenance, or scan result.
- **Status:** Planned.

### 6.5 — Define the single-replica Deployment and RWO state storage

- **Dependencies:** 6.1, 6.2, 6.4; the Phase 3 state-directory contract.
- **Worker boundary:** Deployment, PVC, state-volume wiring, update strategy, and disruption settings only. Do not implement Service/Ingress, RBAC, NetworkPolicy, or live deployment.
- **Done when:** The supported manifest specifies exactly one replica, `Recreate`, one `ReadWriteOnce` PVC at the state path, safe state ownership/mode expectations, and no rollout/disruption setting that can create simultaneous writers. No Kubernetes Job/controller/CronJob is introduced.
- **Verification:** Render and schema/lint the manifests; client-side dry-run and static review prove replica/strategy/access-mode/volume invariants and prove no second writer path exists.
- **External-effect gate:** AG-DEPLOY is required before applying or merging the manifest against a cluster.
- **Status:** Planned.

### 6.6 — Add pod security, resources, probes, and mount permissions

- **Dependencies:** 6.5 and 6.3.
- **Worker boundary:** Pod/container security context, resource bounds, startup/readiness/liveness probes, service-account token policy, and filesystem mount flags only. Do not add external ingress or NetworkPolicy rules.
- **Done when:** The pod is non-root, drops capabilities, uses `seccompProfile: RuntimeDefault`, has a read-only root, bounded resources, semantically correct probes, and automounts no token unless the Kubernetes Secret API path requires an explicit projected token. State/temp mounts are the only writable exceptions; config/resource mounts are read-only.
- **Verification:** Static manifest checks plus a disposable local or approved test-pod run prove UID/GID, capabilities, seccomp, mount modes, probe behavior, resource bounds, and token behavior; readiness/liveness failure semantics are documented.
- **External-effect gate:** AG-DEPLOY is required for a real test pod or cluster change.
- **Status:** Planned.

### 6.7 — Expose the application through a ClusterIP Service

- **Dependencies:** 6.5–6.6.
- **Worker boundary:** Service selector, port, protocol, and exposure type only. Do not add ingress TLS or make the Service externally reachable.
- **Done when:** The Service is `ClusterIP`, selects only the intended single-replica workload, exposes the documented HTTP port, and has no `LoadBalancer`/`NodePort` or unintended external path.
- **Verification:** Render/schema/lint and client-side dry-run checks prove selector/port/exposure invariants; a mocked endpoint test proves health traffic reaches the intended pod.
- **External-effect gate:** AG-DEPLOY is required before applying the Service to a cluster.
- **Status:** Planned.

### 6.8 — Define the TLS Ingress and trusted proxy contract

- **Dependencies:** 6.7 and 6.1.
- **Worker boundary:** TLS Ingress, public URL, host/scheme validation inputs, trusted proxy ranges, forwarded-header policy, HSTS, and secure-cookie ingress settings only. Do not run an external login or change OIDC claims.
- **Done when:** The Ingress requires HTTPS for the expected public host, routes only through the ClusterIP Service, and the application configuration accepts forwarded host/proto/client IP only from configured trusted proxies. HSTS and secure-cookie behavior are explicit; direct pod/service exposure remains denied.
- **Verification:** Rendered manifest/config review, negative Host/scheme/forwarded-header tests, and a local TLS/terminating-proxy fixture prove the expected URL and rejection behavior.
- **External-effect gate:** AG-DEPLOY is required before exposing an ingress; AG-LIVE is additionally required for an external DNS/certificate endpoint.
- **Status:** Planned.

### 6.9 — Exercise OIDC and bearer flows through the real ingress boundary

- **Dependencies:** 6.8 and the Phase 2/5 authentication contracts.
- **Worker boundary:** Deployed-path OIDC redirect/callback/logout/session and bearer-token verification tests only. Do not alter role design, credentials, or reconciliation behavior.
- **Done when:** The expected public HTTPS URL, redirect/logout URLs, role claim mappings, trusted issuer/JWKS path, secure cookies, and bearer automation behavior work through the ingress; direct or spoofed proxy paths fail closed.
- **Verification:** Run browser and bearer-flow tests against a controlled provider/fixture, including expiry, state/nonce, role, logout, proxy, and wrong-host cases; retain sanitized request/result evidence.
- **External-effect gate:** AG-LIVE is required for any external OIDC provider or live endpoint; otherwise use a mock provider and local TLS fixture.
- **Status:** Planned.

### 6.10 — Define the dedicated ServiceAccount and namespaced Secret RBAC

- **Dependencies:** 6.5–6.6 and the Phase 2 Secret client boundary.
- **Worker boundary:** ServiceAccount, Role, RoleBinding, namespace references, and verb/resource scope only. Do not implement application ownership checks or apply them to a live cluster.
- **Done when:** A dedicated namespace and ServiceAccount receive only the required namespaced Secret permissions (`get`, `create`, `update`, and `delete`, plus only any explicitly justified required verb); there is no cluster-wide Secret access, list/watch, or unrelated permission. The Deployment selects this account.
- **Verification:** YAML/schema/lint and rendered RBAC review prove namespace/resource/verb scope; mocked authorization cases prove denied cluster-wide and unrelated-resource access.
- **External-effect gate:** AG-DEPLOY is required before applying namespace/RBAC changes.
- **Status:** Planned.

### 6.11 — Verify Secret ownership boundaries and residual cluster-admin trust

- **Dependencies:** 6.10 and the Phase 2 credential ownership implementation.
- **Worker boundary:** Application prefix/ownership preconditions, integration tests, and operator documentation only. Do not broaden RBAC to compensate for an application check.
- **Done when:** The application enforces the configured namespace, `elastic-maintainer-target-` prefix, exact ownership labels/annotations, target identity, and optimistic preconditions before update/delete; unrelated Secret reads/updates/deletes fail; documentation states the residual trust in cluster administrators and equivalent pod/PVC/runtime access.
- **Verification:** Integration tests cover wrong namespace/name, missing or altered ownership, collisions, stale resource versions, unrelated Secrets, and deletion while a mutation lease exists; inspect logs/responses for safe errors and no Secret values.
- **External-effect gate:** AG-LIVE is required for a live Kubernetes authorization test; mocked/injected Kubernetes tests are the default.
- **Status:** Planned.

### 6.12 — Provide externally orchestrated, read-only resource-set mounts

- **Dependencies:** 6.5–6.6 and the Phase 1 mounted-input contracts.
- **Worker boundary:** Kubernetes volume/mount examples and deployment documentation for ConfigMap, CSI, GitOps-generated, and init-container-populated read-only directories. Do not add Git credentials or application Git operations.
- **Done when:** Server configuration and one or more resource sets mount at separate paths with read-only flags; examples show how an external orchestrator supplies branch/revision content without embedding Git credentials in the application; only the PVC state and explicit temp mount are writable.
- **Verification:** Rendered-manifest inspection and disposable mount tests prove path separation, read-only behavior, symlink/path defenses, and startup diagnostics for missing/unsafe mounts.
- **External-effect gate:** AG-DEPLOY is required for a cluster mount test; AG-LIVE is required if the source is a shared/live orchestrator.
- **Status:** Planned.

### 6.13 — Prove assignment, provenance, and source-switch drift behavior

- **Dependencies:** 6.12 and Phases 1, 3, and 4 source/digest/replan contracts.
- **Worker boundary:** Branch/revision `.source-revision` examples, target-to-resource-set assignment checks, and source-switch/drift acceptance tests only. Do not change digest or plan semantics.
- **Done when:** Separate branches/revisions remain separate resource-set paths; optional bounded `.source-revision` values are provenance only; target assignment is explicit; changing mounted source/config invalidates affected plans before mutation and never edits the mount.
- **Verification:** Switch two controlled mounts, run validation/plan/apply-preflight scenarios, and prove target-scoped digest changes, stale-plan rejection, no Git execution, and no write beneath resource-set roots.
- **External-effect gate:** AG-LIVE is required for a shared/live mount or real preflight; local read-only fixtures are the default.
- **Status:** Planned.

### 6.14 — Add NetworkPolicy and egress/ingress guidance

- **Dependencies:** 6.7–6.10, 6.12, and 6.1's cluster capability record.
- **Worker boundary:** NetworkPolicy examples, allowed paths, and limitation documentation only. Do not weaken pod security or add an unbounded egress exception.
- **Done when:** Policy allows required DNS, configured OIDC issuer/JWKS, Kubernetes API Secret access, and configured Kibana destinations; ingress is limited to Service/Ingress/probe paths as supported by the cluster; hostname-based policy limitations and accidental Secret API blocking are documented.
- **Verification:** Static policy analysis plus a disposable/mock network test proves allowed and denied paths, DNS behavior, proxy/provider/Kibana reachability, and failure diagnostics when a required path is blocked.
- **External-effect gate:** AG-DEPLOY is required before applying policy; AG-LIVE is required for a shared-cluster connectivity test.
- **Status:** Planned.

### 6.15 — Implement the local `start-web.sh` lifecycle and ownership guard

- **Dependencies:** 6.2–6.4 and 6.12; server build/config/examples must exist before the script is tracked as supported test tooling.
- **Worker boundary:** Local launcher argument/config handling, loopback binding, owned disposable Docker resource creation/reuse/removal, and test/demo labeling only. Do not make it a production deployment path.
- **Done when:** The script supports mounted local sources and a configured OIDC development mode or documented safe local identity provider/test authenticator unavailable in production builds/config; it creates only ownership-labeled disposable Elasticsearch/Kibana resources, binds local ports to loopback, and refuses removal/reuse when ownership does not match.
- **Verification:** Shell/static checks and disposable local runs cover clean start, existing-owned resources, foreign-resource refusal, restart, cleanup, loopback binding, and absent production authenticator configuration.
- **External-effect gate:** AG-LOCAL is required before creating/removing Docker resources or pulling their images; no shared or production resource may be used.
- **Status:** Planned.

### 6.16 — Add local ephemeral credentials and TLS-fixture handling

- **Dependencies:** 6.15 and the Phase 2 credential/CA contracts.
- **Worker boundary:** Local-only API-key generation/revocation, temporary CA fixture upload/trust exercise, cleanup, and redaction checks. Do not change production credential storage or TLS architecture.
- **Done when:** Local tests can generate and revoke ephemeral Kibana API keys without printing or persistently storing them, exercise CA trust upload when local TLS is enabled, and label the launcher and output test/demo-only.
- **Verification:** Capture stdout/stderr/filesystem/container logs and scan for API keys, CA bodies, Secret bodies, and authorization headers; test trust success/failure and cleanup after interruption.
- **External-effect gate:** AG-LOCAL is required for disposable local resources; AG-LIVE is required for any non-fixture credential or target.
- **Status:** Planned.

### 6.17 — Specify the exact live matrix and sanitized evidence schema

- **Dependencies:** 6.1, 6.4, and stable Phase 2–5 contracts.
- **Worker boundary:** Matrix inventory, version/image/license/space/resource requirements, privilege checklist, CA scenarios, and evidence schema only. Do not provision targets or run Kibana calls.
- **Done when:** The matrix names exact Elasticsearch/Kibana 9.2.0 and current stable 9.x (initially 9.4.2), image digests, license mode, default/non-default spaces, enough resources for each pagination mode, minimum-privilege API keys, trusted-CA cases, cleanup owner, and sanitized evidence fields.
- **Verification:** Review each planned case against all required API/security/reconciliation acceptance items and confirm the evidence schema excludes credentials, certificate bodies, tokens, and unbounded remote responses.
- **Status:** Planned.

### 6.18 — Provision the approved matrix environments and test identities

- **Dependencies:** 6.17; approved namespace/cluster/target identities and cleanup plan.
- **Worker boundary:** Environment manifests/configuration, isolated spaces/resources, minimum-privilege test API keys, CA trust fixtures, and inventory of image digests only. Do not run the reconciliation matrix or publish evidence.
- **Done when:** Each named matrix target is available with recorded exact versions/digests, license mode, spaces, resource capacity, least-privilege identity, trusted-CA setup, and sanitized teardown instructions; credentials are handled only through the approved Secret path.
- **Verification:** Read-only readiness/version/space/license checks, ownership checks, and evidence review prove target identity and cleanup ownership before any mutation test begins.
- **External-effect gate:** AG-LIVE must explicitly approve target provisioning, credential creation/rotation, and any environment mutation; AG-DEPLOY is also required for Kubernetes-hosted environments.
- **Status:** Planned.

### 6.19 — Run the live compatibility, spaces, and read/pagination matrix

- **Dependencies:** 6.18; read-only AG-LIVE approval for the named targets.
- **Worker boundary:** Version detection, compatibility range, default/non-default spaces, public read adapters, inventory, and every documented pagination style only. Do not test mutations or change target configuration.
- **Done when:** 9.2.0 and the selected current stable 9.x target pass version detection and compatibility checks; all supported read adapters and pagination modes return complete, deterministic, sanitized results in each required space.
- **Verification:** Execute the matrix cases, record exact target/version/space/digest and safe outcomes, verify no credential/body leakage, and retain failures as blockers rather than reducing coverage.
- **External-effect gate:** AG-LIVE is required even for live reads; no mutation/cleanup is authorized by this increment.
- **Status:** Planned.

### 6.20 — Run the authentication and authorization matrix

- **Dependencies:** 6.9, 6.11, 6.18, and 6.19's target readiness evidence.
- **Worker boundary:** OIDC browser login/logout/session, bearer automation, and the full viewer/planner/applier/administrator endpoint-role matrix only. Do not test credential mutation or reconciliation.
- **Done when:** Browser and bearer flows use the same role model through the deployed boundary; denied roles, unknown roles, expiry, logout, wrong issuer/audience, and forbidden endpoints fail safely; audit identifiers are present without secrets.
- **Verification:** Run every protected endpoint for every role in each approved environment, including browser CSRF/origin cases where applicable; compare server denial and UI visibility and retain sanitized audit/result evidence.
- **External-effect gate:** AG-LIVE is required for external OIDC/deployed environments; use mocks for the default non-live verification.
- **Status:** Planned.

### 6.21 — Run the credential, CA, ownership, and no-leakage matrix

- **Dependencies:** 6.11, 6.18, 6.19, and 6.20.
- **Worker boundary:** Credential upload/rotation/delete, Secret ownership collision, CA parse/trust, lease/deletion coordination, and no-readback/no-cache/no-log/no-PVC checks only. Do not run reconciliation mutations.
- **Done when:** Valid and invalid API-key/CA cases, rotation, deletion, ownership collisions, and target-unready behavior are correct; credentials never appear in browser responses/storage, logs, audit, plans, reports, jobs, PVC state, or container output.
- **Verification:** Exercise the complete credential matrix with sanitized sentinel values, scan every listed channel, test Secret resource-version/ownership conflicts and lease blocking, and confirm only non-secret metadata is exposed.
- **External-effect gate:** AG-LIVE is required for live Secret/Kibana credential operations and must separately approve any target credential rotation or deletion.
- **Status:** Planned.

### 6.22 — Run the ingress, proxy, browser/API control matrix

- **Dependencies:** 6.8–6.9, 6.19, and 6.20.
- **Worker boundary:** Ingress/proxy/Host/CORS/CSRF/CSP/security headers, rate/body limits, SSE/polling fallback, request IDs, safe errors, and idempotency behavior only. Do not alter reconciliation or credential storage.
- **Done when:** Expected public HTTPS requests succeed, spoofed proxy/Host/origin paths fail closed, CORS remains disabled or strictly allowlisted, sensitive responses are no-store, limits and rate controls hold, and SSE never becomes a job-lifetime dependency.
- **Verification:** Run positive and negative HTTP/browser cases through the deployed boundary and inspect headers, response envelopes, retries, duplicate idempotency requests, SSE disconnect/reconnect, and logs for leakage.
- **External-effect gate:** AG-DEPLOY is required for a deployed ingress test; AG-LIVE is required when the endpoint or provider is shared/live.
- **Status:** Planned.

### 6.23 — Run the runtime, Secret-RBAC, PVC, and recovery matrix

- **Dependencies:** 6.5–6.6, 6.10–6.14, 6.18, and Phase 3–4 recovery contracts.
- **Worker boundary:** Pod restart, RWO/single-writer enforcement, PVC persistence/corruption/interrupted-write recovery, durable job/audit recovery, and unauthorized Kubernetes Secret access only. Do not add a second replica or Kubernetes operation Job.
- **Done when:** Restart/PVC/job/audit recovery is safe and durable; readiness reflects the state-store contract while liveness remains independent; one-writer enforcement holds; the ServiceAccount cannot read/update unrelated Secrets; NetworkPolicy does not accidentally block required Secret API access.
- **Verification:** Run controlled restart, interruption, corruption, free-space, lock, stale-journal, unrelated-Secret, and allowed/denied-network cases; retain reports/audit and prove no simultaneous writers or secret leakage.
- **External-effect gate:** AG-DEPLOY is required for a real cluster test; AG-LIVE is required for a shared/live cluster or Secret.
- **Status:** Planned.

### 6.24 — Run version, space, package, and downgrade reconciliation cases

- **Dependencies:** 6.18–6.19 and the Phase 4 apply/replan contract.
- **Worker boundary:** Compatibility recheck, default/non-default spaces, exact integration package install, and downgrade conflict behavior only. Do not cover policy/rule CRUD or prebuilt operations.
- **Done when:** Planning/apply preflight rejects unsupported or changed versions, scopes every operation to the correct space, installs the exact requested package version, and rejects downgrades without an automatic fallback.
- **Verification:** Run approved cases against both matrix versions, inspect operation/report/audit content and post-state, and confirm no mutation occurs after a failed precondition or downgrade rejection.
- **External-effect gate:** AG-LIVE must separately approve every mutating case and its cleanup; fixtures/mocks are the default otherwise.
- **Status:** Planned.

### 6.25 — Run caller-ID, dependency, and target-isolation reconciliation cases

- **Dependencies:** 6.24 and Phase 3–4 ownership/DAG contracts.
- **Worker boundary:** Caller-defined agent/package policy IDs, caller-defined detection `rule_id`, automatic/explicit dependency edges, target independence, and failure propagation only. Do not change DAG or identity semantics.
- **Done when:** Caller IDs are preserved, exact-target dependencies execute prerequisite-first, a failed operation skips only transitive dependants, and unrelated targets/resources continue with accurate reports and mandatory replan guidance.
- **Verification:** Use cases with independent targets, dependency failure, ID collisions, and partial outcomes; compare live IDs, reports, audit, and next-plan requirements for both versions.
- **External-effect gate:** AG-LIVE must name the mutating targets and cleanup actions; no live mutation is permitted by default.
- **Status:** Planned.

### 6.26 — Run CRUD, complete replacement, pagination, and collective prebuilt cases

- **Dependencies:** 6.24–6.25.
- **Worker boundary:** Create/update/delete for supported managed kinds, complete detection-rule replacement, all mutation pagination prerequisites, and the collective prebuilt operation only. Do not add individual prebuilt mutation or pruning.
- **Done when:** Create/update/delete behavior is correct and idempotent, complete replacement bodies preserve required live fields, pagination is exhaustive, and prebuilt rules use only the collective install/update operation; no individual prebuilt rule is changed or pruned.
- **Verification:** Run create/update/delete, exact package, rule replacement, collective prebuilt, and second-plan-zero-operation cases on both versions/spaces; inspect live state and sanitized reports for exact IDs and outcomes.
- **External-effect gate:** AG-LIVE must separately approve all mutations and cleanup; no automatic rollback/resume is introduced.
- **Status:** Planned.

### 6.27 — Run drift, ownership, pruning, partial-apply, and replan safety cases

- **Dependencies:** 6.24–6.26, 6.13, and the Phase 4 preflight/journal contract.
- **Worker boundary:** Mounted source/target config/Secret CA/inventory/version/live-baseline drift, marker/inventory pruning, journal/post-state verification, partial failure, and mandatory replan only. Do not weaken preconditions to make a case pass.
- **Done when:** Any relevant drift rejects the affected target before mutation; deletion requires inventory plus the exact live marker; marker-only/unmanaged/altered/ambiguous resources are never adopted or pruned; independent work continues safely; any apply outcome requires a new plan and a converged second plan has zero operations.
- **Verification:** Inject each drift and failure between plan and apply, inspect no-mutation guarantees, journals, inventory, reports, audit, dependency skips, and follow-up plan behavior on both matrix versions.
- **External-effect gate:** AG-LIVE must explicitly approve live mutations, induced drift, and cleanup; otherwise use mocks or isolated disposable targets.
- **Status:** Planned.

### 6.28 — Scan every artifact and output channel for sentinels

- **Dependencies:** 6.4 and 6.19–6.27; all matrix evidence intended for the release dossier exists locally.
- **Worker boundary:** Cross-channel sentinel generation/scanning and evidence collation only. Do not change credential handling or hide a failing result.
- **Done when:** Sanitized sentinel scans cover image layers, container output, HTTP responses, logs, audit, PVC state, jobs, plans, reports, local/live matrix evidence, and generated documentation; no API key, CA body, OIDC token, cookie, Secret body, authorization header, or credential request body is present.
- **Verification:** Run deterministic scans with known canary values and review false-positive handling; a failure blocks the phase and is linked to the owning increment.
- **External-effect gate:** AG-PUBLISH is required before uploading scan/evidence outputs; AG-LIVE is required if collecting from a live environment.
- **Status:** Planned.

### 6.29 — Document deployment, storage, identity, mounts, and network operations

- **Dependencies:** 6.5–6.14 and the verified Phase 3 state-directory contract.
- **Worker boundary:** Operator documentation for Deployment/PVC backup and recovery, single-replica/RWO operation, OIDC, RBAC/Secret privilege, TLS ingress, read-only mounts, resource-set assignment, NetworkPolicy, and local-vs-production boundaries only.
- **Done when:** An operator can understand prerequisites, safe installation review, backup/recovery, credential privilege, ingress/proxy, mount/source ownership, target readiness, and failure responses without obsolete CLI/Job instructions or claims of HA.
- **Verification:** Walk the documentation against rendered manifests, state-directory requirements, and failure tests; link each tested behavior to evidence and keep all unverified items explicitly open.
- **External-effect gate:** AG-DEPLOY and AG-PUBLISH are not granted by writing the documentation; publishing the guide requires AG-PUBLISH.
- **Status:** Planned.

### 6.30 — Document plan/apply/replan, audit, and automation operations

- **Dependencies:** 6.19–6.28 and the Phase 4–5 API/UI contracts.
- **Worker boundary:** Operator workflow, API/OpenAPI, credential rotation status, plan/apply/replan, audit, reports, exact version/privilege matrix, and automation guidance only. Do not add new API behavior.
- **Done when:** Documentation explains read-only source ownership, explicit validation/plan/apply, asynchronous jobs, partial results, replan requirements, audit identifiers, credential no-readback, bearer usage, pagination, and the exact tested version/privilege matrix without real tokens or secrets.
- **Verification:** Check examples against the OpenAPI contract and live/mocked evidence; run documentation link/example/sentinel checks and remove any instruction that implies upload/edit/resume or automatic reconciliation.
- **External-effect gate:** AG-PUBLISH is required before external documentation or matrix evidence publication.
- **Status:** Planned.

### 6.31 — Record limitations, residual risks, and obsolete-instruction cleanup

- **Dependencies:** 6.28–6.30 and the architecture decision.
- **Worker boundary:** Final Phase 6 limitation/risk inventory and repository documentation cleanup only. Do not expand scope or redesign the deployment.
- **Done when:** The documentation states the single-replica/no-database boundary and future HA migration requirement, residual cluster-admin/proxy/ingress/runtime/PVC risks, no-mTLS/no-8.x/no-10.x constraints, no rollback/resume/automatic reconcile, and removes obsolete CLI, one-shot Job, and editable-source instructions without deleting historical evidence that must remain.
- **Verification:** Repository-wide search finds no supported Phase 6 instruction that contradicts the architecture or release range; review residual risks and unresolved approvals with the named owners.
- **Status:** Planned.

### 6.32 — Perform the Phase 6 acceptance review and release decision

- **Dependencies:** 6.2–6.31; every required increment has independently verified evidence and no unresolved blocker.
- **Worker boundary:** Evidence index, constraint checklist, open-risk/approval review, and release recommendation only. Do not deploy, publish, merge, or declare live acceptance from missing evidence.
- **Done when:** The evidence index demonstrates the non-root single-replica `Recreate` Deployment, ClusterIP Service, TLS Ingress, RWO PVC, OIDC, namespaced Secret RBAC, read-only branch-separated mounts, NetworkPolicy, local tooling boundaries, both exact live versions, security/API matrix, reconciliation matrix, and no-leakage scans. The phase gate is then presented for an explicit release decision; it is not automatically passed.
- **Verification:** Independent reviewer checks every increment's focused done/verification result, confirms the target/version/approval records, and reports passed, unverified, blocked, and residual-risk items separately.
- **External-effect gate:** AG-DEPLOY, AG-PUBLISH, and AG-LIVE remain separate approvals even after this review; this increment authorizes none of them.
- **Status:** Planned.

## Phase gate

Phase 6 may pass only after the acceptance review has verified all applicable increments and recorded evidence: the non-root single-replica `Recreate` Deployment, ClusterIP Service, TLS Ingress, `ReadWriteOnce` PVC, OIDC path, namespaced least-privilege Secret RBAC, NetworkPolicy, and branch-separated read-only mounts operate safely; `start-web.sh` remains test/demo-only; both exact live Kibana versions pass the approved compatibility, security/API, and reconciliation matrix; credentials never leak; drift, ownership, dependency, partial-failure, and replan constraints hold; and all deployment, publication, and live-environment actions have their own explicit approval records. Until then, the gate remains open and future work remains planned.
