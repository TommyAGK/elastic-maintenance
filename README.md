# Elastic Maintainer

Elastic Maintainer is being rebuilt as a web-first reconciliation service for Elastic Security configuration in Kibana 9.x.

## Status

The repository has passed the **Phase 2: OIDC, Kubernetes Secrets, Kibana reads, and inventory API** gate and completed **Phase 3.1: versioned non-secret state formats**, **Phase 3.2: hardened state-directory primitives/runtime integration**, **Phase 3.3.1: durable job-record repository**, **Phase 3.3.2a: fail-closed job recovery policy and CAS interruption transition**, **Phase 3.3.2b: bounded startup job recovery**, **Phase 3.3.3: durable scoped idempotency results**, **Phase 3.3.4a: durable scheduler core**, **Phase 3.3.4b: scheduler runtime lifecycle integration**, **Phase 3.3.5: authenticated durable job reads/polling projections**, **Phase 3.3.6a: durable cooperative cancellation mutation core**, **Phase 3.3.6b: authenticated HTTP cancellation and bounded SSE projection**, **Phase 3.4.1: safe durable audit-event schema validation**, **Phase 3.4.2: immutable safe pre-storage audit envelope**, and **Phase 3.4.3a: pure bounded deterministic JSON audit segment codec**. Phase 3 as a whole is not passed and the repository is not yet production-ready. Production OIDC and bearer authentication, audited break-glass access, centralized RBAC/audit hooks, least-privilege owned Kubernetes Secrets, no-readback credential workflows, leased TLS/API-key clients, bounded space-aware Kibana HTTP, complete pagination, typed canonical read adapters, target readiness/version probes, and asynchronous paginated live inventory are implemented in the API and embedded UI. Live inventory jobs and credential replay history are intentionally bounded and process-local in v1. Phase 3.3.2b performs one coherent bounded jobs snapshot, validates and classifies every record before CAS-interrupting queued/running records, preserves terminal bytes, and runs before the listener. Phase 3.3.3 adds a separate durable idempotency repository under the fixed state directory with exact actor/action/key scope hashing, digest conflict protection, expiry-aware replay, and CAS completion; it is not integrated into existing services or routes. Phase 3.3.4a adds the standalone durable scheduler core with bounded admission, scheduler-owned execution contexts, CAS lifecycle transitions, safe executor outcomes, and cooperative shutdown; it does not resume jobs after restart. Phase 3.3.4b wires that scheduler into runtime construction/readiness/lifecycle only: recovery precedes scheduler creation, fixed runtime capacity is used, no route submissions are registered, and safe cleanup retains state if scheduler shutdown fails. Phase 3.3.5 exposes authenticated GET/HEAD job list and polling projections backed by the recovered durable repository, with strict bounded filters/tokens, snapshot-safe pagination, and a redacted public job shape; it performs no scheduling, cancellation, SSE, audit, or writes. Verification timestamp: 2026-09-01T11:05:23Z. Phase 3.3.6b adds authenticated cancellation and bounded non-secret SSE job projections with fixed safe errors, live origin/CSRF enforcement, exact public-projection event IDs, aggregate per-handler admission capped at 32 streams, a 4096-byte serialized event-data bound, strict Accept quality grammar, and no cancellation on disconnect. Verification timestamp: 2026-09-03T11:44:39Z. Phase 3.4.2 adds only the immutable safe pre-storage audit envelope: canonical state bytes are structurally allowlisted, defensively copied, strictly revalidated, and returned through a fixed sentinel without a mutable event accessor; no segment sink, recovery, recorder, runtime integration, or transient call-site coverage is claimed. Verification timestamp: 2026-09-04T10:54:12Z. Phase 3.4.3a adds only pure bounded deterministic JSON audit segments around those envelopes: the versioned compact wrapper has fixed `apiVersion`, `sequence`, `recordCount`, and `records` fields; records contain lowercase SHA-256 corruption checksums over exact canonical events; empty records are `[]`; 1,024-record and 4 MiB complete-document bounds, strict wrapper checks, canonical state validation, duplicate-ID rejection, sequence binding, hostile-array bounds, defensive copies, and fixed safe errors are covered. SHA-256 is a corruption checksum, not tamper authentication. It has no statefs, storage, runtime, recorder, or HTTP integration. Verification timestamp: 2026-09-04T12:33:07Z. Next is Phase 3.4.3b, atomic JSON segment persistence and rotation. Diffing and saved plans remain future work. The active direction is defined by:

- Primary plan: `plan.md`
- Accepted architecture decision: `docs/architecture/0001-web-first-api.md`
- Completed Phase 1 sub-plan: `docs/implementation/subplans/phase-1-mounted-inputs-resource-sets-and-validation-api.md`
- Phase 3 state-format contract: `docs/state-formats.md`
- Production state-directory contract: `docs/operations/state-directory.md`
- Phase 3 sub-plan: `docs/implementation/subplans/phase-3-pvc-state-diff-plans-and-planning-api.md`
- Kibana contract baseline: `docs/kibana-api-contracts.md`

## Target architecture

- Long-running, single-replica Go API service deployed to Kubernetes.
- Embedded web UI as the primary operator experience.
- Versioned `/api/v1` REST API and OpenAPI contract for external automation.
- Application-level OIDC authentication with viewer, planner, applier, and administrator roles, plus one vault-controlled local break-glass administrator for complete IdP outages.
- Mounted Git/YAML resource sets remain authoritative and read-only.
- Each Kibana target is assigned to one mounted resource set, allowing external orchestration to mount separate branches or revisions.
- Administrators upload Kibana API keys and CA trust bundles through the protected UI/API; the service stores them in owned Kubernetes Secrets.
- Non-secret plans, jobs, reports, audit records, managed-resource inventory, and scoped idempotency results are stored as versioned JSON on a ReadWriteOnce PVC. The Linux runtime opens and holds one hardened state store for its lifetime, and readiness checks both serving state and state-directory health.
- Docker and Kubernetes are production delivery mechanisms. `start-web.sh` is local test tooling only and is not currently tracked.

## Supported v1 resources

- Integration packages
- Fleet agent policies
- Fleet package policies
- Custom detection rules
- Collective Elastic prebuilt rules

Compatibility target: stable Kibana releases `>=9.2.0,<10.0.0` using documented public APIs only.

## Source-of-truth boundary

The service does not clone, fetch, poll, edit, or commit Git repositories. GitOps or another external orchestrator mounts branch/revision content as read-only resource-set directories. The service validates, plans, and applies only explicit operator requests against those mounted snapshots.

## Security boundary

- Production access uses a TLS Kubernetes Ingress and application-level OIDC.
- The service never returns uploaded Kibana credentials or CA certificate bodies.
- Credential values must not enter PVC state, plans, reports, audit records, logs, or browser storage.
- V1 is intentionally single-replica because JSON/PVC state has a single-writer design.

## Development baseline

The canonical Go module is `github.com/TommyAGK/elastic-maintenance`. Run the standard build checks and inspect the linker-injected build identity with:

```bash
make test
make vet
make build
make version
```

This creates the server directly at `bin/elastic-maintainer`. Start the current skeleton with the non-secret local fixture:

```bash
bin/elastic-maintainer --config testdata/server-minimal.yaml
```

The server exposes the embedded operator shell at `/`, health endpoints, and `/api/v1/openapi.json`. Authenticated source, target, and validation operations are implemented; the UI consumes those endpoints directly and never offers mounted-resource editing. Browser OIDC is enabled explicitly through mounted configuration and Secret files; the local fixture keeps it disabled and protected APIs deny access by default. Bearer automation authentication is available whenever OIDC is enabled; plan/apply and credential operations remain explicit placeholders. Prototype internal packages remain temporarily for test evidence but are not imported by the production server; their retirement owners are recorded in `docs/implementation/phase-0-retirement-inventory.md`. Supported Kubernetes workload manifests land in Phase 6.
