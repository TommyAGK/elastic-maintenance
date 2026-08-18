# Elastic Maintainer

Elastic Maintainer is being rebuilt as a web-first reconciliation service for Elastic Security configuration in Kibana 9.x.

## Status

The repository has passed the **Phase 0: API-server migration skeleton** gate and is not production-ready. Phase 1 mounted-input and validation work is underway. Strict startup configuration, bounded descriptor-relative mounted-source discovery on Linux, typed `v1alpha1` decoding for all five resource kinds, deterministic target assignment/selector inventory, and prerequisite-first per-target dependency DAGs are implemented. Canonical digests, jobs, and API integration remain incomplete. The active direction is defined by:

- Primary plan: `plan.md`
- Accepted architecture decision: `docs/architecture/0001-web-first-api.md`
- Current phase sub-plan: `docs/implementation/subplans/phase-1-mounted-inputs-resource-sets-and-validation-api.md`
- Kibana contract baseline: `docs/kibana-api-contracts.md`

## Target architecture

- Long-running, single-replica Go API service deployed to Kubernetes.
- Embedded web UI as the primary operator experience.
- Versioned `/api/v1` REST API and OpenAPI contract for external automation.
- Application-level OIDC authentication with viewer, planner, applier, and administrator roles.
- Mounted Git/YAML resource sets remain authoritative and read-only.
- Each Kibana target is assigned to one mounted resource set, allowing external orchestration to mount separate branches or revisions.
- Administrators upload Kibana API keys and CA trust bundles through the protected UI/API; the service stores them in owned Kubernetes Secrets.
- Non-secret plans, jobs, reports, audit records, and managed-resource inventory are stored as versioned JSON on a ReadWriteOnce PVC.
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

The skeleton exposes `/health/live`, `/health/ready`, and `/api/v1/openapi.json`. The initial API contract covers session, mounted sources, targets, credential administration, validations, plans, jobs, reports, and audit. OIDC routes remain explicit placeholders. Protected routes deny access by default until production OIDC lands. Injected test authentication exercises session/RBAC behavior; authorized validation, plan, and apply requests enforce JSON and idempotency contracts but return explicit not-implemented job responses until durable execution is built. Prototype internal packages remain temporarily for test evidence but are not imported by the production server; their retirement owners are recorded in `docs/implementation/phase-0-retirement-inventory.md`. Supported Kubernetes workload manifests land in Phase 6.
