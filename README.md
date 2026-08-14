# Elastic Maintainer

Elastic Maintainer is being rebuilt as a web-first reconciliation service for Elastic Security configuration in Kibana 9.x.

## Status

The repository is in **Phase 0: API-server migration skeleton** and is not production-ready. The superseded CLI has been replaced by a strict server entry point and HTTP routing skeleton with health, readiness, OpenAPI, request-safety middleware, deny-by-default authentication, centralized RBAC, and asynchronous validation/plan/apply job contracts. The active direction is defined by:

- Primary plan: `plan.md`
- Accepted architecture decision: `docs/architecture/0001-web-first-api.md`
- Current phase sub-plan: `docs/implementation/subplans/phase-0-contract-fixtures-and-api-server-migration-skeleton.md`
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

Run the current tests and inspect build identity with:

```bash
go test ./...
go run ./cmd/elastic-maintainer --version
```

Start the current skeleton with:

```bash
go run ./cmd/elastic-maintainer --config internal/config/testdata/server-valid.yaml
```

The skeleton exposes `/health/live`, `/health/ready`, and `/api/v1/openapi.json`. OIDC routes remain explicit placeholders. Protected routes deny access by default until production OIDC lands. Injected test authentication exercises session/RBAC behavior; authorized validation, plan, and apply requests enforce JSON and idempotency contracts but return explicit not-implemented job responses until durable execution is built. The old internal reconciler, JSON desired-state example, and Kubernetes Job remain migration artifacts and are not the final interface.
