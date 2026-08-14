# Phase 0 prototype baseline

Recorded on the `feat/prototype-replacement-skeleton` branch before replacement work.

## Verification

- `go test ./...` passes for every existing package.
- Current module declaration: `module elastic-maintenance`.
- Current binary: `cmd/elastic-maintenance`.
- Current interface: standard-library flags with `--mode=review|apply`.
- Current desired state: one JSON document at `config/desired-state.json`.
- Current credentials: `KIBANA_URL` and `KIBANA_API_KEY`, with an API-key command-line flag also accepted.
- Current reconciliation stops on the first API error and has no saved plan, durable inventory, pruning safety, target isolation, spaces routing, canonical fingerprints, or web server.

## Replacement inventory

| Area | Current tracked path | Phase 0 disposition |
| --- | --- | --- |
| CLI | `cmd/elastic-maintenance/` | Replace with the `cmd/elastic-maintainer/` API-server entry point; no operator CLI |
| Desired-state model | `internal/config/` | Replace with strict target and manifest packages |
| Kibana client | `internal/kibana/` | Replace after contract fixtures are established |
| Reconciler | `internal/reconcile/` | Replace; do not preserve review/apply mode semantics |
| Mock server | `internal/mockkibana/` | Replace with adapter-oriented contract fixtures and HTTP tests |
| Example config | `config/desired-state.json` | Remove; replace with YAML examples |
| Container | `Dockerfile` | Retain packaging, rename binary, harden later |
| Kubernetes | `deploy/kubernetes/job.yaml` | Retain deployment intent; replace obsolete flags and storage model |
| Documentation | `README.md` | Replace old interface and layout |
| Local test script | `start-web.sh` | Keep local and untracked until its dependencies exist |

## Tracked prototype references

The old product/module name appears in the Go module, internal imports, command path, Dockerfile, Kubernetes manifest, tests, API XSRF header, and README. The old `review` and `apply` mode constants appear in the CLI and reconciliation tests. These references must disappear or be deliberately retained only as repository/image history text.

## Preservation rules

- Preserve Git history and the configured `origin` remote.
- Do not track `start-web.sh` during steps 1–4.
- Do not remove passing prototype code until the replacement API-server skeleton can build and its replacement tests exist.
- Do not claim live Kibana compatibility from mock fixtures alone.
