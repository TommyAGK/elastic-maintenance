# Phase 0 retirement inventory

This inventory distinguishes the API-server skeleton from migration artifacts that remain only until later phases replace their test coverage or behavior.

## Current executable surface

- `cmd/elastic-maintainer` is the only Go command.
- The binary starts the HTTP server or prints build identity with `--version`.
- Startup accepts only server configuration, listen, state-directory, public-URL, help, and version flags.
- Tests reject the retired review/apply/plan commands and the retired `--mode`, `--kibana-url`, `--api-key`, and `--namespace` flags.
- `Makefile` builds the server directly as `bin/elastic-maintainer`.

## Removed stale artifacts

- `cmd/elastic-maintenance` was removed when the server entry point landed.
- `config/desired-state.json` was removed. `testdata/server-minimal.yaml` is the non-secret server startup fixture; Phase 1 will add authoritative mounted resource-set examples.
- The one-shot `deploy/kubernetes/job.yaml` was removed because it used the retired CLI and credential environment variables. `deploy/kubernetes/README.md` records that supported manifests land in Phase 6.

## Temporarily retained internal packages

These packages are not wired into the production server command:

| Package | Why it remains | Replacement owner |
| --- | --- | --- |
| `internal/config/config.go` | Preserves prototype desired-state tests while strict resource envelopes are built | Phase 1 |
| `internal/kibana` | Preserves prototype HTTP adapter behavior and tests | Phase 2 read adapters and Phase 4 mutation adapters |
| `internal/mockkibana` | Preserves isolated prototype adapter/reconciler tests | Phase 2 contract-oriented HTTP tests |
| `internal/reconcile` | Preserves prototype review/apply tests without exposing executable behavior | Phase 3 diff/planning and Phase 4 apply engine |

The API server does not import `internal/kibana`, `internal/mockkibana`, or `internal/reconcile`. Removal occurs only after replacement packages own the relevant verified behavior.

## Delivery references

- `Dockerfile` builds and starts `cmd/elastic-maintainer`; image hardening and pinning remain Phase 6 work.
- No Kubernetes workload manifest is currently supported.
- `README.md` describes the web/API architecture and marks the remaining internal reconciler as a migration artifact.
- `start-web.sh` remains local and untracked until its server dependencies exist.
