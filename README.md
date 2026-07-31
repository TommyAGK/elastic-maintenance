# Elastic Maintenance

Go-based maintenance utility for Elastic Security in Kibana.

It supports:

- reviewing current integrations, Fleet policies, and rules
- installing missing assets
- updating drifted assets
- packaging the tool for Kubernetes execution

## Layout

- `cmd/elastic-maintenance`: CLI entrypoint
- `internal/config`: desired-state configuration models
- `internal/kibana`: Kibana API client and reconciliation helpers
- `internal/reconcile`: diff/apply planning
- `deploy/kubernetes`: manifests for running the tool in-cluster

## Test coverage

The project includes both unit tests and integration-style tests.

- Unit tests cover:
  - desired-state config loading
  - Kibana client request helpers and error handling
  - CLI flag validation
  - reconciliation planning and report formatting
  - mock server request recording
- Integration-style tests cover:
  - review mode against the mock Kibana server
  - apply mode against the mock Kibana server
  - end-to-end request flow through the real client and reconciler

