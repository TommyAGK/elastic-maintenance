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

