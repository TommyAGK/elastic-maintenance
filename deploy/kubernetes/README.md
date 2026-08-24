# Kubernetes delivery status

The full production workload manifests remain scheduled for Phase 6. The obsolete one-shot `Job` was removed because it invoked the retired CLI and exposed Kibana credentials through process environment variables.

`secret-rbac.yaml` is the Phase 2 least-privilege RBAC boundary for target credential Secrets. It creates the `elastic-maintainer` ServiceAccount and grants only `get`, `create`, `update`, and `delete` on Secrets in one namespace—never list or watch. Adjust all namespace fields through the authorized deployment workflow, and configure the eventual Deployment with `serviceAccountName: elastic-maintainer`. Kubernetes RBAC cannot express a name-prefix wildcard, so the application independently enforces the configured namespace, `elastic-maintainer-target-` prefix, state ownership annotation, and target ownership annotation before every operation.

Phase 6 will add the supported single-replica `Deployment`, `Service`, TLS `Ingress`, ReadWriteOnce PVC, ConfigMap/Secret mounts, probes, security context, and NetworkPolicy examples described in `plan.md`.
