# Kubernetes delivery status

There are no supported Kubernetes manifests in the Phase 0 API-server skeleton.

The obsolete one-shot `Job` manifest was removed because it invoked the retired review/apply CLI and passed Kibana credentials through process environment variables. It must not be used as a deployment template.

Phase 6 will provide the supported single-replica `Deployment`, `Service`, TLS `Ingress`, ReadWriteOnce PVC, ConfigMap/Secret mounts, namespaced Secret RBAC, probes, security context, and NetworkPolicy examples described in `plan.md`.
