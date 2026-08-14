# Phase 6 — container, Kubernetes exposure, and live matrix

## Objective

Package and expose the single-replica web/API service securely, support externally mounted branch-separated sources, and prove the complete product against Kibana 9.2.0 and current stable 9.x.

## Prerequisites

- Phases 0–5 gates pass.
- API/UI/state formats are stable for v1.
- OIDC provider, ingress domain/TLS, namespace, PVC class, Secret policy, and test targets are available.
- Pulling images, deploying, or publishing remains approval-gated.

## Substeps

### 6.1 Finalize reproducible build/image

1. Pin Go, builder, and runtime image digests.
2. Build with `-trimpath` and deterministic version/commit/date metadata.
3. Run as dedicated non-root UID/GID.
4. Include CA roots and no unnecessary shell/tools.
5. Use read-only root filesystem with explicit writable state/temp mounts.
6. Add OCI metadata and local checksums/SBOM where required.
7. Verify no secrets/examples with credentials enter layers.

### 6.2 Define Kubernetes workload

1. Single-replica Deployment with Recreate strategy.
2. ClusterIP Service and TLS Ingress.
3. ReadWriteOnce PVC mounted at the state path.
4. Read-only mounted server config and one/more resource-set volumes.
5. Session/OIDC client Secrets and non-secret ConfigMaps.
6. Startup/readiness/liveness probes with correct semantics.
7. Non-root, dropped capabilities, seccomp runtime-default, read-only root, bounded resources, and disabled service-account token automount only if incompatible with Secret API access; otherwise use explicit projected token settings.
8. Avoid disruption/rolling settings that create simultaneous writers.

### 6.3 Implement Secret provisioning RBAC

1. Dedicated namespace and ServiceAccount.
2. Namespaced Role for only required Secret verbs.
3. No cluster-wide Secret access.
4. Application prefix/ownership policy remains mandatory because RBAC cannot enforce create-name prefixes fully.
5. Validate no access to unrelated Secrets through integration tests.
6. Document cluster-admin residual trust.

### 6.4 Configure TLS ingress and OIDC

1. Require HTTPS and expected public URL.
2. Configure trusted proxy ranges/forwarded headers.
3. Set HSTS and secure-cookie behavior.
4. Configure OIDC redirect/logout URLs and role claim mappings.
5. Validate browser and bearer-token flows through the real ingress path.
6. Deny direct unintended external pod/service exposure.

### 6.5 Model branch-separated resource mounts

1. Provide examples for ConfigMap, CSI, GitOps-generated volume, or init-container populated read-only directories without embedding Git credentials in the app.
2. Mount separate branches/revisions at separate resource-set paths.
3. Write optional bounded `.source-revision` provenance files externally.
4. Assign targets to resource-set IDs in mounted config.
5. Demonstrate that service never executes Git or edits mounts.
6. Test source switch/drift invalidating existing plans.

### 6.6 Add NetworkPolicy and egress guidance

1. Allow required DNS, OIDC issuer/JWKS, Kubernetes API, and configured Kibana destinations.
2. Restrict unnecessary ingress to Service/Ingress/probe paths according to cluster capabilities.
3. Document limitations of hostname-based Kibana/issuer policies.
4. Avoid blocking Kubernetes Secret API access accidentally.

### 6.7 Finalize local `start-web.sh`

1. Track only after server build/config/examples exist.
2. Support mounted local sources and configured OIDC development mode or a documented safe local identity provider/test authenticator unavailable in production builds/config.
3. Manage owned disposable Elasticsearch/Kibana Docker resources.
4. Bind local ports to loopback and ownership-check all removal/reuse.
5. Generate/revoke ephemeral Kibana API keys without printing/storing them.
6. Exercise CA trust upload when local TLS fixtures are enabled.
7. Label script as test/demo only.

### 6.8 Build exact live matrix

1. Pin Elasticsearch/Kibana 9.2.0 and current stable 9.x, initially 9.4.2.
2. Record image digests, license mode, spaces, and sanitized configuration.
3. Provision enough resources for every pagination mode.
4. Create minimum-privilege Kibana API keys.
5. Configure trusted CA certificate tests.
6. Capture sanitized evidence only.

### 6.9 Run security/API matrix

1. OIDC browser login/logout/session and bearer automation.
2. Full role endpoint matrix.
3. Credential upload/rotation/delete, ownership collision, CA parse/trust, no-readback/no-cache/no-log/no-PVC.
4. Ingress/proxy/Host/CORS/CSRF/CSP/rate/body/SSE/idempotency controls.
5. ServiceAccount cannot read/update unrelated Secrets.
6. Restart/PVC/job/audit recovery and one-writer enforcement.

### 6.10 Run live reconciliation matrix

1. Version detection and compatibility.
2. Default/non-default spaces.
3. Exact package install and downgrade conflict.
4. Caller-defined policy/rule IDs.
5. Pagination, create/update/delete, complete rule replacement, collective prebuilt operation.
6. Successful apply then zero-operation plan.
7. Mounted source/target config/Secret CA/inventory/version/live drift rejection.
8. Inventory-plus-marker pruning only.
9. Independent target/dependency partial failure and mandatory replan.
10. Sentinel scan of every artifact/channel.

### 6.11 Finalize operator and API documentation

1. Deployment, PVC backup/recovery, OIDC, RBAC, Secret privilege, ingress, mount, resource-set assignment, credential rotation, plan/apply/replan, audit, and automation guides.
2. Exact tested version/privilege matrix.
3. Single-replica/no-database limitations and future HA migration boundary.
4. Residual cluster-admin/proxy/ingress risks.
5. Remove obsolete CLI/Job/editable-source instructions.

## Phase gate

The non-root single-replica Deployment, Service, TLS Ingress, PVC, OIDC, Secret RBAC, and branch-separated mounts operate safely; both live Kibana versions pass API/security/reconciliation acceptance; credentials never leak; and deployment/publication remains explicitly approved.
