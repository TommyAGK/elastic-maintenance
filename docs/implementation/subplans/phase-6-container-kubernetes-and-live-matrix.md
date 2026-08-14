# Phase 6 — container, Kubernetes, and live matrix

## Objective

Deliver reproducible workstation/container/Kubernetes workflows and prove supported behavior against Kibana 9.2.0 and the selected current stable 9.x patch.

## Prerequisites

- Phases 0–5 gates pass.
- CLI, web, plan, report, inventory, and journal formats are stable for v1.
- External image publication and deployment remain separately approval-gated.

## Substeps

### 6.1 Finalize local build and release metadata

1. Pin the supported Go toolchain and module dependencies.
2. Build with `-trimpath` and deterministic version/commit/date inputs.
3. Add checksums and software-component metadata where required.
4. Run tests, vet, race tests, and static checks before packaging.
5. Document supported architectures and any CGO assumptions.

### 6.2 Harden the Docker image

1. Use pinned builder and runtime image references.
2. Build the single `elastic-maintainer` binary.
3. Run as a dedicated non-root UID/GID.
4. Include CA certificates and no shell unless operationally justified.
5. Use a read-only root filesystem design with explicit writable mounts.
6. Keep examples and credentials out of image layers.
7. Add OCI labels for version/source/license.
8. Test `validate`, `plan`, `apply`, and `version` in the image.

### 6.3 Define container mount contracts

1. Mount config/manifests read-only.
2. Mount plans, reports, and state on explicit writable paths.
3. Pass API keys only through runtime secret environment injection.
4. Keep planner and applier paths identical so recorded plan source paths resolve.
5. Document UID/permission requirements and CA mounts.
6. Test missing/read-only/unsafe mount failures.

### 6.4 Replace Kubernetes deployment examples

1. Create a planner Job with read-only ConfigMap/projected config/manifests, Secret-backed API keys, and PVC-backed plan/state/report storage.
2. Create a separate applier Job that consumes an explicitly selected plan from the same PVC.
3. Use non-root, read-only root filesystem, dropped capabilities, runtime-default seccomp, and bounded resources.
4. Disable service-account token mounting unless required.
5. Add restart/backoff/deadline behavior that does not imply safe mutation retries.
6. Provide a NetworkPolicy example for DNS and Kibana egress where feasible.
7. Do not create a controller, CronJob reconciliation loop, Service, or Ingress.

### 6.5 Validate the approval workflow

1. Run planner Job and persist the plan.
2. Retrieve/review the plan without exposing Secrets.
3. Require an explicit operator action to create the applier Job.
4. Persist and retrieve the apply report.
5. Generate a new planner Job after partial/rejected apply.
6. Test pod replacement with persistent state and plan storage.
7. Document single-writer state constraints.

### 6.6 Finalize `start-web.sh` local testing

1. Track the script only after its referenced Make targets, binary, examples, and flags exist.
2. Support configured local targets and a disposable Docker Elastic/Kibana stack.
3. Label every created network, volume, and container with owner/project/version metadata.
4. Refuse to reuse or delete objects without exact ownership labels.
5. Bind all published ports to loopback.
6. Generate credentials in memory/tmpfs, avoid printing them, and revoke ephemeral keys when possible.
7. Make failure cleanup idempotent and ownership-safe.
8. Clearly label the script as local test/demo tooling, not production deployment.

### 6.7 Build the live-version matrix harness

1. Pin exact Elasticsearch/Kibana 9.2.0 images.
2. Pin the selected current stable 9.x images, initially 9.4.2 unless superseded at implementation time.
3. Create isolated owned networks/volumes and deterministic test spaces.
4. Provision least-privilege API keys for each adapter workflow.
5. Capture versions, image digests, license mode, test configuration, and sanitized evidence.
6. Avoid retaining credentials in logs/artifacts.
7. Require explicit approval before pulling missing images or running large local stacks.

### 6.8 Run live adapter contracts

1. Verify version discovery and compatibility rejection.
2. Verify default/non-default spaces.
3. Verify all pagination styles with enough resources to cross page boundaries.
4. Verify caller-defined IDs for agent policies, package policies, and rules.
5. Verify exact package installation and newer-version conflict behavior.
6. Verify complete custom-rule update semantics.
7. Verify collective prebuilt status/install/update.
8. Verify minimum privileges and 401/403 behavior.
9. Verify conflict, revision drift, and API failure handling.

### 6.9 Run live reconciliation acceptance

1. Apply all supported kinds and confirm the next plan is empty.
2. Mutate selected inputs, CA, inventory, markers, and remote state and confirm target rejection.
3. Confirm unmanaged resources are untouched.
4. Confirm inventory-plus-marker pruning only.
5. Inject one target and dependency failure and verify independent progress.
6. Confirm partial apply requires a new plan.
7. Scan plans, reports, state, journals, logs, container output, and web responses for secrets.
8. Confirm prebuilt rules are never individually pruned.

### 6.10 Assess web and operator impact

1. For every contract/version difference, decide whether operators need new visibility or control.
2. Update web API/UI, reports, diagnostics, documentation, and tests together.
3. Keep internal mechanics and credentials hidden.
4. Record unsupported or unverified behavior explicitly rather than weakening gates.

### 6.11 Final documentation and handoff

1. Document workstation, container, planner Job, approval, applier Job, report, and replan workflows.
2. Document required Kibana privileges and API-key lifecycle implications.
3. Record the exact tested compatibility matrix and residual risks.
4. Confirm old prototype instructions and artifacts are gone.
5. Prepare a local handoff summary with evidence paths.
6. Do not push, publish images, deploy, or merge without explicit approval.

## Verification

- Build and inspect the container image locally.
- Validate Kubernetes manifests client-side and, when authorized, in a disposable namespace.
- Run complete live matrices against both exact versions.
- Run all unit, contract, race, security, and workflow suites.

## Phase gate

Workstation, container, and Kubernetes planner/applier workflows produce the same safe plan/report formats; both live versions pass the acceptance matrix; packaging is non-root and secret-safe; local Docker tooling is ownership-safe; and all unverified gaps are explicit before handoff.
