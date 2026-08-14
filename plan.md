# elastic-maintainer v1 implementation plan

## 1. Decision record

This plan replaces the existing prototype in place.

- Rename the product and binary from `elastic-maintenance` to `elastic-maintainer`.
- Replace the current JSON desired-state format and `--mode=review|apply` interface. There is no v1 compatibility layer or automatic migration for the prototype.
- Keep container packaging and Kubernetes deployment because Kubernetes is a production execution environment for the CLI.
- Treat `start-web.sh` and its Docker-managed Elastic/Kibana stack as local testing and demonstration tooling only.
- After a partial apply, require the operator to generate a new plan explicitly. Saved plans are not resumable.
- Do not add plan signing, HMACs, or a machine-local integrity key. Plans are trusted local artifacts. Apply still validates plan structure, current desired inputs, operation payloads, ownership authority, and live baselines, but it does not promise to detect arbitrary non-semantic edits to plan JSON.
- Keep the existing Git remote and normal repository workflow. “Local-only” means that the application has no hosted control plane, telemetry, or automatic repository/network side effects; it does not mean removing the repository remote.

## 2. Goal and workflow

Build a Go CLI with an optional loopback web interface that reconciles Git-defined Elastic configuration against multiple Kibana 9.x targets and spaces.

The workflow is Terraform-like:

1. Validate target configuration and YAML manifests.
2. Read each selected target and generate a deterministic, non-secret saved plan.
3. Review that plan through the CLI or local web interface.
4. Apply only the operations in that plan after rechecking desired inputs, ownership authority, compatibility, and live baselines.
5. Process targets independently and report partial success without rollback.
6. Generate a new plan after any partial apply or rejected apply.

## 3. Scope and non-goals

### In scope

- Kibana stable releases `>=9.2.0,<10.0.0`.
- Multiple named targets and Kibana spaces.
- Integration packages, Fleet agent policies, Fleet package policies, custom detection rules, and the complete Elastic prebuilt-rule package.
- CLI execution on a workstation, in a container, or as a Kubernetes Job.
- An explicitly launched, loopback-only web interface for local operator use.
- Local file-backed plans, apply reports, managed-resource inventory, and crash-recovery journals.

### Out of scope

- Elastic 8.x or 10.x.
- Internal or undocumented Kibana endpoints.
- A hosted service, persistent application daemon, database server, telemetry, or automatic polling.
- Automatic Git operations, commits, pushes, pull requests, or deployment.
- Cross-target transactions, rollback, or implicit replanning.
- Individual installation, update, or pruning of Elastic prebuilt rules.
- A Kubernetes Service or Ingress for the web interface.
- Protection against a malicious process acting as the same operating-system user or modifying the binary, plan, state, or mounted files.

## 4. Deliverables and repository migration

Replace the prototype with:

- `cmd/elastic-maintainer`: Cobra CLI entry point.
- `internal/config`: strict target configuration loading and validation.
- `internal/manifest`: strict YAML envelope decoding, indexing, selectors, references, and input digests.
- `internal/kibana`: authenticated HTTP client, spaces routing, version discovery, pagination, canonicalization, and resource adapters.
- `internal/reconcile`: inventory, diffing, ownership checks, dependency graph, plan generation, and apply execution.
- `internal/planfile`: versioned JSON plan and apply-report formats.
- `internal/state`: file-backed managed-ID inventory, locking, atomic writes, and operation journal recovery.
- `internal/web`: embedded static UI and loopback HTTP API using the same application services as the CLI.
- `examples/elastic-maintainer.yaml` and representative manifests for every supported kind.
- `deploy/kubernetes`: production-oriented planner and applier Job examples with ConfigMap/Secret/PVC mounts.
- `Dockerfile`: reproducible, non-root runtime image containing the single binary and CA certificates.
- `Makefile` or equivalent local build/test tooling.
- `start-web.sh`: local-only launcher for configured targets or a disposable Docker Elastic/Kibana test stack.
- Updated operator documentation and tests.

Remove or replace the old `cmd/elastic-maintenance` command, JSON model, `config/desired-state.json`, old review/apply implementation, obsolete tests, and stale documentation. Preserve Git history; do not remove or rewrite the configured remote.

## 5. Command-line interfaces

Produce one `elastic-maintainer` binary with Cobra, `gopkg.in/yaml.v3`, `net/http`, and structured `slog` logging.

Commands:

```text
elastic-maintainer validate --config <file> --manifests <dir>
elastic-maintainer plan --config <file> --manifests <dir> --out <plan.json> [--target <selector>] [--state-dir <dir>]
elastic-maintainer apply --plan <plan.json> [--report <report.json>] [--state-dir <dir>]
elastic-maintainer serve --config <file> --manifests <dir> [--plans-dir <dir>] [--state-dir <dir>] [--listen <loopback:port>]
elastic-maintainer version
```

Rules:

- `--target` may be repeated. Each value is either an exact target name or a comma-separated conjunction of `key=value` target-label clauses. Repeated selectors are ORed. Duplicate selections collapse by target identity.
- Default state directory: `$XDG_STATE_HOME/elastic-maintainer`, falling back to the platform user-state directory. In Kubernetes it must be set to a mounted writable volume.
- `apply` obtains the original configuration and manifest paths from the plan. It has no config or manifest override flags.
- The default apply-report path is `<plan-path>.apply-report.json`; `--report` overrides it.
- Human output is deterministic. `--json` may be added as a global machine-output flag, but logs remain on stderr and results on stdout.
- Exit codes: `0` success, `1` validation/plan/apply rejection or total failure, and `2` partial apply where at least one target succeeded and at least one target failed or was blocked. A successful plan command returns `0` whether or not it contains operations.

## 6. Target configuration

Use strict YAML in `elastic-maintainer.yaml`:

```yaml
apiVersion: elastic-maintainer/v1alpha1
stateID: security-platform

targets:
  production-default:
    url: https://kibana.example.test
    space: default
    labels:
      environment: production
      region: eu-west
    apiKeyEnv: KIBANA_PRODUCTION_API_KEY
    caFile: /etc/elastic-maintainer/ca.pem
```

Requirements:

- Reject unknown fields, duplicate YAML keys, duplicate target names, invalid URLs, invalid label keys, empty API-key environment references, and unreadable CA files.
- `stateID` is required and stable. It separates managed-resource inventories belonging to different desired-state configurations.
- A target identity is the tuple `(stateID, target name, normalized URL, space)`. Renaming a target or changing URL/space creates a new identity and does not transfer pruning authority automatically.
- Omit `space` or use `default` for Kibana’s default space. Non-default API paths use `/s/{url-escaped-space}/...`.
- Require HTTPS except for explicit loopback URLs (`localhost`, `127.0.0.0/8`, or `[::1]`) used for development and tests.
- Resolve and read API keys only when remote access is needed. `validate` verifies the environment-variable name but does not require its value unless remote validation is explicitly added later.
- Read CA contents into a target-specific digest. A changed CA file invalidates that target’s plan.
- Never serialize environment-variable values or authorization headers.

## 7. Manifest format and identity

Read `.yaml` and `.yml` files recursively in lexical relative-path order. Reject symlinks, files escaping the manifest root, duplicate YAML keys, unknown envelope fields, empty documents, and unsupported API versions or kinds. A file may contain one or more YAML documents.

Envelope:

```yaml
apiVersion: elastic-maintainer/v1alpha1
kind: AgentPolicy
metadata:
  id: endpoint-agents
  name: Endpoint agents
  targetSelector:
    matchLabels:
      environment: production
  dependsOn: []
spec: {}
```

Semantics:

- `metadata.id` is a required, caller-defined stable logical ID.
- `(kind, metadata.id)` must be unique across the complete manifest set, not merely per file or target.
- `metadata.name` is required operator-facing text. It is not identity.
- `targetSelector.matchLabels` is an exact-match conjunction. An omitted or empty selector applies to every target.
- `dependsOn` contains explicit references formatted as `<Kind>/<metadata.id>`.
- References must resolve in the manifest set and must apply to every target where the referencing resource applies. Reject dangling, cross-selector, self, and cyclic references.
- Resource-specific references are represented as logical IDs, then resolved into API fields during planning. In particular, `PackagePolicy.spec.agentPolicyRef` and `PackagePolicy.spec.integrationRef` refer to desired `AgentPolicy` and `IntegrationPackage` resources.
- Strict resource schemas reject unknown fields and invalid combinations before any remote request.

Stable remote identity mapping:

| Kind | Stable logical/remote identity |
| --- | --- |
| `IntegrationPackage` | `metadata.id`; `spec.name` is the EPM package name and must be unique per selected target |
| `AgentPolicy` | `metadata.id`, sent as Fleet’s caller-defined policy `id` |
| `PackagePolicy` | `metadata.id`, sent as Fleet’s caller-defined package-policy `id` |
| `DetectionRule` | `metadata.id`, sent as Kibana `rule_id` |
| `PrebuiltRules` | `metadata.id`; only one may apply to a target and it controls the collective prebuilt package operation |

## 8. Supported resources

### IntegrationPackage

- Require `spec.name` and an exact pinned semantic `spec.version`; reject `latest` and ranges.
- Install when missing and upgrade when the installed version differs and the requested transition is supported.
- Never uninstall or downgrade automatically. An installed version newer than desired is a conflict unless the public API contract and an explicit future option permit downgrade.
- Use the public EPM package APIs common to both supported versions, including:
  - installed-package inventory: `GET /api/fleet/epm/packages/installed`
  - exact-version read: `GET /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
  - exact install: `POST /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
- Do not depend on unversioned `GET /api/fleet/epm/packages/{pkgName}` because it is absent from the Kibana 9.2.0 public specification.

### AgentPolicy

- Create and update a caller-ID policy through the public Fleet agent-policy APIs.
- Preserve the ownership marker `[managed-by:elastic-maintainer]` in the description while reconciling operator-supplied description text.
- Prune only with inventory authority and a matching marker.

### PackagePolicy

- Require logical references to an `AgentPolicy` and `IntegrationPackage` that apply to the same target.
- Resolve those references to `policy_id`, package name, and exact package version.
- Create and update through the public Fleet package-policy APIs using the caller-defined ID.
- Preserve `[managed-by:elastic-maintainer]` in the description.
- Prune only with inventory authority and a matching marker.

### DetectionRule

- Manage custom rules only through the public detection-rule APIs.
- Set `rule_id` from `metadata.id` and add `elastic-maintainer:managed` to tags without dropping desired user tags.
- Reject desired rules identified by the API as immutable/prebuilt.
- Use complete update requests because Kibana removes omitted fields during rule replacement.
- Prune only with inventory authority and a matching tag.

### PrebuiltRules

- Allow at most one desired `PrebuiltRules` resource per target.
- Read collective status with `GET /api/detection_engine/rules/prepackaged/_status`.
- Install or update all Elastic prebuilt rules and Timelines with `PUT /api/detection_engine/rules/prepackaged`.
- Never update, disable, or prune individual prebuilt rules.
- Treat the operation as collective and canonicalize only documented status/count/version fields needed to determine drift.

All adapters must use documented Kibana v9 public APIs and add the correct space prefix. API contract references belong in code comments and the operator guide, including:

- Elastic Package Manager: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-elastic-package-manager-epm
- Agent policies: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-elastic-agent-policies
- Package policies: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-fleet-package-policies
- Detection rules and collective prebuilt rules: https://www.elastic.co/docs/api/doc/kibana/v9/group/endpoint-security-detections-api

## 9. API client and canonicalization

- Discover Kibana version before planning and recheck it before apply. Reject unsupported versions before reading mutable resources.
- Use a configured HTTP client with CA support, bounded connect/header/request timeouts, response-size limits, context cancellation, and no automatic cross-host redirects carrying authorization.
- Send `Authorization: ApiKey ...` and `kbn-xsrf` where required. Never place credentials in URLs.
- Implement every documented pagination style used by supported list APIs; never assume a single large page is complete.
- Classify errors as authentication, authorization, unsupported version, validation, conflict, not found, rate limit, timeout, and remote failure without logging sensitive response bodies.
- Do not retry mutations automatically. Bounded retries with backoff are allowed only for demonstrably idempotent reads and documented throttling/transient failures.
- Canonicalize desired and live resources through adapter-specific typed projections. Exclude server IDs not used as stable identity, revisions, timestamps, execution summaries, generated fields, and unrelated defaults.
- Normalize semantically unordered maps, sets, tags, and index lists. Preserve ordering where the public API defines it as meaningful.
- Fingerprint canonical JSON with an explicit algorithm and format version, initially SHA-256 over RFC 8785-style deterministic JSON produced by the tool.

## 10. Dependency graph and planning

Build a per-target directed acyclic graph.

- Add automatic edges from each `PackagePolicy` to its referenced `IntegrationPackage` and `AgentPolicy`.
- Add explicit `metadata.dependsOn` edges.
- Apply a stable phase preference—integrations, agent policies, package policies, detection rules/prebuilt rules—only as a tie-breaker among ready nodes. Phase order alone does not make unrelated resources dependent.
- Use `(phase, kind, metadata.id, action)` as the deterministic operation ordering key.
- If an operation fails, mark only its transitive dependants skipped. Continue independent operations on that target and all operations on independent targets.
- Ownership conflicts and unsupported transitions are planning errors for the affected target. Other selected targets may still produce plans, but the overall plan command fails and must not write an applicable plan unless every selected target planned successfully.

Operation classes are `create`, `update`, and `delete`. Unchanged resources are observations, not operations, so a converged plan has zero operations.

## 11. Managed inventory and pruning authority

Ownership markers are necessary but not sufficient for deletion. Durable inventory grants pruning authority.

Store versioned JSON state under:

```text
<state-dir>/inventories/<hash-of-target-identity>.json
<state-dir>/journals/<hash-of-target-identity>.json
<state-dir>/locks/<hash-of-target-identity>.lock
```

Inventory entries contain only non-secret data: state and target identity, kind, logical ID, remote stable ID, ownership-marker type, last confirmed desired fingerprint, and timestamps used for diagnostics.

Rules:

- A resource becomes inventory-managed only after a successful create/update performed by this tool and confirmation that the expected stable ID and ownership marker exist.
- Merely discovering a matching marker never adopts a resource.
- A missing desired custom rule, agent policy, or package policy produces a delete operation only when the exact target inventory contains the same kind/stable ID and the live object still has the expected marker.
- A missing or altered marker, changed stable identity, ambiguous lookup, or missing inventory produces an ownership conflict or safe orphan observation, never deletion.
- Removing an `IntegrationPackage` or `PrebuiltRules` manifest never creates delete operations.
- Lock state per target during plan state reads and apply mutations. Write files atomically using a same-directory temporary file, fsync where supported, rename, and owner-only permissions.
- Before each remote mutation, write a non-secret journal entry containing the plan ID, operation identity, baseline fingerprint, and expected post-state fingerprint. After success and verification, update inventory and clear the journal atomically.
- On startup, recover a pending journal by reading the resource: commit inventory if it exactly matches expected post-state, clear the journal if it still matches baseline, and otherwise stop with a recovery conflict requiring operator action.
- State corruption or an unavailable writable state directory disables mutation and pruning; it never falls back to marker-only authority.

In Kubernetes, state and plans must be stored on a PVC or another mounted volume with equivalent persistence and single-writer semantics. An ephemeral `emptyDir` is suitable only for disposable tests where pruning authority does not need to survive pod replacement.

## 12. Input digests and saved-plan format

A versioned plan is non-secret JSON containing:

- plan format version, tool version, plan ID, and creation time;
- absolute cleaned config path and manifest-root path used on the planning machine/container;
- `stateID`, selected target identities, discovered Kibana versions, and API contract version;
- for each target, a target-input digest and CA-content digest;
- for each target, the sorted applicable manifest file/document identities and a canonical desired-resource digest;
- canonical operations with dependency IDs, desired payload fingerprints, baseline fingerprints, and expected post-state fingerprints;
- unchanged observations and ownership conflicts needed for review;
- inventory generation/fingerprint used to authorize any delete.

Digest behavior:

- Compute the target-input digest from only the selected target’s normalized configuration, target labels, API-key environment-variable name (not value), URL/space, and CA contents.
- Compute desired digests per target from the canonical decoded resources applicable to that target. An unrelated target or manifest edit must not invalidate another target’s operations.
- Also record source-file SHA-256 values for diagnostics. Whitespace-only source changes may change source-file diagnostics, but apply eligibility is based on canonical target inputs and desired resources.
- Apply re-reads the recorded config and manifest paths and reconstructs the same per-target canonical inputs.
- For create/update, verify that each plan payload fingerprint still equals the current canonical desired resource. For delete, verify that the resource is still absent from desired state and that the recorded inventory still grants authority.

Plan trust model:

- Plans are trusted local/operator-controlled files and are not signed or authenticated.
- Apply performs strict JSON decoding, rejects unknown fields and unsupported format/tool versions, and enforces semantic validations above.
- Apply does not use a self-hash as a security claim and does not promise to reject harmless metadata edits or an attacker capable of modifying all same-user files.
- Editing a plan is unsupported. The documented safe workflow is always to generate a new plan.
- Plans, reports, inventory, journals, and logs must never contain API-key values or authorization headers.

## 13. Apply safety and partial failure

Before mutating a target, apply must:

1. Acquire the target state lock and resolve any journal.
2. Re-read and validate the recorded configuration and manifests.
3. Recompute the target-specific input and desired digests.
4. Resolve the target API key freshly from its declared environment variable.
5. Recheck Kibana version compatibility.
6. Re-read every affected resource and compare its canonical baseline fingerprint, including the absence sentinel for creates.
7. Recheck inventory generation and ownership markers for deletes.
8. Reject the entire target before its first mutation if any precondition changed.

Execution rules:

- Targets are independent. A rejected or failed target does not block unrelated targets.
- Within a target, execute the stable dependency order and skip only transitive dependants of failed operations.
- Verify expected post-state after each mutation before updating inventory.
- Do not roll back completed operations.
- Persist an atomic apply report with per-target and per-operation outcomes: created, updated, deleted, unchanged, skipped, conflicted, rejected, and failed.
- Once any operation has succeeded, the plan is consumed for operational purposes. Whether apply fully or partially succeeds, retry requires an explicit new `plan` command against current state.
- Reapplying an old plan normally fails baseline checks. There is no `resume`, `force`, or implicit replan option in v1.

## 14. Web interface

The embedded Kibana-style web interface exposes:

- validation results;
- selected target and desired-resource inventory;
- saved-plan summaries and operation/dependency review;
- ownership conflicts, drift, and rejected-target explanations;
- apply initiation and persisted per-target reports;
- partial-failure and “generate a new plan” guidance.

The web layer calls the same validation, planning, state, and apply services as the CLI. It must not implement alternate reconciliation logic.

Security requirements:

- Accept only literal loopback listen addresses and reject wildcard or non-loopback binds.
- Permit only expected `Host` values for the bound listener to resist DNS rebinding.
- Make all GET/HEAD routes side-effect free.
- Require `application/json`, a same-origin `Origin` when present, compatible Fetch Metadata headers, and a per-process CSRF token for mutation requests.
- Set a restrictive Content Security Policy, `X-Content-Type-Options: nosniff`, no-store headers for sensitive operational pages/API responses, and conservative frame/referrer policies.
- Serialize mutation jobs: only one plan/apply mutation may run per state directory at a time, with visible busy/conflict responses.
- Keep API keys exclusively in the server process environment. Never return credentials, authorization headers, unrestricted environment data, or sensitive remote response bodies to the browser.
- The Kubernetes manifests do not expose `serve` through a Service or Ingress. Local use against Kubernetes may use an explicitly operator-controlled port-forward only if the loopback security model remains intact.

## 15. Container and Kubernetes delivery

### Container

- Use a pinned Go builder image and a minimal non-root runtime image with CA certificates.
- Build a reproducible `elastic-maintainer` binary, record version/commit metadata at link time, and include no example credentials or writable repository content.
- Support read-only config/manifest mounts and separate writable plan/state/report mounts.
- Document image invocation for `validate`, `plan`, and `apply`.

### Kubernetes

Provide plain manifests or a small Kustomize-ready base for:

- a planner Job that mounts target config/manifests read-only, API keys from Secrets, and writes plans/reports/state to a PVC;
- a separate applier Job that consumes an explicitly selected saved plan from the same PVC;
- least-privilege pod security settings: non-root, read-only root filesystem, dropped capabilities, seccomp runtime default, bounded resources, and no service-account token unless required;
- ConfigMap/Secret/PVC examples without embedding real credentials;
- a NetworkPolicy example limiting egress to DNS and declared Kibana endpoints where cluster policy supports it.

Do not deploy a long-running controller, automatic reconciliation loop, web Service, or Ingress. Operators are responsible for creating the planner and applier Jobs and approving the plan between them.

### Local test launcher

`start-web.sh` may:

- build and launch the loopback web interface against operator-provided targets; or
- create an owned, disposable Docker network, Elasticsearch container, Kibana container, volumes, and ephemeral API key for local contract testing.

It must label and ownership-check every Docker object before reuse/removal, bind published ports to loopback, avoid printing secrets, revoke ephemeral keys when possible, and never be represented as production deployment tooling.

## 16. Logging, redaction, and reports

- Use `slog` with stable fields such as target, space, kind, resource ID, operation, phase, duration, and outcome.
- Centralize redaction. Never log API keys, authorization headers, full environment maps, raw Secret objects, or unbounded remote bodies.
- Sanitize errors before logging or serializing them to plans/reports/web responses.
- Human summaries are deterministic and show each target independently.
- Machine reports use a versioned schema and contain no credentials.
- Add tests that scan serialized plans, reports, state, logs, and HTTP responses using sentinel secret values.

## 17. Implementation phases

### Phase 0 — contract fixtures and migration skeleton

Detailed sub-plan: `docs/implementation/subplans/phase-0-contract-fixtures-and-migration-skeleton.md`

- Confirm documented request/response contracts against Kibana 9.2.0 and the current selected 9.x patch.
- Capture sanitized `httptest` fixtures for every adapter and pagination style.
- Rename the command/module packages and remove prototype-only behavior.
- Add build tooling and version metadata.

Gate: exact public endpoints, caller-defined ID support, required privileges, and canonical fields are documented for all five kinds before adapter implementation proceeds.

### Phase 1 — strict inputs and validation

Detailed sub-plan: `docs/implementation/subplans/phase-1-strict-inputs-and-validation.md`

- Implement target config, manifest envelopes, resource schemas, selectors, references, dependency cycle checks, and canonical input digests.
- Add examples and `validate`.

Gate: malformed, ambiguous, duplicate, dangling, cross-selector, and secret-bearing inputs fail locally with actionable diagnostics.

### Phase 2 — API client and read adapters

Detailed sub-plan: `docs/implementation/subplans/phase-2-api-client-and-read-adapters.md`

- Implement spaces, authentication, TLS/CA, version checks, pagination, error classes, and canonical live-resource projections.
- Implement read/status methods for all kinds.

Gate: contract tests pass for both supported live versions and no single-page assumption remains.

### Phase 3 — inventory, diff, and saved plans

Detailed sub-plan: `docs/implementation/subplans/phase-3-inventory-diff-and-saved-plans.md`

- Implement file state, locks, journals, ownership rules, pruning authority, dependency DAG, per-target planning, deterministic plan JSON, and CLI review output.

Gate: converged plans contain zero operations; unmanaged or marker-only resources cannot produce deletes.

### Phase 4 — apply

Detailed sub-plan: `docs/implementation/subplans/phase-4-apply.md`

- Implement preflight validation, baseline checks, mutation adapters, post-state verification, inventory/journal updates, dependency skips, partial-target continuation, reports, and exit codes.

Gate: every safety and partial-failure acceptance test passes with fault injection around each remote/state write boundary.

### Phase 5 — web interface

Detailed sub-plan: `docs/implementation/subplans/phase-5-web-interface.md`

- Implement embedded assets and the loopback API over shared services.
- Add browser/API tests for validation, planning, apply reporting, CSRF/origin/host enforcement, concurrency, and redaction.

Gate: every operator-relevant CLI outcome has equivalent visibility in the web interface without exposing credentials or internal-only data.

### Phase 6 — container, Kubernetes, and live matrix

Detailed sub-plan: `docs/implementation/subplans/phase-6-container-kubernetes-and-live-matrix.md`

- Finalize the Docker image, Kubernetes planner/applier Jobs, PVC workflow, security contexts, operator guide, and local Docker test launcher.
- Run end-to-end tests against Kibana 9.2.0 and the current selected 9.x patch (initially 9.4.2 unless a newer stable 9.x release is current when implementation begins).

Gate: workstation, container, and Kubernetes Job workflows all produce, review, apply, and persist the same plan/report formats.

Implement in incremental local branches. Require captain approval before guarded fast-forward integration into `main`. Do not push, publish images, deploy, or contact third parties without explicit approval.

## 18. Test strategy

### Unit tests

- Strict YAML decoding, duplicate keys, unknown fields, multi-document input, traversal/symlink rejection.
- Target selectors, stable identity, duplicate/collision handling, references, DAG cycles, and deterministic ordering.
- Resource schemas, exact version validation, canonicalization, default/set ordering, and fingerprints.
- Diffing, ownership conflicts, inventory-only pruning, safe orphan behavior, and collective prebuilt semantics.
- Per-target input digests, CA changes, source relocation behavior, plan schema validation, and operation-to-current-desired verification.
- State locking, atomic writes, corruption handling, and every journal recovery branch.
- Secret redaction and report formatting.

### HTTP contract tests

Use `httptest` for:

- API-key headers and redaction;
- default and non-default Kibana spaces;
- every pagination style and boundary;
- caller-defined ID create/read/update/delete behavior;
- complete detection-rule updates;
- EPM exact-version install and unsupported downgrade conflict;
- collective prebuilt status/install/update;
- 401/403/404/409/429/5xx, timeouts, malformed/oversized responses, redirect rejection, and revision drift;
- per-operation post-state verification.

### Reconciliation and failure tests

- A second plan after successful apply has zero operations.
- Mutated selected configuration, manifests, CA content, inventory, or remote state rejects the affected target before mutation.
- An unrelated target or non-applicable manifest edit does not invalidate another target.
- Unmanaged and marker-only resources are never modified or deleted.
- Missing/altered ownership markers are conflicts, never deletes.
- One failing target does not block unrelated targets.
- A failed operation skips only its transitive dependants.
- A partial apply writes an accurate report and requires a new plan.
- Crash injection before/after remote mutation and state writes recovers safely or stops with a conflict.
- Plans, reports, inventory, journals, logs, and web responses contain no sentinel API keys.
- Prebuilt rules install/update collectively and are never individually pruned.

### Live compatibility matrix

Run integration tests against:

- Kibana 9.2.0, the oldest supported release; and
- the current stable 9.x patch selected at implementation/release time, initially 9.4.2.

Pin exact image versions in test configuration and record the tested matrix in release output. Any discovered contract difference must be assessed for CLI, web, plan/report schema, canonicalization, operator documentation, and Kubernetes impact before compatibility is claimed.

## 19. Acceptance criteria

The v1 implementation is complete when:

- The old prototype interface and JSON format have been replaced and repository documentation is consistent.
- All commands and the loopback web interface reuse one reconciler and safety model.
- All five supported kinds work through documented public APIs in default and non-default spaces.
- A successful apply followed by a new plan is converged with zero operations.
- Selected desired-input, CA, inventory, version, or remote-baseline drift blocks mutation for the affected target.
- Unrelated target changes do not block safe independent targets.
- No resource is pruned without both exact durable inventory authority and a live ownership marker.
- Dependency failures skip only downstream resources and independent targets continue.
- Partial apply is accurately reported, never rolled back, and can proceed only through an explicit new plan.
- No API key appears in plans, reports, state, journals, logs, browser responses, container layers, or Kubernetes ConfigMaps.
- Prebuilt rules are installed/updated only as a complete package and never individually pruned.
- The web interface accurately represents validation, drift, ownership, dependency, rejection, partial failure, and apply outcomes.
- The Docker image runs as non-root, Kubernetes planner/applier Jobs use mounted Secrets and persistent plan/state storage, and `start-web.sh` remains clearly local-test-only.
- Unit, contract, reconciliation, security, container, Kubernetes workflow, and live-version matrix tests pass.
