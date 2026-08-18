# Phase 1 — mounted inputs, resource sets, and validation API

## Objective

Implement authoritative read-only mounted configuration/resource sets and expose deterministic validation/inventory through asynchronous API jobs.

## Prerequisites

- Phase 0 server/API skeleton passes.
- Mounted configuration and resource-set schemas in `plan.md` are approved.

## Current status

Substeps 1.1 through 1.8 are implemented. Strict configuration decoding rejects unknown, duplicate, multi-document, and credential-bearing configuration; startup validation bounds canonical identifiers and labels, enforces mount/Secret policy and HTTPS-or-loopback URL rules, and derives immutable normalized target identities. Resource-set discovery resolves configured roots within mounted boundaries, reads `.yaml`/`.yml` files in lexical order under explicit limits, rejects symlinks/special files/escapes, returns safe relative locations, and validates bounded single-line revision metadata. Resource decoding supports the five narrow `v1alpha1` kind schemas, multi-document YAML, exact versions, typed references, unique identities, sanitized source diagnostics, and deliberate rejection of YAML indirection, credentials, unsupported fields, rule variants, and duplicate prebuilt declarations. Assignment now produces bounded deterministic credential-safe inventories, evaluates exact selectors only against targets assigned to the same resource set, preserves normalized target identity and revision provenance, and rejects defensive structural or applicability inconsistencies. Reference resolution validates explicit and automatic package-policy dependencies across the complete resource set, rejects dangling, self, duplicate, cross-selector, and cyclic edges, and produces bounded deterministic prerequisite-first DAGs for every target. Metadata-only source snapshots now retain raw file hashes and revision provenance while versioned RFC 8785/SHA-256 desired digests cover canonical typed resource sets and target-scoped applicable state without credentials, unrelated mounts, raw formatting, or revision text. Validation execution now uses a bounded asynchronous worker service with idempotent starts, cancellation and restart recovery, a durable-compatible repository boundary, fresh mounted-input reads, scoped metadata-only results, and safe structured diagnostics. Authenticated source, target, and validation endpoints now expose fresh or historical metadata-only views through strict JSON, bounded endpoint-scoped pagination, idempotent planner-authorized job creation, safe error mapping, and handler/OpenAPI parity. Initial web views begin in substep 1.9.

## Substeps

### 1.1 Implement strict server/target configuration

1. Decode strict YAML with duplicate-key and unknown-field rejection.
2. Validate `stateID`, `publicURL`, OIDC references, resource sets, targets, labels, URL/space, Secret namespace/name, and role mappings.
3. Normalize target identities and HTTPS/loopback rules.
4. Restrict resource-set paths to configured mount roots.
5. Restrict credential Secret names/namespaces to configured policy.
6. Keep configuration read-only.

### 1.2 Discover resource-set files safely

1. Resolve each assigned root once.
2. Walk `.yaml`/`.yml` recursively in lexical order.
3. Reject symlinks, traversal, special files, root escapes, and unreadable files.
4. Read optional revision metadata as untrusted display text with strict size limits.
5. Retain file/document locations for diagnostics.
6. Never execute hooks or Git commands.

### 1.3 Decode strict resource envelopes

1. Implement versioned envelope, identity, selector, and dependency fields.
2. Support multi-document YAML.
3. Enforce `(kind,id)` uniqueness per resource set.
4. Add strict schemas for all five kinds.
5. Reject credential fields, unsupported rule variants, `latest`/ranges, and multiple applicable prebuilt resources.
6. Preserve source locations through typed decoding.

Implementation note: Phase 1.3 enforces at most one `PrebuiltRules` declaration per resource set. Phase 1.4 also retains a defensive target-level applicability check after selector evaluation.

### 1.4 Resolve assignments and selectors

1. Assign each target to exactly one resource set.
2. Evaluate target labels only among targets assigned to that set.
3. Treat omitted selector as all assigned targets.
4. Reject selector results/references inconsistent across target applicability.
5. Build deterministic target/resource inventory.
6. Display resource-set ID, optional external revision, and digest per target.

### 1.5 Resolve references and DAGs

1. Parse `<Kind>/<id>` references.
2. Add automatic package-policy edges.
3. Resolve explicit dependencies.
4. Reject dangling, self, duplicate, cross-selector, and cyclic references.
5. Produce stable per-target DAGs for planning.

Implementation note: edge records use dependent-to-prerequisite direction, while target DAG nodes are emitted in prerequisite-first execution order. Dormant resources are excluded from target DAGs but their references and cycles are still validated so label changes cannot activate an invalid graph.

### 1.6 Canonicalize and snapshot sources

1. Canonicalize typed config/resources.
2. Compute per-resource-set and per-target desired digests.
3. Include assigned target config and source contents, not unrelated mounts.
4. Store source-file hashes and revision metadata for diagnostics.
5. Treat whitespace-equivalent canonical resources consistently.
6. Never copy authoritative resource files into writable state as a new source of truth.

Implementation note: desired digests use domain `elastic-maintainer/desired` and format `v1`. Raw hashes and external revision values are diagnostic provenance only; formatting-only and revision-only changes retain the same desired digest. A canonical projection change requires a new digest version.

### 1.7 Implement validation job execution

1. Add durable-compatible validation job service behind an in-memory/file abstraction.
2. Re-read mounted inputs when the job begins.
3. Produce structured diagnostics, counts, assignments, source metadata, and digests.
4. Require planner or administrator permission to initiate; viewers may inspect results.
5. Do not require target credentials or contact Kibana.
6. Bound job concurrency and cancellation.

Implementation note: authorization remains centralized at the Phase 1.8 HTTP boundary. The service records the initiating actor, validates the complete mounted snapshot before applying optional result selection, never reads target credentials or contacts Kibana, and serializes private idempotency state only through an explicit storage DTO.

### 1.8 Implement source/target validation API

1. Implement source and target list/detail endpoints.
2. Implement validation creation/status endpoints with idempotency keys.
3. Paginate large resource/diagnostic lists.
4. Use safe source paths relative to configured roots where possible.
5. Return no environment data or credential values.
6. Update OpenAPI and examples with handler-parity tests.

Implementation note: source and target GETs build a fresh internally consistent mounted snapshot; validation records remain historical. Detail payloads independently paginate files, resources, diagnostics, source summaries, and target summaries. Production runtime authentication remains deny-by-default until OIDC is implemented.

### 1.9 Add initial web views

1. Show mounted source sets, target assignments, revision metadata, and digests.
2. Start validation jobs and show progress/results.
3. Show source-located diagnostics.
4. Make all resource/config views read-only and explain external GitOps ownership.
5. Do not add resource-edit controls.

## Verification

- Unit/property tests cover strict YAML, duplicate keys, traversal/symlinks, schemas, assignments, selectors, references, DAGs, and digests.
- API tests cover role checks, idempotency, pagination, safe diagnostics, and OpenAPI parity.
- Validation succeeds without Kubernetes/Kibana credentials or network access.

## Phase gate

Invalid mounts fail safely with actionable diagnostics. Valid mounts yield deterministic source/target/resource inventories and digests, and the API/UI cannot alter authoritative configuration or resources.
