# Phase 1 — strict inputs and validation

## Objective

Implement deterministic, side-effect-safe target configuration and manifest validation, including selectors, stable identities, references, dependency checks, and canonical per-target input digests.

## Prerequisites

- Phase 0 gate passes.
- The replacement CLI exists and `validate` can be connected to application services.
- YAML v3 is pinned in `go.mod`.

## Substeps

### 1.1 Define typed target configuration

1. Create versioned structs for `apiVersion`, `stateID`, and named targets.
2. Model URL, space, labels, API-key environment reference, and optional CA file.
3. Reject unknown fields, duplicate YAML keys, duplicate targets, invalid labels, malformed URLs, and invalid environment-variable names.
4. Normalize URLs and default spaces without resolving credentials.
5. Define target identity as `(stateID, name, normalized URL, space)`.
6. Require HTTPS except for explicitly recognized loopback development URLs.

### 1.2 Implement secure source discovery

1. Clean and resolve the manifest root once.
2. Walk recursively in lexical relative-path order.
3. Accept only `.yaml` and `.yml` files.
4. Reject symlinks, traversal, special files, unreadable files, and files escaping the root.
5. Decode multiple YAML documents while retaining file/document location for diagnostics.
6. Reject empty documents and duplicate mapping keys before typed decoding.

### 1.3 Define the resource envelope

1. Model `apiVersion`, `kind`, `metadata`, and `spec` strictly.
2. Require stable `metadata.id` and operator-facing `metadata.name`.
3. Model `targetSelector.matchLabels` and `dependsOn`.
4. Reject unsupported API versions/kinds and unknown envelope fields.
5. Enforce global uniqueness of `(kind, metadata.id)`.
6. Keep source location attached to every decoded resource.

### 1.4 Define kind-specific schemas

1. Add strict types for `IntegrationPackage`, `AgentPolicy`, `PackagePolicy`, `DetectionRule`, and `PrebuiltRules`.
2. Require exact integration versions and reject `latest`, ranges, and invalid semantic versions.
3. Require logical agent-policy and integration references on package policies.
4. Reserve ownership markers for tool injection and prevent contradictory user values.
5. Reject custom-rule fields that imply immutable/prebuilt behavior.
6. Enforce at most one applicable `PrebuiltRules` resource per target.
7. Prohibit credential fields in every desired resource schema.

### 1.5 Resolve target selectors

1. Implement exact `matchLabels` conjunction semantics.
2. Treat omitted/empty selectors as applying to all targets.
3. Implement CLI selectors: exact target name or comma-separated `key=value` conjunction.
4. OR repeated CLI selectors and deduplicate selected targets by identity.
5. Reject malformed selectors and zero-match selectors with actionable diagnostics.
6. Preserve stable target ordering.

### 1.6 Resolve references and dependencies

1. Parse `<Kind>/<metadata.id>` references.
2. Add automatic package-policy references to integration and agent policies.
3. Resolve explicit `dependsOn` references.
4. Reject dangling, self, duplicate, cross-selector, and cyclic references.
5. Verify each dependency applies everywhere its dependant applies.
6. Produce a stable per-target DAG representation for Phase 3.

### 1.7 Canonicalize desired inputs

1. Convert typed configuration and resources into canonical semantic projections.
2. Sort maps and semantically unordered sets.
3. Preserve meaningful list ordering.
4. Include selected target labels, API-key variable name, URL/space, and CA contents in the target input digest.
5. Exclude API-key values and unrelated targets.
6. Compute per-target desired-resource digests and separate source-file hashes for diagnostics.
7. Test semantically equivalent YAML and unrelated-target edits.

### 1.8 Connect `validate`

1. Replace the placeholder with config/manifests loading and local validation.
2. Do not require API-key values or contact Kibana.
3. Print deterministic target/resource counts and diagnostics.
4. Return exit `0` on success and `1` on validation failure.
5. Expose the same validation service for later plan and web use.

### 1.9 Add examples and operator guidance

1. Add a complete target config example.
2. Add valid manifests for all five kinds and dependency relationships.
3. Add focused invalid examples only where useful for tests/documentation.
4. Document identity, selector, reference, CA, HTTPS, and secret-handling rules.

## Verification

- Unit tests cover duplicate keys, unknown fields, documents, traversal/symlinks, schemas, selectors, references, cycles, IDs, exact versions, and digests.
- Fuzz or property tests cover selector parsing, YAML decoder failure paths, and canonical determinism.
- `validate` performs no network access and does not require credentials.
- Sentinel credentials never appear in diagnostics.

## Phase gate

Malformed, ambiguous, duplicate, dangling, cross-selector, cyclic, and secret-bearing inputs fail locally with precise source locations. Valid inputs produce stable target/resource indexes and canonical per-target digests.
