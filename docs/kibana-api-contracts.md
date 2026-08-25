# Kibana v9 public API contract baseline

This document records the Phase 0 contract evidence for `elastic-maintainer`. It is an implementation baseline, not a substitute for the live compatibility matrix.

## Sources

Pinned public OpenAPI documents from the Kibana repository:

- Kibana 9.2.0: https://raw.githubusercontent.com/elastic/kibana/v9.2.0/oas_docs/output/kibana.yaml
  - SHA-256: `a5cdd9bca0d0046d64eff8618793f60b1370d2c1b33841d23285cf56d47f156d`
- Kibana 9.4.2: https://raw.githubusercontent.com/elastic/kibana/v9.4.2/oas_docs/output/kibana.yaml
  - SHA-256: `16aec3bc6a2f95f084883306ddfa24ae54d40e396a900a8ec138f17a158e7bf4`

The checked-in JSON fixtures are sanitized, minimal projections of these schemas/examples. They contain no copied credentials or deployment-specific values.

## Endpoint matrix

All paths support the standard non-default space prefix `/s/{space_id}` according to the public operation definitions.

The HTTP core also probes the unscoped public `GET /api/status` endpoint and reads only `version.number`; it rejects malformed versions and versions outside `>=9.2.0,<10.0.0`. This core status route is tested synthetically because it is not part of the adapter operation fixture set below.

| Adapter operation | Method and default-space path | 9.2.0 | 9.4.2 | Notes |
| --- | --- | --- | --- | --- |
| List installed integration packages | `GET /api/fleet/epm/packages/installed` | Yes | Yes | Cursor pagination with `searchAfter` and `perPage` |
| Read an exact package version | `GET /api/fleet/epm/packages/{pkgName}/{pkgVersion}` | Yes | Yes | Use for exact-version detail/status checks |
| Install exact package version | `POST /api/fleet/epm/packages/{pkgName}/{pkgVersion}` | Yes | Yes | Requires `kbn-xsrf`; never use unpinned package install |
| List/create agent policies | `GET|POST /api/fleet/agent_policies` | Yes | Yes | List uses `page` and `perPage`; create body accepts caller `id` |
| Read/update agent policy | `GET|PUT /api/fleet/agent_policies/{agentPolicyId}` | Yes | Yes | Update requires complete required fields including `name` and `namespace` |
| Delete agent policy | `POST /api/fleet/agent_policies/delete` | Yes | Yes | Body contains `agentPolicyId`; requires `kbn-xsrf` |
| List/create package policies | `GET|POST /api/fleet/package_policies` | Yes | Yes | List uses `page` and `perPage`; create body accepts caller `id` |
| Read/update/delete package policy | `GET|PUT|DELETE /api/fleet/package_policies/{packagePolicyId}` | Yes | Yes | Mutations require `kbn-xsrf` |
| Read/create/update/delete custom rule | `GET|POST|PUT|DELETE /api/detection_engine/rules` | Yes | Yes | Stable identity is `rule_id`; PUT is full replacement |
| List rules | `GET /api/detection_engine/rules/_find` | Yes | Yes | Uses `page` and `per_page`; response uses `perPage` |
| Read collective prebuilt status | `GET /api/detection_engine/rules/prepackaged/_status` | Yes | Yes | Collective counts only |
| Install/update collective prebuilt rules | `PUT /api/detection_engine/rules/prepackaged` | Yes | Yes | Also installs/updates prebuilt Timelines |

## Compatibility findings

### Integration package lookup

Kibana 9.2.0 does **not** publish `GET /api/fleet/epm/packages/{pkgName}`. That unversioned endpoint appears in 9.4.2. The v1 adapter must therefore use the common-denominator installed-package list and exact-version endpoint. It must not depend on the unversioned package path.

### Caller-defined IDs

Both pinned specifications accept:

- `id` in agent-policy create bodies;
- `id` in package-policy create bodies; and
- `rule_id` in custom detection-rule create bodies.

The live matrix must prove Kibana preserves and resolves those IDs as documented before pruning is enabled.

### Pagination

Three pagination contracts must be implemented and tested independently:

1. EPM installed packages: `perPage` plus opaque `searchAfter` cursor.
2. Fleet agent/package policies: `page` plus `perPage`.
3. Detection rule find: `page` plus `per_page`, with `perPage` in the response.

Completion must be determined from present, stable documented totals and progressive cursors, not from a short page alone. Missing/changing totals, repeated or oversized cursors, inconsistent page metadata, and excessive page/item counts fail closed.

### Mutations and replacement semantics

- Fleet and EPM mutations require `kbn-xsrf` where declared by the operation.
- Detection-rule `PUT /api/detection_engine/rules` replaces the original rule and deletes unspecified fields. The adapter must construct a complete typed update body.
- Prebuilt-rule PUT is one collective operation. No individual prebuilt mutation belongs in v1.
- Automatic mutation retries remain prohibited until an endpoint is proven idempotent for the exact request and failure mode.

### Required privileges

The pinned specs explicitly identify these Fleet route privileges:

- installed packages: `integrations-read` or `fleet-setup` or `fleet-all`;
- exact package install: `integrations-all` and `fleet-agent-policies-all`;
- agent-policy reads: `fleet-agent-policies-read` or `fleet-agents-read` or `fleet-setup`;
- agent-policy mutations: `fleet-agent-policies-all`;
- package-policy deletion: `fleet-agent-policies-all` and `integrations-all`.

The public operation text does not enumerate explicit privilege names for every package-policy and detection-rule operation. Do not infer or hard-code missing privilege claims. Capture the minimum successful role during the live matrix and document it before the Phase 0 contract gate is declared complete.

## Live projection contract

Typed reads preserve the bounded raw item as a private, defensively copied complete-update baseline while fingerprinting only managed fields. Integration fingerprints include name/version; agent-policy fingerprints include caller identity, name, and namespace; package-policy fingerprints include identity, name, namespace, exact package, and sorted agent-policy IDs; custom query-rule fingerprints include `rule_id`, name, type, enabled state, query, severity, interval, language, and sorted indexes; collective prebuilt fingerprints include all seven documented counts. Generated IDs where they are not the caller identity, revisions, versions, timestamps, actors, ownership markers, and other server-managed fields are excluded. Fingerprints use the versioned `elastic-maintainer/kibana-live` domain and RFC-canonical JSON.

Immutable/prebuilt and unsupported non-query rules remain visible as non-manageable collision evidence rather than being mistaken for absent custom rules.

## Version differences relevant to v1

- The 9.4.2 EPM exact-version operations mark `pkgVersion` as required more consistently than the 9.2.0 generated schema. The application requires it in both versions.
- 9.4.2 adds request/query fields that v1 does not need, including EPM dependency-check controls and detection gap-fill filters. Typed projections must ignore these additions safely.
- Agent-policy schemas gain fields between releases. Canonicalization must select only managed fields and must not overwrite unrelated server-managed additions.

## Fixture status

`testdata/contracts/kibana/v9.2.0/` and `testdata/contracts/kibana/v9.4.2/` contain:

- an operation manifest with methods, paths, pagination, and source provenance;
- successful read and mutation response projections for every adapter;
- two-page fixtures for each pagination style;
- representative authentication, authorization, not-found, conflict, throttling, and server errors.

These fixtures verify parser and request contracts once adapter tests are added. They are not represented as live captures. Live 9.2.0 and 9.4.2 verification remains required by the implementation gate.

## Reproducible verification

Run the repository-only structural, provenance, operation-set, reference, and credential-pattern checks with:

```bash
python3 scripts/verify-contract-fixtures.py
```

For pinned OpenAPI response-schema validation, download the two source documents above as `v9.2.0.yaml` and `v9.4.2.yaml`, then run with Python `PyYAML` and `jsonschema` available:

```bash
python3 scripts/verify-contract-fixtures.py --openapi-dir <download-directory>
```

Verification on 2026-08-14 confirmed:

- both source SHA-256 values match the pinned documents;
- all 62 JSON files parse and are referenced appropriately;
- 48 successful and pagination responses validate against the pinned schemas;
- both version manifests expose the same required operation set;
- the 9.2-incompatible unversioned EPM package path is absent; and
- no forbidden credential keys, authorization values, bearer/API-key values, or private-key blocks occur in the fixture JSON.

The missing explicit privilege names identified above remain a deliberate live-matrix evidence gap, not an inferred contract.
