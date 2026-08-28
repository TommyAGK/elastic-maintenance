# Persisted state formats

**Phase 3.1 status: complete.** These are directory-neutral, non-secret JSON contracts only. Phase 3.3.3 adds repository behavior without changing this state schema or version. Phase 3.2 hardened state-directory runtime integration, Phase 3.3.1 durable job-record persistence, Phase 3.3.2a fail-closed recovery policy/transition, Phase 3.3.2b bounded startup job recovery, and Phase 3.3.3 durable scoped idempotency persistence are also complete; see `docs/operations/state-directory.md` for that production contract. Phase 3 as a whole is **not passed**; scheduling, remaining durable jobs/audit, planning, and API work remain later substeps.

## Contract envelope

Every persisted document is one strict JSON object with one lockstep API version:

```json
{
  "apiVersion": "elastic-maintainer/state/v1alpha1",
  "kind": "..."
}
```

The supported kinds are `SourceSnapshot`, `OwnershipInventory`, `PreMutationJournal`, `Plan`, `Job`, `Report`, `Idempotency`, and `AuditEvent`. The codec rejects unknown fields, duplicate object keys, trailing values, non-canonical key casing, null required arrays, invalid bounded values, unsupported kinds/versions, and invalid cross-field relationships. Encoded documents are validated before they are returned.

Timestamps are UTC RFC3339 values. Collection order is part of the contract wherever identity or execution order is meaningful; validators reject duplicate or non-deterministically ordered values rather than sorting caller-owned data.

## Fingerprint domains

All state-layer fingerprints use this shape:

```json
{
  "domain": "elastic-maintainer/desired",
  "algorithm": "sha256",
  "version": "v1",
  "value": "<64 lowercase hexadecimal characters>"
}
```

The four domains are:

- `elastic-maintainer/desired` — source, target desired, operation desired, and last-desired fingerprints;
- `elastic-maintainer/kibana-live` — remote baseline, expected-post, and observed live state;
- `elastic-maintainer/ownership-inventory` — inventory and per-target aggregate fingerprints;
- `elastic-maintainer/target-config` — target configuration fingerprints.

Every field validates its expected domain. A digest from another domain is invalid even when its algorithm, version, and value are otherwise valid. The embedded `manifest.SourceSnapshot` remains the existing manifest type and is validated as the manifest desired domain; `manifest` and `kibana` packages are not changed by this state contract.

## Document contracts

### `SourceSnapshot`

Stores `id`, UTC `capturedAt`, and the validated `manifest.SourceSnapshot`. It contains metadata, source locations, and canonical desired digests only; it never stores source bodies or Secret contents.

### `OwnershipInventory`

Stores one state instance's inventory ID, state ID, monotonically positive generation, timestamps, an ownership-inventory aggregate fingerprint, and sorted exact target identities. Each target has its own positive generation and inventory-domain aggregate fingerprint. Entries are sorted and unique by manifest kind/logical ID and kind/remote ID, and contain only kind, logical ID, remote ID, marker, and a desired-domain last-desired fingerprint. Marker compatibility is kind-specific: integrations use `none`, agent/package policies use `description`, detection rules use `rule-tag`, and prebuilt status uses `prebuilt-status`.

### `PreMutationJournal`

Stores one mutation operation and lifecycle, including its ownership `marker` and positive `inventoryGeneration` for update/delete journals. Create journals may omit `remoteID` while prepared or mutating; mutation-succeeded, post-verified, and committed create journals must contain the assigned remote ID. Update and delete journals always require a remote ID and a marker compatible with the resource kind. Deletes use the same ownership/prunable-kind restrictions as plans: integrations and prebuilt rules are never deletable.

`baseline` and `expectedPost` are non-pointer `RemoteStateAssertion` values:

```json
{"presence":"absent"}
```

or:

```json
{"presence":"present","fingerprint":{"domain":"elastic-maintainer/kibana-live","algorithm":"sha256","version":"v1","value":"..."}}
```

`absent` must not contain a fingerprint; `present` must contain one. Create requires absent baseline/present expected-post, update requires present/present, and delete requires present/absent.

### `Plan`

Stores the plan `stateID`, creator actor projection, tool version, one `sourceSnapshotID`, sorted exact `PlanTarget` entries, mutation operations, and observations. Every target identity must carry the same state ID as the plan; operation and observation targets must match a declared target exactly. There is no singular plan-level `source` or redundant provenance snapshot ID.

Before saving or using a plan, the service must load and validate the referenced `SourceSnapshot`, require its ID to equal `sourceSnapshotID`, require the plan and every selected target identity to use the same exact `stateID`, and verify the selected target identities plus source/resource-set/target desired fingerprints and revisions match that snapshot. Before use it must also verify the planned target configuration fingerprint against the current target configuration. This cross-document snapshot and configuration linkage is a service-level precondition, not a stateless document-validator check.

Each target stores its Kibana version, source provenance, inventory generation/fingerprint, and `CredentialMetadata`. Source provenance is target-scoped and contains `resourceSetID`, optional revision, resource-set desired fingerprint, target desired fingerprint, and target-config fingerprint. It has no snapshot ID.

Credential metadata contains only a Secret namespace/name, required Secret `resourceVersion`, optional UID/generation, required UTC `rotatedAt`, required `rotatedBy` subject, and optional certificate SHA-256/not-after metadata. It cannot represent Secret keys, request digests, certificate bodies, or credential values.

Plan operations have only `create`, `update`, or `delete` actions. They contain a non-negative phase and are sorted by exact target, phase, resource kind, logical ID, action, and operation ID. Dependencies are sorted, unique, same-target references to earlier operations. Their desired fingerprint is optional only where the action permits it and is always desired-domain; baseline/expected-post are non-pointer live-state assertions. Create operations never contain a remote ID; update and delete operations always do. Deletes require an ownership-compatible marker, a supported prunable kind (`AgentPolicy`, `PackagePolicy`, or `DetectionRule`), and an inventory generation exactly equal to the declared target generation. Integrations and prebuilt rules cannot be deleted.

Non-mutating outcomes (`unchanged`, `conflict`, `skip`, and `reject`) are observations, not operation actions. Observations carry only a bounded safe `code` and `severity`; they never persist arbitrary messages. They may include remote ID, marker, desired fingerprint, live-state assertion, and inventory generation. Their target generation must match the declared target.

### `Job`

Is the durable projection of `jobs.Job`. It stores actor subject/roles/auth method, request metadata, idempotency key/request digest, and safe plan/report/failure links. It contains no request body, credentials, headers, or remote response. `interrupted` is terminal. Startup recovery takes one bounded coherent jobs snapshot, validates and classifies every record before its first write, preserves terminal bytes, and CAS-interrupts queued/running records before the listener starts. It preserves an existing running `startedAt`; a queued job interrupted before execution keeps `startedAt` absent, and both receive one canonical UTC `finishedAt` plus a policy-defined safe failure code. Malformed, ambiguous, over-bound, or concurrently changed records fail closed without exposing document contents or IDs.

### `Report`

Contains safe target and operation outcomes. Operation actions remain mutation actions (`create`, `update`, or `delete`), while outcome values explain execution (`created`, `updated`, `deleted`, `unchanged`, `skipped`, `conflicted`, `rejected`, or `failed`). Create results require a remote ID when created or conflicted; failed, rejected, or skipped creates may have none. Update and delete results always require a remote ID. Results persist only an optional bounded `reasonCode`, never arbitrary messages. Baseline and expected-post values are live-domain remote assertions.

### `Idempotency`

Binds an idempotency key to an actor, a bounded namespaced action, and a request digest. The durable repository stores each record under a domain-separated SHA-256 hash of the exact normalized actor/action/key scope; the request digest is a conflict discriminator and is not part of that hash. `result` is an optional typed `{kind,id}` reference whose kind is `job`, `plan`, `report`, or `credential-mutation`; credential-mutation IDs may identify a durable idempotency/result record. A pending record requires a job ID and a nil (omitted or JSON-null) result. A terminal record requires a typed result and may omit the job ID for synchronous mutations. A job result must match the record's job ID.

`CreateOrReplay` takes an explicit caller-supplied canonical UTC observation time `at`; a new or replacement candidate's `CreatedAt` must exactly equal `at` (a replay candidate may retain the original creation time). Expiry decisions use only `at`, never an implicit candidate timestamp or wall clock. Expiry is inclusive at `ExpiresAt`; nil expiry never expires. Expiry governs replay retention, not completion: a pending record may be completed after expiry while its ETag still matches. Capacity reclamation or replacement may win first, in which case the old ETag fails. Expired replacement is a CAS operation and requires the replacement's canonical `CreatedAt` to be at or after the prior `ExpiresAt`.

### `AuditEvent`

Stores the safe audit projection: event ID/time, request/action/outcome, optional target/plan/job IDs, bounded reason code, and an optional actor containing only subject, roles, and authentication method. Persisted actions use a bounded namespaced action pattern rather than a finite registry, so adding an action does not require changing this state schema.

## Strict codecs and non-secret boundary

Typed `Encode<Type>`/`Decode<Type>` helpers use the strict common codec. `DecodeDocument` dispatches only the eight supported kinds. The package has no filesystem I/O, persistence, locking, job execution, or API behavior.

Actor state contains only subject, sorted unique known roles, and authentication method; subjects must already equal their trimmed form. Persisted schemas cannot represent API keys, CA bodies, OIDC/bearer tokens, CSRF tokens, cookies, sessions, Secret data, request bodies, certificate bodies, or arbitrary diagnostic messages. The state layer does not attempt heuristic secret redaction: unsafe free text is not a representable persisted field.

## Version and migration policy

There is **no silent migration**. `elastic-maintainer/state/v1alpha1` is an immutable lockstep state-set contract. Changing the API version **or changing any kind in the state set** requires an explicit, reviewed migration of the complete state set; a kind must not be changed independently while leaving the rest of the state set silently readable. A document with another version is rejected as unsupported.

An explicit offline migration must read the old version with its old strict decoder, validate the complete old state set, produce a new-version state set, validate every new document, and write it separately with an operator-visible migration report. The online service must not migrate state during startup, reads, writes, recovery, or API requests. Destructive or lossy conversions require explicit operator approval and a backup/rollback plan.

Adding the fixed `idempotency/` directory is a pre-release state-layout change, not a state-document schema migration: no document kind or version changed. However, once this binary has opened a state directory, an older binary that rejects the new directory cannot roll back in place. Use a backup/restore procedure to return to an older binary.
