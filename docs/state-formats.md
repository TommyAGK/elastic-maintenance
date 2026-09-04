# Persisted state formats

**Phase 3.1 status: complete.** The state documents are directory-neutral, non-secret JSON contracts, and audit segments use their own versioned deterministic JSON contract below. Later repository, scheduler, and HTTP work does not change these state schemas or versions. Phase 3.2 hardened state-directory runtime integration, Phase 3.3 work through authenticated HTTP cancellation and bounded SSE projection (3.3.6b), Phase 3.4.1 safe durable audit-event schema validation, Phase 3.4.2 immutable safe pre-storage audit envelope, and Phase 3.4.3a bounded JSON audit segment codec are complete; see `docs/operations/state-directory.md` for the production storage contract and the Phase 3 subplan for implementation evidence. Phase 3 as a whole is **not passed**; atomic audit persistence/rotation (3.4.3b), recovery/reads, durable recorder/runtime integration, planning, and later API work remain.

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

Is the durable projection of `jobs.Job`. It stores actor subject/roles/auth method, request metadata, idempotency key/request digest, safe plan/report/failure links, and the internal cooperative `cancellationRequested` flag. It contains no request body, credentials, headers, or remote response. The cancellation flag is never included in the public `JobResponse` polling or SSE projection. `interrupted` is terminal. Startup recovery takes one bounded coherent jobs snapshot, validates and classifies every record before its first write, preserves terminal bytes, and CAS-interrupts queued/running records before the listener starts. It preserves an existing running `startedAt`; a queued job interrupted before execution keeps `startedAt` absent, and both receive one canonical UTC `finishedAt` plus a policy-defined safe failure code. Malformed, ambiguous, over-bound, or concurrently changed records fail closed without exposing document contents or IDs.

### `Report`

Contains safe target and operation outcomes. Operation actions remain mutation actions (`create`, `update`, or `delete`), while outcome values explain execution (`created`, `updated`, `deleted`, `unchanged`, `skipped`, `conflicted`, `rejected`, or `failed`). Create results require a remote ID when created or conflicted; failed, rejected, or skipped creates may have none. Update and delete results always require a remote ID. Results persist only an optional bounded `reasonCode`, never arbitrary messages. Baseline and expected-post values are live-domain remote assertions.

### `Idempotency`

Binds an idempotency key to an actor, a bounded namespaced action, and a request digest. The durable repository stores each record under a domain-separated SHA-256 hash of the exact normalized actor/action/key scope; the request digest is a conflict discriminator and is not part of that hash. `result` is an optional typed `{kind,id}` reference whose kind is `job`, `plan`, `report`, or `credential-mutation`; credential-mutation IDs may identify a durable idempotency/result record. A pending record requires a job ID and a nil (omitted or JSON-null) result. A terminal record requires a typed result and may omit the job ID for synchronous mutations. A job result must match the record's job ID.

`CreateOrReplay` takes an explicit caller-supplied canonical UTC observation time `at`; a new or replacement candidate's `CreatedAt` must exactly equal `at` (a replay candidate may retain the original creation time). Expiry decisions use only `at`, never an implicit candidate timestamp or wall clock. Expiry is inclusive at `ExpiresAt`; nil expiry never expires. Expiry governs replay retention, not completion: a pending record may be completed after expiry while its ETag still matches. Capacity reclamation or replacement may win first, in which case the old ETag fails. Expired replacement is a CAS operation and requires the replacement's canonical `CreatedAt` to be at or after the prior `ExpiresAt`.

### `AuditEvent`

Stores the safe audit projection: caller-supplied event ID, canonical UTC occurrence time, request/action/outcome, optional target/plan/job IDs, bounded reason code, and an optional actor containing only subject, sorted unique known roles, and authentication method. Successful events require an actor; denied and failed events may be anonymous. IDs and request/reason values use the v1 bounded safe-code grammar (up to 128 ASCII bytes). Persisted actions use a bounded namespaced action pattern (`[a-z][a-z0-9_-]*([.][a-z][a-z0-9_-]*)+`, up to 128 bytes) rather than a finite registry, so adding an action does not require changing this state schema.

`state.NewAuditEvent` is the narrow transient-to-durable projection boundary. It supplies the version/kind, canonicalizes the timestamp to UTC, normalizes the auth actor, drops display/session/CSRF/token-bearing auth fields, requires newly projected job references to use the current durable job ID grammar (`[A-Za-z0-9_-]{1,64}`), copies only the safe event metadata, and validates before returning. It does not generate IDs, redact arbitrary input, persist, rotate, recover, or expose HTTP. Empty optional values and anonymous actors are omitted on canonical encoding. For v1 compatibility, decoding continues to treat explicit JSON `null` optionals as absent and accepts legacy job references using the wider safe-code grammar; tightening those reads requires an explicit complete state-set migration. `EncodeAuditEvent` and `DecodeAuditEvent` use the common strict bounded codec (including exact keys and duplicate/trailing/unknown-field rejection).

`auditenvelope.Envelope` is the immutable pre-storage boundary over those canonical bytes. Its `New` constructor calls `state.NewAuditEvent` and then `state.EncodeAuditEvent`, retains only a defensive byte copy, and exposes no mutable `state.AuditEvent` accessor. `Bytes` returns another defensive copy. `Validate` rejects the zero value and any malformed, over-bound, or non-canonical bytes by requiring strict decode followed by byte-for-byte canonical re-encoding; all failures use one fixed `ErrInvalidEnvelope` sentinel. This package does not generate IDs or perform persistence, statefs, sink, recorder, runtime, HTTP, or call-site work. The safe grammar is not heuristic secret detection: callers are responsible for supplying only producer-owned reason codes and metadata, and grammar-valid secret-looking text is not a security approval.

### Audit segments

`internal/auditsegment` provides the pure deterministic JSON codec for audit segment files. It introduces no new `state` document kind and performs no filesystem, locking, rotation, recovery, or runtime work. Version 1 is a compact wrapper with this exact key order and no optional fields:

```json
{"apiVersion":"elastic-maintainer/audit-segment/v1","sequence":7,"recordCount":1,"records":[{"sha256":"<64 lowercase hex>","event":<canonical AuditEvent object>}]}
```

`records` is always an array; an empty segment encodes `[]`, never `null`. `sequence` is strictly positive and must match the caller's expected sequence. `recordCount` is bounded by `MaxRecords = 1024` and must equal the records-array length. `MaxSegmentBytes` is 4,194,304 bytes (4 MiB), including the complete compact JSON document. Appends are accepted at the exact byte boundary but return `ErrSegmentFull` if either the byte or record bound would be crossed.

`Decode` caps input before decoding, uses a bounded duplicate-key/allowlist scan for the segment and record wrappers, and then strictly decodes and exactly re-encodes the wrapper. Unknown fields, duplicate keys at every wrapper depth, non-canonical casing, key order, whitespace, number/string representations, trailing JSON, and `null` forms are rejected. Each raw event is passed through `state.DecodeAuditEvent` and must equal its exact `state.EncodeAuditEvent` output. This rejects explicit-null optionals in segments, while preserving the state decoder's documented compatibility for canonical legacy dotted job references. The bounded records decoder retains at most 1,024 records; even a hostile records array within the 4 MiB input cap cannot cause an unbounded records-list allocation.

`sha256` is the lowercase SHA-256 digest of the exact canonical event bytes. It is a corruption-detection checksum only, not tamper authentication: an actor able to rewrite a segment can recompute it. `New` creates an empty segment, and `Append` accepts only a validated immutable `auditenvelope.Envelope`; both return new immutable values. `Bytes` and `Record.Bytes` are defensive copies, while `Records` exposes only ordered immutable IDs and canonical event bytes. Duplicate event IDs and all malformed, inconsistent, or non-canonical values use fixed safe errors without caller bytes.

## Strict codecs and non-secret boundary

Typed `Encode<Type>`/`Decode<Type>` helpers use the strict common codec. `DecodeDocument` dispatches only the eight supported kinds. The package has no filesystem I/O, persistence, locking, job execution, or API behavior.

Actor state contains only subject, sorted unique known roles, and authentication method; subjects must already equal their trimmed form. Persisted schemas cannot represent API keys, CA bodies, OIDC/bearer tokens, CSRF tokens, cookies, sessions, Secret data, request bodies, certificate bodies, or arbitrary diagnostic messages. The state layer does not attempt heuristic secret redaction: unsafe free text is not a representable persisted field.

## Version and migration policy

There is **no silent migration**. `elastic-maintainer/state/v1alpha1` is an immutable lockstep state-set contract. Changing the API version **or changing any kind in the state set** requires an explicit, reviewed migration of the complete state set; a kind must not be changed independently while leaving the rest of the state set silently readable. A document with another version is rejected as unsupported.

An explicit offline migration must read the old version with its old strict decoder, validate the complete old state set, produce a new-version state set, validate every new document, and write it separately with an operator-visible migration report. The online service must not migrate state during startup, reads, writes, recovery, or API requests. Destructive or lossy conversions require explicit operator approval and a backup/rollback plan.

Adding the fixed `idempotency/` directory is a pre-release state-layout change, not a state-document schema migration: no document kind or version changed. However, once this binary has opened a state directory, an older binary that rejects the new directory cannot roll back in place. Use a backup/restore procedure to return to an older binary.
