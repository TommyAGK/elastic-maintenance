# Phase 3 — inventory, diff, and saved plans

## Objective

Convert validated desired inputs and canonical live reads into deterministic, reviewable plans while enforcing durable pruning authority and dependency ordering.

## Prerequisites

- Phase 2 gate passes.
- Canonical desired and live projections exist for all kinds.
- Resource identities and per-target DAGs are stable.

## Substeps

### 3.1 Define file-state formats

1. Define versioned inventory, journal, lock, plan, and observation schemas.
2. Keep formats non-secret and strict about unknown fields.
3. Derive target state paths from a collision-resistant hash of target identity.
4. Record kind, logical/remote IDs, marker type, desired fingerprint, and diagnostic timestamps.
5. Define safe format-upgrade rejection for unsupported versions.

### 3.2 Implement state-directory safety

1. Resolve platform/XDG defaults and explicit overrides.
2. Require owner-only permissions where supported.
3. Reject symlinks and unsafe path components.
4. Implement same-directory temporary writes, flush/fsync where supported, and atomic rename.
5. Implement per-target locks with clear busy/stale behavior.
6. Treat unavailable or corrupt state as mutation/pruning-disabled, never marker-authoritative.

### 3.3 Implement recovery journals

1. Record plan ID, operation identity, baseline, and expected post-state before mutation.
2. Define journal lifecycle states without credentials or request bodies containing secrets.
3. Resolve pending journals by reading current remote state.
4. Commit inventory when exact post-state is observed.
5. Clear when exact baseline remains.
6. Stop with a recovery conflict for every other state.
7. Fault-test each write/rename boundary before Phase 4 uses journals.

### 3.4 Implement ownership evaluation

1. Detect exact custom-rule tag and Fleet description markers.
2. Distinguish managed, marker-only, inventory-only, altered-marker, ambiguous, and unmanaged states.
3. Grant deletion authority only when exact target inventory and live marker agree on kind/stable ID.
4. Never auto-adopt marker-only resources.
5. Never create delete operations for integrations or prebuilt rules.
6. Produce operator-readable ownership observations/conflicts.

### 3.5 Implement adapter-specific diffing

1. Compare canonical desired and live projections.
2. Produce create for absent desired identities.
3. Produce update for managed drift with valid ownership.
4. Produce unchanged observations for convergence.
5. Produce conflicts for unmanaged collisions, immutable rules, downgrade attempts, marker changes, and ambiguous identity.
6. Produce inventory-authorized deletes only for missing custom rules, agent policies, and package policies.
7. Attach desired, baseline, and expected-post fingerprints.

### 3.6 Build deterministic dependency plans

1. Build a per-target DAG from automatic and explicit edges.
2. Validate acyclicity defensively even though Phase 1 already checked desired references.
3. Order ready nodes by phase, kind, logical ID, and action.
4. Store operation dependency IDs explicitly.
5. Do not make unrelated resources dependent merely because they share a phase.
6. Represent unchanged observations outside the operation list.

### 3.7 Define per-target plan safety data

1. Record config and manifest source paths.
2. Record target identity, Kibana version, target-input digest, CA digest, desired digest, and source-file diagnostics.
3. Record inventory generation/fingerprint for delete authority.
4. Record absence sentinels for creates and canonical baselines for updates/deletes.
5. Include selected targets only; unrelated target changes must not invalidate them.
6. Ensure operation payload fingerprints map back to current canonical desired resources.

### 3.8 Implement plan serialization

1. Use deterministic canonical JSON and a versioned plan format.
2. Write plans atomically with restrictive permissions.
3. Reject unknown/unsupported fields on read.
4. Keep plans trusted but unsigned, matching the documented threat model.
5. Ensure zero-operation plans remain valid and reviewable.
6. Scan serialized output for sentinel API keys.

### 3.9 Connect the `plan` command

1. Load/validate inputs and select targets.
2. Resolve API keys only for selected remote reads.
3. Verify versions, read complete live state, evaluate ownership, diff, and order operations.
4. Refuse to write an applicable plan if any selected target fails planning.
5. Write the plan only after all selected targets succeed.
6. Print deterministic per-target summaries and operation details.
7. Return `0` for both converged and change-bearing successful plans.

### 3.10 Add planning tests

1. Test create/update/delete/unchanged/conflict for every kind.
2. Test marker/inventory combinations exhaustively.
3. Test target independence, selectors, dependency ordering, and cycles.
4. Test deterministic bytes across repeated runs.
5. Test changed CA/desired inputs and unrelated edits.
6. Test state corruption, locks, atomic-write failures, and journal recovery.

## Verification

- A converged target produces zero operations.
- Marker-only and unmanaged resources never produce deletes.
- Plans contain no credentials.
- Repeated planning against identical inputs/live state produces byte-stable canonical content except explicitly controlled creation metadata.

## Phase gate

Saved plans are deterministic, target-scoped, non-secret, dependency-aware, and incapable of authorizing prune without exact durable inventory plus a live marker.
