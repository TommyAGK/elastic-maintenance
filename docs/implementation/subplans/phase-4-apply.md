# Phase 4 — apply

## Objective

Apply only saved-plan operations after target-scoped preflight checks, preserve independent progress, verify every mutation, maintain durable state safely, and report partial outcomes without rollback or resume.

## Prerequisites

- Phase 3 gate passes.
- Mutation request/response contracts are represented by versioned fixtures.
- Inventory locking, atomic writes, and journal recovery are fault-tested.

## Substeps

### 4.1 Define apply result semantics

1. Define target and operation statuses: created, updated, deleted, unchanged, skipped, conflicted, rejected, and failed.
2. Define versioned apply-report JSON.
3. Define deterministic human summaries.
4. Map all-success to exit `0`, rejection/total failure to `1`, and mixed target success/failure to `2`.
5. Distinguish preflight rejection from mutation failure.

### 4.2 Load and validate the plan

1. Strictly decode plan JSON and reject unknown/unsupported versions.
2. Validate plan structure, unique operation IDs, target identities, dependencies, and fingerprints.
3. Resolve recorded config/manifests paths without override flags.
4. Reconstruct selected canonical inputs.
5. Verify create/update payload fingerprints against current desired resources.
6. Verify deletes remain absent from desired and still have recorded inventory authority.
7. Do not claim cryptographic plan authenticity.

### 4.3 Run per-target preflight

1. Acquire the target state lock and resolve pending journals.
2. Recompute target input, CA, desired, and inventory fingerprints.
3. Resolve the API key freshly from the declared environment variable.
4. Recheck Kibana version compatibility.
5. Read every affected resource completely.
6. Compare baseline fingerprints, including absence sentinels for creates.
7. Recheck ownership markers for deletes.
8. Reject the target before its first mutation if any check differs.

### 4.4 Implement integration mutations

1. Install only exact pinned versions through the documented endpoint.
2. Treat missing/older desired versions according to planned operation.
3. Reject installed-newer downgrade conflicts.
4. Do not uninstall integrations.
5. Verify exact installed version after the mutation.

### 4.5 Implement agent-policy mutations

1. Create with caller-defined ID and managed description marker.
2. Build complete safe update bodies from desired plus required preserved fields.
3. Delete only with fresh inventory/marker authority.
4. Verify stable ID, marker, and canonical expected post-state.
5. Update/clear inventory through the journal protocol.

### 4.6 Implement package-policy mutations

1. Resolve desired logical references to exact package and agent-policy IDs.
2. Create/update caller-defined IDs with ownership marker.
3. Preserve API-required inputs and managed variable semantics.
4. Delete only with fresh inventory/marker authority.
5. Verify assignments, package version, stable ID, marker, and expected post-state.

### 4.7 Implement custom-rule mutations

1. Create with `rule_id` from logical ID and the managed tag.
2. Construct complete typed replacement updates so omitted fields are not lost.
3. Refuse immutable/prebuilt targets.
4. Delete by `rule_id` only with inventory/marker authority.
5. Verify canonical rule content, stable ID, immutable flag, and marker after mutation.
6. Account for API-key ownership behavior in operator guidance.

### 4.8 Implement collective prebuilt mutation

1. Invoke the one collective PUT operation when status indicates missing/outdated content.
2. Never address individual prebuilt rules.
3. Verify collective post-status counts.
4. Represent the result as one operation even when many rules/timelines change.

### 4.9 Execute dependency-aware operations

1. Traverse ready operations in deterministic order.
2. Write the operation journal before every mutation.
3. Execute, read back, and compare exact expected post-state.
4. Commit inventory and clear the journal only after verification.
5. On failure, mark transitive dependants skipped.
6. Continue unrelated operations on the same target where safe.
7. Continue independent targets regardless of another target’s result.
8. Never roll back completed operations.

### 4.10 Persist reports and consume plans operationally

1. Write the report atomically to the explicit/default path.
2. Include safe error categories and evidence without credentials.
3. Clearly instruct operators to generate a new plan after any success, partial result, rejection, or failure that changed remote state.
4. Do not add resume, force, or implicit-replan behavior.
5. Reapplying an old plan should normally fail baseline checks.

### 4.11 Add failure and safety tests

1. Fault-inject before/after remote mutation and every journal/inventory write.
2. Mutate config, manifests, CA, inventory, version, markers, and remote baselines.
3. Verify affected-target rejection occurs before its first mutation.
4. Verify unrelated targets continue.
5. Verify only transitive dependencies skip.
6. Verify reports and exit codes for every outcome combination.
7. Scan requests, logs, reports, state, and errors for sentinel credentials.

## Verification

Run unit, contract, race, and end-to-end `httptest` suites. Apply against disposable live 9.2.0 and current-9.x targets only after explicit local test setup is approved.

## Phase gate

Every safety and partial-failure acceptance test passes, post-state is verified before inventory commits, target independence holds, no rollback/resume exists, and all reports remain accurate and non-secret.
