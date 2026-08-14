# Phase 3 — PVC state, diff, plans, and planning API

## Objective

Implement single-writer non-secret PVC state, durable jobs/audit/inventory, ownership-safe diffing, deterministic plans, and web/API plan review.

## Prerequisites

- Phase 2 authentication, Secrets, and read adapters pass.
- Mounted desired and live canonical projections share stable identity/fingerprint contracts.

## Substeps

### 3.1 Define versioned state formats

1. Define source snapshot, inventory, journal, plan, job, report, idempotency, and audit schemas.
2. Reject unknown/unsupported versions.
3. Keep all formats non-secret.
4. Define migration policy: explicit offline/new-version migration only, no silent destructive upgrades.
5. Store actor IDs/roles and Secret metadata references, never tokens/values.

### 3.2 Harden the state directory

1. Enforce expected mount, owner permissions, symlink/path defenses, and free-space checks.
2. Implement atomic temp-write/fsync/rename.
3. Implement process, job, and target locks.
4. Detect multiple writers and fail readiness.
5. Use ReadWriteOnce/single replica assumptions explicitly.
6. Test corruption and interrupted writes.

### 3.3 Implement durable job storage

1. Persist queued/running/succeeded/failed/cancelled metadata.
2. Restore safe jobs after restart; mark interrupted non-resumable work accurately.
3. Persist idempotency-key results scoped to actor/action/request digest.
4. Bound concurrency and queue size.
5. Never tie job lifetime to browser connections.
6. Add polling and authenticated SSE event projection.

### 3.4 Implement durable audit events

1. Record actor subject/roles, request/job IDs, action, target/plan IDs, outcome, and safe reason.
2. Segment/rotate append-oriented files atomically.
3. Provide paginated authorized reads.
4. Redact before persistence.
5. Audit credential metadata operations without values.
6. Test restart and partial-write behavior.

### 3.5 Implement inventory and journal recovery

1. Key inventory by exact target identity.
2. Record kind/logical/remote IDs, marker type, and last desired fingerprint.
3. Define pre-mutation journals with baseline/expected post-state.
4. Recover by exact baseline/current/post comparison.
5. Commit inventory only after verified tool mutation.
6. Never auto-adopt marker-only resources.

### 3.6 Implement ownership evaluation and pruning

1. Detect exact Fleet description/rule tag markers.
2. Classify managed, unmanaged, marker-only, inventory-only, altered-marker, ambiguous, and safe orphan.
3. Require inventory plus marker for custom-rule/agent/package-policy delete.
4. Never prune integrations/prebuilt rules.
5. Produce reviewable conflict observations.

### 3.7 Implement per-kind diffing

1. Create for absent desired identities.
2. Update only safely owned drift.
3. Record unchanged observations.
4. Reject unmanaged collisions, immutable rules, downgrades, ambiguity, and marker changes.
5. Attach desired, baseline, expected-post, and inventory fingerprints.
6. Test canonical false-drift exclusions.

### 3.8 Build deterministic dependency plans

1. Add automatic/explicit DAG edges.
2. Order ready nodes by phase/kind/id/action.
3. Store dependency IDs explicitly.
4. Scope mounted source/config digests per selected target/resource set.
5. Include external revision metadata only as provenance.
6. Keep plans server-managed; expose read projections, not filesystem paths/edit APIs.

### 3.9 Implement planning jobs/API

1. Authorize planner/admin initiation and viewer inspection.
2. Apply idempotency keys.
3. Snapshot mounted inputs, fetch target Secrets, verify versions, read live state, diff, and save plans.
4. Refuse applicable-plan creation if any selected target fails planning.
5. Return `202` plus job ID; expose plan only after success.
6. Paginate plans/operations/observations.
7. Audit initiation/completion.

### 3.10 Implement plan-review UI

1. Show creator/time, source set/revision/digest, targets/versions, operation counts, DAG dependencies, ownership conflicts, and unchanged observations.
2. Show credential status without values.
3. Prevent client editing/upload.
4. Explain why a plan is blocked or requires replan.
5. Gate apply controls by role; actual apply lands in Phase 4.

## Verification

- Repeated identical input/live state yields deterministic operation content.
- Converged plans have zero operations.
- Marker-only/unmanaged resources never delete.
- Jobs/idempotency/audit survive restart safely.
- Plans/state contain no API keys, CA bodies, OIDC tokens, cookies, or Secret bodies.

## Phase gate

Durable single-writer state is recoverable and non-secret; planning is asynchronous/idempotent/audited; plans are source/target scoped and deterministic; prune requires inventory plus marker.
