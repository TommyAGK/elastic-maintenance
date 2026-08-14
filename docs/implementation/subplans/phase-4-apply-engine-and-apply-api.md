# Phase 4 — apply engine and apply API

## Objective

Apply reviewed server-managed plans through authorized asynchronous jobs with complete preflight, journaled mutations, post-verification, independent-target progress, and durable reports.

## Prerequisites

- Phase 3 plan/state/job/audit/ownership gate passes.
- Mutation request/response contracts exist for both supported Kibana versions.

## Substeps

### 4.1 Define approval/apply semantics

1. Permit `applier` and `administrator` roles.
2. Permit an authorized plan creator to apply their own plan.
3. Require explicit confirmation and idempotency key.
4. Store actor/plan/job relationship and audit it.
5. Reject already consumed, incompatible, blocked, or missing plans.

### 4.2 Validate the saved plan

1. Strict-decode internal plan state.
2. Validate operation/dependency/target identities and fingerprints.
3. Re-read mounted authoritative config/resource set.
4. Verify current operation desired payloads against canonical desired resources.
5. Verify deletes remain absent and inventory-authorized.
6. Do not accept plan payloads from clients.

### 4.3 Run target preflight

1. Acquire state/target locks and recover journals.
2. Recompute mounted config/source/CA-secret metadata/desired/inventory fingerprints.
3. Fetch API key and CA from the configured Secret into memory.
4. Recheck Kibana version.
5. Re-read all affected resources and compare baselines/absence sentinels.
6. Recheck delete markers.
7. Reject the target before first mutation on any drift.

### 4.4 Implement integration mutation

1. Install exact desired version.
2. Reject installed-newer downgrade.
3. Never uninstall.
4. Verify exact post-version/status.
5. Journal the operation even though no prune inventory is granted.

### 4.5 Implement Fleet policy mutations

1. Create/update caller-defined IDs with managed description marker.
2. Build complete API-required request bodies.
3. Resolve package-policy references to exact package/agent IDs.
4. Delete only with fresh inventory plus marker.
5. Verify stable ID, assignments, marker, and canonical post-state.

### 4.6 Implement custom-rule mutation

1. Create with desired `rule_id` and managed tag.
2. Build complete replacement PUT body.
3. Refuse immutable/prebuilt collisions.
4. Delete by `rule_id` only with inventory plus marker.
5. Verify post-state and account for API-key ownership behavior in diagnostics.

### 4.7 Implement collective prebuilt mutation

1. Call one collective PUT when planned.
2. Never address individual prebuilt rules.
3. Verify collective status/counts.
4. Represent one operation/report outcome.

### 4.8 Execute DAG safely

1. Write journal before mutation.
2. Execute, read back, and compare expected post-state.
3. Commit inventory and clear journal only after verification.
4. Skip transitive dependants on failure.
5. Continue unrelated resources/targets.
6. Never retry mutations automatically or roll back completed work.
7. Bound job runtime and handle shutdown without false success.

### 4.9 Persist reports and plan consumption

1. Save per-operation/target created/updated/deleted/unchanged/skipped/conflicted/rejected/failed statuses.
2. Record safe evidence and actor/job/plan references.
3. Mark plans operationally consumed once any mutation succeeds.
4. Require explicit new planning after every apply result where retry might be desired.
5. Expose no resume/force/implicit-replan operation.

### 4.10 Implement apply API/UI

1. `POST /api/v1/plans/{id}/apply` returns `202` and job ID.
2. Enforce CSRF for cookie clients and bearer auth for automation.
3. Enforce idempotency and role checks at route/service layers.
4. Show preflight, target, dependency, operation, and report status.
5. Show new-plan guidance after partial/rejected results.
6. Audit request and final outcome.

### 4.11 Fault/security tests

1. Inject failures around remote mutation and each journal/inventory/report write.
2. Mutate mounted files, target config, Secret metadata/content, CA, inventory, version, markers, and live baselines.
3. Verify target rejects before first mutation.
4. Verify independent target/resource progress.
5. Verify transitive-only skips.
6. Verify job/report/audit consistency after restart.
7. Sentinel-scan requests, state, logs, API/UI, reports, audit, and errors.

## Phase gate

Every mutation is preflighted, journaled, and post-verified; target/dependency isolation works; partial results are durable and audited; replan is mandatory; no credentials leak; and all fault-injection acceptance tests pass.
