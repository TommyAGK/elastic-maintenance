# Phase 4 — apply engine and apply API

## Objective

Apply reviewed server-managed plans through authorized asynchronous jobs with complete preflight, journaled mutations, post-verification, independent-target progress, and durable reports.

## Prerequisites

- Phase 3 plan/state/job/audit/ownership gate passes.
- Mutation request/response contracts exist for both supported Kibana versions.

## How to use this living plan

This document is a refinement of the Phase 4 scope, not an implementation-status report. No increment below is marked complete. Each numbered increment is intended to be one independently reviewable, verifiable, and committable change; a commit for an increment includes only its focused implementation and evidence. The increment may add a narrow contract or test seam before its consumer, but it must not silently absorb adjacent increments.

- **Dependency** names the exact prerequisite gate or increment IDs. If discovery shows that a dependency is larger than one focused change, refine that dependency before implementation rather than working around it.
- **Done / verification evidence** is the focused proof required for that increment: normally named unit, contract, integration, fault-injection, or UI/API evidence plus the invariant it proves. Evidence is a requirement, not a claim that the increment is done.
- **Worker opportunity** marks work that can be delegated without overlapping another worker's write ownership. A `Yes` opportunity is available only after its listed dependencies are stable and its owned files/fixtures are reserved. `No` means the work is sequencing-sensitive or shares an integration boundary that should remain with the primary implementer.
- The server remains authoritative for plans, asynchronous jobs, authorization, target identity, journals, inventory, reports, and audit. Mounted sources remain read-only; clients never supply or edit executable plan payloads.
- Every mutation remains target-scoped, preflighted, journaled before the remote call, read back, and post-verified. No increment may weaken partial-failure isolation, ownership checks, secret handling, or explicit replan semantics to make its local test pass.

### Living-plan refinement rule

Before starting an increment and after its focused evidence is reviewed, compare its actual change surface with this plan. Split it again if it contains more than one independently reviewable behavior, spans unrelated resource kinds or layers, needs different rollback/recovery evidence, or cannot be given one clear commit boundary. Add the new IDs, dependencies, worker ownership, and focused evidence before implementation; update downstream dependencies when IDs change. Record newly discovered safety constraints in this document and preserve all existing constraints. Do not mark an increment, substep, or phase complete merely because a prerequisite or partial implementation exists, and do not use refinement to change the architecture or defer a required gate.

## Substeps

### 4.1 Define approval/apply semantics

#### 4.1.1 — Enforce apply roles

- **Dependency:** Phase 3 plan/state/job/audit/ownership gate; Phase 2 actor and RBAC contracts.
- **Worker opportunity:** **Yes — non-overlapping.** Own the apply permission policy and its role-matrix tests; do not change HTTP routing, UI, or the apply runner.
- **Done / verification evidence:** The service authorization policy permits only `applier` and `administrator` for apply initiation, denies viewer/planner-only and unknown actors, and returns the existing safe denial shape without creating a job or mutating a target. A table-driven role matrix covers both supported authentication methods.

#### 4.1.2 — Permit an authorized creator to apply their own plan

- **Dependency:** 4.1.1; Phase 3 plan creator/actor projection.
- **Worker opportunity:** **Yes — non-overlapping.** Own creator-versus-plan-actor matching tests and policy code only; do not alter general role checks or route behavior.
- **Done / verification evidence:** An authorized plan creator can apply the exact plan they created even when the actor is not otherwise the plan's administrator, while a different actor without an allowed role is denied. Tests cover actor subject, role, authentication method, and plan creator mismatch.

#### 4.1.3 — Require explicit confirmation

- **Dependency:** 4.1.1; versioned apply request contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own strict request decoding and confirmation validation; do not implement idempotency storage or job execution.
- **Done / verification evidence:** Missing, false, malformed, or duplicated confirmation is rejected before job creation and before any target preflight/mutation; only the explicit confirmation value reaches the apply service. Strict JSON and safe-error tests prove no client payload is treated as a plan.

#### 4.1.4 — Require and bind an idempotency key

- **Dependency:** 4.1.1 and 4.1.3; Phase 3 idempotency state contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own the bounded idempotency-key validation and request-digest binding tests; do not change mutation execution.
- **Done / verification evidence:** A bounded idempotency key is mandatory and is bound to actor, apply action, and request digest. Repeating the same request returns the original job/result reference; reusing the key with another actor, action, or digest fails closed without a second job or mutation.

#### 4.1.5 — Persist the actor/plan/job relationship

- **Dependency:** 4.1.2 and 4.1.4; Phase 3 durable Job and Plan contracts.
- **Worker opportunity:** **No — integration boundary.** This connects authorization, idempotency, job creation, and durable state and should have one owner.
- **Done / verification evidence:** The accepted apply job durably references the exact plan and records the safe actor projection and request relationship. Reloading state yields the same linkage; persisted data contains no request body, credentials, headers, or remote response.

#### 4.1.6 — Emit the apply-request audit projection

- **Dependency:** 4.1.5; Phase 3 durable AuditEvent contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own the apply-initiation audit projection and redaction tests; do not own final report/outcome auditing.
- **Done / verification evidence:** Every accepted and rejected apply request produces the required safe request audit outcome with actor, request/job/plan references, action, and bounded reason where applicable. An audit fixture scan proves no API key, CA body, token, cookie, Secret body, or arbitrary request content is persisted.

#### 4.1.7 — Reject an already consumed plan

- **Dependency:** 4.1.5; Phase 3 plan consumption/rejection state contract.
- **Worker opportunity:** **No — shared plan admission decision.** Keep this with the other plan-admission rejection paths so they have identical no-job/no-mutation behavior.
- **Done / verification evidence:** A plan with any prior successful mutation is rejected before target preflight and no new apply job or mutation is started. The rejection has a stable safe reason and audit evidence, and a repeated request cannot bypass consumption through a new idempotency key.

#### 4.1.8 — Reject an incompatible plan

- **Dependency:** 4.1.5; 4.2.1–4.2.2.
- **Worker opportunity:** **No — shared plan admission decision.** The compatibility check must remain aligned with strict plan and fingerprint validation.
- **Done / verification evidence:** Unsupported state/schema, tool, target, version, operation, dependency, or fingerprint compatibility is rejected before any mutation, with a durable job/report or safe rejection projection as applicable. Tests cover each incompatibility without accepting client-supplied substitutions.

#### 4.1.9 — Reject a blocked plan

- **Dependency:** 4.1.5; Phase 3 blocked/conflict observation contract.
- **Worker opportunity:** **No — shared plan admission decision.** Keep blocked-plan handling adjacent to the other terminal admission paths.
- **Done / verification evidence:** A plan containing a blocking conflict/reject observation or otherwise blocked state cannot start apply. The service emits the safe blocked reason and audit evidence, and confirms that no target lock, journal, or remote mutation is acquired/created as a side effect.

#### 4.1.10 — Reject a missing plan

- **Dependency:** 4.1.1 and 4.1.3; authoritative durable plan repository.
- **Worker opportunity:** **Yes — non-overlapping.** Own not-found and malformed-reference handler/service tests; do not alter plan validation or job execution.
- **Done / verification evidence:** Unknown, deleted, inaccessible, or malformed plan IDs fail safely and consistently at the authorization/service boundary, without revealing whether unrelated plans exist and without creating a job or touching a target.

### 4.2 Validate the saved plan

#### 4.2.1 — Strictly decode the internal plan

- **Dependency:** 4.1.5; Phase 3 strict `Plan` codec and state-directory read boundary.
- **Worker opportunity:** **Yes — non-overlapping.** Own the strict decoder integration tests and malformed-state fixtures; do not change the state schema.
- **Done / verification evidence:** Apply loads the server-persisted plan through the strict decoder and rejects unknown/duplicate fields, unsupported versions/kinds, trailing data, invalid bounded values, and nil/invalid destinations. Decode failures cannot reach preflight or mutation.

#### 4.2.2 — Validate identities, dependencies, and fingerprints

- **Dependency:** 4.2.1; Phase 3 deterministic plan validator.
- **Worker opportunity:** **Yes — non-overlapping.** Own cross-field identity/dependency/fingerprint admission tests; do not own mounted-input rereads.
- **Done / verification evidence:** Every operation, dependency, observation, target, operation ID, remote ID, desired fingerprint, baseline, expected-post assertion, marker, and inventory generation is checked against the declared exact target and plan contracts. Invalid target isolation, ordering, dependency direction, or fingerprint domains are rejected before preflight.

#### 4.2.3 — Re-read the mounted authoritative configuration and resource set

- **Dependency:** 4.2.1–4.2.2; Phase 1 fresh mounted-input snapshot contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own the fresh mounted snapshot adapter and read-twice/drift fixtures; do not own target clients or mutation adapters.
- **Done / verification evidence:** Apply reads the current mounted configuration and selected authoritative resource set at apply time, bounded and read-only, rather than relying on request or stale plan payloads. Tests mutate source/config between planning and apply and show the current snapshot is captured for later comparison.

#### 4.2.4 — Reconcile operation desired payloads with canonical desired resources

- **Dependency:** 4.2.3; 4.2.2; canonical desired-resource projections.
- **Worker opportunity:** **Yes — non-overlapping.** Own desired-payload canonicalization/comparison fixtures; do not change the resource-kind mutation adapters.
- **Done / verification evidence:** Each planned create/update desired payload is reconstructed from the current canonical desired resources and compared to the plan's desired fingerprint/content. Any changed, missing, extra, or cross-target payload rejects the affected apply before its first mutation; formatting-only differences do not create false drift.

#### 4.2.5 — Verify delete absence and inventory authorization

- **Dependency:** 4.2.2–4.2.3; Phase 3 ownership inventory and plan delete rules.
- **Worker opportunity:** **Yes — non-overlapping.** Own delete-specific plan validation and inventory-generation fixtures; do not implement remote delete calls.
- **Done / verification evidence:** Delete operations require the current desired resource to remain absent, an exact target-scoped inventory generation/fingerprint, a supported prunable kind, and an ownership-compatible marker. Integrations and prebuilt rules are rejected as deletes; stale or missing inventory is rejected.

#### 4.2.6 — Reject client-supplied plan payloads

- **Dependency:** 4.1.3; 4.2.1; apply API request schema.
- **Worker opportunity:** **Yes — non-overlapping.** Own request-schema rejection and tampered-payload tests; do not change server plan storage.
- **Done / verification evidence:** The apply request accepts only the plan reference, explicit confirmation, and idempotency material required by the contract; embedded operations, desired bodies, inventory, or target credentials are rejected or ignored according to the strict schema, never used. Tests demonstrate that changing a client payload cannot alter the server-managed plan.

### 4.3 Run target preflight

#### 4.3.1 — Acquire the state lock for the apply job

- **Dependency:** 4.1.5; Phase 3 single-writer state-store and lock contract.
- **Worker opportunity:** **No — runtime serialization boundary.** State-lock lifetime must be integrated with job lifecycle and shutdown by one owner.
- **Done / verification evidence:** An apply job acquires the required state lock before reading or writing apply state, cannot run concurrently with another state writer, and releases the lock on success, rejection, failure, cancellation, and shutdown. Contention tests show no unsafe interleaving.

#### 4.3.2 — Acquire exact target locks and recover journals

- **Dependency:** 4.3.1; Phase 3 target-lock and `PreMutationJournal` contracts.
- **Worker opportunity:** **No — recovery/locking boundary.** Target lock ownership, journal recovery, and job restart behavior must be integrated.
- **Done / verification evidence:** Each selected target gets an exact-identity lock, and any existing journal is recovered by comparing its recorded baseline/current/post state before a new mutation is admitted. A recovered uncertain journal blocks unsafe continuation rather than guessing, adopting marker-only state, or replaying a mutation.

#### 4.3.3 — Recompute mounted-config and source fingerprints

- **Dependency:** 4.2.3; 4.3.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own mounted configuration/source metadata fingerprint fixtures; do not change Secret or live-target preflight.
- **Done / verification evidence:** Current mounted configuration and source/resource-set metadata fingerprints are recomputed and compared to the plan's target-scoped provenance. A mounted-file or revision/source-set drift rejects that target before its first mutation and leaves unrelated targets eligible.

#### 4.3.4 — Recompute CA/Secret metadata fingerprints without reading values into state

- **Dependency:** 4.2.2; 4.3.1; Phase 2 owned-Secret and CA metadata contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own Secret metadata/CA fingerprint comparison and redaction fixtures; do not own the leased client.
- **Done / verification evidence:** Current configured Secret metadata/content fingerprint and CA trust metadata are compared with the plan baseline, while API-key and certificate values remain memory-only. Tests cover Secret metadata/content and CA drift and scan state, logs, errors, and audit for secret material.

#### 4.3.5 — Recompute desired, target-config, and inventory fingerprints

- **Dependency:** 4.2.2–4.2.5; 4.3.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own desired/target-config/inventory fingerprint recomputation and stale-generation fixtures; do not own remote live reads.
- **Done / verification evidence:** The current selected target's desired, exact target-config, and ownership-inventory fingerprints/generation are recomputed and compared to the plan. Any mismatch rejects only that target before mutation and cannot be bypassed by a plan or request payload.

#### 4.3.6 — Lease API key and CA into memory for the target client

- **Dependency:** 4.3.4–4.3.5; Phase 2 target-client lease contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own the apply-time credential lease lifecycle and memory-clearing tests; do not change Kubernetes Secret authorization.
- **Done / verification evidence:** The target client obtains the configured API key and CA only after metadata preflight, binds them to the full captured target identity, and releases/clears them on close or rejection. No credential value is written to PVC state, journals, reports, audit, logs, responses, or browser storage.

#### 4.3.7 — Recheck Kibana version

- **Dependency:** 4.3.5; 4.3.6; version probe contract for both supported versions.
- **Worker opportunity:** **Yes — non-overlapping.** Own version-drift fixtures and safe classification; do not alter version negotiation or mutation request bodies.
- **Done / verification evidence:** Apply re-probes the target and requires the supported exact version/range and the planned version compatibility. Version drift, malformed version, or probe failure rejects the target before any mutation with a safe reason.

#### 4.3.8 — Re-read affected resources and compare baselines/absence sentinels

- **Dependency:** 4.3.6–4.3.7; 4.2.2; typed live-read adapters.
- **Worker opportunity:** **Yes — non-overlapping by resource-kind fixture.** A worker may own one isolated live-read fixture set (integration, Fleet, custom, or prebuilt) after the adapter owner reserves it; no shared executor changes.
- **Done / verification evidence:** Every affected remote resource is freshly read and compared to the plan/journal live baseline; planned absence uses the explicit absence sentinel. Any changed baseline, unexpected presence/absence, malformed response, or unmanageable collision rejects the target before first mutation.

#### 4.3.9 — Recheck delete markers and inventory ownership

- **Dependency:** 4.2.5; 4.3.8; current live ownership projection.
- **Worker opportunity:** **Yes — non-overlapping.** Own live-marker/inventory mismatch fixtures; do not change generic target locking.
- **Done / verification evidence:** Immediately before a delete, the live marker and exact inventory entry still match the planned kind, logical ID, remote ID, target identity, and generation. Marker removal/change, inventory staleness, ambiguity, or marker-only status rejects the target without a delete request.

#### 4.3.10 — Enforce the all-or-nothing pre-mutation target gate

- **Dependency:** 4.3.1–4.3.9.
- **Worker opportunity:** **No — orchestration boundary.** This gate must combine every preflight result and establish the single point before the first remote mutation.
- **Done / verification evidence:** Any preflight drift or failure marks only the affected target rejected, records safe evidence, releases its lease/lock, and proves through a remote-call counter that no mutation was attempted for that target. Other targets remain independently schedulable.

### 4.4 Implement integration mutation

#### 4.4.1 — Send the exact desired integration version

- **Dependency:** 4.3.10; mutation request/response contracts for both supported Kibana versions.
- **Worker opportunity:** **Yes — non-overlapping.** Own the integration mutation adapter and versioned request fixtures; do not change the shared executor or other kind adapters.
- **Done / verification evidence:** The adapter installs exactly the planned desired integration version using the supported API contract, with no client-controlled substitution. Both fixture versions validate the request and safe remote error classification.

#### 4.4.2 — Reject an installed-newer downgrade before mutation

- **Dependency:** 4.3.7–4.3.8; 4.4.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own integration version-order tests; do not alter generic version probing.
- **Done / verification evidence:** If the installed integration version is newer than the desired version, the operation is rejected before an install request. Equal and older installed versions follow their planned path; downgrade attempts produce a safe report/audit outcome and no remote mutation.

#### 4.4.3 — Never uninstall an integration

- **Dependency:** 4.4.1–4.4.2; Phase 3 plan action restrictions.
- **Worker opportunity:** **Yes — non-overlapping.** Own negative request/plan fixtures proving no uninstall path exists; do not add alternate cleanup behavior.
- **Done / verification evidence:** No apply route, adapter, recovery path, or delete operation can issue an integration uninstall or represent it as a prune. Tests with absent desired integrations and stale inventory prove no integration delete request is made.

#### 4.4.4 — Verify exact integration post-version and status

- **Dependency:** 4.4.1; 4.8.4 read-back contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own integration post-state fixtures and mismatch tests; do not change report persistence.
- **Done / verification evidence:** After install/update, the adapter reads the integration and requires the exact desired version and acceptable status/post-state. A wrong version, status, identity, or malformed read is a failed operation, not success, and leaves the journal for recovery.

#### 4.4.5 — Journal integrations without granting prune inventory

- **Dependency:** 4.4.1–4.4.4; Phase 3 journal schema and inventory rules.
- **Worker opportunity:** **Yes — non-overlapping.** Own integration journal/result mapping; do not change the generic journal lifecycle.
- **Done / verification evidence:** Integration create/update mutations carry a pre-mutation journal and post-verification evidence but never create or commit prune inventory. A fixture confirms a verified integration mutation cannot authorize a later integration delete.

### 4.5 Implement Fleet policy mutations

#### 4.5.1 — Preserve caller-defined IDs and apply managed markers

- **Dependency:** 4.3.10; Fleet canonical identity/ownership projections.
- **Worker opportunity:** **Yes — non-overlapping.** Own Fleet ID and description-marker mapping fixtures; do not own package-policy reference resolution.
- **Done / verification evidence:** Create/update requests use the caller-defined stable policy ID and the required managed description marker. The adapter rejects an identity or marker it cannot prove safe, and both supported API versions preserve the exact ID on read-back.

#### 4.5.2 — Build complete Fleet create/update request bodies

- **Dependency:** 4.2.4; 4.5.1; versioned Fleet mutation contracts.
- **Worker opportunity:** **Yes — non-overlapping.** Own complete-body builders and missing-field/unknown-field fixtures; do not change delete or verification logic.
- **Done / verification evidence:** Every required API field, nested policy field, package reference, and supported-version field is populated from canonical desired state; update is not a partial body that drops unmanaged-but-required server fields. Strict fixtures prove request parity and no secret leakage.

#### 4.5.3 — Resolve package-policy references to exact package and agent IDs

- **Dependency:** 4.5.2; Phase 3 resolved dependency DAG and typed live inventory.
- **Worker opportunity:** **Yes — non-overlapping.** Own reference-resolution fixtures for exact package/agent IDs; do not change the DAG scheduler.
- **Done / verification evidence:** Every Fleet package-policy reference resolves to the exact package and agent-policy remote IDs planned for that target. Dangling, ambiguous, cross-target, or changed references reject before the policy mutation; no guessed or name-only ID is sent.

#### 4.5.4 — Gate Fleet deletes on fresh inventory and marker

- **Dependency:** 4.2.5; 4.3.9; 4.5.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own Fleet delete authorization fixtures; do not change generic delete scheduling.
- **Done / verification evidence:** A Fleet agent/package policy is deleted only when its exact inventory entry is fresh and its live managed description marker matches. Missing inventory, marker-only state, altered marker, remote-ID mismatch, and stale generation all produce no-delete outcomes.

#### 4.5.5 — Verify Fleet identity, assignment, marker, and canonical post-state

- **Dependency:** 4.5.1–4.5.4; 4.8.4.
- **Worker opportunity:** **Yes — non-overlapping.** Own Fleet read-back fixtures and canonical false-drift tests; do not change report aggregation.
- **Done / verification evidence:** Post-verification requires stable policy ID, expected agent assignment/package reference, managed marker, and canonical post-state/fingerprint. Any mismatch is failed rather than unchanged/updated success and retains sufficient journal evidence for recovery.

### 4.6 Implement custom-rule mutation

#### 4.6.1 — Create custom rules with desired `rule_id` and managed tag

- **Dependency:** 4.3.10; custom-rule canonical identity/ownership projections.
- **Worker opportunity:** **Yes — non-overlapping.** Own custom-rule create request fixtures; do not own replacement PUT or collision policy.
- **Done / verification evidence:** A create request uses the desired caller-defined `rule_id` and managed tag exactly. The adapter rejects missing/unsafe identity or tag and verifies both on the created resource.

#### 4.6.2 — Build a complete replacement PUT body

- **Dependency:** 4.2.4; 4.6.1; complete-update baseline from Phase 2 typed adapter.
- **Worker opportunity:** **Yes — non-overlapping.** Own custom-rule replacement-body builders and complete-field fixtures; do not change ownership or delete checks.
- **Done / verification evidence:** Update sends a complete replacement body built from canonical desired state plus the defensively cloned permitted baseline fields required by the API, with no accidental field loss or client-supplied body. Both supported versions reject malformed or incomplete updates in focused tests.

#### 4.6.3 — Refuse immutable or prebuilt collisions

- **Dependency:** 4.3.8; 4.6.1–4.6.2; ownership collision classifications.
- **Worker opportunity:** **Yes — non-overlapping.** Own collision fixtures and no-mutation assertions; do not change prebuilt collective handling.
- **Done / verification evidence:** A custom-rule operation is rejected when the `rule_id` collides with an immutable/prebuilt/unmanageable rule or otherwise cannot be safely owned. The remote mutation counter remains zero and the safe conflict/rejection is available to the report.

#### 4.6.4 — Gate custom-rule deletes on `rule_id`, inventory, and tag

- **Dependency:** 4.2.5; 4.3.9; 4.6.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own custom-rule delete authorization fixtures; do not change generic delete scheduling.
- **Done / verification evidence:** Delete addresses only the exact planned `rule_id` and requires fresh target-scoped inventory plus the matching managed tag. No name search, broad cleanup, marker-only adoption, stale inventory, or altered tag can authorize deletion.

#### 4.6.5 — Verify custom-rule post-state and API-key ownership diagnostics

- **Dependency:** 4.6.1–4.6.4; 4.8.4; API-key ownership behavior contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own custom-rule post-state and ownership-diagnostic fixtures; do not change credential storage or report persistence.
- **Done / verification evidence:** Create/update/delete read-back proves exact `rule_id`, ownership tag, and canonical desired/live post-state. API-key ownership behavior is represented in a bounded safe diagnostic/report reason without exposing key material, and ownership-related failures cannot be mislabeled as successful convergence.

### 4.7 Implement collective prebuilt mutation

#### 4.7.1 — Issue one collective PUT when planned

- **Dependency:** 4.3.10; collective prebuilt mutation contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own the collective PUT adapter and request fixtures; do not change individual rule adapters.
- **Done / verification evidence:** A planned prebuilt operation emits exactly one supported collective PUT for the target and desired collective state. The request contains no individual prebuilt rule mutation and follows both supported version contracts.

#### 4.7.2 — Prohibit individual prebuilt addressing

- **Dependency:** 4.7.1; Phase 3 plan action restrictions.
- **Worker opportunity:** **Yes — non-overlapping.** Own negative route/adapter/plan fixtures for individual prebuilt IDs; do not alter collective request behavior.
- **Done / verification evidence:** Individual prebuilt rules cannot be created, updated, deleted, journaled as independent mutations, or selected by a force/resume path. A plan or remote response containing individual prebuilt actions is rejected before a remote call.

#### 4.7.3 — Verify collective status and counts

- **Dependency:** 4.7.1; 4.8.4.
- **Worker opportunity:** **Yes — non-overlapping.** Own collective response fixtures, status, and count invariants; do not change generic post-verification.
- **Done / verification evidence:** Post-verification reads the collective status and requires valid expected counts/status for the planned operation. Malformed, partial, or mismatched collective results are failed safely rather than treated as individual success.

#### 4.7.4 — Represent one collective operation and report outcome

- **Dependency:** 4.7.1–4.7.3; 4.9.1.
- **Worker opportunity:** **No — report/executor integration.** The single-operation representation must align with DAG, journal, target, and report aggregation.
- **Done / verification evidence:** One planned collective operation produces one journal lifecycle and one operation/target report outcome, with no fabricated per-rule outcomes. Counts/status and safe evidence remain attached to that one result.

### 4.8 Execute DAG safely

#### 4.8.1 — Select ready operations from the deterministic DAG

- **Dependency:** 4.2.2; Phase 3 sorted same-target dependency DAG.
- **Worker opportunity:** **No — scheduler boundary.** Ready selection, target isolation, and dependency state are shared by every mutation kind.
- **Done / verification evidence:** The executor considers operations only in the saved deterministic order, starts an operation only after all same-target dependencies have verified success, and never treats observations or unrelated-target operations as dependencies. Scheduler tests cover empty, linear, branching, and multi-target DAGs.

#### 4.8.2 — Write the pre-mutation journal before every remote mutation

- **Dependency:** 4.8.1; Phase 3 `PreMutationJournal` schema; 4.3.10.
- **Worker opportunity:** **No — critical durability boundary.** One owner must enforce the ordering for all resource-kind adapters.
- **Done / verification evidence:** Before any remote create/update/delete/collective PUT, the durable journal records operation, exact target, action, marker/inventory generation where applicable, baseline, expected-post, and lifecycle. A failure to durably write/flush the journal prevents the remote mutation and leaves an auditable safe failure.

#### 4.8.3 — Execute one mutation without automatic mutation retries

- **Dependency:** 4.8.2; 4.4–4.7 mutation adapters.
- **Worker opportunity:** **No — shared remote-call boundary.** Retry, cancellation, error classification, and journal transitions must be consistent across kinds.
- **Done / verification evidence:** Each operation makes one intentional mutation attempt using the selected adapter; remote errors, context cancellation, and timeouts become failed outcomes without automatically replaying the mutation. Read-only probes may retain their separately documented retry rules, but mutation calls do not.

#### 4.8.4 — Read back and compare the expected post-state

- **Dependency:** 4.8.3; 4.4.4, 4.5.5, 4.6.5, and 4.7.3.
- **Worker opportunity:** **No — shared post-verification boundary.** It must preserve kind-specific checks while enforcing one journal lifecycle.
- **Done / verification evidence:** The executor performs the required read-back and compares exact live identity, presence/absence, canonical fingerprint, and kind-specific postconditions to the journal's expected-post assertion. A mismatch is failed/uncertain as specified, never success, and no inventory commit occurs.

#### 4.8.5 — Commit inventory only after verified mutation

- **Dependency:** 4.8.4; Phase 3 ownership inventory write contract.
- **Worker opportunity:** **No — critical durability boundary.** Inventory commit ordering is shared across all prunable resource kinds and targets.
- **Done / verification evidence:** Only a mutation with successful post-verification can update the exact target inventory, generation, remote ID, marker, and last-desired fingerprint. Failed, rejected, skipped, conflicted, or unverified operations do not grant ownership; an inventory-write failure retains journal evidence and is not reported as durable success.

#### 4.8.6 — Clear the journal only after durable inventory commit

- **Dependency:** 4.8.5; state-store atomic write/recovery contract.
- **Worker opportunity:** **No — critical durability boundary.** Journal clearing and inventory persistence must be ordered and recovered as one executor policy.
- **Done / verification evidence:** The journal is cleared only after post-verification and the required inventory/report state are durably committed. Injected clear/rename/interruption failures leave a recoverable journal; restart classification does not replay a completed remote mutation or falsely erase uncertain work.

#### 4.8.7 — Skip only transitive dependants after failure

- **Dependency:** 4.8.1–4.8.4; operation outcome model.
- **Worker opportunity:** **Yes — non-overlapping.** Own DAG failure-propagation fixtures and skip-code assertions; do not change remote mutation or persistence code.
- **Done / verification evidence:** A failed, rejected, or unverified operation marks only its transitive dependants as skipped, with dependency evidence. Siblings and operations that do not depend on the failed node remain eligible; no skipped operation makes a remote call.

#### 4.8.8 — Continue unrelated resources and targets

- **Dependency:** 4.3.10; 4.8.1 and 4.8.7; target-lock contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own multi-target/independent-resource scheduler fixtures; do not change target preflight or per-kind adapters.
- **Done / verification evidence:** A target or resource failure does not cancel unrelated target/resource work, while each target retains its own preflight, lock, journal, inventory, and report scope. Tests prove progress and durable outcomes for independent targets after one target fails.

#### 4.8.9 — Do not retry mutations or roll back completed work

- **Dependency:** 4.8.3–4.8.8.
- **Worker opportunity:** **Yes — non-overlapping.** Own negative retry/rollback tests and remote-call counts; do not add recovery behavior.
- **Done / verification evidence:** An apply result never automatically retries a mutation and never rolls back a previously verified mutation because a later operation/target failed. Reports preserve the partial result and mark the remaining affected work according to dependency and preflight status.

#### 4.8.10 — Bound job runtime and per-operation execution

- **Dependency:** 4.8.1–4.8.3; Phase 3 durable job limits and Phase 2 bounded HTTP contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own timeout/budget fixtures and safe timeout outcomes; do not change scheduler dependency semantics.
- **Done / verification evidence:** Overall apply jobs, target preflight, remote calls, reads, and post-verification have bounded deadlines/response sizes consistent with existing contracts. Exhaustion produces a durable failed/rejected outcome and never extends indefinitely or becomes false success.

#### 4.8.11 — Handle shutdown without false success

- **Dependency:** 4.8.2–4.8.10; runtime lifecycle and durable job recovery contract.
- **Worker opportunity:** **No — lifecycle integration boundary.** Shutdown, lock release, journal retention, job state, and restart recovery must be tested together.
- **Done / verification evidence:** Graceful and abrupt shutdowns stop admitting work, cancel only what is in flight, retain journals for uncertain mutations, and persist job/report states that distinguish interrupted work from success. Restart never claims success without post-verification and never silently resumes or replays a mutation.

### 4.9 Persist reports and plan consumption

#### 4.9.1 — Persist the complete per-target/per-operation outcome vocabulary

- **Dependency:** 4.8.1–4.8.8; Phase 3 `Report` contract.
- **Worker opportunity:** **Yes — non-overlapping.** Own report schema mapping and status fixture coverage; do not own journal or job transitions.
- **Done / verification evidence:** Reports persist target and operation outcomes for `created`, `updated`, `deleted`, `unchanged`, `skipped`, `conflicted`, `rejected`, and `failed`, including no-operation/preflight outcomes where applicable. Actions, IDs, and collective outcomes remain consistent with the plan and no status is dropped on partial completion.

#### 4.9.2 — Persist safe evidence and actor/job/plan references

- **Dependency:** 4.1.5–4.1.6; 4.8.4–4.8.8; Phase 3 non-secret report/audit schemas.
- **Worker opportunity:** **Yes — non-overlapping.** Own report evidence projections and secret-scan fixtures; do not change remote adapters.
- **Done / verification evidence:** Each report retains bounded safe reason/evidence, exact actor/job/plan/target references, baseline/expected-post assertions where permitted, and dependency/ownership context needed to explain the outcome. A persisted-state/log/error/API scan proves no credentials, request bodies, response bodies, or arbitrary messages leak.

#### 4.9.3 — Checkpoint reports durably through partial progress and restart

- **Dependency:** 4.8.5–4.8.11; durable state-store write/recovery contract.
- **Worker opportunity:** **No — report/job/journal consistency boundary.** Checkpoint ordering must be integrated with operation completion and restart recovery.
- **Done / verification evidence:** Report checkpoints survive a later operation failure, target failure, process restart, and persistence interruption without converting an unverified operation into success or erasing earlier verified outcomes. Recovery tests compare job, journal, inventory, report, and audit projections.

#### 4.9.4 — Consume a plan after the first successful mutation

- **Dependency:** 4.8.4–4.8.6; 4.9.1–4.9.3.
- **Worker opportunity:** **No — plan/job/report transaction boundary.** Consumption must be coordinated with verified mutation evidence and durable state.
- **Done / verification evidence:** Once any mutation succeeds and is post-verified, the plan is operationally consumed durably, even if later operations/targets fail. Preflight rejection, all-no-op, all-skipped, or all-failed results do not falsely consume a plan; a consumed plan cannot be applied again.

#### 4.9.5 — Require an explicit new plan after an apply result

- **Dependency:** 4.9.1–4.9.4; Phase 3 server-managed planning API.
- **Worker opportunity:** **Yes — non-overlapping.** Own replan-required reason codes and plan/report contract fixtures; do not add replan execution.
- **Done / verification evidence:** Every partial, rejected, failed, conflicted, or otherwise non-converged apply result that might be retried tells the operator to create a new plan from current state. The next plan is generated through the normal planning path and rechecks current mounted inputs, target config, Secret metadata, inventory, version, and live state.

#### 4.9.6 — Expose no resume, force, or implicit-replan operation

- **Dependency:** 4.1.7–4.1.10; 4.8.9 and 4.8.11; 4.9.4–4.9.5.
- **Worker opportunity:** **Yes — non-overlapping.** Own negative API/service/UI contract tests; do not alter normal apply initiation.
- **Done / verification evidence:** No API, job worker, UI control, or recovery path accepts resume/force/skip-preflight/implicit-replan semantics. Retrying requires a newly planned server-managed plan and a new explicit confirmation/idempotency request.

### 4.10 Implement apply API/UI

#### 4.10.1 — Add the asynchronous apply route

- **Dependency:** 4.1.3–4.1.5; 4.2.1; durable job creation.
- **Worker opportunity:** **No — route/service contract boundary.** The `POST /api/v1/plans/{id}/apply` response, admission, and job creation must be integrated once.
- **Done / verification evidence:** A valid request to `POST /api/v1/plans/{id}/apply` returns HTTP `202` with the authoritative job ID and safe polling reference, and does not wait for mutations. Invalid admission returns the established error envelope without a job or remote call; OpenAPI and handler behavior match.

#### 4.10.2 — Enforce cookie CSRF and bearer automation boundaries

- **Dependency:** 4.10.1; Phase 2 CSRF/origin and bearer-auth contracts.
- **Worker opportunity:** **Yes — non-overlapping.** Own apply-route browser/bearer security tests; do not change identity or service authorization policy.
- **Done / verification evidence:** Cookie-authenticated apply requests require the existing CSRF and same-origin/origin protections; bearer automation requests use the documented bearer boundary and do not receive cookie-based bypass behavior. Missing/duplicate/mixed identities fail closed before job creation.

#### 4.10.3 — Enforce idempotency and roles at route and service layers

- **Dependency:** 4.1.1–4.1.4; 4.10.1.
- **Worker opportunity:** **No — defense-in-depth integration.** Route checks and service checks must be exercised together so internal callers cannot bypass policy.
- **Done / verification evidence:** Both the HTTP route and apply service enforce role, creator, confirmation, and idempotency rules. Direct service tests and HTTP tests show equivalent denial/replay behavior and no mutation on either bypass path.

#### 4.10.4 — Expose preflight, target, dependency, operation, and report status

- **Dependency:** 4.9.1–4.9.3; durable job/report projections; 4.10.1.
- **Worker opportunity:** **Yes — non-overlapping.** Own read-only status projections, pagination, and safe-error tests; do not change the executor's state transitions.
- **Done / verification evidence:** Authorized job/report views expose durable preflight state, independent target progress, dependency skips, per-operation outcomes, and final report references without filesystem paths or secret fields. Polling after disconnect/restart returns the same safe projection.

#### 4.10.5 — Render apply progress and reports in the UI

- **Dependency:** 4.10.4; Phase 3 plan-review UI and embedded `/api/v1` client conventions.
- **Worker opportunity:** **Yes — non-overlapping.** Own embedded UI views and fixtures; do not add UI-only apply routes or server behavior.
- **Done / verification evidence:** The UI starts apply only through the shared API, shows `202` job progress, target/dependency/operation status, durable reports, and partial outcomes, and remains usable after refresh or polling fallback. It renders safe data only and has no plan-edit/upload/resume/force control.

#### 4.10.6 — Show explicit new-plan guidance after partial or rejected results

- **Dependency:** 4.9.5–4.9.6; 4.10.5.
- **Worker opportunity:** **Yes — non-overlapping.** Own UI copy/state tests for replan guidance; do not change planner behavior.
- **Done / verification evidence:** Partial, rejected, conflicted, failed, stale, and blocked results visibly explain that current state must be replanned before another apply. The guidance does not offer an implicit retry or imply rollback/resume, and it remains available from the durable report after refresh.

#### 4.10.7 — Audit request and final outcome

- **Dependency:** 4.1.6; 4.9.1–4.9.4; 4.10.1.
- **Worker opportunity:** **No — durable outcome integration.** Request, job, target, report, plan-consumption, and final audit links must be consistent across success and partial failure.
- **Done / verification evidence:** The accepted/rejected request and final job outcome emit durable safe audit events linked by actor, request, job, plan, target, and report IDs where applicable. Restart and persistence-failure tests prove audit never claims success without the corresponding report/journal evidence and never contains credentials or arbitrary remote details.

### 4.11 Fault/security tests

#### 4.11.1 — Provide bounded deterministic fault-injection seams

- **Dependency:** 4.3.1–4.3.2; 4.8.2–4.8.6; 4.9.3.
- **Worker opportunity:** **Yes — non-overlapping.** Own test-only remote/state failure seams and fixture controls; do not change production safety decisions beyond injectable boundaries.
- **Done / verification evidence:** Tests can deterministically fail a remote mutation and each journal, inventory, and report write at named lifecycle points without changing production defaults. The harness records call ordering and supports restart/recovery assertions without storing secret values.

#### 4.11.2 — Test remote mutation failure and uncertain outcomes

- **Dependency:** 4.11.1; 4.8.3–4.8.4.
- **Worker opportunity:** **Yes — non-overlapping.** Own remote-failure fixtures and call-count assertions; do not edit persistence-failure fixtures.
- **Done / verification evidence:** Remote errors, timeouts, disconnects, malformed acknowledgements, and post-read mismatches produce failed/uncertain outcomes, retain the journal as required, do not auto-retry, do not commit inventory, and do not report false success.

#### 4.11.3 — Test journal write/flush/clear failures

- **Dependency:** 4.11.1; 4.8.2 and 4.8.6.
- **Worker opportunity:** **Yes — non-overlapping.** Own journal fault fixtures and recovery evidence; do not edit inventory/report fault tests.
- **Done / verification evidence:** A pre-mutation journal write/flush failure prevents the remote call; an update/clear failure retains enough journal state for safe restart classification. Tests prove no mutation is replayed merely because journal persistence failed.

#### 4.11.4 — Test inventory write failures

- **Dependency:** 4.11.1; 4.8.4–4.8.5.
- **Worker opportunity:** **Yes — non-overlapping.** Own inventory fault fixtures and ownership assertions; do not edit journal or report fault fixtures.
- **Done / verification evidence:** An inventory commit failure after remote post-verification is surfaced as a durable non-success/uncertain result with journal retained for recovery; stale inventory cannot authorize a later prune, and the executor does not silently repeat the remote mutation.

#### 4.11.5 — Test report write failures

- **Dependency:** 4.11.1; 4.9.1–4.9.3.
- **Worker opportunity:** **Yes — non-overlapping.** Own report fault fixtures and job/report/audit consistency assertions; do not edit remote mutation fixtures.
- **Done / verification evidence:** A report checkpoint/final-write failure is visible in job and audit state, preserves earlier durable evidence, and cannot turn a missing report into an apparent successful apply. Restart recovery exposes the safe incomplete/failed state and retains journal/inventory consistency.

#### 4.11.6 — Exercise the complete preflight drift matrix

- **Dependency:** 4.3.3–4.3.9; 4.11.1.
- **Worker opportunity:** **Yes — non-overlapping by drift category.** Workers may own separate mounted-file, target-config, Secret/CA, inventory, version, marker, or live-baseline fixtures; no worker changes the shared preflight gate.
- **Done / verification evidence:** Tests mutate mounted files, target configuration, Secret metadata/content, CA trust, ownership inventory, Kibana version, live markers, and live baselines between plan and apply. Each affected target rejects before first mutation with a safe reason, while unrelated targets retain their own valid path.

#### 4.11.7 — Prove rejection occurs before the first mutation

- **Dependency:** 4.11.2 and 4.11.6; 4.3.10.
- **Worker opportunity:** **No — acceptance-boundary integration.** This combines all preflight rejection sources and the remote-call counter.
- **Done / verification evidence:** For every preflight rejection category, an instrumented target shows zero mutation calls, zero unauthorized inventory grant, and no journal lifecycle that falsely claims a mutation occurred. The durable report/job/audit still records the safe rejection.

#### 4.11.8 — Prove independent target and resource progress

- **Dependency:** 4.8.7–4.8.8; 4.11.2 and 4.11.6.
- **Worker opportunity:** **Yes — non-overlapping.** Own multi-target and unrelated-resource acceptance fixtures; do not change dependency propagation.
- **Done / verification evidence:** A failed/rejected target or resource does not prevent an unrelated target/resource from completing its own preflight, mutation, verification, inventory, and report path. The combined report preserves both outcomes without rollback of verified work.

#### 4.11.9 — Prove transitive-only skip behavior

- **Dependency:** 4.8.1 and 4.8.7; 4.11.2.
- **Worker opportunity:** **Yes — non-overlapping.** Own branching-DAG skip fixtures; do not change scheduler implementation.
- **Done / verification evidence:** A failed ancestor causes every transitive dependant to be skipped, but not siblings or unrelated branches. Skip reports identify the dependency safely, and remote-call counters prove skipped operations were never attempted.

#### 4.11.10 — Prove restart consistency for jobs, reports, and audit

- **Dependency:** 4.8.11; 4.9.3–4.9.4; 4.10.7; 4.11.3–4.11.5.
- **Worker opportunity:** **No — end-to-end durability boundary.** Restart sequencing must cover all durable projections and cannot be split by file type without losing consistency evidence.
- **Done / verification evidence:** Restart at queued, preflight, journaled, mutating, post-verified, inventory-committed, report-checkpointed, and final states yields consistent job/report/audit/plan-consumption state. No restart path resumes, retries, rolls back, or claims success without the required evidence.

#### 4.11.11 — Sentinel-scan all secret-bearing surfaces

- **Dependency:** 4.3.6; 4.9.2; 4.10.4–4.10.7; 4.11.10.
- **Worker opportunity:** **Yes — non-overlapping.** Own the repository-wide apply-path sentinel scanner and safe-fixture corpus; do not modify production code to suppress findings.
- **Done / verification evidence:** Automated scans cover requests, state/PVC, journals, inventory, jobs, reports, logs, API responses, UI DOM/storage, audit, and errors. API keys, CA bodies, OIDC/bearer tokens, cookies, Secret bodies, certificate bodies, and arbitrary remote response data are absent; any finding fails the Phase 4 gate.

## Phase gate

Every mutation is preflighted, journaled, and post-verified; target/dependency isolation works; partial results are durable and audited; replan is mandatory; no credentials leak; and all fault-injection acceptance tests pass.
