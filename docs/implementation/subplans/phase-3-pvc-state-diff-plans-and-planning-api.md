# Phase 3 — PVC state, diff, plans, and planning API

**Status: Phase 3.1, Phase 3.2, Phase 3.3.1, Phase 3.3.2a, Phase 3.3.2b, Phase 3.3.3, and Phase 3.3.4a complete; Phase 3 not passed.** Versioned non-secret schemas/codecs, hardened state-directory primitives/runtime integration, the durable job-record repository, fail-closed job recovery policy/transition, bounded startup job recovery, durable scoped idempotency persistence, and the standalone durable scheduler core are implemented. Scheduler runtime integration, remaining durable jobs/audit, planning, and API work remain.

## Objective

Implement single-writer non-secret PVC state, durable jobs/audit/inventory, ownership-safe diffing, deterministic plans, and web/API plan review.

## Prerequisites

- Phase 2 authentication, Secrets, and read adapters pass.
- Mounted desired and live canonical projections share stable identity/fingerprint contracts.

## Substeps

### 3.1 Define versioned state formats — **Complete**

1. Define source snapshot, inventory, journal, plan, job, report, idempotency, and audit schemas.
2. Use one lockstep `elastic-maintainer/state/v1alpha1` API version and reject unknown/unsupported versions, kinds, fields, duplicate keys/identities, trailing JSON, invalid bounded values, and nil decode destinations.
3. Use domain-bearing v1 SHA-256 fingerprints for desired, Kibana-live, ownership-inventory, and target-config state; reject domain confusion.
4. Distinguish remote absence from missing state with explicit `RemoteStateAssertion` presence values.
5. Keep plan mutations to create/update/delete; represent unchanged/conflict/skip/reject as observations, with deterministic target/phase/kind/logical/action/ID ordering and earlier same-target dependencies.
6. Store actor IDs/roles/auth method and credential Secret metadata only, never tokens, values, request digests in credential metadata, or certificate bodies.
7. Require explicit migration of the complete state set for any version or kind change; never migrate silently.
8. Keep this increment directory-neutral: no filesystem persistence, locking, recovery engine, or API.

### 3.2 Harden the state directory — **Complete**

1. Enforce expected mount, owner permissions, symlink/path defenses, and free-space checks.
2. Implement atomic temp-write/fsync/rename.
3. Implement process, job, and target locks.
4. Detect multiple writers and fail readiness.
5. Use ReadWriteOnce/single replica assumptions explicitly.
6. Test corruption and interrupted writes.
7. Open the store before listening with the effective UID, the state-schema size limit, a documented advisory free-space reserve, and bounded build/instance lock metadata.
8. Hold the store for the runtime lifetime; release it on constructor failure, normal or unexpected serve exit, and idempotent shutdown. Readiness requires both an active server and a passing state-store check while liveness remains independent.

The deployment contract is documented in `docs/operations/state-directory.md`. Integration coverage lives in the `internal/server` package; filesystem primitive tests remain in `internal/statefs`.

**Planning status:** 3.3.4a is complete; 3.3.4b through 3.10 remain future work. Each increment is intended to be one independently reviewable and verifiable unit. Dependencies below are completion dependencies; increments without a listed dependency may proceed in parallel, provided their workers do not share write ownership.

**Living-plan rule:** When implementation discoveries change an assumption, update the scope, dependencies, definition of done, focused verification, and worker boundary of the affected *remaining* increments before starting them. Preserve completed status and safety requirements, and do not mark a future increment complete without its evidence.

### 3.3 Implement durable job storage

#### 3.3.1 Persist the durable job record — **Complete**

- **Evidence:** `internal/jobrecord` provides a context-gated file repository over `*statefs.Store`, strict queued-only `state.Job` creation, CAS-protected transitions, restart-stable SHA-256 ETags, append-only lifecycle/result metadata, filtered snapshot-digest pagination, bounded scans, and fail-closed corruption/unsafe-entry handling. `internal/statefs.Store.WriteAtomicIfMatch` holds the store lock through metadata validation, content ETag comparison, and replacement; `ReadDocuments` returns sorted defensive bytes under one lock with 10,000-record and 32 MiB aggregate bounds, while `ListDocuments` remains metadata-only.
- **Verification:** Focused `internal/jobrecord`, `internal/state`, and `internal/statefs` tests cover lifecycle fixtures/links, transitions/immutability/ETags, concurrent CAS conflict, filtering/token scope and changed snapshots, corruption, unsafe entries, aggregate bounds, gate cancellation, and secret-safe errors. `go test ./internal/statefs ./internal/jobrecord`, `go test -race ./internal/statefs ./internal/jobrecord`, `go test ./...`, `go vet ./...`, and `git diff --check` pass. No startup recovery, idempotency index, scheduler, HTTP/SSE, runtime migration, or cancellation mutation is included.
- **Next:** 3.3.2b — scan and recover durable jobs at startup.

#### 3.3.2a Define fail-closed recovery policy and transitions — **Complete**

- **Scope:** Define a pure recovery classification for every existing `internal/jobs.Type` and status, plus a dedicated CAS-protected repository transition from queued/running to `interrupted`. Terminal records are preserved. No current job type may be declared resumable until its complete durable input and side-effect policy exists; apply is always non-resumable.
- **Dependencies:** 3.3.1 and the existing `internal/jobs` type/status contracts.
- **Definition of done:** Classification is deterministic and exhaustive; nonterminal jobs without an approved safe-resume contract receive a bounded safe interruption code and finish time, while terminal records remain byte-unchanged. The dedicated recovery transition cannot mutate identities, links, prior start time, or terminal records and is safe under stale ETags.
- **Focused verification:** Table-test every status for validation, plan, apply, and target-inventory jobs; test queued/running interruption, terminal preservation, stale ETags, repeated classification, timestamp bounds, and secret-safe errors.
- **Evidence:** `internal/jobrecovery/recovery.go` classifies all four current job types across all six statuses, preserves terminal jobs, interrupts queued/running jobs, uses bounded constant codes with apply-specific queued/running codes, and returns safe sentinel errors for invalid inputs. `internal/jobrecord/repository.go` adds the context-gated `Interrupt` CAS transition with state validation, immutable/link/started-time preservation, terminal rejection, and safe missing/stale mappings. `internal/jobrecovery/recovery_test.go` and `internal/jobrecord/interrupt_test.go` cover the full matrix, serialization, timestamp/code validation, metadata/cancellation preservation, terminal/repeat behavior, CAS races, context cancellation, and sentinel-safe errors.
- **Verification:** `gofmt -w internal/jobrecovery/recovery.go internal/jobrecovery/recovery_test.go internal/jobrecord/repository.go internal/jobrecord/interrupt_test.go`; `go test ./internal/jobrecovery ./internal/jobrecord`; `go test -race ./internal/jobrecovery ./internal/jobrecord`; `go test ./...`; `go vet ./...`; and `git diff --check` pass. No startup enumeration/runtime wiring, scheduler, idempotency, HTTP/SSE, or cancellation mutation is included.
- **Worker boundary:** A recovery-policy worker owns pure classification and the narrow repository recovery transition only; it does not enumerate startup state, wire runtime startup, schedule jobs, or resume execution.

#### 3.3.2b Scan and recover durable jobs at startup — **Complete**

- **Scope:** Enumerate one coherent bounded job snapshot before schedulers start, apply 3.3.2a decisions with CAS, and expose a bounded recovery summary. Fail startup on malformed, ambiguous, or concurrently changing records; never infer success or resume a remote mutation.
- **Dependencies:** 3.3.2a and the Phase 3.2 runtime state-store lifecycle.
- **Definition of done:** Startup recovery is deterministic, idempotent after partial interruption, runs before listening/scheduling, marks every non-resumable queued/running record accurately, preserves terminal records, and leaves unrelated records readable.
- **Focused verification:** `internal/jobrecord/recovery_test.go` covers all four types and six statuses, exact summary counts and policy codes, terminal byte preservation, malformed-later and wrong-filename zero-mutation behavior, one-scan bounds, future timestamps, cancellation, safe sentinels, and rerun idempotency. `internal/server/recovery_test.go` pre-seeds queued/running/terminal state and proves recovery completes before the listener callback, rejects malformed startup state without listening, and releases the state lock for reopen.
- **Evidence:** `FileRepository.Recover` acquires the repository gate, calls `Store.ReadDocuments` once with `MaxRecordsScan`/`MaxTotalBytes`, decodes and classifies the complete sorted snapshot before preparing any write, and uses store-level CAS writes for queued/running records only. `HTTPRuntime` constructs the durable repository and invokes recovery at one `time.Now().UTC()` immediately after `statefs.Open`, before listening or service construction; it retains the repository/summary, logs only three bounded counts, and maps recovery failures to safe categories.
- **Verification:** `gofmt` on the changed Go files; focused `go test ./internal/jobrecovery ./internal/jobrecord ./internal/server`; focused and full race tests; `go test ./...`; `go vet ./...`; and `git diff --check`. No scheduler, idempotency, HTTP/SSE, or cancellation mutation is included.
- **Worker boundary:** A startup-recovery worker owns bounded enumeration, orchestration, summary, and runtime startup integration; it does not own queue limits, idempotency, remote reads, HTTP presentation, or execution resumption.
- **Next:** 3.3.3 — persist scoped idempotency results (now complete; see below).

#### 3.3.3 Persist scoped idempotency results — **Complete**

- **Scope:** Add a generic durable file repository under the fixed `idempotency` statefs directory. Scope records by exact normalized actor/action/key; keep request digest as the conflict discriminator. Support atomic create-or-replay with an explicit trusted UTC observation time, direct digest-checked lookup, expiry-aware replacement, bounded capacity reclamation, and narrow pending-to-terminal CAS completion. Do not integrate validation, inventory, credentials, plans, routes, scheduling, HTTP/SSE, or audit.
- **Dependencies:** 3.3.1; Phase 2 substep 2.4 actor projection and substep 2.6 idempotency/request-digest contracts.
- **Definition of done:** Repeated equivalent requests return one durable record with an explicit replay result, different digests conflict without rewriting unexpired state, other scopes remain independent, terminal results are typed and immutable, and bounded state is fail-closed and non-secret.
- **Evidence:** `internal/idempotencyrecord` implements domain-separated length-safe scope hashing, deterministic hash filenames/body IDs, strict `state.IdempotencyRecord` codecs, explicit caller-time validation for new/replacement candidates (`candidate.CreatedAt == at`), context gating, no-replace/CAS writes, restart-stable SHA-256 ETags, inclusive expiry semantics, 10,000-record/32 MiB coherent scan limits, ETag-conditional expiry reclamation under a capacity lock, and safe unavailable-versus-corrupt error mapping. `statefs` creates and validates the fixed `idempotency` directory on normal open and provides descriptor-relative `RemoveIfMatch` with directory fsync. Tests cover scope separation, replay/restart, digest conflicts, independent scopes, pending completion/terminal immutability, direct terminal records, create/completion/expiry replacement CAS races, expiry boundary/replacement, nil-expiry retention, reclamation, cross-repository 9,999-record capacity races, corruption/unsafe entries, context cancellation, strict serialized bytes, and sentinel-safe errors.
- **Verification:** `gofmt`, focused idempotency/statefs tests, focused and full race tests, `go test ./...`, `go vet ./...`, and `git diff --check` pass for this increment.
- **Worker boundary:** An idempotency worker owns only the keyed result repository and lookup semantics; it does not own general job transitions, route authorization, credential handling, or any scheduler/HTTP/SSE/audit integration.
- **Next:** 3.3.4b — integrate scheduler runtime lifecycle.

#### 3.3.4a Implement the durable scheduler core

- **Scope:** Add a generic scheduler over `jobrecord.Repository` with explicit queued-job submissions and in-memory executor closures, bounded waiting capacity and worker concurrency, CAS lifecycle transitions, scheduler-owned execution contexts, safe fixed failure results, and deterministic cooperative shutdown. Current durable job records intentionally do not persist complete validation or target-inventory inputs, so no existing route/service is switched in this increment and no work is resumable after restart.
- **Dependencies:** 3.3.1 and 3.3.2b; existing `jobs` status/transition contracts.
- **Definition of done:** Admission reserves a bounded slot before durable create; accepted work continues after its submitting context/browser disconnects; only configured workers execute; queued/running/succeeded/failed/canceled records are durably accurate; overload and closed schedulers reject safely; executor panics/invalid results cannot leak arbitrary diagnostics; persistence failure closes admission and leaves restart recovery authoritative.
- **Focused verification:** Fill waiting and running capacity, exceed limits, cancel the submitting context after acceptance, inject success/failure/panic/invalid executor results, race submissions and CAS changes across repositories, and shut down with running/queued work. Verify exact max concurrency, one execution per accepted ID, bounded safe codes, accurate durable states, race safety, and sentinel-free errors.
- **Worker boundary:** A scheduler-core worker owns admission, worker lifetimes, execution context, durable lifecycle transitions, health, and cooperative shutdown only; it does not wire server startup, existing validation/inventory services, idempotency, cancellation APIs, SSE, or planning logic.
- **Evidence:** `internal/jobscheduler` implements the standalone core over a minimal `jobrecord.Repository` interface. It validates explicit queued `state.Job` submissions and every returned record/ETag, reserves `QueueCapacity+Workers` before durable create, applies a bounded scheduler-owned persistence context to every lifecycle repository call, keeps accepted work independent of submitter contexts, limits execution to configured workers, CAS-claims and terminalizes jobs with UTC timestamps, preserves metadata and type-valid plan/report links, maps invalid results/panics to `executor_result_invalid`/`executor_panic`, linearizes shutdown cancellation under admission, closes admission on unexpected or ambiguous persistence failures, and cancels accepted queued/running work cooperatively without `jobrecovery.Interrupt`.
- **Verification:** `internal/jobscheduler/scheduler_test.go` covers real `statefs`/`jobrecord` lifecycle, exact capacity and concurrency, submit-context disconnect, pre-canceled admission, success/failure/panic/invalid results, shutdown cancellation/idempotency/barrier races, non-cooperative executor retry, stale start/finish ownership, malformed ETags, persistence timeouts, post-rename unknown Create outcomes, persistence-failure health sentinels, metadata/link preservation, and concurrent submissions. `go test ./internal/jobscheduler`, `go test -race ./internal/jobscheduler`, `go test ./...`, `go vet ./...`, and `git diff --check` pass. Verification timestamp: 2026-08-31T12:39:45Z. No runtime/service/route adapter, restart resumption, idempotency, cancellation API, SSE, planning, or audit was added.
- **Next:** 3.3.4b — integrate scheduler runtime lifecycle.

#### 3.3.4b Integrate scheduler runtime lifecycle

- **Scope:** Construct the scheduler only after 3.3.2b startup recovery, retain it in `HTTPRuntime`, and shut it down before closing the durable state store. Keep all existing request services on their current executors until their durable input/result adapters exist; do not imply that process-local validation or live-inventory jobs have become durable.
- **Dependencies:** 3.3.4a and the Phase 3.2/3.3.2b runtime lifecycle.
- **Definition of done:** No scheduler starts before recovery; listener/service construction failures stop it and release state; normal and timeout shutdown ordering is deterministic; readiness fails after fatal scheduler persistence failure; zero registered route adapters cannot execute work.
- **Focused verification:** Constructor ordering, recovery failure, listener failure, normal shutdown, scheduler timeout/fatal health, state-lock cleanup, and no-work startup tests pass without changing existing endpoint behavior.
- **Worker boundary:** A runtime-lifecycle worker owns server construction/readiness/shutdown integration only; it does not adapt route submissions, alter persisted formats, or implement job read/cancellation/SSE APIs.

#### 3.3.5 Expose authenticated job list and polling projections

- **Scope:** Project durable job state into the existing authenticated `Get` and paginated `List` read projections. Keep projections safe and make polling the authoritative fallback; do not add browser-dependent execution semantics.
- **Dependencies:** 3.3.1 and 3.3.4b; `internal/jobs.Queue.Get`/`List` and `ListOptions` contracts, Phase 2 substeps 2.1–2.4 authentication/RBAC, and Phase 1 substep 1.8 API response/pagination conventions.
- **Definition of done:** Authorized viewers can retrieve one job or bounded filtered pages of jobs, unauthorized callers are denied, all existing statuses are representable, and reads do not alter execution or persisted state.
- **Focused verification:** Test role authorization, malformed/unknown job IDs, each status including `canceled` and `interrupted`, type/status filters, first/middle/last/empty pages, invalid page bounds/tokens, polling after restart, and response sentinel scans.
- **Worker boundary:** A job-read worker owns `Get`/`List` handlers, serializers, and pagination only; it does not own queue scheduling, cancellation transitions, SSE, or planning.

#### 3.3.6 Expose authenticated SSE and existing cancellation projection

- **Scope:** Project durable job changes into the bounded authenticated SSE stream and wire the existing `Queue.RequestCancellation`/`CancellationPolicy` contract where the API exposes cancellation. Use only existing status transitions; do not add a new cancellation mode or make execution browser-dependent.
- **Dependencies:** 3.3.1, 3.3.4b, and 3.3.5; Phase 2 substeps 2.1–2.4 authentication/RBAC and the existing job cancellation contract.
- **Definition of done:** Authorized cancellation requests follow the existing policy and transitions, unsupported/terminal requests fail safely, SSE events are bounded and non-secret, and client disconnect does not cancel or duplicate the job.
- **Focused verification:** Test authorized/denied cancellation, queued/running/terminal jobs, unsupported cancellation, event ordering/bounds, stream limits, client disconnect, restart, and polling after SSE loss. Sentinel-scan job responses and events.
- **Worker boundary:** A job-event worker owns cancellation/API projection adapters and SSE plumbing only; it does not modify scheduler limits, persisted record formats, state-transition policy, or plan execution.

### 3.4 Implement durable audit events

#### 3.4.1 Define and validate safe audit events

- **Scope:** Implement the durable event shape and validation for actor subject/roles, request ID, job ID, action, target ID, plan ID, outcome, timestamp, and bounded safe reason code. Keep actions within the bounded namespaced pattern required by the architecture, and hand validated events to the storage worker.
- **Dependencies:** 3.1 and 3.2; Phase 2 substep 2.4 actor and audit-hook contracts.
- **Definition of done:** Valid events are strictly encoded as non-secret versioned records, required identifiers are preserved, optional identifiers are explicit, and invalid/unbounded events are rejected before the append layer.
- **Focused verification:** Test required/optional field validation, bounded action/reason/identifier values, deterministic serialization, duplicate/invalid event rejection, and reopen/read of validated fixtures.
- **Worker boundary:** An audit-schema worker owns event types and validation in `internal/state`; it does not own redaction policy, file append/rotation, HTTP reads, or caller-specific hooks.

#### 3.4.2 Redact before audit persistence

- **Scope:** Apply the shared safe serialization/redaction boundary before any audit event reaches the PVC writer. Retain only metadata and safe reason codes; never persist tokens, API keys, certificates, Secret values, or sensitive request bodies.
- **Dependencies:** 3.4.1; Phase 2 substeps 2.4, 2.6, and 2.7 redaction and safe-error contracts.
- **Definition of done:** All audit call sites pass through the redaction boundary, redacted events still satisfy the event schema, and unsafe input is rejected or reduced without leaking it in errors.
- **Focused verification:** Inject each prohibited credential and sensitive body type at the audit boundary, inspect stored bytes/errors/log hooks, and verify safe metadata remains available for authorized review.
- **Worker boundary:** A redaction worker owns the audit serialization boundary and sentinel tests; it does not change event storage layout, authorization, or business outcomes.

#### 3.4.3 Append and rotate audit segments atomically

- **Scope:** Implement append-oriented audit files with bounded segment/rotation behavior using the completed atomic write and fsync primitives. Rotation must preserve required evidence and must not expose partial records to readers.
- **Dependencies:** 3.2, 3.4.1, and 3.4.2.
- **Definition of done:** Appends, segment naming/order, size bounds, and rotation are deterministic and safe for the single-writer model; a completed event is either readable in one segment or not acknowledged as persisted.
- **Focused verification:** Append across rotation thresholds, inject write/fsync/rename failures, reopen segments, and verify no truncated acknowledged event or accidental deletion of required evidence.
- **Worker boundary:** A segment-storage worker owns audit file layout, append, fsync, and rotation; it does not own redaction rules, pagination, or audit authorization.

#### 3.4.4 Recover audit state after restart and partial writes

- **Scope:** Reopen audit segments after clean and interrupted shutdown, discard or quarantine only incomplete trailing data according to the state contract, and keep valid prior events available.
- **Dependencies:** 3.4.3.
- **Definition of done:** Restart recovery is deterministic and fail-closed for malformed non-trailing corruption, while valid events before an interrupted append remain readable and audit persistence resumes safely.
- **Focused verification:** Use fixtures for torn final records, interrupted rotation, invalid headers, missing segments, and clean restart. Verify event ordering, no invented events, and no secret bytes in recovery errors.
- **Worker boundary:** An audit-recovery worker owns segment scanning and recovery diagnostics; it does not own event creation, redaction, or API pagination.

#### 3.4.5 Provide authorized paginated audit reads

- **Scope:** Expose the durable audit read projection with the existing role/policy checks, stable ordering, and bounded page size already defined by the API surface.
- **Dependencies:** 3.4.3 and 3.4.4; Phase 2 substep 2.4 RBAC and Phase 1 substep 1.8 API pagination contracts.
- **Definition of done:** Authorized viewers can read complete pages of safe events, unauthorized or out-of-bound requests fail safely, and pagination does not mutate or rewrite audit files.
- **Focused verification:** Test every permitted/denied role, first/middle/last/empty pages, invalid cursors or bounds, rotation-spanning reads, and response sentinel scans.
- **Worker boundary:** An audit-read worker owns the read service/handler and pagination adapter; it does not write segments or alter audit policy.

#### 3.4.6 Audit credential metadata operations safely

- **Scope:** Connect credential metadata operations to the bounded namespaced audit-action pattern, retaining only Secret namespace/name, resource version, rotation metadata, actor, and other explicitly non-secret metadata.
- **Dependencies:** 3.4.1 and 3.4.2; Phase 2 substep 2.6 credential metadata hooks.
- **Definition of done:** Upload/rotation/deletion events are distinguishable by bounded actions and contain no credential values, certificate bodies, tokens, or request digests where prohibited by the state schema.
- **Focused verification:** Exercise each credential metadata action, inspect persisted events and safe errors, and run repository sentinel scans over audit fixtures.
- **Worker boundary:** An audit-integration worker owns credential-operation event call-site mapping only; it does not own Kubernetes Secret operations, plan/job lifecycle audit events, or the generic audit store.

### 3.5 Implement inventory and journal recovery

#### 3.5.1 Key inventory by exact target identity

- **Scope:** Implement inventory records keyed by the complete target identity, not a display name or mutable URL alone, and preserve the state-schema identity/fingerprint version contracts.
- **Dependencies:** 3.1 and 3.2; Phase 1 substeps 1.1 and 1.4 target identity plus Phase 2 substep 2.10 live-inventory contracts.
- **Definition of done:** Inventory lookup, create, and replacement cannot cross state ID, target name, normalized URL, or space boundaries; identity changes create a distinct record rather than transferring authority.
- **Focused verification:** Exercise default/non-default spaces, URL normalization, renamed targets, duplicate identities, and cross-target lookup attempts. Verify no record is returned for a mismatched identity.
- **Worker boundary:** An inventory-key worker owns identity indexing and target scoping; it does not own resource classification, journal recovery, or API handlers.

#### 3.5.2 Record managed inventory metadata

- **Scope:** Store per-resource inventory entries containing kind, logical ID, remote ID, exact marker type, and last desired fingerprint, using the completed versioned state schema.
- **Dependencies:** 3.5.1; Phase 2 substep 2.9 canonical live-resource projections.
- **Definition of done:** Entries are strictly validated, bounded, deterministically serialized, and associated with one exact target inventory generation; absent/unknown metadata cannot silently authorize pruning.
- **Focused verification:** Round-trip each supported kind, reject missing/duplicate/invalid IDs and markers, check fingerprint-domain validation, and inspect persisted records for credential absence.
- **Worker boundary:** An inventory-record worker owns entry shape and serialization; it does not decide ownership, compute diffs, or perform remote mutations.

#### 3.5.3 Define pre-mutation journals and exact recovery

- **Scope:** Persist a journal before a mutation with the target/resource identity, operation identity, baseline state or explicit absence assertion, expected post-state, and the recovery status needed for exact comparison.
- **Dependencies:** 3.2, 3.5.1, and 3.5.2.
- **Definition of done:** Journal records are written atomically before mutation, contain enough non-secret data to compare baseline/current/expected post-state, and reject incomplete or cross-target records.
- **Focused verification:** Test create/absent, update, and delete journal fixtures; verify ordering before a mutation seam, strict validation, target scoping, and no credential-bearing values.
- **Worker boundary:** A journal-format worker owns journal construction and persistence contracts; it does not own recovery decisions, inventory commits, or remote client calls.

#### 3.5.4 Recover and commit inventory only after verified mutation

- **Scope:** Recover a journal only by exact baseline/current/expected-post comparison, and permit inventory updates only after the caller supplies the verified tool-mutation result required by the apply contract. Marker-only resources remain unadopted.
- **Dependencies:** 3.5.2 and 3.5.3; exact marker detection from 3.6.1.
- **Definition of done:** Recovery distinguishes already-applied, not-applied, ambiguous, and changed states without guessing; inventory commit rejects missing/failed post-verification and cannot adopt marker-only resources.
- **Focused verification:** Exercise all exact comparison outcomes, interrupted writes, current-state drift, failed verification, marker-only resources, and repeated recovery. Verify no inventory authority is granted before verified post-state.
- **Worker boundary:** A journal/inventory recovery worker owns comparison and commit gating; it does not implement Phase 4 mutation adapters or choose plan operations.

### 3.6 Implement ownership evaluation and pruning

#### 3.6.1 Detect exact ownership markers

- **Scope:** Parse only the exact managed Fleet description marker and detection-rule tag marker already specified by the architecture; preserve marker type and malformed/absent distinctions.
- **Dependencies:** 3.1 and Phase 2 substep 2.9 canonical live-resource adapters.
- **Definition of done:** Marker detection is exact, case/format behavior is specified by existing contracts, and no approximate text/tag match is treated as ownership.
- **Focused verification:** Test exact matches, missing markers, altered markers, near matches, duplicate markers, malformed responses, and each supported resource kind.
- **Worker boundary:** A marker worker owns marker parsing and classification inputs; it does not read inventory, authorize deletes, or emit final plan operations.

#### 3.6.2 Classify ownership and orphan states

- **Scope:** Combine live markers and inventory presence to classify `managed`, `unmanaged`, `marker-only`, `inventory-only`, `altered-marker`, `ambiguous`, and `safe orphan` without adopting or deleting anything.
- **Dependencies:** 3.5.1 and 3.6.1.
- **Definition of done:** Every supported live/inventory combination yields one deterministic reviewable classification, with ambiguity and missing evidence represented as non-destructive outcomes.
- **Focused verification:** Table-test every classification combination, target identity mismatch, changed logical/remote ID, duplicate live match, and missing inventory generation.
- **Worker boundary:** An ownership-classification worker owns the pure classification function and result types; it does not own marker parsing, persistence, or diff decisions.

#### 3.6.3 Enforce pruning authority and exclusions

- **Scope:** Make custom `DetectionRule`, `AgentPolicy`, and `PackagePolicy` deletion eligible only when exact inventory and a matching live marker are present. Exclude `IntegrationPackage` and `PrebuiltRules` from pruning in every path.
- **Dependencies:** 3.5.2, 3.6.1, and 3.6.2.
- **Definition of done:** The deletion-authority predicate is fail-closed for missing/stale inventory, marker mismatch, ambiguity, or target mismatch, and integrations/prebuilt rules can never yield delete operations.
- **Focused verification:** Exercise each eligible and ineligible delete case, including marker-only, inventory-only, altered-marker, stale-generation, ambiguous, integration, and prebuilt inputs. Assert zero unsafe delete operations.
- **Worker boundary:** A pruning-policy worker owns delete eligibility and exclusions; it does not own inventory storage, remote deletion, or UI rendering.

#### 3.6.4 Emit reviewable conflict observations

- **Scope:** Convert ownership conflicts and safe-orphan outcomes into deterministic plan observations with safe reason codes and sufficient target/resource identifiers for review.
- **Dependencies:** 3.6.2 and 3.6.3; the observation schema from 3.1.
- **Definition of done:** Conflicts are visible to plan consumers, carry no mutation action, use bounded safe reasons, and remain distinguishable from unchanged/skipped/rejected outcomes.
- **Focused verification:** Assert observation output for every ownership classification and reason, stable ordering/serialization, and no delete/update operation alongside a conflict observation.
- **Worker boundary:** An ownership-observation worker owns observation mapping; it does not change classification predicates, plan ordering, or API/UI presentation.

### 3.7 Implement per-kind diffing

#### 3.7.1 Produce creates for absent desired identities

- **Scope:** Match desired resources to live resources by the exact per-kind identity and produce create mutations only for absent desired identities. Preserve explicit remote-absence assertions for absence.
- **Dependencies:** 3.1; Phase 1 substeps 1.3–1.4 canonical desired resources and Phase 2 substep 2.9 live adapters.
- **Definition of done:** Each supported kind maps an absent desired identity to one correctly shaped create candidate, while existing, duplicate, or ambiguous matches do not become creates.
- **Focused verification:** Test all supported kinds, caller-defined IDs, absent versus unknown state, duplicate live identities, and target/space mismatch. Verify deterministic create candidates.
- **Worker boundary:** A create-diff worker owns identity matching and create candidates; it does not own updates, deletes, ownership policy, or plan persistence.

#### 3.7.2 Produce owned updates and unchanged observations

- **Scope:** Compare canonical desired/live projections, emit updates only for safely owned drift, and record converged resources as unchanged observations.
- **Dependencies:** 3.6.2, 3.6.3, and 3.7.1.
- **Definition of done:** Owned semantic drift yields one update candidate with required baseline data; unchanged resources yield no mutation and one reviewable unchanged observation; unmanaged drift never becomes an update.
- **Focused verification:** Test owned drift, no drift, unmanaged drift, generated-field-only drift, and duplicate/ambiguous matches for every supported kind.
- **Worker boundary:** An update-diff worker owns update/unchanged comparison; it does not own canonicalizer definitions, create matching, delete authority, or dependency ordering.

#### 3.7.3 Reject unsafe collisions and changes

- **Scope:** Convert unmanaged collisions, immutable/prebuilt rules, installed-newer package versions, downgrades, ambiguous matches, and marker changes into non-mutating reject/conflict observations.
- **Dependencies:** 3.6.2, 3.6.3, 3.7.1, and 3.7.2.
- **Definition of done:** None of the listed unsafe cases produces an unsafe mutation, and each has a bounded reason that allows the plan to explain the block.
- **Focused verification:** Table-test each rejection, including package downgrade/newer-installed cases, immutable and prebuilt collisions, marker changes, and ambiguous lookups; assert no create/update/delete is emitted.
- **Worker boundary:** A safety-diff worker owns rejection predicates and observations; it does not own remote API behavior, inventory writes, or UI explanations.

#### 3.7.4 Attach fingerprints and exclude canonical false drift

- **Scope:** Attach desired, baseline, and expected-post fingerprints to diff results, and propagate the applicable target-scoped inventory fingerprint and generation through plan evidence as defined by 3.1. Exclude only the generated/unrelated fields already excluded by canonical projections; do not add a per-operation inventory-fingerprint field.
- **Dependencies:** 3.5.2 and 3.7.1–3.7.3; Phase 2 substep 2.9 canonical projection contracts.
- **Definition of done:** Operations/observations carry the required desired/live assertions, plan targets carry the matching inventory fingerprint/generation, domain confusion is rejected, and canonical false drift does not create a mutation or weaken baseline safety.
- **Focused verification:** Repeat identical desired/live inputs, vary excluded timestamps/revisions/execution fields, vary meaningful fields, and supply wrong-domain fingerprints. Verify deterministic fingerprints, target-level inventory evidence, and expected operation changes only for meaningful drift.
- **Worker boundary:** A fingerprint worker owns attachment and canonical comparison integration; it does not alter resource schemas, diff safety predicates, or plan storage.

### 3.8 Build deterministic dependency plans

#### 3.8.1 Collect automatic and explicit DAG edges

- **Scope:** Build per-target dependency edges from package-policy references and mounted `dependsOn` declarations, retaining dependent-to-prerequisite direction and rejecting dangling, self, duplicate, cross-selector, or cyclic references according to Phase 1 contracts.
- **Dependencies:** 3.7 diff identities and Phase 1 substep 1.5 manifest/reference graph.
- **Definition of done:** Each selected target receives only applicable, valid edges and a deterministic cycle/dangling diagnostic; no edge crosses exact target identity.
- **Focused verification:** Test automatic references, explicit edges, dormant resources, duplicate/cross-selector/self/cyclic/dangling inputs, and multiple targets sharing a resource set.
- **Worker boundary:** A DAG-input worker owns edge extraction and graph validation; it does not own operation sorting, fingerprint scoping, or plan/API persistence.

#### 3.8.2 Order ready operations deterministically

- **Scope:** Treat dependency readiness as the primary ordering constraint. Among currently ready nodes, order by exact target, stable phase preference, kind, logical ID, action, and operation ID; phase preference is only a tie-breaker among otherwise ready nodes.
- **Dependencies:** 3.7.4 and 3.8.1.
- **Definition of done:** Equivalent inputs produce byte-stable operation ordering, every prerequisite precedes its dependant, and unrelated targets/resources remain independently ordered rather than arbitrarily interleaved. Phase assignments are dependency-compatible with the required sort key; a phase-inverting edge is a bounded planning conflict rather than an invalid plan or a reason to weaken dependency ordering.
- **Focused verification:** Shuffle source/live input order, vary ready-node discovery order, use independent and dependent targets, and compare serialized operation order across repeated runs. Include a phase-inverting dependency and verify a bounded conflict/no invalid plan rather than a reordered or unsortable plan.
- **Worker boundary:** An operation-ordering worker owns ready-node selection and sort keys; it does not own graph construction, diff generation, or state persistence.

#### 3.8.3 Serialize safe dependency lists

- **Scope:** Store sorted, unique dependency IDs for each operation, with every dependency pointing to an earlier operation on the same exact target. Reject missing, duplicated, later, or cross-target references.
- **Dependencies:** 3.8.1 and 3.8.2; the plan schema from 3.1.
- **Definition of done:** Dependency serialization and validation are deterministic and preserve the DAG contract without introducing implicit cross-target dependencies.
- **Focused verification:** Test duplicate, missing, self, later, cross-target, and transitive dependency fixtures; verify sorted unique output and strict rejection.
- **Worker boundary:** A plan-dependency worker owns dependency list serialization/validation; it does not choose edges, sort operations, or render them.

#### 3.8.4 Scope fingerprints and retain revision provenance

- **Scope:** Compute and attach mounted source/resource-set, target desired, and target-config fingerprints per selected target. Retain external revision metadata only as provenance/diagnostics and never as eligibility authority.
- **Dependencies:** 3.7.4 and 3.8.2; Phase 1 substep 1.6 source/config digest contracts.
- **Definition of done:** A plan cannot compare or authorize one target using another target/resource set's digest; revision-only changes do not alter canonical eligibility, while displayed revision provenance remains available.
- **Focused verification:** Select multiple targets/resource sets, change unrelated mounts, vary formatting and external revision text, and change assigned target config. Assert only the appropriate scoped fingerprints change.
- **Worker boundary:** A plan-scope worker owns digest selection and provenance fields; it does not change canonicalization, revision ingestion, or operation ordering.

#### 3.8.5 Enforce delete marker and inventory-generation safeguards

- **Scope:** Require live marker compatibility and the exact declared inventory generation for delete operations, and reject integration/prebuilt deletes at plan construction even if another layer supplied them.
- **Dependencies:** 3.5.2, 3.6.3, 3.8.3, and 3.8.4.
- **Definition of done:** A delete is representable only with exact target-scoped inventory authority and marker compatibility; stale/missing/ambiguous authority and all integration/prebuilt delete attempts become non-mutating observations.
- **Focused verification:** Test current versus stale generation, matching/altered/missing marker, target mismatch, inventory-only/marker-only, integration, and prebuilt cases. Assert no unsafe delete plan is serialized.
- **Worker boundary:** A delete-plan safety worker owns final delete eligibility validation; it does not write inventory, inspect remote resources, or implement apply-time preflight.

#### 3.8.6 Define server-managed plan artifacts and read projections

- **Scope:** Define constructors/validators and the read-only projection contract for a plan assembled from validated operations, dependencies, fingerprints, observations, and provenance. This increment does not create a request-specific plan or persist one. Do not expose filesystem paths, plan upload, or plan-edit APIs.
- **Dependencies:** 3.8.2–3.8.5 and the plan schema from 3.1.
- **Definition of done:** The plan artifact contract is strict, deterministic, non-secret, and sufficient for later planning/API/UI consumers; its external projection contains identifiers and data only, never filesystem paths or writable payloads.
- **Focused verification:** Round-trip representative artifact/projection fixtures, reject unknown fields/versions and invalid cross-target dependencies, attempt upload/edit/path exposure through the projection boundary, and sentinel-scan artifact/projection data.
- **Worker boundary:** A plan-contract worker owns constructors, validators, and read-only projection types; it does not own request-specific plan assembly, job scheduling, HTTP authorization, or UI components.

### 3.9 Implement planning jobs/API

#### 3.9.1 Authorize planning initiation and inspection

- **Scope:** Enforce planner/administrator authorization for plan initiation and viewer-authorized inspection through both route and service layers, using the existing actor model and target/plan policy.
- **Dependencies:** 3.3.5 and Phase 2 substep 2.4 RBAC/audit-hook contracts.
- **Definition of done:** Authorized actors can initiate or inspect only permitted plans/jobs; viewers cannot initiate planning, and unknown/no-role or service-layer bypass attempts fail closed.
- **Focused verification:** Exercise viewer, planner, applier, administrator, unknown, and unauthenticated actors at route and direct-service boundaries, including target/plan scope checks.
- **Worker boundary:** An authorization worker owns planning permission checks and policy tests; it does not own plan construction, idempotency, or UI role display.

#### 3.9.2 Apply planning idempotency

- **Scope:** Require and enforce the existing idempotency-key contract for plan creation, returning the durable equivalent result for an equivalent scoped request and rejecting conflicting reuse.
- **Dependencies:** 3.3.3 and 3.9.1.
- **Definition of done:** Repeated authorized plan initiation cannot enqueue duplicate equivalent jobs, restart-safe replay returns the same safe job/plan result, and conflicting scope/digest is rejected without a second plan.
- **Focused verification:** Test same-key retries before/after enqueue and completion, actor/action/target selection changes, request-digest conflicts, and browser disconnect/retry.
- **Worker boundary:** A planning-idempotency worker owns route-to-idempotency integration; it does not own the generic idempotency store, plan builder, or job executor.

#### 3.9.3 Capture the metadata-only source snapshot

- **Scope:** For one planning request, re-read the authoritative mounted configuration/resource sets and create the versioned `SourceSnapshot` metadata document with its ID, source/resource-set identity, raw file hashes, optional revisions, and canonical desired digests. Persist no source bodies or Secret data.
- **Dependencies:** 3.2, 3.3.1, and 3.9.1; Phase 1 substep 1.6 source-snapshot/digest contract.
- **Definition of done:** The planning request has exactly one strictly validated, durably persisted metadata-only source snapshot and stable `sourceSnapshotID` for its eventual plan; mount boundaries, canonical digests, and revision provenance are captured without changing mounted authority.
- **Focused verification:** Re-read changed mounts, formatting-only changes, revision-only changes, duplicate/invalid snapshot metadata, and interrupted snapshot writes. Reopen the snapshot, verify deterministic IDs/digests and source-body absence, and scan persisted bytes for credentials.
- **Worker boundary:** A source-snapshot worker owns mounted-input reread, snapshot construction, and snapshot persistence; it does not own target Secret reads, live Kibana reads, diffing, or plan publication.

#### 3.9.4 Read live state for each selected target

- **Scope:** For each selected target associated with the captured snapshot, fetch the configured Secret through the Phase 2 boundary, verify the supported Kibana version, read the required live resources, compute the current target-config fingerprint, and capture the non-secret `PlanTarget` credential metadata required by the state contract: Secret namespace/name/resource version (and available UID/generation), rotation time/actor, and certificate fingerprint/expiry metadata.
- **Dependencies:** 3.9.3; Phase 2 substeps 2.5–2.10 Secret, credential-metadata, client, version, and live-read contracts.
- **Definition of done:** Each target read is bound to the exact target identity, space, resource set, target desired digest, and revision in the snapshot; current target-config evidence and required `CredentialMetadata` are validated separately for the eventual plan. Credential values and certificate bodies exist only for the in-memory job/client lifetime and never enter jobs, snapshots, plans, logs, or errors.
- **Focused verification:** Test default/non-default spaces, missing/invalid Secret, changed Secret resource version/metadata, target identity/config changes, unsupported/version-drifted Kibana, read pagination/failure, and live-state absence. Verify required PlanTarget metadata, safe per-target diagnostics, and credential sentinel scans.
- **Worker boundary:** A target-read worker owns Secret lease/use, version checks, and live-read orchestration; it does not own snapshot persistence, diff algorithms, job scheduling, or API response publication.

#### 3.9.5 Build non-published per-target plan contributions

- **Scope:** Run ownership evaluation, per-kind diffing, and deterministic dependency-plan construction for each target with successful read evidence. Produce an in-memory target contribution containing operations, dependencies, observations, and target-scoped fingerprints; do not persist it as a standalone applicable `Plan`.
- **Dependencies:** 3.5.4, 3.6.4, 3.7.4, 3.8.6, 3.9.3, and 3.9.4.
- **Definition of done:** Each successful target yields one strict, non-secret, deterministic contribution, including zero-operation converged results and reviewable observations; a contribution is not independently visible or apply-eligible before aggregate planning succeeds.
- **Focused verification:** Run absent/drift/converged/ownership-conflict cases for every kind, repeat identical target inputs, validate contribution evidence, and assert that a successful contribution cannot appear in plan listing without aggregate publication.
- **Worker boundary:** A target-plan worker owns orchestration from read evidence through an in-memory contribution; it does not own aggregate success gating, durable Plan writes, HTTP admission, or UI rendering.

#### 3.9.6 Gate all targets and persist one linked plan

- **Scope:** Apply the all-selected-target eligibility rule. If every selected target contribution succeeds, assign deterministic globally unique operation/observation IDs, perform the final plan sort and dependency rebinding/validation, then assemble and persist one `Plan` with one `sourceSnapshotID`, all exact selected targets, their required `CredentialMetadata`, and their contributions. Before saving, load/validate the referenced `SourceSnapshot` and cross-check state ID, target identities, source/resource-set/target desired fingerprints and revisions from that snapshot, plus current target-config fingerprints and inventory evidence. If any target fails, retain the metadata-only source snapshot and bounded job diagnostics but persist no target contribution or applicable `Plan` document.
- **Dependencies:** 3.9.3 and 3.9.5; 3.1 plan/source-snapshot contracts and 3.2 atomic state persistence.
- **Definition of done:** A successful request produces exactly one strict, non-secret, globally ordered saved plan, including zero-operation plans; every selected target has validated required `CredentialMetadata`; every dependency points to an earlier operation on the same exact target; a mixed or failed target set produces no saved applicable plan and cannot silently narrow selection or expose a partial contribution. The metadata-only source snapshot may remain as historical evidence after failure, while the saved plan's cross-document snapshot linkage validates before publication.
- **Focused verification:** Mix successful and failing targets (auth, version, read, diff, inventory, and digest failures), inspect job/plan listing, and repeat successful runs byte-for-byte. Exercise operation-ID collisions, shuffled contribution order, stale/mismatched sourceSnapshotID, state ID, target/resource-set, revision, target-config, and inventory evidence; assert final global ordering, valid dependencies, and no partial Plan document is applicable.
- **Worker boundary:** An aggregate-plan worker owns contribution aggregation, global ID assignment/order, dependency rebinding, cross-document validation, and the single Plan write; it does not own per-target reads/diffs, HTTP enqueue, or UI display.

#### 3.9.7 Return asynchronous planning jobs and gate publication

- **Scope:** Implement `POST /api/v1/plans` as an authenticated asynchronous operation returning `202` and a job ID, and expose a plan only after the durable job reaches successful completion. Preserve cookie/bearer separation and the existing CSRF and same-origin requirements for cookie-authenticated mutation.
- **Dependencies:** 3.3.4, 3.3.5, 3.3.6, 3.9.1, 3.9.2, and 3.9.6.
- **Definition of done:** Request handling is bounded and side-effect-safe under retries; the response contains only the safe job reference, polling/SSE observes progress, and failed/running jobs cannot be read as saved applicable plans.
- **Focused verification:** Test response status/body, duplicate requests, disconnect before completion, polling/SSE, restart at each publication boundary, queued/running/succeeded/failed/canceled/interrupted visibility, cookie Origin/CSRF failures, bearer-only success, and cookie-plus-bearer ambiguity.
- **Worker boundary:** A planning-route worker owns HTTP enqueue/publication gating and transport checks; it does not own scheduler limits, plan construction, or UI display.

#### 3.9.8 Paginate plans, operations, and observations

- **Scope:** Add authorized bounded pagination for plan lists and the operations/observations within a saved plan, preserving deterministic ordering and safe read-only projections.
- **Dependencies:** 3.8.6, 3.9.1, and 3.9.6; the bounded API pagination conventions from Phase 1 substep 1.8.
- **Definition of done:** Valid pages cover all plans/operations/observations without duplication or omission, invalid bounds/cursors fail safely, and no read request changes plan state.
- **Focused verification:** Test empty/single/multi-page results, stable repeated cursors, boundary sizes, malformed cursors, unauthorized plans, zero-operation plans, and large observation sets.
- **Worker boundary:** A plan-read worker owns list/detail pagination adapters; it does not own plan writes, job execution, or UI-specific formatting.

#### 3.9.9 Audit planning initiation and completion

- **Scope:** Emit durable audit events for authorized initiation, rejection, successful completion, and failed completion, linking safe actor/request/job/plan/target identifiers and bounded reasons.
- **Dependencies:** 3.4.5, 3.4.6, 3.9.1, 3.9.6, and 3.9.7.
- **Definition of done:** Each terminal planning outcome has the required audit record, duplicate/replayed initiation is distinguishable without leaking request data, and audit failure follows the established safe persistence policy.
- **Focused verification:** Exercise authorized/denied initiation, idempotent replay, per-target failure, aggregate refusal, restart, and successful zero-operation planning; compare job/plan/audit identifiers and scan for secrets.
- **Worker boundary:** A planning-audit worker owns planning event emission and correlation fields; it does not own audit storage, authorization decisions, or planning outcomes.

### 3.10 Implement plan-review UI

#### 3.10.1 Render plan identity and source/target summary

- **Scope:** Display creator, creation time, source set/revision/digest provenance, selected target identities, Kibana versions, and operation counts from the read-only plan API.
- **Dependencies:** 3.9.7 and 3.9.8; the embedded UI/API conventions from Phase 1 substep 1.9 and Phase 2 substep 2.10.
- **Definition of done:** A viewer can identify what was planned, when, from which source, and for which target/version without the UI recomputing or editing authoritative data.
- **Focused verification:** Render complete, empty-operation, multi-target, optional-revision, and failed-job states; verify API request/response use and no source filesystem path exposure.
- **Worker boundary:** A plan-summary UI worker owns summary components/styles and their tests; it does not own plan API handlers, operation rendering, or apply controls.

#### 3.10.2 Render operations, dependencies, conflicts, and observations

- **Scope:** Display operation counts/details, DAG dependencies, ownership conflicts, and unchanged observations using paginated server projections; preserve blocked/non-mutating distinctions.
- **Dependencies:** 3.9.8 and 3.10.1.
- **Definition of done:** Reviewers can inspect deterministic operation/dependency order and distinguish conflicts, unchanged, and other observations without client-side mutation or invented status.
- **Focused verification:** Render paginated operations, transitive dependencies, zero-operation plans, each ownership classification, and long identifiers; verify stable ordering and safe empty/error states.
- **Worker boundary:** A plan-detail UI worker owns operation/dependency/observation views; it does not own summary data fetching, API pagination semantics, or apply authorization.

#### 3.10.3 Show credential status without values

- **Scope:** Display the existing target credential status and non-secret certificate metadata only. Do not render, retain, or request API-key, CA, Secret, or other credential contents.
- **Dependencies:** 3.10.1; Phase 2 substeps 2.6 and 2.10 credential-status API.
- **Definition of done:** Authorized viewers see status sufficient to understand target readiness, while credential values are never returned to or stored by the browser/UI.
- **Focused verification:** Test present/missing/invalid/rotated credential states and role access, inspect network responses/form state/browser storage, and run credential sentinel scans.
- **Worker boundary:** A credential-status UI worker owns status presentation only; it does not own credential endpoints, Secret operations, or plan data.

#### 3.10.4 Explain blocked plans and replan requirements

- **Scope:** Present safe, server-provided reasons when planning is blocked or a plan requires replan, including target-level failure and ownership/digest/version/inventory conflicts. Do not infer permission to bypass a block.
- **Dependencies:** 3.9.6, 3.9.8, 3.10.1, and 3.10.2.
- **Definition of done:** Every supported blocked/replan outcome has an understandable bounded explanation and explicit non-bypass guidance; the UI does not suggest resume, force, edit, or implicit replan.
- **Focused verification:** Render each safe failure/rejection reason, mixed-target refusal, stale plan, and missing credential state; assert no bypass control or secret-bearing diagnostic appears.
- **Worker boundary:** A plan-status UI worker owns explanation mapping and copy; it does not change server reason codes, plan eligibility, or apply behavior.

#### 3.10.5 Keep plan review read-only

- **Scope:** Ensure the UI uses only server-managed plan read projections and has no client plan editing, plan upload, filesystem-path API, or authoritative source/resource mutation flow.
- **Dependencies:** 3.8.6, 3.9.7, 3.9.8, and 3.10.1–3.10.4.
- **Definition of done:** All plan-review views are read-only, no upload/edit controls or routes exist, and mounted sources remain visibly authoritative and unchanged.
- **Focused verification:** Inspect routes, network calls, DOM controls, and direct API attempts for upload/edit/path access; verify mounted source fixtures are byte-unchanged after UI use.
- **Worker boundary:** A read-only UI hardening worker owns plan-review route/component integration; it does not alter server plan artifacts, source mounts, or Phase 4 apply routes.

#### 3.10.6 Gate apply controls by role and preserve the Phase 4 boundary

- **Scope:** Show or disable apply controls according to the existing role contract, while leaving mutation implementation and apply API behavior to Phase 4. No UI control may bypass a blocked, stale, or unauthorized plan.
- **Dependencies:** 3.9.1, 3.9.8, 3.10.2, 3.10.4, and the Phase 4 apply contract.
- **Definition of done:** Viewer/planner/applier/administrator control visibility and enabled state match the existing authorization policy, with server-side authorization remaining decisive when Phase 4 apply behavior exists; Phase 3 provides review/gating only and performs no apply mutation.
- **Focused verification:** Test each role, blocked/stale/zero-operation/valid plan states, keyboard paths, and outbound requests from each role. Confirm viewers cannot initiate an apply request from this UI and no remote mutation, apply handler, or Phase 4 endpoint implementation is introduced in this increment.
- **Worker boundary:** An apply-gate UI worker owns control gating and role-state tests; it does not own apply handlers, mutation adapters, or Phase 4 execution/reporting.

## Verification

- Repeated identical input/live state yields deterministic operation content.
- Converged plans have zero operations.
- Marker-only/unmanaged resources never delete.
- Jobs/idempotency/audit survive restart safely.
- Plans/state contain no API keys, CA bodies, OIDC tokens, cookies, or Secret bodies.

## Phase gate

Durable single-writer state is recoverable and non-secret; planning is asynchronous/idempotent/audited; plans are source/target scoped and deterministic; prune requires inventory plus marker.
