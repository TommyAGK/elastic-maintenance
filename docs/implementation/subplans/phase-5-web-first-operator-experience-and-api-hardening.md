# Phase 5 — web-first operator experience and API hardening

## Objective

Complete the browser-first operator experience and harden the shared versioned API for interactive operators and external automation. This phase changes neither the accepted web-first architecture nor the source-of-truth, single-replica, credential, reconciliation, or replan decisions in `docs/architecture/0001-web-first-api.md` and `plan.md`.

## Planning status and authority

This is the authoritative living plan for Phase 5. Every increment below is **planned**; this document makes no claim that a Phase 5 increment or gate is complete. Existing Phase 1/2 UI slices and security boundaries are inputs to the work, not completion evidence for the increments below. Phase 3 and Phase 4 gates remain prerequisites where noted.

The original workstreams remain visible in the numbering (`5.1` through `5.9`), but each workstream is split into smaller increments. An increment is intentionally narrow enough for one worker to implement, verify, review, and commit independently. A later increment may consume the prior increment's behavior, but must not silently absorb its scope.

## Prerequisites and dependency notation

The following prerequisite gates are referred to by shorthand. They are prerequisites, not status claims made by this file:

- **P1** — Phase 1 mounted-input, resource-set, validation API/UI gate.
- **P2** — Phase 2 OIDC, break-glass, RBAC, Kubernetes Secret, Kibana-read, and inventory gate.
- **P3** — Phase 3 durable PVC state, jobs, audit, plans, and planning API gate.
- **P4** — Phase 4 apply, reports, target/dependency isolation, and mandatory-replan gate.
- **C** — The `/api/v1` OpenAPI schemas, error/job/actor types, and domain result types are versioned and stable for the increment. A required contract change is a dependency/blocker, not an unplanned UI workaround.

An increment may be developed before every prerequisite is available only when it is limited to a contract-preserving seam or test fixture. Its definition of done cannot be claimed until the listed prerequisites and focused verification are available.

## Non-negotiable constraints for every increment

- The embedded UI consumes the same `/api/v1` API and service authorization as automation. Do not add UI-only reconciliation routes, hidden mutation endpoints, a second business-logic path, or client-side authority.
- Mounted configuration and resource sets remain authoritative and read-only. GitOps/orchestration owns source changes; the UI may explain a problem and request an explicit refresh, but never edits, uploads, commits, polls, or implies that it edits mounted files.
- Server authorization remains decisive for every role and endpoint. Viewer, planner, applier, and administrator controls may be hidden or disabled for usability, but the server must still deny unauthorized requests. An applier may apply an authorized own plan only under the existing Phase 4 rules.
- Plans remain server-managed. The UI cannot upload, edit, force, resume, or implicitly replan a plan. Any apply result that could lead to another attempt directs the operator to create a new plan.
- API keys, CA bodies, OIDC tokens, cookies, session material, authorization headers, password values, and credential request bodies never enter browser storage, URLs, logs, traces, audit records, plans, reports, jobs, or PVC state. Credential responses are status-only and sensitive responses are `no-store`.
- Cookie-authenticated mutations require CSRF and same-origin/origin validation. Bearer clients remain separate from cookie identity and use the existing CORS and authorization rules.
- Validation, planning, and apply remain durable asynchronous jobs. Browser disconnect, refresh, SSE failure, or server restart must not turn durable work into false failure or false success. Polling is always available; SSE is bounded and optional for job execution.
- V1 remains one writer/one replica. Mutation serialization, state locks, target locks, bounded queues, bounded workers, and safe shutdown/recovery remain in force. No increment may introduce a second writer, an unbounded goroutine/client/job pool, automatic mutation retry, rollback, or resume.
- Audit events retain actor subject/roles/authentication source, request/job/action identifiers, relevant target/plan/report identifiers, outcome, timestamp, and safe reason while excluding sensitive values and unbounded bodies. UI filters must obey the existing role policy.
- Accessibility is part of behavior, not a final cosmetic pass: keyboard operation, focus, labels, contrast, status announcements, reduced-motion behavior, responsive layouts, and browser failure paths must be verified.
- Security headers, proxy trust, CORS, limits, rate limits, safe error envelopes, request IDs, and OpenAPI-handler parity are externally observable contracts. A change that weakens one is not an acceptable implementation shortcut.

## Worker and commit boundaries

- One increment has one owning worker. The worker may change the implementation, focused tests/fixtures, and narrowly necessary contract/documentation artifacts inside that increment's boundary. The worker must not opportunistically refactor another increment.
- **UI workers** own the relevant slice of `internal/web/**` and its browser/UI tests. They consume existing API contracts and do not change server authorization, state, or reconciliation behavior.
- **API/security workers** own only the relevant `internal/api/**`, `internal/server/**`, or `internal/auth/**` seam and its focused HTTP/security tests. They do not redesign UI flows or domain reconciliation.
- **Contract/documentation workers** own the relevant OpenAPI examples/schema documentation and user-facing contract text. They do not weaken handlers to make documentation pass.
- **Verification workers** may add focused test harnesses, fixtures, scans, and evidence for their assigned increment, but do not fix unrelated failures in the same change.
- Shared files such as central middleware, route registration, OpenAPI contracts, and common UI client code are serialized ownership boundaries. Do not assign two workers to edit them concurrently. The later worker starts from the earlier worker's reviewed handoff.
- Each increment is one independently reviewable commit in implementation work. Tests required by that increment belong in that commit; unrelated cleanup, formatting-only churn, and future-increment behavior do not.
- No worker may alter the accepted architecture. If an increment appears to require a new route family, a writable source, a database/multi-replica model, credential persistence, automatic reconciliation, plan mutation, or another architectural decision, stop and record a blocker for an explicit architecture decision instead.

## Numbered increments

### 5.1 Embedded UI foundation and shared operator shell

#### 5.1.1 — Close the embedded-asset boundary

- **Depends on:** P1, C.
- **Worker boundary:** UI foundation worker; `internal/web/**` embedding, asset-serving tests, and the build/smoke assertion for the embedded bundle. Do not change API handlers or auth middleware.
- **Definition of done:** Every production UI asset is embedded in the Go binary; there is no runtime CDN, remote font, third-party script, or network-loaded module. Static asset lookup rejects traversal and unintended paths, serves only the approved asset set, and preserves the existing safe content types. The binary can serve the shell with no external network access.
- **Focused verification:** Build the production binary, inspect/scan the embedded asset references for external dependencies, run `go test ./internal/web/...`, and perform a no-network static-asset/shell smoke test. Include a negative path-traversal lookup test.

#### 5.1.2 — Establish one safe `/api/v1` UI client

- **Depends on:** 5.1.1, C.
- **Worker boundary:** UI client worker; the shared browser request/response/pagination/job client and its tests. Do not add UI-only routes or duplicate domain/service logic.
- **Definition of done:** All UI requests go through one bounded client that uses `/api/v1`, understands the versioned safe error envelope and request ID, handles authentication failure without exposing response bodies, and provides the existing pagination and asynchronous-job contracts to every view. API values are rendered through safe text/DOM construction rather than HTML interpolation.
- **Focused verification:** Mock each supported response/error envelope, pagination termination, `401/403`, request-ID propagation, body-limit failure, and malformed JSON. Scan UI sources for non-`/api/v1` API calls, unsafe HTML insertion, credential-like storage, and URLs containing sensitive values.

#### 5.1.3 — Add the complete navigation and route shell

- **Depends on:** 5.1.2.
- **Worker boundary:** UI shell worker; route state, navigation, page placeholders, and route tests. Do not implement workflow-specific data fetching or server routes.
- **Definition of done:** The shell provides stable navigation for sources, targets, credentials, validations, plans, jobs, reports, audit, and authorized API documentation. Deep links, refreshes, unknown routes, loading states, and unavailable views fail safely. Navigation visibility is a usability decision only; it is never treated as authorization.
- **Focused verification:** Exercise every route/deep link from a fresh load and after refresh, including unknown and unauthorized views. Verify the route matrix has no reconciliation endpoint outside `/api/v1` and no mutation control enabled merely by navigation visibility.

#### 5.1.4 — Display actor, roles, authentication source, and expiry

- **Depends on:** P2, 5.1.2, 5.1.3.
- **Worker boundary:** Session-shell UI worker; session inspection, identity display, logout control, and session-expiry handling. Do not change token validation or session issuance.
- **Definition of done:** The UI displays the non-secret active actor, effective roles, authentication source where exposed by the existing actor contract, and session-expiry state. It clearly distinguishes OIDC, bearer-inapplicable browser state, and break-glass warnings without displaying tokens or verifier data. Logout and expiry return to a safe signed-out state and do not leave protected data interactive.
- **Focused verification:** Use viewer/planner/applier/administrator, expired, logged-out, and break-glass session fixtures; verify controls and expiry behavior after refresh. Scan DOM, network fixtures, storage, and URLs for token/session contents.

#### 5.1.5 — Make authority and read-only boundaries visible

- **Depends on:** P1, 5.1.2, 5.1.3.
- **Worker boundary:** Read-only UI worker; source/target/config presentation framing and negative UI tests. Do not add write methods or server-side edit support.
- **Definition of done:** Authoritative source and resource views visibly say read-only, identify external GitOps/orchestration as the owner of changes, and provide guidance to refresh/validate after an external change. No UI control, client method, route, or copy implies editing branches/files, uploading desired resources, or changing target configuration.
- **Focused verification:** Inspect every source/target/resource page and keyboard-accessible control; assert no write control or edit/upload wording is present where it would imply authority. Run HTTP tests proving the UI never issues source/config mutation requests.

### 5.2 Source and validation workflow

#### 5.2.1 — Complete source and assignment details

- **Depends on:** P1, 5.1.5.
- **Worker boundary:** Sources/targets UI worker; source and target list/detail projections only. Do not change mounted-input discovery or digest algorithms.
- **Definition of done:** Source and target views show resource-set identity, optional branch/revision provenance, canonical digest, target assignment, normalized target identity, and safe bounded metadata. Unrelated mounts, absolute server paths, Secret values, and raw credential-bearing configuration are not exposed.
- **Focused verification:** Use multiple resource sets, optional/changed revision metadata, shared and separately assigned targets, long/bounded values, and paginated results. Compare UI projections with API fixtures and assert canonical digests—not raw formatting or revision text—drive eligibility.

#### 5.2.2 — Launch and follow validation jobs

- **Depends on:** P1, P3, 5.1.2, 5.1.3.
- **Worker boundary:** Validation workflow worker; validation initiation, status, progress, cancellation/terminal-state display, and history views. Do not change validation execution or mount reads.
- **Definition of done:** Planner/administrator controls can request validation using the existing idempotency contract; viewers can inspect results but cannot start jobs. The UI shows queued/running/terminal progress and historical jobs, remains correct after disconnect/refresh, and never suggests that validation contacts or changes Kibana.
- **Focused verification:** Exercise every role, duplicate idempotency request, queued/running/succeeded/failed/cancelled/recovered job, browser disconnect, and stale job response. Confirm no credential or mounted-content body is sent by the UI.

#### 5.2.3 — Render diagnostics, inventory, and dependency views

- **Depends on:** P1, P3, 5.2.1, 5.2.2.
- **Worker boundary:** Validation-result UI worker; source-located diagnostics, resource/DAG inventory, counts, dependencies, and safe truncation. Do not alter manifest validation or DAG construction.
- **Definition of done:** Operators can locate validation diagnostics to bounded source files/documents, inspect resource and target inventory, and understand dependency/DAG results and dormant/invalid states. Unsafe or overlong diagnostic content is bounded and rendered as data; no server paths, secrets, or unbounded remote text are exposed.
- **Focused verification:** Feed valid, invalid, cyclic, dangling, dormant, duplicate, and oversized diagnostic fixtures. Verify deterministic ordering, pagination, safe escaping, and that failure details remain actionable without leaking environment or credential data.

#### 5.2.4 — Enforce explicit refresh and external-change guidance

- **Depends on:** 5.2.1–5.2.3, 5.7.5.
- **Worker boundary:** Source/validation refresh worker; refresh controls, stale/loading/error states, and copy explaining external ownership. Do not introduce a watcher, polling loop, Git operation, or automatic plan/apply.
- **Definition of done:** Refresh is an explicit bounded API request; changed mounts are represented by fresh validation/source results, not silently merged into the current view. The UI explains that GitOps/orchestration must change the source and that a new validation/plan may be needed. Repeated refreshes respect request/read concurrency limits.
- **Focused verification:** Change the mounted snapshot between requests, refresh during an in-flight request, disconnect/reconnect, and exceed the configured read limit. Verify no automatic polling or source mutation occurs and that the operator sees a safe stale/error state.

### 5.3 Credential administration experience

#### 5.3.1 — Complete status-only credential and target-readiness views

- **Depends on:** P2, 5.1.4, 5.2.1.
- **Worker boundary:** Credential-status UI worker; status/readiness projections and role-based visibility. Do not change Secret-client ownership or credential retrieval.
- **Definition of done:** Authorized viewers see only credential presence/status, configured Secret reference as permitted, rotation time/actor, and non-secret certificate metadata/fingerprint. Missing, malformed, unavailable, or in-use credentials produce a safe target-unready state without failing process liveness or revealing values. Non-administrators see no mutation affordance.
- **Focused verification:** Test missing/valid/malformed API key and CA states, certificate metadata, target readiness versus server liveness, every role, pagination, and safe errors. Assert no response, DOM, log fixture, or URL contains credential bytes.

#### 5.3.2 — Implement bounded credential entry controls

- **Depends on:** P2, 5.1.2, 5.6.2.
- **Worker boundary:** Credential-form worker; API-key/password-style and PEM-CA inputs, client-side bounds, and form validation. Do not alter Kubernetes Secret payloads or add credential read-back.
- **Definition of done:** Only administrators can reach a usable credential mutation form. API-key input is password-style, CA input accepts only the supported bounded PEM trust-bundle form, validation is non-echoing, and submission uses the existing protected JSON/idempotency API. The form never puts credential values in query strings, paths, headings, analytics, or diagnostic copy.
- **Focused verification:** Test valid, empty, malformed, oversized, multi-certificate, and unsupported PEM inputs plus each role and cookie/bearer mode. Inspect requests and browser history/referrer to prove values are not placed in URLs or non-sensitive headers.

#### 5.3.3 — Add explicit rotation/deletion confirmation and safe outcomes

- **Depends on:** P2, P3, 5.3.1, 5.3.2, 5.7.6.
- **Worker boundary:** Credential-mutation UI worker; confirmation dialogs, mutation result states, idempotency retry presentation, and in-use/conflict handling. Do not change Secret ownership rules or deletion semantics.
- **Definition of done:** Rotation and deletion are distinct, administrator-only actions requiring explicit confirmation. The UI handles accepted, duplicate, rejected, in-use, ownership, and target-unready outcomes without retrying mutations automatically or displaying values. Each action has the existing non-secret audit identity and request/result linkage.
- **Focused verification:** Exercise cancel/confirm, double-submit, duplicate idempotency, stale ownership, in-use deletion, server denial, network timeout after acceptance, and audit-result fixtures. Verify no automatic mutation retry or ambiguous success message.

#### 5.3.4 — Clear credential state and prohibit browser persistence

- **Depends on:** 5.3.2, 5.3.3, 5.6.3, 5.6.4.
- **Worker boundary:** Credential privacy verification worker; form lifecycle, browser persistence controls, and sentinel tests. Do not change server Secret storage.
- **Definition of done:** API-key/password and CA values are cleared from form state immediately after submission or terminal failure, are not written to local/session storage, cookies, URLs, reports, or application caches, and autocomplete/password-manager retention is disabled where practical for this product flow. The UI remains usable after clearing and gives only safe status feedback.
- **Focused verification:** Capture DOM/form state before and after every outcome, inspect local/session storage, IndexedDB, cookies, history, referrers, cache/test traces, and serialized job/audit/report fixtures. Run a credential sentinel scan over browser artifacts and server response fixtures.

### 5.4 Plan, apply, and report workflow

#### 5.4.1 — Provide one durable asynchronous job experience

- **Depends on:** P3, P4, 5.1.2.
- **Worker boundary:** Shared job UI worker; job list/detail/status projection, polling, optional bounded SSE subscription, terminal states, and reconnect behavior. Do not change job execution, queue, or journal recovery.
- **Definition of done:** Validation, planning, and apply jobs use one honest status model. Polling works without SSE; SSE disconnects fall back to polling; browser close/refresh does not cancel or duplicate a durable job; restart/recovery states are shown accurately. The UI never reports success solely because an SSE connection opened or failed.
- **Focused verification:** Test polling-only, SSE success, SSE timeout/overflow/reconnect, browser disconnect, duplicate attach, server restart, queued/running/recovered/failed/cancelled terminal states, and bounded event history. Verify the server-side queue and mutation serialization are not bypassed.

#### 5.4.2 — Select targets/resource sets and start plans

- **Depends on:** P1, P3, 5.1.3, 5.2.1, 5.4.1.
- **Worker boundary:** Plan-initiation UI worker; selection controls, request payload projection, idempotency, and initiation result. Do not calculate plans in the browser or change planning rules.
- **Definition of done:** Authorized planner/administrator users can select valid target/resource-set combinations and request a server plan job. The request uses the existing strict `/api/v1/plans` contract, returns/handles `202` plus job identity, and refuses invalid, stale, unauthorized, or empty selections safely. Viewers cannot initiate plans.
- **Focused verification:** Test each role, target/resource assignment, duplicate selection, empty selection, idempotency replay, stale source digest, malformed response, and `202`/error handling. Compare submitted fields with the OpenAPI schema and assert no desired-state calculation or secret value is client-generated.

#### 5.4.3 — Render complete saved-plan review

- **Depends on:** P3, 5.2.1, 5.2.3, 5.4.1, 5.4.2.
- **Worker boundary:** Plan-review UI worker; plan metadata, operations, observations, dependencies, ownership, and drift presentation. Do not alter plan persistence, diffing, or operation ordering.
- **Definition of done:** A saved plan shows creator/time, source set/revision/digests, target identities and versions, operation counts and details, dependencies, conflicts, unchanged observations, fingerprints, and safe preconditions. Operations and observations remain deterministically ordered and large plans are bounded/paginated without hiding safety details.
- **Focused verification:** Render create/update/delete, unchanged, conflict, rejected, dependency, ownership, and drift fixtures across multiple targets and versions. Verify no plan upload/edit control, filesystem path, credential, or raw remote body appears.

#### 5.4.4 — Gate apply with role and explicit confirmation

- **Depends on:** P2, P4, 5.1.4, 5.4.1, 5.4.3, 5.6.2.
- **Worker boundary:** Apply-gate UI worker; role-aware control, confirmation content, CSRF/idempotency request, and initiation result. Do not change apply preflight or mutation semantics.
- **Definition of done:** Apply is visible and usable only when the server-authorized actor and saved-plan state permit it. Confirmation identifies the exact plan/targets and warns that apply is irreversible/no rollback and may be partial. The request uses the existing `POST /api/v1/plans/{id}/apply` contract and cannot upload, edit, force, resume, or implicitly replan.
- **Focused verification:** Exercise viewer/planner/applier/administrator and own-plan/other-plan cases, consumed/blocked/incompatible plans, cancel/confirm, CSRF/origin failure, bearer mode, duplicate idempotency, and double-submit. Assert the UI cannot turn a denial into an enabled mutation.

#### 5.4.5 — Show partial outcomes and mandatory replan guidance

- **Depends on:** P4, 5.4.1, 5.4.3, 5.4.4.
- **Worker boundary:** Reports/outcomes UI worker; per-target/per-operation reports, skipped dependencies, rejection reasons, and replan guidance. Do not change report classification or apply recovery.
- **Definition of done:** Reports distinguish created, updated, deleted, unchanged, skipped, conflicted, rejected, and failed outcomes with safe evidence and actor/job/plan references. Independent target progress and transitive-dependent skips are understandable. Any apply result that could be retried directs the operator to make a new plan; no resume/force/implicit retry control exists.
- **Focused verification:** Use successful, independent-target partial-failure, transitive-skip, preflight-rejection, journal-recovery, and consumed-plan fixtures. Verify reports survive refresh/restart, links resolve by durable identifiers, and new-plan guidance appears for every applicable non-success outcome.

### 5.5 Audit and automation experience

#### 5.5.1 — Add the authorized paginated audit view

- **Depends on:** P3, 5.1.3, 5.1.4.
- **Worker boundary:** Audit UI worker; audit list/detail projections, pagination, bounded filters, and role-policy handling. Do not change audit persistence or event schema.
- **Definition of done:** Authorized roles can inspect only the audit events permitted by policy through bounded pagination and safe filters. The view shows actor/auth source, action, outcome, time, request/job/target/plan/report identifiers, and safe reason without sensitive bodies or unbounded data. Unauthorized, malformed, and unavailable audit responses fail closed.
- **Focused verification:** Test each role, empty/large/rotated segments, filters, invalid cursors, pagination limits, missing linked records, restart/recovery fixtures, and sentinel values for tokens, API keys, CA bodies, cookies, and passwords.

#### 5.5.2 — Link request, job, plan, report, and audit identities

- **Depends on:** P3, P4, 5.4.1, 5.4.5, 5.5.1.
- **Worker boundary:** Cross-record navigation worker; identifier links and safe not-found/stale-record states. Do not invent identifiers or alter durable record retention.
- **Definition of done:** Where the API provides identifiers, UI views link request, job, plan, report, and audit records using exact IDs and preserve target/operation context. Missing, unauthorized, expired, or stale records display a safe explanation instead of guessing or exposing another actor's data.
- **Focused verification:** Traverse every supported link from initiation through audit and report, then exercise missing, duplicate, unauthorized, and stale identifiers. Verify links never include credentials, raw state paths, or unsanitized upstream URLs.

#### 5.5.3 — Publish authorized interactive OpenAPI documentation

- **Depends on:** C, 5.1.2, 5.1.3, 5.7.8.
- **Worker boundary:** API documentation UI/contract worker; authorized docs route/link, downloadable schema projection, and examples. Do not change handler behavior to match an inaccurate document.
- **Definition of done:** Authorized users can reach the versioned OpenAPI document and API documentation from the embedded UI; unauthenticated/unauthorized access follows the documented policy. The published schema matches the active `/api/v1` surface, uses safe examples, and contains no real token, credential, or private path.
- **Focused verification:** Compare registered routes/methods and response schemas with the published document, test authorization/cache headers on docs and download responses, and scan schema/examples for credential-like values and external runtime dependencies.

#### 5.5.4 — Document the automation contract

- **Depends on:** C, 5.5.3, 5.7.3, 5.7.4, 5.7.5, 5.7.6, 5.7.7.
- **Worker boundary:** Automation documentation worker; API examples and operator/automation contract text only. Do not add a client library, token issuer, or alternate API.
- **Definition of done:** Documentation covers bearer authentication without real tokens, authorization roles, idempotency, pagination, strict JSON/errors/request IDs, asynchronous polling/SSE, rate limits, CSRF/cookie-versus-bearer behavior, partial results, audit identifiers, and mandatory replanning. Examples use placeholders and the same `/api/v1` routes the UI uses.
- **Focused verification:** Execute or schema-validate every example against contract fixtures, check that examples cannot be copied with a real secret, and review each documented limit/error/status against the handler/OpenAPI contract.

### 5.6 Browser and session security

#### 5.6.1 — Complete OIDC/session lifecycle coverage

- **Depends on:** P2, 5.1.4.
- **Worker boundary:** Authentication verification worker; OIDC/browser session tests and narrowly necessary auth test fixtures. Do not redesign OIDC discovery, claim mapping, or break-glass architecture.
- **Definition of done:** Tests cover PKCE, state, nonce, issuer/audience/signature/expiry, callback origin, login failure, logout, session expiry, key rotation/invalidation, and the explicitly identified break-glass session behavior. Existing successful sessions do not require unsafe provider fallback; failures are fail-closed and non-disclosing.
- **Focused verification:** Run focused `internal/auth/**` and HTTP tests with unreachable/malformed IdP, replayed state/nonce, wrong callback, expired/rotated sessions, logout, and break-glass outage fixtures. Include race coverage for concurrent callback/session use.

#### 5.6.2 — Enforce cookie, CSRF, and same-origin mutation controls

- **Depends on:** P2, 5.6.1.
- **Worker boundary:** Session-mutation security worker; cookie attributes, CSRF middleware, Origin/Referer policy, and negative HTTP tests. Do not alter UI forms beyond consuming the contract.
- **Definition of done:** Session and transaction cookies retain Secure, HttpOnly, and appropriate SameSite settings. Every cookie-authenticated mutation rejects missing/invalid CSRF or unacceptable origin; valid bearer automation remains cookie-independent and authorized. Duplicate/ambiguous cookie-plus-bearer identities fail closed.
- **Focused verification:** Test every mutation route with valid/invalid/missing CSRF, trusted/untrusted/missing Origin, Referer fallback policy, cookie flag inspection, bearer-only requests, cookie-plus-bearer ambiguity, and cross-site preflight. Run race tests around token/session checks.

#### 5.6.3 — Apply security headers and sensitive-response caching policy

- **Depends on:** P2, 5.1.1, 5.6.2.
- **Worker boundary:** HTTP response-security worker; middleware/header tests and embedded-asset CSP compatibility. Do not weaken the asset boundary or add unsafe script sources.
- **Definition of done:** Responses apply the approved strict CSP and no-sniff, frame, referrer, permissions, HSTS-at-ingress, and cache policies. Credential/session/security-sensitive responses are `no-store`; public static assets use only an explicitly safe policy. CSP permits the embedded UI only and does not require a CDN, inline secret, or broad unsafe source.
- **Focused verification:** Assert exact headers on health, auth, API, credential, docs, SSE, error, and static responses; run browser CSP violation checks and cache-control tests. Verify HSTS is applied only at the configured TLS ingress boundary and is not falsely claimed on an unsafe local HTTP path.

#### 5.6.4 — Keep tokens/credentials out of storage, URLs, and redirects

- **Depends on:** 5.3.4, 5.6.1, 5.6.2, 5.6.3.
- **Worker boundary:** Browser privacy/redirect worker; browser network/history/storage tests and login/callback redirect validation. Do not change credential or OIDC data models.
- **Definition of done:** Tokens, credentials, session secrets, and authorization headers do not enter local/session storage, IndexedDB, URLs, referrers, logs, or rendered error content. Login and callback accept only configured safe return destinations and reject open redirects, external callback confusion, and crafted encoded destinations.
- **Focused verification:** Capture browser storage/history/network/referrer artifacts for login, callback, logout, credential, and job flows; run a secret sentinel scan. Exercise absolute, scheme-relative, encoded, nested, malformed, and unconfigured redirect destinations.

### 5.7 Reverse-proxy and API behavior hardening

#### 5.7.1 — Restrict trusted forwarded headers

- **Depends on:** P2, C.
- **Worker boundary:** Proxy-trust worker; forwarded host/proto/client-IP parsing and focused server tests. Do not change ingress manifests or trust arbitrary headers.
- **Definition of done:** Forwarded host, scheme, and client IP influence security decisions only when the immediate peer is in configured trusted proxy ranges and the header chain is valid. Direct clients and untrusted proxies cannot spoof public URL, secure-cookie, origin, audit, or rate-limit identity decisions.
- **Focused verification:** Exercise direct, trusted, untrusted, malformed, chained, duplicate, IPv4/IPv6, and absent forwarding headers. Verify safe rejection/normalization, request IDs, audit fields, and rate-limit keys never accept an attacker-controlled forwarded identity.

#### 5.7.2 — Validate public URL, Host, and scheme

- **Depends on:** P2, 5.7.1.
- **Worker boundary:** Public-origin worker; configured public URL and Host/scheme validation, including auth callback integration. Do not add host aliases or redirect-based bypasses.
- **Definition of done:** Requests and generated auth/cookie/security decisions accept only the configured public URL/Host/scheme under the trusted-proxy rules. Spoofed Host, forwarded scheme, port, path, Unicode/ambiguous host, and malformed authority inputs fail safely without open redirects or origin confusion.
- **Focused verification:** Test direct ingress, trusted TLS termination, wrong host, wrong scheme, alternate port/path, malformed authority, and encoded host fixtures. Verify login/callback, CSRF, absolute links, and error responses all use the same validated origin.

#### 5.7.3 — Keep CORS disabled by default

- **Depends on:** P2, 5.7.2.
- **Worker boundary:** CORS worker; preflight/allowlist middleware and API tests. Do not broaden origins to make the embedded same-origin UI work.
- **Definition of done:** No CORS allowance is emitted unless an explicit configured origin allowlist is present. Allowlisted origins are exact and bounded; wildcard origins are incompatible with credentials; preflight, methods, headers, and credential behavior are least-privilege and do not weaken CSRF or RBAC.
- **Focused verification:** Test absent, empty, exact, near-match, wildcard, credentialed, preflight, and disallowed-origin cases for browser and bearer requests. Assert default same-origin UI operation requires no CORS and no secret is exposed through an error/preflight response.

#### 5.7.4 — Bound HTTP bodies, headers, responses, SSE, and pagination

- **Depends on:** C, 5.7.2.
- **Worker boundary:** HTTP resource-boundary worker; request/header/response/SSE/pagination limits and negative tests. Do not change domain limits silently or truncate safety-critical plan/report details without an explicit response contract.
- **Definition of done:** JSON bodies, headers, upstream responses, SSE event size/history, concurrent SSE clients, page sizes, cursors, and aggregate list/detail projections have explicit bounded behavior. Oversized or malformed inputs fail before unsafe processing; truncation is labeled and never hides a safety decision, credential status, conflict, or dependency reason.
- **Focused verification:** Hit every configured boundary and one-over-limit case on credential, plan, apply, audit, inventory, report, error, and SSE paths. Verify bounded memory/time behavior, safe status/envelope, cursor invariants, and no partial secret-bearing response.

#### 5.7.5 — Enforce bounded concurrency and durable job queue behavior

- **Depends on:** P3, P4, 5.4.1, 5.7.4.
- **Worker boundary:** Concurrency worker; read/mutation semaphores, job queue limits, SSE admission, target locks, shutdown, and race/fault tests. Do not introduce a new queue, replica, or resume mechanism.
- **Definition of done:** Configured read concurrency, expensive-read concurrency, SSE client count, job queue size, worker count, and mutation serialization are enforced. At most one mutation job runs per state directory under the existing one-replica model; target locks remain effective; saturation returns safe bounded responses; queued durable jobs outlive browser connections; shutdown cannot report false success.
- **Focused verification:** Run load-shaped unit/HTTP tests that exceed each bound, concurrent read plus mutation tests, duplicate enqueue attempts, target-lock contention, queue saturation, cancellation, shutdown, restart recovery, and `go test -race` for affected packages. Confirm unrelated read work and independent targets retain the documented isolation.

#### 5.7.6 — Add operation-specific rate limits

- **Depends on:** P2, P3, 5.7.1, 5.7.2, 5.7.5.
- **Worker boundary:** Rate-limit worker; login, credential mutation, plan, apply, and expensive-read limiters and their tests. Do not log raw credentials or use an untrusted forwarded IP as the sole identity.
- **Definition of done:** Login, credential mutation, plan creation, apply initiation, and expensive reads have explicit bounded rate limits with safe `429` behavior and bounded retry guidance. Keys and exemptions follow the authenticated actor/source and trusted-client model; rate limiting does not bypass authorization, idempotency, target locks, or durable queue limits.
- **Focused verification:** Exercise anonymous/authenticated/bearer/break-glass identities, trusted/untrusted proxy addresses, burst and sustained limits, retry-after bounds, concurrent workers, and independent endpoint buckets. Verify rate-limit logs/audit contain only non-secret identifiers and that a rejected request has no mutation side effect.

#### 5.7.7 — Standardize safe errors and request IDs

- **Depends on:** C, 5.7.4, 5.7.5, 5.7.6.
- **Worker boundary:** Error-contract worker; response envelope/request-ID middleware and cross-endpoint tests. Do not expose upstream bodies, filesystem paths, auth material, stack traces, or implementation details.
- **Definition of done:** Every API/auth/mutation, limit, queue, SSE, proxy, and upstream failure maps to the versioned safe error envelope with a stable machine-readable code, bounded message, request ID, and correct HTTP status. Request IDs are propagated to jobs/audit where allowed and remain non-secret; duplicate/idempotent outcomes are unambiguous.
- **Focused verification:** Inject malformed input, auth failure, CSRF/origin failure, proxy failure, limit exhaustion, queue full, timeout, cancellation, upstream response, state corruption, and duplicate idempotency errors. Assert envelope/schema parity, absence of sensitive text, and request-ID consistency across response, job, and audit fixtures.

#### 5.7.8 — Prove OpenAPI-handler parity in CI

- **Depends on:** C, 5.5.3, 5.7.7.
- **Worker boundary:** Contract verification worker; route registration/OpenAPI comparison and CI checks. Do not add undocumented exceptions or weaken strict decoding.
- **Definition of done:** CI fails when a registered `/api/v1` method/path, auth requirement, request body, response status/schema, pagination/error contract, or documented security scheme diverges from the published OpenAPI document. Health/auth/static exceptions are explicitly scoped and do not create UI-only reconciliation APIs.
- **Focused verification:** Run the parity test against every registered route, intentional `401/403/202/4xx/5xx` response, schema example, security scheme, and pagination response. Include a mutation test that proves a deliberate contract mismatch fails CI, then restore the mismatch and verify the clean check.

### 5.8 Accessibility and resilience

#### 5.8.1 — Make all workflows keyboard-operable

- **Depends on:** 5.1.3, 5.3.2, 5.4.2, 5.4.4, 5.5.1.
- **Worker boundary:** Accessibility interaction worker; semantic controls, tab order, keyboard dialogs, focus targets, and UI accessibility tests. Do not change server behavior.
- **Definition of done:** Every navigation, refresh, pagination, filter, form, confirmation, job/report link, and recovery action works without a pointer. Focus is visible, ordered, trapped only in active dialogs, restored after close/route change, and moved to meaningful content after errors or terminal job updates.
- **Focused verification:** Run keyboard-only journeys through validation, credential, plan, apply, report, audit, and logout flows at narrow and desktop layouts. Test focus after modal cancel/confirm, pagination, refresh, error, reconnect, and authorization changes.

#### 5.8.2 — Associate labels, descriptions, and errors with controls

- **Depends on:** 5.8.1, 5.3.2, 5.4.2.
- **Worker boundary:** Form/accessibility semantics worker; labels, field descriptions, validation associations, table semantics, and accessible-name tests. Do not change credential validation policy.
- **Definition of done:** All inputs/buttons/links/tables/status regions have meaningful accessible names, labels, descriptions, and error associations. Credential fields do not expose values through labels or errors. Repeated rows and paginated data remain understandable to assistive technology.
- **Focused verification:** Use an accessibility engine plus manual/DOM assertions for accessible names, `label`/`id`, `aria-describedby`, error focus, table headers, landmarks, and status regions. Include malformed/oversized input and server-error fixtures.

#### 5.8.3 — Meet visual, status-announcement, and reduced-motion requirements

- **Depends on:** 5.8.1, 5.8.2, 5.6.3.
- **Worker boundary:** Visual/status accessibility worker; contrast tokens, focus styling, live regions, busy/progress states, and motion media-query behavior. Do not weaken CSP or embed new external assets.
- **Definition of done:** Text, controls, focus indicators, disabled states, warnings, errors, and status content meet the selected contrast requirements. Progress, completion, failure, stale data, and target-unready changes are announced without excessive repetition. Transitions and progress animation honor `prefers-reduced-motion` and do not conceal safety details.
- **Focused verification:** Run contrast checks on representative states, inspect keyboard focus against all themes/states, test screen-reader-oriented live-region output for jobs/errors, and emulate reduced motion while checking that all content remains available.

#### 5.8.4 — Preserve durable state across refresh, reconnect, and restart

- **Depends on:** P3, P4, 5.4.1, 5.7.5.
- **Worker boundary:** Resilience worker; durable-ID rehydration, polling fallback, reconnect state machine, and browser failure tests. Do not add browser persistence for secrets or a new job execution path.
- **Definition of done:** Refresh and reconnect rehydrate from server-side source/target/validation/plan/job/report/audit state using safe IDs and bounded requests. SSE loss falls back to polling; restart-recovered jobs/reports are represented accurately; a browser failure cannot duplicate apply or lose mandatory replan guidance.
- **Focused verification:** Interrupt network/SSE, refresh at every job state, restart the server between enqueue and terminal state, revisit stale/missing IDs, and repeat after partial apply. Verify only durable non-secret identifiers are retained in the URL or safe view state.

#### 5.8.5 — Handle large inventories and plans without hiding safety details

- **Depends on:** P1, P3, P4, 5.2.3, 5.4.3, 5.7.4.
- **Worker boundary:** Large-data UI worker; endpoint-scoped pagination, virtualization where safe, summaries, and expansion behavior. Do not change server pagination semantics or omit operations/observations needed for apply safety.
- **Definition of done:** Large source inventories, diagnostics, plans, reports, and audit histories remain responsive through bounded pagination or virtualization. Counts, conflicts, dependencies, ownership warnings, rejection reasons, and safety-critical details remain discoverable and are not hidden by virtualization or collapsed summaries.
- **Focused verification:** Use data at, above, and far above configured page/window bounds; test keyboard and assistive navigation through virtualized rows; verify stable cursors/order, no duplicate/missing rows, safe loading/error states, and complete safety summaries.

#### 5.8.6 — Verify responsive layouts and browser failure paths

- **Depends on:** 5.8.1–5.8.5, 5.6.3.
- **Worker boundary:** Browser compatibility/responsive worker; narrow/desktop layout tests and failure-state presentation. Do not add unsupported runtime dependencies.
- **Definition of done:** The primary workflows work at supported narrow and desktop viewport sizes without clipping, inaccessible controls, or misleading status. Browser failures—JavaScript error, blocked asset, offline request, timeout, malformed response, expired session, authorization change, and unsupported SSE—produce recoverable, accessible states with safe guidance.
- **Focused verification:** Run browser checks at the supported narrow/desktop breakpoints with throttled/offline/network-error modes and blocked/CSP-violating asset fixtures. Capture severe-layout and accessibility results; verify recovery through refresh/re-login/polling without secret persistence.

### 5.9 Parity, security, and acceptance verification

#### 5.9.1 — Prove UI and automation use the same API/services

- **Depends on:** P1–P4, 5.1.2, 5.2.2, 5.3.3, 5.4.2, 5.4.4, 5.5.3, 5.7.8.
- **Worker boundary:** Parity verification worker; route/request/service tracing and contract tests. Do not add UI-specific handlers or test-only bypasses to production authorization.
- **Definition of done:** Validation, credential status/mutation, inventory, planning, apply, jobs, reports, audit, and docs flows demonstrably use the same versioned API and service checks for browser and bearer automation. Differences are limited to browser CSRF/session transport and presentation.
- **Focused verification:** Trace representative browser requests and replay equivalent bearer requests against the same handler/service seams. Compare response schemas, authorization results, idempotency, errors, request IDs, audit events, and side effects; assert no UI-only reconciliation route exists.

#### 5.9.2 — Verify every role's controls and server denial

- **Depends on:** P2, P3, P4, 5.1.4, 5.3.1, 5.4.4, 5.5.1.
- **Worker boundary:** Authorization-matrix worker; role/session/browser/API test matrix. Do not change role policy to make a test pass.
- **Definition of done:** Viewer, planner, applier, administrator, unknown/no-role, expired, bearer, OIDC, and break-glass actors see only appropriate controls and receive server-enforced denial for every disallowed endpoint/action. UI hiding never substitutes for middleware/service authorization.
- **Focused verification:** Run the full endpoint/action matrix, including source/target/validation/credential/plan/apply/job/report/audit/docs routes, with cookie and bearer transports. Assert denial status/envelope, no side effect, safe audit outcome, and no cross-actor record disclosure.

#### 5.9.3 — Run the browser/API security-control matrix

- **Depends on:** 5.6.1–5.6.4, 5.7.1–5.7.8.
- **Worker boundary:** Security verification worker; integrated HTTP/browser attack-negative cases and evidence. Do not introduce production bypasses or security-test exceptions.
- **Definition of done:** Integrated tests cover CSRF, origin, CORS, Host/proxy trust, session/cookie, cache, CSP, no-sniff/frame/referrer/permissions/HSTS, body/header/SSE/pagination bounds, queue/concurrency, rate limits, safe errors, request IDs, and OpenAPI parity together. Failures fail closed and do not create mutation side effects.
- **Focused verification:** Run the complete negative matrix with spoofed headers, cross-site requests, malformed bodies, oversized inputs, queue exhaustion, SSE floods, rate bursts, upstream failures, stale sessions, and contract mismatches. Collect status/envelope/header/request-ID evidence without storing secret payloads.

#### 5.9.4 — Prove credential privacy end to end

- **Depends on:** 5.3.1–5.3.4, 5.6.3, 5.6.4, 5.9.1.
- **Worker boundary:** Credential privacy verification worker; end-to-end sentinel scans across browser/server artifacts. Do not change credential semantics or replace real protections with redaction-only assertions.
- **Definition of done:** Submitted API keys, PEM CA bodies, passwords, authorization headers, OIDC tokens, cookies, and session material are absent from UI state/storage/URLs, HTTP responses, logs/traces, errors, audit, jobs, plans, reports, PVC state, and container/test output. Only approved status and certificate metadata remain visible.
- **Focused verification:** Submit unique sentinel values through upload/rotation/login/job flows and scan every available artifact/channel, including failure, timeout, duplicate, restart, audit, and report paths. Verify Secret values are never returned by status/detail APIs and sensitive responses are not cached.

#### 5.9.5 — Verify operator-relevant drift, ownership, dependency, and partial outcomes

- **Depends on:** P3, P4, 5.2.3, 5.4.3, 5.4.5, 5.8.4.
- **Worker boundary:** Reconciliation-experience verification worker; plan/apply/report fixtures and UI assertions. Do not alter reconciliation algorithms or safety classifications.
- **Definition of done:** The UI accurately exposes source/config/CA/credential/inventory/version/live-baseline drift, unmanaged/marker-only/ownership conflicts, dependency failures and transitive skips, independent target progress, partial results, consumed plans, and mandatory replan behavior. It never implies pruning, adoption, rollback, resume, or automatic retry where the architecture forbids it.
- **Focused verification:** Replay each Phase 3/4 safety fixture through browser and bearer/API views, including stale source, target configuration, Secret metadata/content/CA, inventory, version, marker, live baseline, independent-target failure, dependency failure, and zero-operation replan cases. Compare displayed classifications with durable reports/audit.

#### 5.9.6 — Run final browser accessibility and severe-layout checks

- **Depends on:** 5.8.1–5.8.6, 5.9.1, 5.9.2.
- **Worker boundary:** Independent browser verification worker; accessibility engine, keyboard journeys, responsive screenshots/layout assertions, and evidence only. Do not combine unrelated fixes with the verification change.
- **Definition of done:** All primary workflows pass the agreed browser accessibility checks and severe-layout thresholds at supported viewports, including signed-out, each role, error, loading, empty, partial, and break-glass-warning states. Outstanding violations are either fixed in their owning increment or recorded as blockers; none is silently waived.
- **Focused verification:** Run the browser accessibility suite, keyboard-only journeys, contrast checks, reduced-motion checks, and narrow/desktop severe-layout assertions. Preserve concise evidence tied to each affected increment and record any unresolved blocker.

#### 5.9.7 — Assemble Phase 5 gate evidence and reconcile this plan

- **Depends on:** Every increment 5.1.1–5.9.6 and P1–P4.
- **Worker boundary:** Phase owner/reviewer; evidence index, gate review, and plan-status reconciliation only. Do not add unreviewed feature work or mark an increment complete without its focused evidence.
- **Definition of done:** The phase owner can show that all increments have reviewed evidence, the UI and automation use the same secured `/api/v1` API, server authorization remains decisive, sources remain read-only, jobs/concurrency/audit behavior remains durable and bounded, credential leakage scans are clean, and accessibility/security/API parity checks pass. Residual risks, skipped tests, and required approvals are explicit.
- **Focused verification:** Re-run the phase-level targeted suites plus the full repository checks appropriate to the changed packages, inspect `git diff --check`, review the evidence index against every increment, and independently review the gate before changing any increment or phase status from planned/blocked to verified/passed.

## Living-plan rule

1. Before starting an increment, the worker and phase owner confirm its dependencies, boundary, contract version, and focused verification. If a dependency is not met, the increment remains blocked or is reduced to a contract-preserving test seam; it is not declared complete.
2. During work, update this file when scope, dependency, evidence, or worker ownership changes. Keep increment identifiers stable. If discovery reveals more work, add a new numbered increment under the owning workstream and link it from the dependency list; do not enlarge an existing increment or silently renumber later work.
3. A worker may report implementation evidence, but only the phase owner/reviewer may change an increment's status after the listed focused verification passes. Passing a broad suite alone does not prove an increment's definition of done.
4. Each implementation increment remains independently committable. A commit that spans multiple increments must be split or explicitly recorded as an integration-only follow-up with the same evidence boundaries; it must not obscure which increment is verified.
5. Any proposed architecture, API version, persistence, scaling, authority, credential, reconciliation, or security-policy change is a blocker requiring an explicit decision/ADR update. This plan must not be used to smuggle such a change into Phase 5.
6. At every handoff, retain the current status (`planned`, `blocked`, `in progress`, or `verified`), the exact focused evidence, unresolved risks, and the next dependency. Do not mark future work complete in advance, and do not claim the Phase 5 gate until 5.9.7 is independently reviewed.

## Future phase gate

The Phase 5 gate is satisfied only when all numbered increments above are independently verified and the evidence review confirms:

- the embedded UI is complete for sources, targets, credentials, validations, plans, jobs, reports, audit, and API documentation;
- the UI and external automation use the same versioned `/api/v1` API and server/service authorization;
- mounted sources remain visibly and technically read-only, and plans cannot be uploaded, edited, resumed, or implicitly replanned;
- OIDC/session, break-glass/session-expiry, CSRF/origin, cookie, CORS, proxy/Host, security-header, storage/URL, body/header/SSE/pagination, concurrency, queue, rate-limit, error, request-ID, and OpenAPI-parity controls pass;
- durable asynchronous jobs survive browser disconnect/restart as designed, mutation serialization and target/dependency isolation remain intact, and audit records are paginated, authorized, linked, durable, and non-secret;
- keyboard, focus, labels, contrast, announcements, reduced motion, responsive layout, large-data, and browser-failure checks pass; and
- end-to-end role, drift/ownership/dependency/partial-outcome, and credential sentinel tests pass without changing the accepted architecture.

No Phase 5 completion or future-work status is asserted by this planning refinement.
