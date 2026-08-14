# Phase 0 — contract fixtures and migration skeleton

## Objective

Replace the prototype foundation with a buildable `elastic-maintainer` skeleton and establish version-pinned public API evidence before implementing adapters.

## Current status

Completed evidence:

- Prototype baseline: `docs/implementation/phase-0-baseline.md`
- API contract baseline: `docs/kibana-api-contracts.md`
- Sanitized fixtures: `testdata/contracts/kibana/v9.2.0/` and `testdata/contracts/kibana/v9.4.2/`
- Public OpenAPI response fixtures validate against both pinned schemas.

Remaining work begins with the replacement command skeleton.

## Substeps

### 0.1 Preserve the baseline

1. Keep `go test ./...` passing before each migration slice.
2. Use `docs/implementation/phase-0-baseline.md` as the inventory of prototype files and references.
3. Preserve Git history, the configured remote, and unrelated files.
4. Keep `start-web.sh` local and untracked until its required binary, examples, and build targets exist.

### 0.2 Maintain contract provenance

1. Pin exact 9.2.0 and selected current 9.x OpenAPI source URLs and hashes.
2. Keep one operation manifest per tested version.
3. Validate successful fixtures against their pinned response schemas.
4. Keep fixture values synthetic and scan them for credentials.
5. Record version differences rather than silently coding to the newer API.
6. Leave missing privilege claims as live-matrix evidence gaps.

### 0.3 Build the testable CLI boundary

1. Add Cobra at an exact Go-1.22-compatible version.
2. Create `internal/cli` with injected stdin, stdout, stderr, arguments, and build information.
3. Construct fresh command trees per invocation; avoid mutable package-global commands.
4. Centralize deterministic error output and exit-code mapping.
5. Keep `os.Exit` confined to the executable entry point.

### 0.4 Create the replacement command

1. Add `cmd/elastic-maintainer/main.go` as wiring only.
2. Register exactly `validate`, `plan`, `apply`, `serve`, and `version`.
3. Define the flags from `plan.md` section 5.
4. Reject positional arguments, missing required flags, and legacy credential/mode flags.
5. Make unfinished commands return a stable not-implemented error without side effects.
6. Make `version` print deterministic development metadata.
7. Add table-driven command, flag, stream, help, and side-effect tests.

### 0.5 Retire the old entry point

1. Build and test the replacement command first.
2. Remove `cmd/elastic-maintenance` and its command-specific tests.
3. Keep old internal packages temporarily so deletion does not combine unrelated migration risks.
4. Inventory remaining old-name and old-flag references for their owning later substeps.

### 0.6 Normalize module and build identity

1. Replace the placeholder module declaration with the repository module path.
2. Update all retained imports in one mechanical change.
3. Run `go mod tidy` and verify no accidental dependencies entered the graph.
4. Add version, commit, and build-date variables with linker-flag support.
5. Test development defaults and injected build values.

### 0.7 Replace local build tooling

1. Add build, test, vet, clean, and versioned-binary targets.
2. Build `bin/elastic-maintainer` reproducibly with `-trimpath` and linker metadata.
3. Keep packaging references temporarily consistent with the renamed binary.
4. Do not implement production container/Kubernetes hardening before Phase 6.

### 0.8 Replace stale baseline documentation

1. Update `README.md` to identify the replacement interface.
2. State that prototype JSON and `--mode=review|apply` are unsupported.
3. Mark unfinished commands honestly.
4. Remove `config/desired-state.json` only when YAML examples arrive in Phase 1.
5. Remove obsolete prototype internal code only after replacement packages cover its necessary build/test roles.

### 0.9 Close API contract gaps

1. Confirm caller-defined IDs and required privileges in live 9.2.0 and current-9.x environments.
2. Confirm spaces behavior, pagination completion, mutation response shapes, and detection-rule replacement semantics.
3. Sanitize any retained live-derived fixtures.
4. Update the contract document, fixture manifests, operator privilege guidance, and plan assumptions together.

## Verification

```bash
go mod tidy
gofmt -w cmd/elastic-maintainer internal/cli
go test ./... -count=1
go test -race ./internal/cli
go vet ./...
make build
bin/elastic-maintainer --help
bin/elastic-maintainer version
git diff --check
```

## Phase gate

- Exact public endpoints, caller-defined IDs, required privileges, pagination, and canonical fields are documented for all five kinds.
- The renamed command and build tooling work.
- The old executable is gone.
- No reconciliation behavior is falsely claimed.
- All retained tests pass and no credential appears in fixtures or output.
