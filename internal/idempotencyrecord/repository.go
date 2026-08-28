// Package idempotencyrecord provides durable, scoped idempotency records over
// the versioned statefs store. It owns only the keyed result index; callers
// remain responsible for authorization, jobs, and business operations.
package idempotencyrecord

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

const (
	// MaxRecordsScan is both the maximum durable record count and the maximum
	// number of records considered by one coherent capacity/list scan.
	MaxRecordsScan = 10000
	// MaxTotalBytes bounds a coherent scan. Direct lookup does not scan this
	// aggregate and remains available when the directory is at capacity.
	MaxTotalBytes = 32 << 20

	capacityLockID       = "idempotency-capacity"
	capacityRetryBackoff = time.Millisecond
	maxSubjectBytes      = 64 << 10
)

var (
	// ErrNotFound covers both an absent and an expired record. Expiry is
	// deliberately not distinguishable to callers that do not need it.
	ErrNotFound = errors.New("idempotency record not found")
	// ErrConflict means that the scope exists with a different request digest,
	// or that a CAS expected ETag is stale.
	ErrConflict = errors.New("idempotency record conflict")
	// ErrInvalidRecord means a caller supplied an invalid state projection or
	// scope. Its errors never include caller values.
	ErrInvalidRecord = errors.New("invalid idempotency record")
	// ErrCorrupt means durable state failed closed. It never includes document
	// contents, filenames, scope values, or IDs.
	ErrCorrupt = errors.New("idempotency record state is corrupt")
	// ErrUnavailable means a transient or operational storage failure prevented
	// the operation. It never includes filesystem paths or persisted data.
	ErrUnavailable = errors.New("idempotency record storage unavailable")
	// ErrCapacity means a valid directory already contains MaxRecordsScan
	// records. Existing records are still directly readable and replayable.
	ErrCapacity = errors.New("idempotency record capacity reached")
	// ErrScanLimit means a coherent validation scan could not be completed
	// within its fixed record or aggregate-byte budget.
	ErrScanLimit = errors.New("idempotency record scan limit exceeded")
	// ErrImmutable means a terminal record cannot be completed again.
	ErrImmutable = errors.New("idempotency terminal record is immutable")
	// ErrInvalidTimestamp means a caller-supplied observation time was not a
	// canonical UTC value.
	ErrInvalidTimestamp = errors.New("invalid idempotency observation time")
	// ErrInvalidETag is returned for a malformed expected ETag without echoing
	// it. A well-formed but stale ETag returns ErrConflict.
	ErrInvalidETag = errors.New("invalid idempotency record ETag")

	scopeActionPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	scopeIDPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	jobIDPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	stateIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

// Record is one validated durable idempotency record and the SHA-256 ETag of
// its exact stored JSON bytes. Replay is true only when CreateOrReplay found
// an unexpired equivalent record; replay never rewrites the file.
type Record struct {
	Idempotency state.IdempotencyRecord
	ETag        string
	Replay      bool
}

// Repository is the durable scoped idempotency contract.
type Repository interface {
	CreateOrReplay(context.Context, state.IdempotencyRecord, time.Time) (Record, error)
	Lookup(context.Context, state.Actor, audit.Action, string, string, time.Time) (Record, error)
	Complete(context.Context, string, string, state.IdempotencyOutcome, state.ResultReference) (Record, error)
	Get(context.Context, string, string, time.Time) (Record, error)
}

// FileRepository stores one strict state.IdempotencyRecord at the filename
// derived from its actor/action/key scope. The instance gate bounds work for
// one repository; statefs atomic no-replace/CAS operations coordinate other
// repository instances sharing the Store.
type FileRepository struct {
	gate  chan struct{}
	store *statefs.Store

	// capacityBeforeReclaim is only used by same-package race tests to pause
	// the snapshot/CAS gap; production repositories leave it nil.
	capacityBeforeReclaim func()
}

var _ Repository = (*FileRepository)(nil)

// New constructs a repository over an already-open state store.
func New(store *statefs.Store) (*FileRepository, error) {
	if store == nil {
		return nil, statefs.ErrClosed
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return &FileRepository{gate: gate, store: store}, nil
}

func (repository *FileRepository) acquire(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	select {
	case <-repository.gate:
		if err := contextErr(ctx); err != nil {
			repository.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (repository *FileRepository) release() { repository.gate <- struct{}{} }

// ScopeID returns the deterministic, domain-separated SHA-256 scope hash.
// The request digest is not included. The supplied actor must already be the
// normalized state.Actor projection: subject trimmed, roles sorted and unique.
func ScopeID(actor state.Actor, action audit.Action, key string) (string, error) {
	encoded, err := canonicalScope(actor, action, key)
	if err != nil {
		return "", ErrInvalidRecord
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// CreateOrReplay atomically creates candidate or returns the first existing
// equivalent record. The caller supplies the trusted observation time; it must
// be canonical UTC. For a new or replacement candidate, candidate.CreatedAt
// must be exactly that value. A record at or after its non-nil ExpiresAt is
// expired at that observation time and may be replaced using CAS. An unexpired
// record is never overwritten, including by a changed candidate. This method
// never reads the wall clock.
func (repository *FileRepository) CreateOrReplay(ctx context.Context, candidate state.IdempotencyRecord, at time.Time) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if err := validateLookupTime(at); err != nil {
		return Record{}, err
	}
	candidate = clone(candidate)
	encoded, scopeID, err := validateCandidate(candidate)
	if err != nil {
		return Record{}, err
	}
	// The exact UTC value was checked above. Keep it as the sole time input for
	// expiry decisions; candidate.CreatedAt is only persisted state.
	if candidate.ExpiresAt != nil {
		expires := candidate.ExpiresAt.UTC()
		candidate.ExpiresAt = &expires
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	gateHeld := true
	defer func() {
		if gateHeld {
			repository.release()
		}
	}()

	for {
		if !gateHeld {
			if err := repository.acquire(ctx); err != nil {
				return Record{}, err
			}
			gateHeld = true
		}
		if err := contextErr(ctx); err != nil {
			return Record{}, err
		}
		current, readErr := repository.readByID(scopeID)
		switch {
		case readErr == nil:
			if !sameScope(current.Idempotency, candidate) {
				return Record{}, ErrCorrupt
			}
			if !expiredAt(current.Idempotency, at) {
				if current.Idempotency.RequestDigest != candidate.RequestDigest {
					return Record{}, ErrConflict
				}
				current.Replay = true
				return current, nil
			}

			// Expiry is inclusive: at ExpiresAt the old record is expired. A
			// replacement must bind its CreatedAt to the trusted observation
			// time before CAS prevents it from silently winning over a
			// concurrent completion or replacement.
			if candidate.CreatedAt != at {
				return Record{}, ErrInvalidRecord
			}
			if err := contextErr(ctx); err != nil {
				return Record{}, err
			}
			if err := repository.store.WriteAtomicIfMatch(idempotencyPath(scopeID), encoded, current.ETag); err != nil {
				if errors.Is(err, statefs.ErrETagMismatch) || errors.Is(err, statefs.ErrNotFound) {
					continue
				}
				return Record{}, mapStoreError(err)
			}
			return Record{Idempotency: candidate, ETag: etag(encoded)}, nil

		case errors.Is(readErr, ErrNotFound):
			// The capacity lock closes the scan/write gap between repository
			// instances sharing one Store. Release this repository's gate while
			// waiting so direct lookups are not blocked by another admission;
			// Store.mu and the lock protect the admission itself.
			repository.release()
			gateHeld = false
			lock, lockErr := repository.acquireCapacityLock(ctx)
			if lockErr != nil {
				return Record{}, lockErr
			}
			current, readErr = repository.readByID(scopeID)
			if readErr == nil {
				if closeErr := closeCapacityLock(lock); closeErr != nil {
					return Record{}, closeErr
				}
				continue
			}
			if !errors.Is(readErr, ErrNotFound) {
				if closeErr := closeCapacityLock(lock); closeErr != nil {
					return Record{}, closeErr
				}
				return Record{}, readErr
			}
			if candidate.CreatedAt != at {
				if closeErr := closeCapacityLock(lock); closeErr != nil {
					return Record{}, closeErr
				}
				return Record{}, ErrInvalidRecord
			}
			countErr := repository.checkCapacity(ctx, at)
			if countErr != nil {
				if closeErr := closeCapacityLock(lock); closeErr != nil {
					return Record{}, closeErr
				}
				return Record{}, countErr
			}
			// The scan can be expensive and may reclaim records. Do not begin a
			// write after cancellation, even though the capacity lock is held.
			if err := contextErr(ctx); err != nil {
				if closeErr := closeCapacityLock(lock); closeErr != nil {
					return Record{}, closeErr
				}
				return Record{}, err
			}
			writeErr := repository.store.WriteAtomic(idempotencyPath(scopeID), encoded, false)
			if closeErr := closeCapacityLock(lock); closeErr != nil {
				return Record{}, closeErr
			}
			switch {
			case writeErr == nil:
				return Record{Idempotency: candidate, ETag: etag(encoded)}, nil
			case errors.Is(writeErr, statefs.ErrDestinationExists):
				continue
			default:
				return Record{}, mapStoreError(writeErr)
			}

		default:
			return Record{}, readErr
		}
	}
}

// Lookup performs an exact actor/action/key/digest lookup at the caller's
// supplied canonical UTC time. It never scans the directory. A record at or
// after its ExpiresAt is not found; nil ExpiresAt never expires.
func (repository *FileRepository) Lookup(ctx context.Context, actor state.Actor, action audit.Action, key, requestDigest string, at time.Time) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if err := validateLookupTime(at); err != nil {
		return Record{}, err
	}
	at = at.UTC()
	if err := validateDigest(requestDigest); err != nil {
		return Record{}, ErrInvalidRecord
	}
	scopeID, err := ScopeID(actor, action, key)
	if err != nil {
		return Record{}, err
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	record, err := repository.readByID(scopeID)
	if err != nil {
		return Record{}, err
	}
	if expiredAt(record.Idempotency, at) {
		return Record{}, ErrNotFound
	}
	if record.Idempotency.RequestDigest != requestDigest {
		return Record{}, ErrConflict
	}
	return record, nil
}

// Get reads a record directly by its deterministic scope hash while still
// requiring the request digest and caller-supplied lookup time. This direct
// form is useful when a caller already has the derived hash; it cannot bypass
// expiry or digest-conflict checks. Invalid IDs are reported as not found and
// are never echoed.
func (repository *FileRepository) Get(ctx context.Context, id, requestDigest string, at time.Time) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !scopeIDPattern.MatchString(id) {
		return Record{}, ErrNotFound
	}
	if err := validateLookupTime(at); err != nil {
		return Record{}, err
	}
	at = at.UTC()
	if err := validateDigest(requestDigest); err != nil {
		return Record{}, ErrInvalidRecord
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	record, err := repository.readByID(id)
	if err != nil {
		return Record{}, err
	}
	if expiredAt(record.Idempotency, at) {
		return Record{}, ErrNotFound
	}
	if record.Idempotency.RequestDigest != requestDigest {
		return Record{}, ErrConflict
	}
	return record, nil
}

// Complete atomically changes one pending record to succeeded or failed. The
// typed result is mandatory, all identity/scope/job/timestamp/expiry fields
// are preserved, and terminal records cannot be changed.
func (repository *FileRepository) Complete(ctx context.Context, id, expectedETag string, outcome state.IdempotencyOutcome, result state.ResultReference) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !scopeIDPattern.MatchString(id) {
		return Record{}, ErrNotFound
	}
	if !digestPattern.MatchString(expectedETag) {
		return Record{}, ErrInvalidETag
	}
	if outcome != state.IdempotencySucceeded && outcome != state.IdempotencyFailed {
		return Record{}, ErrInvalidRecord
	}
	if err := validateResult(result); err != nil {
		return Record{}, err
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	current, err := repository.readByID(id)
	if err != nil {
		return Record{}, err
	}
	if !sameETag(current.ETag, expectedETag) {
		return Record{}, ErrConflict
	}
	if current.Idempotency.Outcome != state.IdempotencyPending {
		return Record{}, ErrImmutable
	}
	if result.Kind == state.ResultKindJob && (current.Idempotency.JobID == "" || result.ID != current.Idempotency.JobID) {
		return Record{}, ErrInvalidRecord
	}
	replacement := clone(current.Idempotency)
	replacement.Outcome = outcome
	resultCopy := result
	replacement.Result = &resultCopy
	encoded, encodeErr := state.EncodeIdempotency(replacement)
	if encodeErr != nil {
		return Record{}, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if err := repository.store.WriteAtomicIfMatch(idempotencyPath(id), encoded, expectedETag); err != nil {
		switch {
		case errors.Is(err, statefs.ErrETagMismatch):
			return Record{}, ErrConflict
		case errors.Is(err, statefs.ErrNotFound):
			return Record{}, ErrNotFound
		default:
			return Record{}, mapStoreError(err)
		}
	}
	return Record{Idempotency: replacement, ETag: etag(encoded)}, nil
}

func (repository *FileRepository) readByID(id string) (Record, error) {
	data, err := repository.store.Read(idempotencyPath(id))
	if err != nil {
		if errors.Is(err, statefs.ErrNotFound) {
			return Record{}, ErrNotFound
		}
		if errors.Is(err, statefs.ErrClosed) {
			return Record{}, ErrUnavailable
		}
		return Record{}, mapStoreError(err)
	}
	return decodeStored(id, data)
}

const maxCapacityReclaimPasses = 4

// checkCapacity takes bounded coherent snapshots while the caller holds the
// cross-repository capacity lock. At capacity it removes only records whose
// snapshot ETags still match and whose expiry is observed at the caller's at.
// Every successful removal is followed by a fresh scan, so a stale snapshot
// can never be used to admit a physical record beyond MaxRecordsScan.
func (repository *FileRepository) checkCapacity(ctx context.Context, at time.Time) error {
	protected := make(map[string]struct{})
	baselineETags := make(map[string]string)
	for pass := 0; pass < maxCapacityReclaimPasses; pass++ {
		if err := contextErr(ctx); err != nil {
			return err
		}
		records, err := repository.scan(ctx)
		if err != nil {
			return err
		}
		if len(records) < MaxRecordsScan {
			return nil
		}
		if pass == 0 {
			for _, record := range records {
				baselineETags[record.Idempotency.ID] = record.ETag
			}
		} else {
			// Only the original snapshot's unchanged records are eligible
			// for this admission. A record that appeared or changed between
			// scans is protected even if its new value is expired.
			for _, record := range records {
				if expected, ok := baselineETags[record.Idempotency.ID]; !ok || expected != record.ETag {
					protected[record.Idempotency.ID] = struct{}{}
				}
			}
		}

		reclaimed := false
		observedChange := false
		for _, record := range records {
			if _, skip := protected[record.Idempotency.ID]; skip {
				continue
			}
			if !expiredAt(record.Idempotency, at) {
				continue
			}
			if err := contextErr(ctx); err != nil {
				return err
			}
			if repository.capacityBeforeReclaim != nil {
				repository.capacityBeforeReclaim()
			}
			removeErr := repository.store.RemoveIfMatch(idempotencyPath(record.Idempotency.ID), record.ETag)
			switch {
			case removeErr == nil:
				reclaimed = true
			case errors.Is(removeErr, statefs.ErrETagMismatch):
				// A concurrent completion or replacement won. Never delete
				// that changed record from a later rescan in this admission.
				protected[record.Idempotency.ID] = struct{}{}
				observedChange = true
				continue
			case errors.Is(removeErr, statefs.ErrNotFound):
				// A concurrent removal won; rescan because physical capacity
				// may now be available.
				observedChange = true
				continue
			default:
				return mapStoreError(removeErr)
			}
		}
		if !reclaimed && !observedChange {
			return ErrCapacity
		}
	}
	return ErrCapacity
}

func (repository *FileRepository) scan(ctx context.Context) ([]Record, error) {
	documents, err := repository.store.ReadDocuments(statefs.IdempotencyDir, MaxRecordsScan, MaxTotalBytes)
	if err != nil {
		switch {
		case errors.Is(err, statefs.ErrTooManyDocuments), errors.Is(err, statefs.ErrAggregateTooLarge):
			return nil, ErrScanLimit
		case errors.Is(err, statefs.ErrClosed):
			return nil, ErrUnavailable
		default:
			return nil, mapStoreError(err)
		}
	}
	result := make([]Record, 0, len(documents))
	for _, document := range documents {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		id, ok := filenameID(document.Name)
		if !ok {
			return nil, ErrCorrupt
		}
		record, decodeErr := decodeStored(id, document.Data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Idempotency.ID < result[j].Idempotency.ID })
	return result, nil
}

func decodeStored(id string, data []byte) (Record, error) {
	if !scopeIDPattern.MatchString(id) {
		return Record{}, ErrCorrupt
	}
	value, err := state.DecodeIdempotency(data)
	if err != nil {
		return Record{}, ErrCorrupt
	}
	scopeID, scopeErr := ScopeID(value.Actor, value.Action, value.Key)
	if scopeErr != nil || value.ID != id || scopeID != id {
		return Record{}, ErrCorrupt
	}
	return Record{Idempotency: clone(value), ETag: etag(data)}, nil
}

func validateCandidate(candidate state.IdempotencyRecord) ([]byte, string, error) {
	encoded, err := state.EncodeIdempotency(candidate)
	if err != nil {
		return nil, "", ErrInvalidRecord
	}
	scopeID, scopeErr := ScopeID(candidate.Actor, candidate.Action, candidate.Key)
	if scopeErr != nil || candidate.ID != scopeID {
		return nil, "", ErrInvalidRecord
	}
	return encoded, scopeID, nil
}

func validateResult(result state.ResultReference) error {
	switch result.Kind {
	case state.ResultKindJob:
		if !jobIDPattern.MatchString(result.ID) {
			return ErrInvalidRecord
		}
	case state.ResultKindPlan, state.ResultKindReport, state.ResultKindCredentialMutation:
		if !stateIDPattern.MatchString(result.ID) {
			return ErrInvalidRecord
		}
	default:
		return ErrInvalidRecord
	}
	return nil
}

func canonicalScope(actor state.Actor, action audit.Action, key string) ([]byte, error) {
	if actor.Subject != strings.TrimSpace(actor.Subject) || actor.Subject == "" || len(actor.Subject) > maxSubjectBytes || !utf8.ValidString(actor.Subject) || strings.IndexFunc(actor.Subject, unicode.IsControl) >= 0 {
		return nil, ErrInvalidRecord
	}
	if len(actor.Roles) == 0 || len(actor.Roles) > len(auth.KnownRoles()) {
		return nil, ErrInvalidRecord
	}
	previous := auth.Role("")
	seen := make(map[auth.Role]struct{}, len(actor.Roles))
	for _, role := range actor.Roles {
		if !knownRole(role) || role <= previous {
			return nil, ErrInvalidRecord
		}
		if _, exists := seen[role]; exists {
			return nil, ErrInvalidRecord
		}
		seen[role] = struct{}{}
		previous = role
	}
	if !knownMethod(actor.Method) || len(action) == 0 || len(action) > 128 || !scopeActionPattern.MatchString(string(action)) {
		return nil, ErrInvalidRecord
	}
	if err := jobs.ValidateIdempotencyKey(key); err != nil {
		return nil, ErrInvalidRecord
	}

	// Every variable-length value is length-prefixed, and the fixed domain
	// separates this hash from all other application digests. Digest is
	// intentionally absent from this encoding.
	encoded := make([]byte, 0, len(actor.Subject)+len(action)+len(key)+128)
	encoded = append(encoded, []byte("elastic-maintainer/idempotency-scope/v1")...)
	encoded = appendScopePart(encoded, actor.Subject)
	encoded = append(encoded, byte(len(actor.Roles)))
	for _, role := range actor.Roles {
		encoded = appendScopePart(encoded, string(role))
	}
	encoded = appendScopePart(encoded, string(actor.Method))
	encoded = appendScopePart(encoded, string(action))
	encoded = appendScopePart(encoded, key)
	return encoded, nil
}

func appendScopePart(buffer []byte, value string) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	buffer = append(buffer, length[:]...)
	return append(buffer, value...)
}

func validateLookupTime(value time.Time) error {
	// Round(0) strips a monotonic reading. A monotonic component cannot be
	// represented in the persisted RFC3339 contract, so reject it as well as
	// non-UTC locations and zero values.
	if value.IsZero() || value.Location() != time.UTC || value.Round(0) != value {
		return ErrInvalidTimestamp
	}
	return nil
}

func validateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return ErrInvalidRecord
	}
	return nil
}

func expiredAt(record state.IdempotencyRecord, at time.Time) bool {
	return record.ExpiresAt != nil && !at.Before(*record.ExpiresAt)
}

func sameScope(left, right state.IdempotencyRecord) bool {
	if left.Actor.Subject != right.Actor.Subject || left.Actor.Method != right.Actor.Method || left.Action != right.Action || left.Key != right.Key || len(left.Actor.Roles) != len(right.Actor.Roles) {
		return false
	}
	for index := range left.Actor.Roles {
		if left.Actor.Roles[index] != right.Actor.Roles[index] {
			return false
		}
	}
	return true
}

func filenameID(name string) (string, bool) {
	if len(name) != len(".json")+64 || !strings.HasSuffix(name, ".json") {
		return "", false
	}
	id := strings.TrimSuffix(name, ".json")
	return id, scopeIDPattern.MatchString(id)
}

func idempotencyPath(id string) string { return statefs.IdempotencyDir + "/" + id + ".json" }

func knownRole(value auth.Role) bool {
	switch value {
	case auth.RoleViewer, auth.RolePlanner, auth.RoleApplier, auth.RoleAdministrator:
		return true
	default:
		return false
	}
}

func knownMethod(value auth.Method) bool {
	switch value {
	case auth.MethodSession, auth.MethodOIDC, auth.MethodBearer, auth.MethodBreakGlass:
		return true
	default:
		return false
	}
}

func clone(value state.IdempotencyRecord) state.IdempotencyRecord {
	value.Actor.Roles = append([]auth.Role(nil), value.Actor.Roles...)
	if value.ExpiresAt != nil {
		expires := *value.ExpiresAt
		value.ExpiresAt = &expires
	}
	if value.Result != nil {
		result := *value.Result
		value.Result = &result
	}
	return value
}

func etag(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func sameETag(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func closeCapacityLock(lock *statefs.Lock) error {
	if lock == nil {
		return nil
	}
	if err := lock.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (repository *FileRepository) acquireCapacityLock(ctx context.Context) (*statefs.Lock, error) {
	for {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		lock, err := repository.store.AcquireIdempotencyLock(capacityLockID)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, statefs.ErrLockConflict) {
			return nil, mapStoreError(err)
		}
		timer := time.NewTimer(capacityRetryBackoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func mapStoreError(err error) error {
	switch {
	case errors.Is(err, statefs.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, statefs.ErrInsufficientFree), errors.Is(err, statefs.ErrFreeSpaceUnavailable), errors.Is(err, statefs.ErrWriteFailed), errors.Is(err, statefs.ErrDurabilityUnknown), errors.Is(err, statefs.ErrFileUnavailable), errors.Is(err, statefs.ErrLockUnavailable), errors.Is(err, statefs.ErrLockConflict), errors.Is(err, statefs.ErrClosed):
		return ErrUnavailable
	case errors.Is(err, statefs.ErrSymlink), errors.Is(err, statefs.ErrNotRegular), errors.Is(err, statefs.ErrHardLinked), errors.Is(err, statefs.ErrUnsafeFile), errors.Is(err, statefs.ErrUnsafePermissions), errors.Is(err, statefs.ErrUnsafeOwnership), errors.Is(err, statefs.ErrDocumentTooLarge), errors.Is(err, statefs.ErrUnexpectedEntry), errors.Is(err, statefs.ErrCorrupt), errors.Is(err, statefs.ErrInvalidStateDir):
		return ErrCorrupt
	default:
		return ErrCorrupt
	}
}
