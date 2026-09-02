// Package jobrecord provides durable persistence for the versioned job
// projection. It owns job-file concurrency, bounded startup recovery, the
// narrow exceptional recovery transition, and pagination, but deliberately
// does not resume, schedule, or expose jobs over HTTP.
package jobrecord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecovery"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

const (
	DefaultPageSize = 50
	MaxPageSize     = 100
	MaxRecordsScan  = 10000
	MaxTotalBytes   = 32 << 20
	maxPageTokenLen = 512
)

var (
	// ErrInvalidOptions identifies an invalid list filter or page-size value.
	ErrInvalidOptions = errors.New("invalid job list options")
	// ErrInvalidPageToken is intentionally non-descriptive: tokens and their
	// contents must never be reflected in an error.
	ErrInvalidPageToken = errors.New("invalid job page token")
	// ErrImmutableChange identifies an attempted change to a job identity or
	// request field that is immutable for the lifetime of a job.
	ErrImmutableChange = errors.New("immutable job field changed")
	// ErrScanLimit indicates that listing would exceed the bounded scan budget.
	ErrScanLimit = errors.New("job record scan limit exceeded")
	// ErrPageChanged means a page token no longer describes the same filtered
	// record snapshot. Callers must restart pagination from the first page.
	ErrPageChanged = errors.New("job record page snapshot changed")
	// ErrRecovery is the safe top-level startup recovery failure. Recovery
	// errors never include persisted document diagnostics or identifiers.
	ErrRecovery = errors.New("job recovery failed")
	// ErrRecoveryCorrupt means the bounded startup snapshot contained an
	// unusable or semantically unsafe durable record.
	ErrRecoveryCorrupt = errors.New("job recovery found corrupt state")
	// ErrRecoveryConflict means a record changed or disappeared after the
	// coherent snapshot and before its CAS interruption.
	ErrRecoveryConflict = errors.New("job recovery encountered concurrent state change")
	// ErrRecoveryScanLimit means the bounded startup snapshot exceeded one of
	// its fixed record or aggregate-byte limits.
	ErrRecoveryScanLimit = errors.New("job recovery scan limit exceeded")
	// ErrInvalidRecoveryTimestamp means the caller did not supply one usable,
	// non-future UTC recovery timestamp.
	ErrInvalidRecoveryTimestamp = errors.New("invalid job recovery timestamp")

	jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Record is a validated durable job and the SHA-256 ETag of its stored strict
// JSON bytes. Create/Put writes are canonical; the narrow cancellation flag
// mutation preserves already-valid non-flag bytes. Content-derived ETags are
// stable across process restarts.
type Record struct {
	Job  state.Job `json:"job"`
	ETag string    `json:"etag"`
}

// Page is a bounded, deterministically ordered job-record page.
type Page struct {
	Records       []Record `json:"records"`
	NextPageToken string   `json:"nextPageToken,omitempty"`
}

// RecoverySummary is the bounded, identifier-free result of one successful
// startup recovery pass. The counts are at most MaxRecordsScan.
type RecoverySummary struct {
	Examined    int `json:"examined"`
	Preserved   int `json:"preserved"`
	Interrupted int `json:"interrupted"`
}

// Repository is the durable job-record contract. Create and Put accept the
// state projection rather than Record so callers cannot manufacture an ETag.
type Repository interface {
	Create(context.Context, state.Job) (Record, error)
	Get(context.Context, string) (Record, error)
	Put(context.Context, string, state.Job, string) (Record, error)
	RequestCancellation(context.Context, string, string) (Record, error)
	Interrupt(context.Context, string, string, time.Time, jobrecovery.FailureCode) (Record, error)
	Recover(context.Context, time.Time) (RecoverySummary, error)
	List(context.Context, jobs.ListOptions) (Page, error)
}

// FileRepository stores exactly one strict state.Job document in the statefs
// jobs directory. Its context-aware gate serializes each operation, including
// a complete List, relative to other operations on this instance; Store's
// mutex provides the shared-store serialization needed by CAS writes.
type FileRepository struct {
	gate                chan struct{}
	store               *statefs.Store
	recoveryBeforeWrite func()
}

var _ Repository = (*FileRepository)(nil)

// New constructs the canonical file-backed repository over store.
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

// Create validates and atomically creates one job without replacing an
// existing destination.
func (repository *FileRepository) Create(ctx context.Context, job state.Job) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	encoded, err := state.EncodeJob(job)
	if err != nil {
		return Record{}, err
	}

	if job.Status != jobs.StatusQueued {
		return Record{}, jobs.ErrInvalidTransition
	}
	if err := validateInitialLinks(job); err != nil {
		return Record{}, err
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	if err := repository.store.WriteAtomic(jobPath(job.ID), encoded, false); err != nil {
		if errors.Is(err, statefs.ErrDestinationExists) {
			return Record{}, jobs.ErrConflict
		}
		return Record{}, err
	}
	return Record{Job: job, ETag: etag(encoded)}, nil
}

// Get reads and strictly validates one durable job record.
func (repository *FileRepository) Get(ctx context.Context, id string) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !jobIDPattern.MatchString(id) {
		return Record{}, jobs.ErrNotFound
	}

	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	return repository.readLocked(id)
}

// Put validates a replacement for the explicitly named job, checks the
// expected content ETag, preserves immutable/append-only metadata, and
// requires one of jobs.CanTransition's existing status transitions. The
// exceptional queued/running-to-interrupted transition is reserved for
// Interrupt, and same-status cancellation mutation is reserved for
// RequestCancellation.
func (repository *FileRepository) Put(ctx context.Context, id string, replacement state.Job, expectedETag string) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !jobIDPattern.MatchString(id) {
		return Record{}, jobs.ErrNotFound
	}
	if replacement.ID != id {
		return Record{}, ErrImmutableChange
	}
	if err := validatePersistedJob(replacement); err != nil {
		return Record{}, err
	}
	encoded, err := state.EncodeJob(replacement)
	if err != nil {
		return Record{}, err
	}

	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	current, err := repository.readLocked(id)
	if err != nil {
		return Record{}, err
	}
	if !sameETag(current.ETag, expectedETag) {
		return Record{}, jobs.ErrConflict
	}
	if !sameImmutableFields(current.Job, replacement) {
		return Record{}, ErrImmutableChange
	}
	if err := validateAppendOnlyFields(current.Job, replacement); err != nil {
		return Record{}, err
	}
	if replacement.Status == jobs.StatusInterrupted && (current.Job.Status == jobs.StatusQueued || current.Job.Status == jobs.StatusRunning) {
		// Recovery is the sole exceptional path for marking an outstanding
		// durable record interrupted. Keep it narrow so callers cannot bypass
		// its finish-time, failure-code, and CAS contract through Put.
		return Record{}, jobs.ErrInvalidTransition
	}
	if !jobs.CanTransition(current.Job.Status, replacement.Status) {
		return Record{}, jobs.ErrInvalidTransition
	}
	// The caller context gates the operation until this point. Once the
	// descriptor-relative CAS begins, statefs does not cancel it; its outcome
	// is authoritative even if ctx is canceled concurrently.
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if err := repository.store.WriteAtomicIfMatch(jobPath(id), encoded, expectedETag); err != nil {
		switch {
		case errors.Is(err, statefs.ErrETagMismatch):
			return Record{}, jobs.ErrConflict
		case errors.Is(err, statefs.ErrNotFound):
			return Record{}, jobs.ErrNotFound
		default:
			return Record{}, err
		}
	}
	return Record{Job: replacement, ETag: etag(encoded)}, nil
}

// RequestCancellation durably requests cancellation by changing only the
// cancellationRequested flag on a queued or running record. A request already
// observed on a queued/running record is an idempotent no-op, as is replaying a
// canceled record whose flag is already set. Only the false state is protected
// by expectedETag; this lets concurrent retries replay the winning request.
func (repository *FileRepository) RequestCancellation(ctx context.Context, id, expectedETag string) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !jobIDPattern.MatchString(id) {
		return Record{}, jobs.ErrNotFound
	}
	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()

	current, encoded, err := repository.readEncodedLocked(id)
	if err != nil {
		return Record{}, err
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}

	switch current.Job.Status {
	case jobs.StatusQueued, jobs.StatusRunning:
		if current.Job.CancellationRequested {
			return current, nil
		}
		if !sameETag(current.ETag, expectedETag) {
			return Record{}, jobs.ErrConflict
		}
		if err := contextErr(ctx); err != nil {
			return Record{}, err
		}
		replacement, err := cancellationReplacement(encoded)
		if err != nil {
			return Record{}, err
		}
		if err := contextErr(ctx); err != nil {
			return Record{}, err
		}
		// All caller-gated work is complete before this descriptor-relative CAS
		// begins. The statefs write is not cancellable, so its result remains
		// authoritative if ctx is canceled concurrently. The replacement keeps
		// the original validated bytes except for this flag; scheduler-owned
		// callers separately require canonical bytes before accepting the result.
		if err := repository.store.WriteAtomicIfMatch(jobPath(id), replacement, expectedETag); err != nil {
			switch {
			case errors.Is(err, statefs.ErrETagMismatch):
				return Record{}, jobs.ErrConflict
			case errors.Is(err, statefs.ErrNotFound):
				return Record{}, jobs.ErrNotFound
			default:
				return Record{}, err
			}
		}
		requested := current.Job
		requested.CancellationRequested = true
		return Record{Job: requested, ETag: etag(replacement)}, nil
	case jobs.StatusCanceled:
		if current.Job.CancellationRequested {
			return current, nil
		}
		return Record{}, jobs.ErrCancellationUnsupported
	default:
		return Record{}, jobs.ErrCancellationUnsupported
	}
}

// Interrupt performs the exceptional queued/running to interrupted recovery
// transition. It validates the caller-provided finish time and failure code as
// part of the replacement state document, preserves every existing job field
// other than status/finish/failure, and uses the expected ETag for CAS. It
// never changes cancellationRequested and never writes terminal records.
func (repository *FileRepository) Interrupt(ctx context.Context, id string, expectedETag string, finishedAt time.Time, failureCode jobrecovery.FailureCode) (Record, error) {
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if !jobIDPattern.MatchString(id) {
		return Record{}, jobs.ErrNotFound
	}
	if err := state.ValidateJobInterruption(finishedAt, string(failureCode)); err != nil {
		return Record{}, err
	}

	if err := repository.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer repository.release()
	current, err := repository.readLocked(id)
	if err != nil {
		return Record{}, err
	}
	if !sameETag(current.ETag, expectedETag) {
		return Record{}, jobs.ErrConflict
	}
	return repository.interruptRecordLocked(current, finishedAt, failureCode)
}

// Recover takes one coherent, bounded snapshot of the jobs directory, fully
// decodes and classifies it before the first mutation, then CAS-interrupts
// every queued/running record. Terminal records are not rewritten. The caller
// supplies one UTC timestamp so every interruption in a pass has the exact
// same finish time. A non-nil error invalidates the returned summary; callers
// can safely retry because completed interruptions are terminal and preserved
// by the next pass.
func (repository *FileRepository) Recover(ctx context.Context, finishedAt time.Time) (RecoverySummary, error) {
	if err := contextErr(ctx); err != nil {
		return RecoverySummary{}, recoveryContextError(err)
	}
	if err := validateRecoveryTimestamp(finishedAt); err != nil {
		return RecoverySummary{}, errors.Join(ErrRecovery, ErrInvalidRecoveryTimestamp)
	}
	if err := repository.acquire(ctx); err != nil {
		return RecoverySummary{}, recoveryContextError(err)
	}
	defer repository.release()

	documents, err := repository.store.ReadDocuments(statefs.JobsDir, MaxRecordsScan, MaxTotalBytes)
	if err != nil {
		return RecoverySummary{}, mapRecoverySnapshotError(err)
	}
	if err := contextErr(ctx); err != nil {
		return RecoverySummary{}, recoveryContextError(err)
	}

	type candidate struct {
		name         string
		expectedETag string
		replacement  []byte
	}
	candidates := make([]candidate, 0, len(documents))
	summary := RecoverySummary{Examined: len(documents)}
	for _, document := range documents {
		if err := contextErr(ctx); err != nil {
			return RecoverySummary{}, recoveryContextError(err)
		}
		id := strings.TrimSuffix(document.Name, ".json")
		record, decodeErr := decodeRecord(id, document.Data)
		if decodeErr != nil {
			return RecoverySummary{}, mapRecoverySnapshotError(decodeErr)
		}
		decision, classifyErr := jobrecovery.ClassifyJob(record.Job)
		if classifyErr != nil {
			return RecoverySummary{}, errors.Join(ErrRecovery, ErrRecoveryCorrupt)
		}
		switch decision.Action {
		case jobrecovery.ActionPreserve:
			summary.Preserved++
		case jobrecovery.ActionInterrupt:
			replacement, encodeErr := interruptionReplacement(record.Job, finishedAt, decision.FailureCode)
			if encodeErr != nil {
				return RecoverySummary{}, errors.Join(ErrRecovery, ErrRecoveryCorrupt)
			}
			candidates = append(candidates, candidate{name: document.Name, expectedETag: record.ETag, replacement: replacement})
		default:
			return RecoverySummary{}, errors.Join(ErrRecovery, ErrRecoveryCorrupt)
		}
	}

	// All decoding, validation, policy classification, and replacement encoding
	// above precede the first write. CAS remains the authority if another
	// repository changes or removes a file after this snapshot.
	if err := contextErr(ctx); err != nil {
		return RecoverySummary{}, recoveryContextError(err)
	}
	for _, item := range candidates {
		if err := contextErr(ctx); err != nil {
			return RecoverySummary{}, recoveryContextError(err)
		}
		if repository.recoveryBeforeWrite != nil {
			repository.recoveryBeforeWrite()
		}
		if err := repository.store.WriteAtomicIfMatch(jobPath(strings.TrimSuffix(item.name, ".json")), item.replacement, item.expectedETag); err != nil {
			return RecoverySummary{}, mapRecoveryMutationError(err)
		}
		summary.Interrupted++
	}
	if err := contextErr(ctx); err != nil {
		return RecoverySummary{}, recoveryContextError(err)
	}
	return summary, nil
}

func (repository *FileRepository) interruptRecordLocked(current Record, finishedAt time.Time, failureCode jobrecovery.FailureCode) (Record, error) {
	decision, policyErr := jobrecovery.ClassifyJob(current.Job)
	if policyErr != nil {
		return Record{}, statefs.ErrCorrupt
	}
	if decision.Action != jobrecovery.ActionInterrupt {
		return Record{}, jobs.ErrInvalidTransition
	}
	if failureCode != decision.FailureCode {
		return Record{}, jobrecovery.ErrInvalidFailureCode
	}
	encoded, err := interruptionReplacement(current.Job, finishedAt, failureCode)
	if err != nil {
		return Record{}, err
	}
	if err := repository.store.WriteAtomicIfMatch(jobPath(current.Job.ID), encoded, current.ETag); err != nil {
		switch {
		case errors.Is(err, statefs.ErrETagMismatch):
			return Record{}, jobs.ErrConflict
		case errors.Is(err, statefs.ErrNotFound):
			return Record{}, jobs.ErrNotFound
		default:
			return Record{}, err
		}
	}
	return Record{Job: interruptedJob(current.Job, finishedAt, failureCode), ETag: etag(encoded)}, nil
}

func interruptionReplacement(current state.Job, finishedAt time.Time, failureCode jobrecovery.FailureCode) ([]byte, error) {
	replacement := interruptedJob(current, finishedAt, failureCode)
	return state.EncodeJob(replacement)
}

func interruptedJob(current state.Job, finishedAt time.Time, failureCode jobrecovery.FailureCode) state.Job {
	replacement := current
	replacement.Status = jobs.StatusInterrupted
	finish := finishedAt
	replacement.FinishedAt = &finish
	replacement.FailureCode = string(failureCode)
	return replacement
}

func validateRecoveryTimestamp(value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC || value.After(time.Now().UTC()) {
		return ErrInvalidRecoveryTimestamp
	}
	return nil
}

func recoveryContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.Join(ErrRecovery, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrRecovery, context.DeadlineExceeded)
	}
	return ErrRecovery
}

func mapRecoveryMutationError(err error) error {
	switch {
	case errors.Is(err, statefs.ErrETagMismatch), errors.Is(err, statefs.ErrNotFound):
		return errors.Join(ErrRecovery, ErrRecoveryConflict)
	case errors.Is(err, statefs.ErrCorrupt):
		return errors.Join(ErrRecovery, ErrRecoveryCorrupt, statefs.ErrCorrupt)
	case errors.Is(err, statefs.ErrFileUnavailable), errors.Is(err, statefs.ErrUnexpectedEntry), errors.Is(err, statefs.ErrDocumentTooLarge), errors.Is(err, statefs.ErrSymlink), errors.Is(err, statefs.ErrNotRegular), errors.Is(err, statefs.ErrHardLinked), errors.Is(err, statefs.ErrUnsafeFile), errors.Is(err, statefs.ErrUnsafePermissions), errors.Is(err, statefs.ErrUnsafeOwnership):
		return errors.Join(ErrRecovery, ErrRecoveryCorrupt)
	default:
		return ErrRecovery
	}
}

func mapRecoverySnapshotError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return recoveryContextError(context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return recoveryContextError(context.DeadlineExceeded)
	case errors.Is(err, statefs.ErrTooManyDocuments), errors.Is(err, statefs.ErrAggregateTooLarge):
		return errors.Join(ErrRecovery, ErrRecoveryScanLimit)
	case errors.Is(err, statefs.ErrCorrupt):
		return errors.Join(ErrRecovery, ErrRecoveryCorrupt, statefs.ErrCorrupt)
	case errors.Is(err, statefs.ErrFileUnavailable), errors.Is(err, statefs.ErrUnexpectedEntry), errors.Is(err, statefs.ErrDocumentTooLarge), errors.Is(err, statefs.ErrSymlink), errors.Is(err, statefs.ErrNotRegular), errors.Is(err, statefs.ErrHardLinked), errors.Is(err, statefs.ErrUnsafeFile), errors.Is(err, statefs.ErrUnsafePermissions), errors.Is(err, statefs.ErrUnsafeOwnership):
		return errors.Join(ErrRecovery, ErrRecoveryCorrupt)
	default:
		return ErrRecovery
	}
}

// List returns a complete, strictly decoded snapshot of the bounded jobs
// directory, filtered and ordered by creation time then ID. Page tokens are
// filter-scoped keyset cursors bound to a digest of the ordered filtered
// record IDs and ETags; a changed snapshot is never silently paged through.
func (repository *FileRepository) List(ctx context.Context, options jobs.ListOptions) (Page, error) {
	if err := contextErr(ctx); err != nil {
		return Page{}, err
	}
	filters, pageSize, err := normalizeOptions(options)
	if err != nil {
		return Page{}, err
	}
	cursor, err := decodePageToken(options.PageToken, filters.scope)
	if err != nil {
		return Page{}, err
	}

	if err := repository.acquire(ctx); err != nil {
		return Page{}, err
	}
	defer repository.release()
	documents, err := repository.store.ReadDocuments(statefs.JobsDir, MaxRecordsScan, MaxTotalBytes)
	if err != nil {
		if errors.Is(err, statefs.ErrTooManyDocuments) || errors.Is(err, statefs.ErrAggregateTooLarge) {
			return Page{}, fmt.Errorf("%w: %w", ErrScanLimit, err)
		}
		return Page{}, err
	}

	all := make([]Record, 0, len(documents))
	for _, document := range documents {
		id := strings.TrimSuffix(document.Name, ".json")
		record, readErr := decodeRecord(id, document.Data)
		if readErr != nil {
			return Page{}, readErr
		}
		if record.Job.ID != id {
			// A valid document under the wrong controlled filename is not a
			// second record; it is corruption and is never silently skipped.
			return Page{}, statefs.ErrCorrupt
		}
		if !matches(record.Job, filters) {
			continue
		}
		all = append(all, record)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].Job.CreatedAt.Equal(all[j].Job.CreatedAt) {
			return all[i].Job.CreatedAt.Before(all[j].Job.CreatedAt)
		}
		return all[i].Job.ID < all[j].Job.ID
	})

	digest := filteredSnapshotDigest(all)
	if cursor != nil && !sameETag(cursor.SnapshotDigest, digest) {
		return Page{}, ErrPageChanged
	}
	if cursor != nil && !containsCursor(all, cursor) {
		return Page{}, ErrInvalidPageToken
	}
	start := 0
	if cursor != nil {
		for start < len(all) && !after(all[start].Job, cursor) {
			start++
		}
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	records := make([]Record, end-start)
	copy(records, all[start:end])
	page := Page{Records: records}
	if end < len(all) {
		page.NextPageToken, err = encodePageToken(all[end-1], filters.scope, digest)
		if err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

type normalizedFilters struct {
	types    []jobs.Type
	statuses []jobs.Status
	scope    string
}

func normalizeOptions(options jobs.ListOptions) (normalizedFilters, int, error) {
	if options.PageSize < 0 || options.PageSize > MaxPageSize {
		return normalizedFilters{}, 0, fmt.Errorf("%w: page size must be between 1 and %d", ErrInvalidOptions, MaxPageSize)
	}
	pageSize := options.PageSize
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	types, err := normalizeTypes(options.Types)
	if err != nil {
		return normalizedFilters{}, 0, err
	}
	statuses, err := normalizeStatuses(options.Statuses)
	if err != nil {
		return normalizedFilters{}, 0, err
	}
	return normalizedFilters{types: types, statuses: statuses, scope: filterScope(types, statuses)}, pageSize, nil
}

func normalizeTypes(values []jobs.Type) ([]jobs.Type, error) {
	if len(values) > 16 {
		return nil, fmt.Errorf("%w: too many job type filters", ErrInvalidOptions)
	}
	result := append([]jobs.Type(nil), values...)
	for _, value := range result {
		if !value.Valid() {
			return nil, fmt.Errorf("%w: unsupported job type filter", ErrInvalidOptions)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return uniqueTypes(result), nil
}

func normalizeStatuses(values []jobs.Status) ([]jobs.Status, error) {
	if len(values) > 16 {
		return nil, fmt.Errorf("%w: too many job status filters", ErrInvalidOptions)
	}
	result := append([]jobs.Status(nil), values...)
	for _, value := range result {
		if !value.Valid() {
			return nil, fmt.Errorf("%w: unsupported job status filter", ErrInvalidOptions)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return uniqueStatuses(result), nil
}

func uniqueTypes(values []jobs.Type) []jobs.Type {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func uniqueStatuses(values []jobs.Status) []jobs.Status {
	if len(values) == 0 {
		return nil
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func filterScope(types []jobs.Type, statuses []jobs.Status) string {
	hash := sha256.New()
	hash.Write([]byte("elastic-maintainer/jobrecord-page/v1\x00"))
	hash.Write([]byte("types\x00"))
	for _, value := range types {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	hash.Write([]byte("statuses\x00"))
	for _, value := range statuses {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func matches(job state.Job, filters normalizedFilters) bool {
	if len(filters.types) != 0 && !containsType(filters.types, job.Type) {
		return false
	}
	if len(filters.statuses) != 0 && !containsStatus(filters.statuses, job.Status) {
		return false
	}
	return true
}

func containsType(values []jobs.Type, target jobs.Type) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsStatus(values []jobs.Status, target jobs.Status) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type cursor struct {
	CreatedAt      time.Time
	ID             string
	ETag           string
	SnapshotDigest string
}

type encodedCursor struct {
	Version        string `json:"version"`
	Scope          string `json:"scope"`
	CreatedAt      string `json:"createdAt"`
	ID             string `json:"id"`
	ETag           string `json:"etag"`
	SnapshotDigest string `json:"snapshotDigest"`
}

func encodePageToken(record Record, scope, snapshotDigest string) (string, error) {
	value := encodedCursor{
		Version:        "v2",
		Scope:          scope,
		CreatedAt:      record.Job.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID:             record.Job.ID,
		ETag:           record.ETag,
		SnapshotDigest: snapshotDigest,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalidPageToken
	}
	token := base64.RawURLEncoding.EncodeToString(encoded)
	if len(token) > maxPageTokenLen {
		return "", ErrInvalidPageToken
	}
	return token, nil
}

func decodePageToken(token, scope string) (*cursor, error) {
	if token == "" {
		return nil, nil
	}
	if len(token) > maxPageTokenLen {
		return nil, ErrInvalidPageToken
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(encoded) == 0 {
		return nil, ErrInvalidPageToken
	}
	var value encodedCursor
	if !decodeCursorJSON(encoded, &value) {
		return nil, ErrInvalidPageToken
	}
	if value.Version != "v2" || len(value.Scope) != sha256.Size*2 || subtle.ConstantTimeCompare([]byte(value.Scope), []byte(scope)) != 1 {
		return nil, ErrInvalidPageToken
	}
	if !isLowerHexDigest(value.ETag) || !isLowerHexDigest(value.SnapshotDigest) {
		return nil, ErrInvalidPageToken
	}
	if !jobIDPattern.MatchString(value.ID) {
		return nil, ErrInvalidPageToken
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.CreatedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value.CreatedAt {
		return nil, ErrInvalidPageToken
	}
	return &cursor{CreatedAt: parsed, ID: value.ID, ETag: value.ETag, SnapshotDigest: value.SnapshotDigest}, nil
}

func decodeCursorJSON(encoded []byte, destination *encodedCursor) bool {
	// Scan object keys separately because encoding/json's strict decoder
	// rejects unknown fields but accepts duplicate ones. State records reject
	// duplicates, so page tokens do as well.
	scanner := json.NewDecoder(bytes.NewReader(encoded))
	first, err := scanner.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	allowed := map[string]struct{}{"version": {}, "scope": {}, "createdAt": {}, "id": {}, "etag": {}, "snapshotDigest": {}}
	seen := make(map[string]struct{}, len(allowed))
	for scanner.More() {
		key, err := scanner.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return false
		}
		if _, allowed := allowed[name]; !allowed {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		seen[name] = struct{}{}
		var raw json.RawMessage
		if err := scanner.Decode(&raw); err != nil {
			return false
		}
	}
	if end, err := scanner.Token(); err != nil || end != json.Delim('}') {
		return false
	}
	var extra any
	if err := scanner.Decode(&extra); err != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	return decoder.Decode(&extra) == io.EOF
}

func after(job state.Job, value *cursor) bool {
	return job.CreatedAt.After(value.CreatedAt) || (job.CreatedAt.Equal(value.CreatedAt) && job.ID > value.ID)
}

func containsCursor(records []Record, value *cursor) bool {
	for _, record := range records {
		if record.Job.ID == value.ID && record.Job.CreatedAt.Equal(value.CreatedAt) && sameETag(record.ETag, value.ETag) {
			return true
		}
	}
	return false
}

func filteredSnapshotDigest(records []Record) string {
	hash := sha256.New()
	hash.Write([]byte("elastic-maintainer/jobrecord-snapshot/v1\x00"))
	for _, record := range records {
		hash.Write([]byte(fmt.Sprintf("%d:", len(record.Job.ID))))
		hash.Write([]byte(record.Job.ID))
		hash.Write([]byte(fmt.Sprintf("%d:", len(record.ETag))))
		hash.Write([]byte(record.ETag))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func isLowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func (repository *FileRepository) readLocked(id string) (Record, error) {
	record, _, err := repository.readEncodedLocked(id)
	return record, err
}

func (repository *FileRepository) readEncodedLocked(id string) (Record, []byte, error) {
	encoded, err := repository.store.Read(jobPath(id))
	if err != nil {
		if errors.Is(err, statefs.ErrNotFound) {
			return Record{}, nil, jobs.ErrNotFound
		}
		return Record{}, nil, err
	}
	record, err := decodeRecord(id, encoded)
	if err != nil {
		return Record{}, nil, err
	}
	return record, encoded, nil
}

func decodeRecord(id string, encoded []byte) (Record, error) {
	job, err := state.DecodeJob(encoded)
	if err != nil {
		// Do not include decoder diagnostics: a corrupt file may contain
		// attacker-controlled or sensitive text, while the package only needs
		// to report that the durable record is unusable.
		return Record{}, statefs.ErrCorrupt
	}
	if job.ID != id {
		return Record{}, statefs.ErrCorrupt
	}
	if err := validatePersistedJob(job); err != nil {
		return Record{}, statefs.ErrCorrupt
	}
	return Record{Job: job, ETag: etag(encoded)}, nil
}

func jobPath(id string) string { return statefs.JobsDir + "/" + id + ".json" }

// cancellationReplacement changes only the root cancellationRequested value
// in the already validated document. Keeping the original bytes avoids
// needlessly reformatting or re-encoding every immutable field.
func cancellationReplacement(encoded []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, statefs.ErrCorrupt
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, statefs.ErrCorrupt
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, statefs.ErrCorrupt
		}
		keyEnd := decoder.InputOffset()
		if key == "cancellationRequested" {
			valueStart := jsonValueStart(encoded, keyEnd)
			valueToken, err := decoder.Token()
			valueEnd := decoder.InputOffset()
			value, ok := valueToken.(bool)
			if err != nil || !ok || value || valueStart < 0 || valueEnd < int64(valueStart) || int(valueEnd) > len(encoded) || !bytes.Equal(encoded[valueStart:int(valueEnd)], []byte("false")) {
				return nil, statefs.ErrCorrupt
			}
			replacement := make([]byte, 0, len(encoded)+1)
			replacement = append(replacement, encoded[:valueStart]...)
			replacement = append(replacement, "true"...)
			replacement = append(replacement, encoded[valueEnd:]...)
			return replacement, nil
		}
		if err := skipJSONValue(decoder); err != nil {
			return nil, statefs.ErrCorrupt
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, statefs.ErrCorrupt
	}
	insertAt := int(decoder.InputOffset()) - 1
	if insertAt < 0 || insertAt >= len(encoded) || encoded[insertAt] != '}' {
		return nil, statefs.ErrCorrupt
	}
	replacement := make([]byte, 0, len(encoded)+len(`,"cancellationRequested":true`))
	replacement = append(replacement, encoded[:insertAt]...)
	replacement = append(replacement, `,"cancellationRequested":true`...)
	replacement = append(replacement, encoded[insertAt:]...)
	return replacement, nil
}

func jsonValueStart(encoded []byte, keyEnd int64) int {
	position := int(keyEnd)
	if position < 0 || position > len(encoded) {
		return -1
	}
	for position < len(encoded) && isJSONWhitespace(encoded[position]) {
		position++
	}
	if position >= len(encoded) || encoded[position] != ':' {
		return -1
	}
	position++
	for position < len(encoded) && isJSONWhitespace(encoded[position]) {
		position++
	}
	return position
}

func isJSONWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || (delimiter != '{' && delimiter != '[') {
		return nil
	}
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			if _, ok := key.(string); !ok {
				return errors.New("object key is not a string")
			}
		}
		if err := skipJSONValue(decoder); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != json.Delim(map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]) {
		return errors.New("JSON value is not closed")
	}
	return nil
}

func etag(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func sameETag(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sameImmutableFields(left, right state.Job) bool {
	return left.ID == right.ID &&
		left.Type == right.Type &&
		left.CreatedAt.Equal(right.CreatedAt) &&
		left.Actor.Subject == right.Actor.Subject &&
		left.Actor.Method == right.Actor.Method &&
		sameRoles(left.Actor.Roles, right.Actor.Roles) &&
		left.RequestID == right.RequestID &&
		left.IdempotencyKey == right.IdempotencyKey &&
		left.RequestDigest == right.RequestDigest
}

func validateAppendOnlyFields(current, replacement state.Job) error {
	if current.Status == jobs.StatusQueued && replacement.Status == jobs.StatusCanceled && replacement.StartedAt != nil {
		return jobs.ErrInvalidTransition
	}
	if current.StartedAt != nil && !sameTime(current.StartedAt, replacement.StartedAt) {
		return ErrImmutableChange
	}
	if current.PlanID != "" {
		if replacement.PlanID != current.PlanID {
			return ErrImmutableChange
		}
	} else if replacement.PlanID != "" && !canEstablishPlanID(current, replacement) {
		return ErrImmutableChange
	}
	if current.ReportID != "" {
		if replacement.ReportID != current.ReportID {
			return ErrImmutableChange
		}
	} else if replacement.ReportID != "" && (replacement.Type != jobs.TypeApply || !isTerminal(replacement.Status)) {
		return ErrImmutableChange
	}
	if current.CancellationRequested && !replacement.CancellationRequested {
		return ErrImmutableChange
	}
	return nil
}

func canEstablishPlanID(current, replacement state.Job) bool {
	return replacement.Type == jobs.TypePlan && replacement.Status == jobs.StatusSucceeded
}

func validatePersistedJob(job state.Job) error {
	switch job.Type {
	case jobs.TypeApply:
		if job.PlanID == "" {
			return ErrImmutableChange
		}
		if job.ReportID != "" && !isTerminal(job.Status) {
			return ErrImmutableChange
		}
	case jobs.TypePlan:
		if job.PlanID != "" && job.Status != jobs.StatusSucceeded {
			return ErrImmutableChange
		}
		if job.ReportID != "" {
			return ErrImmutableChange
		}
	case jobs.TypeValidation, jobs.TypeTargetInventory:
		if job.PlanID != "" || job.ReportID != "" {
			return ErrImmutableChange
		}
	}
	return nil
}

func validateInitialLinks(job state.Job) error {
	if err := validatePersistedJob(job); err != nil {
		return err
	}
	if job.CancellationRequested || job.ReportID != "" {
		return ErrImmutableChange
	}
	return nil
}

func isTerminal(status jobs.Status) bool {
	return status == jobs.StatusSucceeded || status == jobs.StatusFailed || status == jobs.StatusCanceled || status == jobs.StatusInterrupted
}

func sameTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func sameRoles(left, right []auth.Role) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
