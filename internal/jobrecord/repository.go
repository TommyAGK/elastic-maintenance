// Package jobrecord provides durable persistence for the versioned job
// projection. It owns job-file concurrency and pagination, but deliberately
// does not execute, recover, schedule, or expose jobs over HTTP.
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

	jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Record is a validated durable job and the SHA-256 ETag of its stored strict
// JSON bytes. Repository writes are canonical, and content-derived ETags are
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

// Repository is the durable job-record contract. Create and Put accept the
// state projection rather than Record so callers cannot manufacture an ETag.
type Repository interface {
	Create(context.Context, state.Job) (Record, error)
	Get(context.Context, string) (Record, error)
	Put(context.Context, string, state.Job, string) (Record, error)
	List(context.Context, jobs.ListOptions) (Page, error)
}

// FileRepository stores exactly one strict state.Job document in the statefs
// jobs directory. Its context-aware gate serializes each operation, including
// a complete List, relative to other operations on this instance; Store's
// mutex provides the shared-store serialization needed by CAS writes.
type FileRepository struct {
	gate  chan struct{}
	store *statefs.Store
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
// requires one of jobs.CanTransition's existing status transitions. Same-status
// cancellation mutation belongs to the later cancellation increment.
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
	if !jobs.CanTransition(current.Job.Status, replacement.Status) {
		return Record{}, jobs.ErrInvalidTransition
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
	encoded, err := repository.store.Read(jobPath(id))
	if err != nil {
		if errors.Is(err, statefs.ErrNotFound) {
			return Record{}, jobs.ErrNotFound
		}
		return Record{}, err
	}
	return decodeRecord(id, encoded)
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
