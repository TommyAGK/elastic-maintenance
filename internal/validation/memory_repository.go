package validation

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
)

type MemoryRepository struct {
	mu          sync.RWMutex
	records     map[string]Record
	idempotency map[string]string
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: make(map[string]Record), idempotency: make(map[string]string)}
}

func (repository *MemoryRepository) FindByIdempotency(_ context.Context, actor, key string) (Record, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	id := repository.idempotency[idempotencyIndex(actor, key)]
	if id == "" {
		return Record{}, jobs.ErrNotFound
	}
	return cloneRecord(repository.records[id])
}

func (repository *MemoryRepository) Create(_ context.Context, record Record) (Record, bool, error) {
	if err := record.Job.Validate(); err != nil {
		return Record{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	index := idempotencyIndex(record.Job.ActorSubject, record.Job.IdempotencyKey)
	if id := repository.idempotency[index]; id != "" {
		existing := repository.records[id]
		if existing.Job.RequestDigest != record.Job.RequestDigest {
			return Record{}, false, jobs.ErrConflict
		}
		copy, err := cloneRecord(existing)
		return copy, false, err
	}
	if _, exists := repository.records[record.Job.ID]; exists {
		return Record{}, false, jobs.ErrConflict
	}
	record.Version = 1
	copy, err := cloneRecord(record)
	if err != nil {
		return Record{}, false, err
	}
	repository.records[record.Job.ID] = copy
	repository.idempotency[index] = record.Job.ID
	result, err := cloneRecord(copy)
	return result, true, err
}

func (repository *MemoryRepository) Get(_ context.Context, id string) (Record, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	record, exists := repository.records[id]
	if !exists {
		return Record{}, jobs.ErrNotFound
	}
	return cloneRecord(record)
}

func (repository *MemoryRepository) Put(_ context.Context, record Record, expectedVersion uint64) (Record, error) {
	if err := record.Job.Validate(); err != nil {
		return Record{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.records[record.Job.ID]
	if !exists {
		return Record{}, jobs.ErrNotFound
	}
	if current.Version != expectedVersion {
		return Record{}, jobs.ErrConflict
	}
	if current.Job.ID != record.Job.ID || current.Job.Type != record.Job.Type || current.Job.ActorSubject != record.Job.ActorSubject || current.Job.RequestID != record.Job.RequestID || !current.Job.CreatedAt.Equal(record.Job.CreatedAt) || current.Job.IdempotencyKey != record.Job.IdempotencyKey || current.Job.RequestDigest != record.Job.RequestDigest || !reflect.DeepEqual(current.Selection, record.Selection) {
		return Record{}, errors.New("immutable job request fields changed")
	}
	if current.Job.Status != record.Job.Status && !jobs.CanTransition(current.Job.Status, record.Job.Status) {
		return Record{}, jobs.ErrInvalidTransition
	}
	if current.Job.Terminal() && current.Job.Status != record.Job.Status {
		return Record{}, jobs.ErrInvalidTransition
	}
	record.Version = expectedVersion + 1
	copy, err := cloneRecord(record)
	if err != nil {
		return Record{}, err
	}
	repository.records[record.Job.ID] = copy
	return cloneRecord(copy)
}

func (repository *MemoryRepository) List(_ context.Context, options jobs.ListOptions) (RecordPage, error) {
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	records := make([]Record, 0, len(repository.records))
	for _, record := range repository.records {
		if !matchesJobFilters(record.Job, options) {
			continue
		}
		copy, err := cloneRecord(record)
		if err != nil {
			return RecordPage{}, err
		}
		records = append(records, copy)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if !records[i].Job.CreatedAt.Equal(records[j].Job.CreatedAt) {
			return records[i].Job.CreatedAt.Before(records[j].Job.CreatedAt)
		}
		return records[i].Job.ID < records[j].Job.ID
	})
	start := 0
	if options.PageToken != "" {
		found := false
		for index := range records {
			if records[index].Job.ID == options.PageToken {
				start, found = index+1, true
				break
			}
		}
		if !found {
			return RecordPage{}, errors.New("invalid page token")
		}
	}
	pageSize := options.PageSize
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize < 1 || pageSize > 100 {
		return RecordPage{}, errors.New("page size must be between 1 and 100")
	}
	end := start + pageSize
	if end > len(records) {
		end = len(records)
	}
	page := RecordPage{Records: append([]Record{}, records[start:end]...)}
	if end < len(records) {
		page.NextPageToken = records[end-1].Job.ID
	}
	return page, nil
}

func idempotencyIndex(actor, key string) string { return actor + "\x00" + key }

func cloneRecord(record Record) (Record, error) {
	encoded, err := EncodeStoredRecord(record)
	if err != nil {
		return Record{}, err
	}
	return DecodeStoredRecord(encoded)
}

func matchesJobFilters(job jobs.Job, options jobs.ListOptions) bool {
	if len(options.Types) != 0 {
		matched := false
		for _, value := range options.Types {
			if job.Type == value {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(options.Statuses) != 0 {
		matched := false
		for _, value := range options.Statuses {
			if job.Status == value {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
