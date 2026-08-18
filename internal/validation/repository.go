package validation

import (
	"context"
	"encoding/json"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
)

type Selection struct {
	ResourceSetIDs []string `json:"resourceSetIds,omitempty"`
	TargetIDs      []string `json:"targetIds,omitempty"`
}

type Record struct {
	Job                   jobs.Job  `json:"job"`
	Selection             Selection `json:"selection"`
	Result                *Result   `json:"result,omitempty"`
	CancellationRequested bool      `json:"cancellationRequested,omitempty"`
	Version               uint64    `json:"version"`
}

type storedRecord struct {
	Job                   jobs.Job  `json:"job"`
	IdempotencyKey        string    `json:"idempotencyKey"`
	RequestDigest         string    `json:"requestDigest"`
	Selection             Selection `json:"selection"`
	Result                *Result   `json:"result,omitempty"`
	CancellationRequested bool      `json:"cancellationRequested,omitempty"`
	Version               uint64    `json:"version"`
}

func EncodeStoredRecord(record Record) ([]byte, error) {
	return json.Marshal(storedRecord{Job: record.Job, IdempotencyKey: record.Job.IdempotencyKey, RequestDigest: record.Job.RequestDigest, Selection: record.Selection, Result: record.Result, CancellationRequested: record.CancellationRequested, Version: record.Version})
}

func DecodeStoredRecord(encoded []byte) (Record, error) {
	var stored storedRecord
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return Record{}, err
	}
	stored.Job.IdempotencyKey, stored.Job.RequestDigest = stored.IdempotencyKey, stored.RequestDigest
	return Record{Job: stored.Job, Selection: stored.Selection, Result: stored.Result, CancellationRequested: stored.CancellationRequested, Version: stored.Version}, nil
}

type RecordPage struct {
	Records       []Record `json:"records"`
	NextPageToken string   `json:"nextPageToken,omitempty"`
}

type Repository interface {
	FindByIdempotency(context.Context, string, string) (Record, error)
	Create(context.Context, Record) (Record, bool, error)
	Get(context.Context, string) (Record, error)
	Put(context.Context, Record, uint64) (Record, error)
	List(context.Context, jobs.ListOptions) (RecordPage, error)
}
