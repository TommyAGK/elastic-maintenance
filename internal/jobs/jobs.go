package jobs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotImplemented          = errors.New("job execution is not implemented")
	ErrNotFound                = errors.New("job not found")
	ErrConflict                = errors.New("job conflict")
	ErrInvalidTransition       = errors.New("invalid job status transition")
	ErrCancellationUnsupported = errors.New("job cancellation is not supported")
	ErrQueueFull               = errors.New("job queue is full")
	ErrQueueClosed             = errors.New("job queue is closed")

	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	jobIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	codePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

type Type string

const (
	TypeValidation      Type = "validation"
	TypePlan            Type = "plan"
	TypeApply           Type = "apply"
	TypeTargetInventory Type = "target-inventory"
)

type Status string

const (
	StatusQueued      Status = "queued"
	StatusRunning     Status = "running"
	StatusSucceeded   Status = "succeeded"
	StatusFailed      Status = "failed"
	StatusCanceled    Status = "canceled"
	StatusInterrupted Status = "interrupted"
)

type Job struct {
	ID             string     `json:"id"`
	Type           Type       `json:"type"`
	Status         Status     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
	ActorSubject   string     `json:"actorSubject"`
	RequestID      string     `json:"requestId"`
	IdempotencyKey string     `json:"-"`
	RequestDigest  string     `json:"-"`
	FailureCode    string     `json:"failureCode,omitempty"`
}

func (job Job) Terminal() bool {
	return job.Status == StatusSucceeded || job.Status == StatusFailed || job.Status == StatusCanceled || job.Status == StatusInterrupted
}

func (job Job) Validate() error {
	if !jobIDPattern.MatchString(job.ID) {
		return errors.New("job ID is invalid")
	}
	if !job.Type.Valid() {
		return errors.New("job type is invalid")
	}
	if !job.Status.Valid() {
		return errors.New("job status is invalid")
	}
	if job.CreatedAt.IsZero() {
		return errors.New("job creation time is required")
	}
	if strings.TrimSpace(job.ActorSubject) == "" {
		return errors.New("job actor subject is required")
	}
	if !codePattern.MatchString(job.RequestID) {
		return errors.New("job request ID is invalid")
	}
	if err := ValidateIdempotencyKey(job.IdempotencyKey); err != nil {
		return err
	}
	if !digestPattern.MatchString(job.RequestDigest) {
		return errors.New("job request digest must be lowercase SHA-256")
	}
	if job.Status == StatusQueued && (job.StartedAt != nil || job.FinishedAt != nil) {
		return errors.New("queued job must not have start or finish times")
	}
	if job.Status == StatusRunning && job.StartedAt == nil {
		return errors.New("running job requires a start time")
	}
	if job.Terminal() && job.FinishedAt == nil {
		return errors.New("terminal job requires a finish time")
	}
	if job.StartedAt != nil && job.StartedAt.Before(job.CreatedAt) {
		return errors.New("job start time precedes creation time")
	}
	if job.FinishedAt != nil && job.FinishedAt.Before(job.CreatedAt) {
		return errors.New("job finish time precedes creation time")
	}
	if job.StartedAt != nil && job.FinishedAt != nil && job.FinishedAt.Before(*job.StartedAt) {
		return errors.New("job finish time precedes start time")
	}
	if job.FailureCode != "" && !codePattern.MatchString(job.FailureCode) {
		return errors.New("job failure code is invalid")
	}
	if (job.Status == StatusFailed || job.Status == StatusInterrupted) && job.FailureCode == "" {
		return errors.New("failed or interrupted job requires a failure code")
	}
	if (job.Status == StatusQueued || job.Status == StatusRunning || job.Status == StatusSucceeded || job.Status == StatusCanceled) && job.FailureCode != "" {
		return errors.New("non-failed job must not have a failure code")
	}
	return nil
}

func (jobType Type) Valid() bool {
	return jobType == TypeValidation || jobType == TypePlan || jobType == TypeApply || jobType == TypeTargetInventory
}

func (status Status) Valid() bool {
	return status == StatusQueued || status == StatusRunning || status == StatusSucceeded || status == StatusFailed || status == StatusCanceled || status == StatusInterrupted
}

func CanTransition(from, to Status) bool {
	switch from {
	case StatusQueued:
		return to == StatusRunning || to == StatusCanceled
	case StatusRunning:
		return to == StatusSucceeded || to == StatusFailed || to == StatusCanceled || to == StatusInterrupted
	default:
		return false
	}
}

type NewJobInput struct {
	Type           Type
	ActorSubject   string
	RequestID      string
	IdempotencyKey string
	RequestDigest  string
}

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (function ClockFunc) Now() time.Time { return function() }

type IDGenerator interface {
	NewJobID(Type) (string, error)
}

type IDGeneratorFunc func(Type) (string, error)

func (function IDGeneratorFunc) NewJobID(jobType Type) (string, error) { return function(jobType) }

func NewQueued(input NewJobInput, clock Clock, generator IDGenerator) (Job, error) {
	if clock == nil {
		return Job{}, errors.New("job clock is required")
	}
	if generator == nil {
		return Job{}, errors.New("job ID generator is required")
	}
	if !input.Type.Valid() {
		return Job{}, errors.New("job type is invalid")
	}
	if err := ValidateIdempotencyKey(input.IdempotencyKey); err != nil {
		return Job{}, err
	}
	if !digestPattern.MatchString(input.RequestDigest) {
		return Job{}, errors.New("job request digest must be lowercase SHA-256")
	}
	id, err := generator.NewJobID(input.Type)
	if err != nil {
		return Job{}, fmt.Errorf("generate job ID: %w", err)
	}
	job := Job{
		ID:             id,
		Type:           input.Type,
		Status:         StatusQueued,
		CreatedAt:      clock.Now().UTC(),
		ActorSubject:   strings.TrimSpace(input.ActorSubject),
		RequestID:      strings.TrimSpace(input.RequestID),
		IdempotencyKey: input.IdempotencyKey,
		RequestDigest:  input.RequestDigest,
	}
	if err := job.Validate(); err != nil {
		return Job{}, err
	}
	return job, nil
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

func ValidateIdempotencyKey(value string) error {
	if !idempotencyKeyPattern.MatchString(value) {
		return errors.New("idempotency key must be 8-128 safe ASCII characters")
	}
	return nil
}

type EnqueueRequest struct {
	Type           Type
	ActorSubject   string
	RequestID      string
	IdempotencyKey string
	RequestDigest  string
}

type ListOptions struct {
	Types     []Type
	Statuses  []Status
	PageSize  int
	PageToken string
}

type Page struct {
	Jobs          []Job  `json:"jobs"`
	NextPageToken string `json:"nextPageToken,omitempty"`
}

type CancellationRequest struct {
	JobID        string
	ActorSubject string
	RequestID    string
}

type Queue interface {
	Enqueue(context.Context, EnqueueRequest) (Job, error)
	Get(context.Context, string) (Job, error)
	List(context.Context, ListOptions) (Page, error)
	RequestCancellation(context.Context, CancellationRequest) (Job, error)
}

type CancellationPolicy interface {
	CanCancel(Job) bool
}

type UnavailableQueue struct{}

func (UnavailableQueue) Enqueue(context.Context, EnqueueRequest) (Job, error) {
	return Job{}, ErrNotImplemented
}

func (UnavailableQueue) Get(context.Context, string) (Job, error) {
	return Job{}, ErrNotImplemented
}

func (UnavailableQueue) List(context.Context, ListOptions) (Page, error) {
	return Page{}, ErrNotImplemented
}

func (UnavailableQueue) RequestCancellation(context.Context, CancellationRequest) (Job, error) {
	return Job{}, ErrNotImplemented
}
