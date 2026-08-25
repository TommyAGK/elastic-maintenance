package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const fixtureDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewQueuedUsesInjectedClockAndIDGenerator(t *testing.T) {
	wantTime := time.Date(2026, 8, 14, 12, 30, 0, 0, time.FixedZone("test", 3600))
	var generatedFor Type
	job, err := NewQueued(NewJobInput{
		Type:           TypePlan,
		ActorSubject:   " operator-1 ",
		RequestID:      "request-1",
		IdempotencyKey: "plan-request-1",
		RequestDigest:  fixtureDigest,
	}, ClockFunc(func() time.Time { return wantTime }), IDGeneratorFunc(func(jobType Type) (string, error) {
		generatedFor = jobType
		return "plan-job-1", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if generatedFor != TypePlan || job.ID != "plan-job-1" || job.Type != TypePlan || job.Status != StatusQueued || job.ActorSubject != "operator-1" || !job.CreatedAt.Equal(wantTime.UTC()) {
		t.Fatalf("job = %#v, generatedFor = %q", job, generatedFor)
	}
	if err := job.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNewQueuedRejectsInvalidInputsBeforeGeneratingID(t *testing.T) {
	called := false
	generator := IDGeneratorFunc(func(Type) (string, error) {
		called = true
		return "job-1", nil
	})
	_, err := NewQueued(NewJobInput{
		Type:           TypePlan,
		ActorSubject:   "operator-1",
		RequestID:      "request-1",
		IdempotencyKey: "short",
		RequestDigest:  fixtureDigest,
	}, ClockFunc(time.Now), generator)
	if err == nil || called {
		t.Fatalf("error=%v generatorCalled=%v", err, called)
	}
}

func TestNewQueuedWrapsIDGeneratorFailure(t *testing.T) {
	want := errors.New("entropy unavailable")
	_, err := NewQueued(NewJobInput{
		Type:           TypeValidation,
		ActorSubject:   "operator-1",
		RequestID:      "request-1",
		IdempotencyKey: "validation-request-1",
		RequestDigest:  fixtureDigest,
	}, ClockFunc(time.Now), IDGeneratorFunc(func(Type) (string, error) { return "", want }))
	if !errors.Is(err, want) {
		t.Fatalf("NewQueued() error = %v", err)
	}
}

func TestJobTerminal(t *testing.T) {
	for status, want := range map[Status]bool{
		StatusQueued: false, StatusRunning: false,
		StatusSucceeded: true, StatusFailed: true, StatusCanceled: true, StatusInterrupted: true,
	} {
		if got := (Job{Status: status}).Terminal(); got != want {
			t.Errorf("status %q Terminal() = %v", status, got)
		}
	}
}

func TestJobValidateStatusInvariants(t *testing.T) {
	created := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	started := created.Add(time.Minute)
	finished := started.Add(time.Minute)
	base := Job{
		ID: "job-1", Type: TypePlan, Status: StatusSucceeded,
		CreatedAt: created, StartedAt: &started, FinishedAt: &finished,
		ActorSubject: "operator-1", RequestID: "request-1",
		IdempotencyKey: "plan-request-1", RequestDigest: fixtureDigest,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid job error = %v", err)
	}

	for name, change := range map[string]func(*Job){
		"unsafe ID":            func(job *Job) { job.ID = "job secret" },
		"invalid type":         func(job *Job) { job.Type = "export" },
		"invalid status":       func(job *Job) { job.Status = "paused" },
		"missing actor":        func(job *Job) { job.ActorSubject = "" },
		"unsafe request ID":    func(job *Job) { job.RequestID = "request\nforged" },
		"bad idempotency":      func(job *Job) { job.IdempotencyKey = "short" },
		"bad digest":           func(job *Job) { job.RequestDigest = "not-a-digest" },
		"queued with times":    func(job *Job) { job.Status = StatusQueued },
		"failure without code": func(job *Job) { job.Status = StatusFailed; job.FailureCode = "" },
		"success with code":    func(job *Job) { job.FailureCode = "remote secret message" },
		"finish before start":  func(job *Job) { before := created.Add(30 * time.Second); job.FinishedAt = &before },
	} {
		t.Run(name, func(t *testing.T) {
			job := base
			change(&job)
			if err := job.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestIdempotencyKeyValidation(t *testing.T) {
	for _, valid := range []string{"request-1", "client:plan:1234", "A2345678", "key.with_underscores"} {
		if err := ValidateIdempotencyKey(valid); err != nil {
			t.Errorf("ValidateIdempotencyKey(%q) error = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "short", " leading-space", "contains secret value", "line\nfeed"} {
		if err := ValidateIdempotencyKey(invalid); err == nil {
			t.Errorf("ValidateIdempotencyKey(%q) error = nil", invalid)
		}
	}
}

func TestJobAPISerializationExcludesIdempotencyAndRequestDigest(t *testing.T) {
	job := Job{
		ID: "job-1", Type: TypePlan, Status: StatusQueued,
		CreatedAt:    time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
		ActorSubject: "operator-1", RequestID: "request-1",
		IdempotencyKey: "plan-request-1", RequestDigest: fixtureDigest,
	}
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"plan-request-1", fixtureDigest, "Idempotency", "RequestDigest"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("serialized job contains %q: %s", forbidden, encoded)
		}
	}
}

func TestUnavailableQueueIsExplicit(t *testing.T) {
	queue := UnavailableQueue{}
	if _, err := queue.Enqueue(context.Background(), EnqueueRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if _, err := queue.Get(context.Background(), "job-1"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := queue.List(context.Background(), ListOptions{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("List() error = %v", err)
	}
	if _, err := queue.RequestCancellation(context.Background(), CancellationRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RequestCancellation() error = %v", err)
	}
}

func TestCanTransition(t *testing.T) {
	allowed := map[[2]Status]bool{
		{StatusQueued, StatusRunning}:      true,
		{StatusQueued, StatusCanceled}:     true,
		{StatusRunning, StatusSucceeded}:   true,
		{StatusRunning, StatusFailed}:      true,
		{StatusRunning, StatusCanceled}:    true,
		{StatusRunning, StatusInterrupted}: true,
	}
	statuses := []Status{StatusQueued, StatusRunning, StatusSucceeded, StatusFailed, StatusCanceled, StatusInterrupted}
	for _, from := range statuses {
		for _, to := range statuses {
			if got := CanTransition(from, to); got != allowed[[2]Status{from, to}] {
				t.Errorf("CanTransition(%q, %q) = %v", from, to, got)
			}
		}
	}
}

func TestKnownTypesAndStatuses(t *testing.T) {
	for _, jobType := range []Type{TypeValidation, TypePlan, TypeApply, TypeTargetInventory} {
		if !jobType.Valid() {
			t.Errorf("type %q is not valid", jobType)
		}
	}
	for _, status := range []Status{StatusQueued, StatusRunning, StatusSucceeded, StatusFailed, StatusCanceled, StatusInterrupted} {
		if !status.Valid() {
			t.Errorf("status %q is not valid", status)
		}
	}
	if Type("unknown").Valid() {
		t.Fatal("unknown job type is valid")
	}
}
