package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type testIDs struct {
	mu   sync.Mutex
	next int
}

func (ids *testIDs) NewJobID(jobType jobs.Type) (string, error) {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return fmt.Sprintf("%s-%d", jobType, ids.next), nil
}

type sequenceReader struct {
	mu        sync.Mutex
	snapshots []InputSnapshot
	errors    []error
	calls     int
}

func (reader *sequenceReader) Read(context.Context) (InputSnapshot, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	index := reader.calls
	reader.calls++
	var snapshot InputSnapshot
	var err error
	if len(reader.snapshots) != 0 {
		snapshot = reader.snapshots[min(index, len(reader.snapshots)-1)]
	}
	if len(reader.errors) != 0 {
		err = reader.errors[min(index, len(reader.errors)-1)]
	}
	return snapshot, err
}

type blockingReader struct {
	started chan struct{}
	once    sync.Once
}

func (reader *blockingReader) Read(ctx context.Context) (InputSnapshot, error) {
	reader.once.Do(func() { close(reader.started) })
	<-ctx.Done()
	return InputSnapshot{}, ctx.Err()
}

func TestServiceExecutesValidationAndRereadsInputs(t *testing.T) {
	reader := &sequenceReader{snapshots: []InputSnapshot{validInputs("First"), validInputs("Second")}}
	service := newTestService(t, reader, 1, 4)
	defer shutdownService(t, service)

	first, err := service.Start(context.Background(), startRequest("request-key-0001"))
	if err != nil {
		t.Fatal(err)
	}
	firstRecord := waitForTerminal(t, service, first.ID)
	if firstRecord.Job.Status != jobs.StatusSucceeded || firstRecord.Result == nil || !firstRecord.Result.Valid {
		t.Fatalf("first record = %#v", firstRecord)
	}
	if firstRecord.Result.Counts != (Counts{ResourceSets: 1, Targets: 1, Resources: 1, Files: 1}) {
		t.Fatalf("counts = %#v", firstRecord.Result.Counts)
	}

	second, err := service.Start(context.Background(), startRequest("request-key-0002"))
	if err != nil {
		t.Fatal(err)
	}
	secondRecord := waitForTerminal(t, service, second.ID)
	if firstRecord.Result.Snapshot.Targets[0].DesiredDigest == secondRecord.Result.Snapshot.Targets[0].DesiredDigest {
		t.Fatal("second validation did not re-read changed mounted inputs")
	}
	if reader.calls != 2 {
		t.Fatalf("input reads = %d", reader.calls)
	}
}

func TestServiceStartIsIdempotentAndDetectsConflicts(t *testing.T) {
	reader := &sequenceReader{snapshots: []InputSnapshot{validInputs("Name")}}
	service := newTestService(t, reader, 1, 4)
	defer shutdownService(t, service)
	request := startRequest("same-key-0001")
	first, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("idempotent jobs differ: %q %q", first.ID, second.ID)
	}
	request.Selection.TargetIDs = []string{"different"}
	if _, err := service.Start(context.Background(), request); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("conflicting Start() error = %v", err)
	}
	_ = waitForTerminal(t, service, first.ID)
}

func TestServiceAppliesSelectionAfterGlobalValidation(t *testing.T) {
	reader := &sequenceReader{snapshots: []InputSnapshot{validInputs("Name")}}
	service := newTestService(t, reader, 1, 2)
	defer shutdownService(t, service)
	request := startRequest("selection-key-0001")
	request.Selection.TargetIDs = []string{"missing"}
	job, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	record := waitForTerminal(t, service, job.ID)
	if record.Job.Status != jobs.StatusFailed || record.Job.FailureCode != "invalid_selection" {
		t.Fatalf("selection record = %#v", record)
	}
}

func TestServiceRecoversQueuedAndInterruptsRunningRecords(t *testing.T) {
	repository := NewMemoryRepository()
	clock := &testClock{now: time.Unix(500, 0)}
	ids := &testIDs{}
	queued := createRepositoryJob(t, repository, clock, ids, "recovery-key-0001")
	running := createRepositoryJob(t, repository, clock, ids, "recovery-key-0002")
	runningRecord, _ := repository.Get(context.Background(), running.ID)
	started := clock.Now().UTC()
	runningRecord.Job.Status, runningRecord.Job.StartedAt = jobs.StatusRunning, &started
	if _, err := repository.Put(context.Background(), runningRecord, runningRecord.Version); err != nil {
		t.Fatal(err)
	}

	reader := &sequenceReader{snapshots: []InputSnapshot{validInputs("Recovered")}}
	service, err := NewService(Options{Inputs: reader, Repository: repository, Workers: 1, QueueCapacity: 2, Clock: clock, IDGenerator: ids})
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownService(t, service)
	if waitForTerminal(t, service, queued.ID).Job.Status != jobs.StatusSucceeded {
		t.Fatal("queued job was not recovered")
	}
	interrupted := waitForTerminal(t, service, running.ID)
	if interrupted.Job.Status != jobs.StatusInterrupted || interrupted.Job.FailureCode != "service_restarted" {
		t.Fatalf("running recovery = %#v", interrupted.Job)
	}
}

func TestServiceBoundsQueueAndCancelsRunningAndQueuedJobs(t *testing.T) {
	reader := &blockingReader{started: make(chan struct{})}
	service := newTestService(t, reader, 1, 1)
	first, err := service.Start(context.Background(), startRequest("queue-key-0001"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	second, err := service.Start(context.Background(), startRequest("queue-key-0002"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(context.Background(), startRequest("queue-key-0003")); !errors.Is(err, jobs.ErrQueueFull) {
		t.Fatalf("full queue Start() error = %v", err)
	}
	canceledQueued, err := service.Cancel(context.Background(), second.ID)
	if err != nil || canceledQueued.Status != jobs.StatusCanceled {
		t.Fatalf("queued cancel = %#v, %v", canceledQueued, err)
	}
	if _, err := service.Cancel(context.Background(), first.ID); err != nil {
		t.Fatal(err)
	}
	firstRecord := waitForTerminal(t, service, first.ID)
	if firstRecord.Job.Status != jobs.StatusCanceled {
		t.Fatalf("running status = %s", firstRecord.Job.Status)
	}
	if waitForTerminal(t, service, second.ID).Job.Status != jobs.StatusCanceled {
		t.Fatal("queued job was not canceled")
	}
}

func TestServiceStoresSafeStructuredFailure(t *testing.T) {
	reader := &sequenceReader{errors: []error{errors.New("credential-sentinel /absolute/secret/path")}}
	service := newTestService(t, reader, 1, 2)
	defer shutdownService(t, service)
	job, err := service.Start(context.Background(), startRequest("failure-key-0001"))
	if err != nil {
		t.Fatal(err)
	}
	record := waitForTerminal(t, service, job.ID)
	if record.Job.Status != jobs.StatusFailed || record.Job.FailureCode != "invalid_inputs" || record.Result == nil || record.Result.Valid {
		t.Fatalf("failed record = %#v", record)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "credential-sentinel") || strings.Contains(string(encoded), "/absolute/") {
		t.Fatalf("record leaked raw failure: %s", encoded)
	}
	if len(record.Result.Diagnostics) != 1 || record.Result.Diagnostics[0].Code != "invalid_inputs" {
		t.Fatalf("diagnostics = %#v", record.Result.Diagnostics)
	}
}

func TestMemoryRepositoryTransitionsCopiesAndPaginates(t *testing.T) {
	repository := NewMemoryRepository()
	clock := &testClock{now: time.Unix(100, 0)}
	ids := &testIDs{}
	for index := 0; index < 3; index++ {
		job, err := jobs.NewQueued(jobs.NewJobInput{Type: jobs.TypeValidation, ActorSubject: "actor", RequestID: fmt.Sprintf("request-%d", index), IdempotencyKey: fmt.Sprintf("repo-key-%04d", index), RequestDigest: strings.Repeat(fmt.Sprintf("%x", index+1), 64)[:64]}, clock, ids)
		if err != nil {
			t.Fatal(err)
		}
		if _, created, err := repository.Create(context.Background(), Record{Job: job}); err != nil || !created {
			t.Fatalf("Create() = %v, %v", created, err)
		}
	}
	page, err := repository.List(context.Background(), jobs.ListOptions{PageSize: 2})
	if err != nil || len(page.Records) != 2 || page.NextPageToken == "" {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	secondPage, err := repository.List(context.Background(), jobs.ListOptions{PageSize: 2, PageToken: page.NextPageToken})
	if err != nil || len(secondPage.Records) != 1 {
		t.Fatalf("second page = %#v, %v", secondPage, err)
	}

	record := page.Records[0]
	now := clock.Now().UTC()
	record.Job.Status, record.Job.StartedAt = jobs.StatusRunning, &now
	updated, err := repository.Put(context.Background(), record, record.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Put(context.Background(), updated, record.Version); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("stale Put() error = %v", err)
	}
	updated.Job.Status = jobs.StatusQueued
	updated.Job.StartedAt = nil
	if _, err := repository.Put(context.Background(), updated, updated.Version); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("invalid transition error = %v", err)
	}

	stored, err := EncodeStoredRecord(updated)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeStoredRecord(stored)
	if err != nil || restored.Job.IdempotencyKey == "" || restored.Job.RequestDigest == "" {
		t.Fatalf("stored record lost idempotency data: %#v, %v", restored, err)
	}
	publicJSON, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), updated.Job.IdempotencyKey) || strings.Contains(string(publicJSON), updated.Job.RequestDigest) {
		t.Fatalf("public record leaked idempotency data: %s", publicJSON)
	}

	copy, err := repository.Get(context.Background(), record.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	copy.Selection.TargetIDs = append(copy.Selection.TargetIDs, "mutated")
	again, _ := repository.Get(context.Background(), record.Job.ID)
	if len(again.Selection.TargetIDs) != 0 {
		t.Fatal("repository returned aliased record")
	}
}

func createRepositoryJob(t *testing.T, repository *MemoryRepository, clock jobs.Clock, ids jobs.IDGenerator, key string) jobs.Job {
	t.Helper()
	job, err := jobs.NewQueued(jobs.NewJobInput{Type: jobs.TypeValidation, ActorSubject: "actor", RequestID: "request-1", IdempotencyKey: key, RequestDigest: strings.Repeat("a", 64)}, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	created, ok, err := repository.Create(context.Background(), Record{Job: job})
	if err != nil || !ok {
		t.Fatalf("Create() = %#v, %v, %v", created, ok, err)
	}
	return created.Job
}

func newTestService(t *testing.T, reader InputReader, workers, capacity int) *Service {
	t.Helper()
	service, err := NewService(Options{Inputs: reader, Repository: NewMemoryRepository(), Workers: workers, QueueCapacity: capacity, Clock: &testClock{now: time.Unix(1000, 0)}, IDGenerator: &testIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func startRequest(key string) StartRequest {
	return StartRequest{ActorSubject: " planner ", RequestID: "request-1", IdempotencyKey: key}
}

func validInputs(name string) InputSnapshot {
	cfg := &config.ServerConfig{StateID: "state", ResourceSets: map[string]config.ResourceSetConfig{"set": {}}, Targets: map[string]config.TargetConfig{"target": {URL: "http://localhost:5601", ResourceSet: "set"}}}
	contents := "apiVersion: elastic-maintainer/v1alpha1\nkind: AgentPolicy\nmetadata:\n  id: agents\n  name: " + name + "\nspec: {}\n"
	set := source.ResourceSet{ID: "set", Files: []source.File{{Location: source.Location{ResourceSetID: "set", RelativePath: "resource.yaml"}, Contents: []byte(contents)}}}
	return InputSnapshot{Config: cfg, ResourceSets: []source.ResourceSet{set}}
}

func waitForTerminal(t *testing.T, service *Service, id string) Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := service.Get(context.Background(), id)
		if err == nil && record.Job.Terminal() {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("job %q did not become terminal", id)
	return Record{}
}

func shutdownService(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
