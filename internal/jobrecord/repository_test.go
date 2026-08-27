package jobrecord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecovery"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

var jobTestTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func testJob(id string, createdAt time.Time, status jobs.Status) state.Job {
	job := state.Job{
		APIVersion:     state.APIVersion,
		Kind:           state.KindJob,
		ID:             id,
		Type:           jobs.TypePlan,
		Status:         status,
		CreatedAt:      createdAt.UTC(),
		Actor:          state.Actor{Subject: "operator@example.test", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC},
		RequestID:      "request-" + id,
		IdempotencyKey: "idem-" + id,
		RequestDigest:  strings.Repeat("a", 64),
	}
	if status == jobs.StatusRunning {
		started := createdAt.Add(time.Minute).UTC()
		job.StartedAt = &started
	}
	if status == jobs.StatusSucceeded || status == jobs.StatusFailed || status == jobs.StatusCanceled || status == jobs.StatusInterrupted {
		finished := createdAt.Add(2 * time.Minute).UTC()
		job.FinishedAt = &finished
		if status == jobs.StatusFailed || status == jobs.StatusInterrupted {
			job.FailureCode = "failed"
		}
	}
	return job
}

func testRepository(t *testing.T) (*FileRepository, *statefs.Store, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	repository, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	return repository, store, root
}

func TestNewRequiresStore(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, statefs.ErrClosed) {
		t.Fatalf("New(nil) error=%v", err)
	}
}

func TestReadRejectsRepositorySemanticCorruption(t *testing.T) {
	repository, store, _ := testRepository(t)
	apply := testJob("semantic-apply", jobTestTime, jobs.StatusQueued)
	apply.Type = jobs.TypeApply
	encoded, err := state.EncodeJob(apply)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/"+apply.ID+".json", encoded, false); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(context.Background(), apply.ID); !errors.Is(err, statefs.ErrCorrupt) {
		t.Fatalf("Get error=%v", err)
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{}); !errors.Is(err, statefs.ErrCorrupt) {
		t.Fatalf("List error=%v", err)
	}
}

func TestCreateGetAndReopenETagStability(t *testing.T) {
	repository, store, root := testRepository(t)
	job := testJob("job-one", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := state.EncodeJob(job)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if created.ETag != hex.EncodeToString(digest[:]) {
		t.Fatalf("etag=%q", created.ETag)
	}
	got, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, created) {
		t.Fatalf("get=%#v, create=%#v", got, created)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedStore, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedStore.Close() })
	reopenedRepository, err := New(reopenedStore)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reopenedRepository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened, created) {
		t.Fatalf("reopened=%#v, create=%#v", reopened, created)
	}
}

func TestConcurrentPutThroughRepositoriesHasOneWinner(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	queued := testJob("job-cas", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	started := jobTestTime.Add(time.Minute)
	replacement := queued
	replacement.Status = jobs.StatusRunning
	replacement.StartedAt = &started
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []*FileRepository{repository, other} {
		go func(candidate *FileRepository) {
			<-start
			_, putErr := candidate.Put(context.Background(), replacement.ID, replacement, created.ETag)
			results <- putErr
		}(candidate)
	}
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("CAS results=%v,%v, want one success and one conflict", first, second)
	}
	if first != nil && !errors.Is(first, jobs.ErrConflict) || second != nil && !errors.Is(second, jobs.ErrConflict) {
		t.Fatalf("CAS errors=%v,%v", first, second)
	}
	if got, err := repository.Get(context.Background(), replacement.ID); err != nil || got.Job.Status != jobs.StatusRunning {
		t.Fatalf("CAS winner record=%#v err=%v", got, err)
	}
}

func TestRepositoryGateHonorsContextCancellation(t *testing.T) {
	repository, _, _ := testRepository(t)
	token := <-repository.gate
	defer func() { repository.gate <- token }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := repository.Get(ctx, "job-gated")
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("gate cancellation error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gate waiter did not observe cancellation")
	}
}

func TestCreateRejectsInvalidInitialLinks(t *testing.T) {
	repository, _, _ := testRepository(t)
	apply := testJob("apply-missing-plan", jobTestTime, jobs.StatusQueued)
	apply.Type = jobs.TypeApply
	if _, err := repository.Create(context.Background(), apply); !errors.Is(err, ErrImmutableChange) {
		t.Fatalf("missing apply plan error=%v", err)
	}
	plan := testJob("plan-prebound", jobTestTime, jobs.StatusQueued)
	plan.PlanID = "plan-early"
	if _, err := repository.Create(context.Background(), plan); !errors.Is(err, ErrImmutableChange) {
		t.Fatalf("early plan result error=%v", err)
	}
	cancel := testJob("cancel-initial", jobTestTime, jobs.StatusQueued)
	cancel.CancellationRequested = true
	if _, err := repository.Create(context.Background(), cancel); !errors.Is(err, ErrImmutableChange) {
		t.Fatalf("initial cancellation error=%v", err)
	}
}

func TestCreateDuplicateAndPutTransitionRules(t *testing.T) {
	repository, _, _ := testRepository(t)
	job := testJob("job-one", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(context.Background(), job); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	canceled := job
	canceled.Status = jobs.StatusCanceled
	finished := jobTestTime.Add(time.Minute)
	canceled.FinishedAt = &finished
	canceledRecord, err := repository.Put(context.Background(), canceled.ID, canceled, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	if canceledRecord.Job.Status != jobs.StatusCanceled {
		t.Fatalf("canceled record=%#v", canceledRecord)
	}

	runningQueued := testJob("job-running", jobTestTime, jobs.StatusQueued)
	runningQueuedRecord, err := repository.Create(context.Background(), runningQueued)
	if err != nil {
		t.Fatal(err)
	}
	running := runningQueued
	running.Status = jobs.StatusRunning
	started := jobTestTime.Add(time.Minute)
	running.StartedAt = &started
	runningRecord, err := repository.Put(context.Background(), running.ID, running, runningQueuedRecord.ETag)
	if err != nil {
		t.Fatal(err)
	}
	succeeded := running
	succeeded.Status = jobs.StatusSucceeded
	succeeded.FinishedAt = &finished
	succeededRecord, err := repository.Put(context.Background(), succeeded.ID, succeeded, runningRecord.ETag)
	if err != nil {
		t.Fatal(err)
	}
	if succeededRecord.Job.Status != jobs.StatusSucceeded {
		t.Fatalf("succeeded record=%#v", succeededRecord)
	}
	if _, err := repository.Put(context.Background(), succeeded.ID, succeeded, succeededRecord.ETag); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("same-status error=%v", err)
	}
}

func TestTransitionMetadataLinksAreAppendOnlyAndTypeScoped(t *testing.T) {
	repository, _, _ := testRepository(t)
	cancelJob := testJob("job-cancel-request", jobTestTime, jobs.StatusQueued)
	cancelRecord, err := repository.Create(context.Background(), cancelJob)
	if err != nil {
		t.Fatal(err)
	}
	cancelJob.CancellationRequested = true
	if _, err := repository.Put(context.Background(), cancelJob.ID, cancelJob, cancelRecord.ETag); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("same-status cancellation error=%v", err)
	}
	queued := testJob("job-plan-link", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	running := queued
	running.Status = jobs.StatusRunning
	started := jobTestTime.Add(time.Minute)
	running.StartedAt = &started
	runningRecord, err := repository.Put(context.Background(), running.ID, running, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	terminal := running
	terminal.Status = jobs.StatusSucceeded
	finished := jobTestTime.Add(2 * time.Minute)
	terminal.FinishedAt = &finished
	terminal.PlanID = "plan-result"
	terminalRecord, err := repository.Put(context.Background(), terminal.ID, terminal, runningRecord.ETag)
	if err != nil {
		t.Fatalf("successful plan link: %v", err)
	}
	if terminalRecord.Job.PlanID != terminal.PlanID || terminalRecord.Job.StartedAt == nil {
		t.Fatalf("successful plan link record=%#v", terminalRecord)
	}

	apply := testJob("job-apply-link", jobTestTime, jobs.StatusQueued)
	apply.Type = jobs.TypeApply
	apply.PlanID = "plan-bound"
	applyRecord, err := repository.Create(context.Background(), apply)
	if err != nil {
		t.Fatalf("pre-bound apply: %v", err)
	}
	applyRunning := apply
	applyRunning.Status = jobs.StatusRunning
	applyRunning.StartedAt = &started
	applyRunning.CancellationRequested = true
	badReport := apply
	badReport.Status = jobs.StatusRunning
	badReport.StartedAt = &started
	badReport.ReportID = "report-early"
	if _, err := repository.Put(context.Background(), badReport.ID, badReport, applyRecord.ETag); err == nil {
		t.Fatal("non-terminal apply report link accepted")
	}
	applyRunningRecord, err := repository.Put(context.Background(), applyRunning.ID, applyRunning, applyRecord.ETag)
	if err != nil {
		t.Fatalf("pre-bound apply transition: %v", err)
	}
	applyTerminal := applyRunning
	applyTerminal.Status = jobs.StatusSucceeded
	applyTerminal.FinishedAt = &finished
	applyTerminal.ReportID = "report-1"
	revertedCancellation := applyTerminal
	revertedCancellation.CancellationRequested = false
	if _, err := repository.Put(context.Background(), revertedCancellation.ID, revertedCancellation, applyRunningRecord.ETag); !errors.Is(err, ErrImmutableChange) {
		t.Fatalf("cancellation revert error=%v", err)
	}
	applyTerminalRecord, err := repository.Put(context.Background(), applyTerminal.ID, applyTerminal, applyRunningRecord.ETag)
	if err != nil {
		t.Fatalf("terminal apply link: %v", err)
	}
	if applyTerminalRecord.Job.ReportID != applyTerminal.ReportID {
		t.Fatalf("terminal apply link record=%#v", applyTerminalRecord)
	}
	badClear := applyTerminal
	badClear.ReportID = ""
	if _, err := repository.Put(context.Background(), badClear.ID, badClear, applyTerminalRecord.ETag); !errors.Is(err, ErrImmutableChange) {
		t.Fatalf("report clear error=%v", err)
	}
}

func TestPutRejectsInvalidTransitionsImmutableChangesAndStaleETag(t *testing.T) {
	repository, _, _ := testRepository(t)
	job := testJob("job-one", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	invalid := []jobs.Status{jobs.StatusQueued, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusInterrupted}
	for _, status := range invalid {
		candidate := job
		candidate.Status = status
		if status == jobs.StatusSucceeded || status == jobs.StatusFailed || status == jobs.StatusCanceled || status == jobs.StatusInterrupted {
			finished := jobTestTime.Add(time.Minute)
			candidate.FinishedAt = &finished
			if status == jobs.StatusFailed || status == jobs.StatusInterrupted {
				candidate.FailureCode = "failed"
			}
		}
		if _, err := repository.Put(context.Background(), candidate.ID, candidate, created.ETag); !errors.Is(err, jobs.ErrInvalidTransition) {
			t.Errorf("status %s error=%v", status, err)
		}
	}
	for name, mutate := range map[string]func(*state.Job){
		"id":             func(value *state.Job) { value.ID = "job-two" },
		"type":           func(value *state.Job) { value.Type = jobs.TypeApply },
		"createdAt":      func(value *state.Job) { value.CreatedAt = value.CreatedAt.Add(time.Second) },
		"actor":          func(value *state.Job) { value.Actor.Subject = "other@example.test" },
		"requestID":      func(value *state.Job) { value.RequestID = "request-other" },
		"idempotencyKey": func(value *state.Job) { value.IdempotencyKey = "idem-other" },
		"requestDigest":  func(value *state.Job) { value.RequestDigest = strings.Repeat("b", 64) },
	} {
		candidate := job
		mutate(&candidate)
		if _, err := repository.Put(context.Background(), job.ID, candidate, created.ETag); !errors.Is(err, ErrImmutableChange) {
			t.Errorf("immutable %s error=%v", name, err)
		}
	}
	if _, err := repository.Put(context.Background(), job.ID, job, "wrong"); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("stale etag error=%v", err)
	}
}

func TestQueuedCancellationCannotClaimStart(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("queued-cancel", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	canceled := queued
	canceled.Status = jobs.StatusCanceled
	started := jobTestTime.Add(time.Minute)
	finished := jobTestTime.Add(2 * time.Minute)
	canceled.StartedAt = &started
	canceled.FinishedAt = &finished
	if _, err := repository.Put(context.Background(), queued.ID, canceled, created.ETag); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("error=%v", err)
	}
}

func TestListFiltersKeysetOrderingAndTokenScope(t *testing.T) {
	repository, _, _ := testRepository(t)
	fixtures := []state.Job{
		testJob("job-c", jobTestTime, jobs.StatusQueued),
		testJob("job-a", jobTestTime, jobs.StatusQueued),
		testJob("job-b", jobTestTime.Add(time.Minute), jobs.StatusQueued),
		testJob("job-d", jobTestTime.Add(2*time.Minute), jobs.StatusQueued),
	}
	fixtures[2].Type = jobs.TypeApply
	fixtures[2].PlanID = "plan-for-job-b"
	for _, job := range fixtures {
		if _, err := repository.Create(context.Background(), job); err != nil {
			t.Fatal(err)
		}
	}
	options := jobs.ListOptions{Types: []jobs.Type{jobs.TypePlan}, PageSize: 2}
	first, err := repository.List(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{first.Records[0].Job.ID, first.Records[1].Job.ID}; !reflect.DeepEqual(got, []string{"job-a", "job-c"}) {
		t.Fatalf("first IDs=%v", got)
	}
	if first.NextPageToken == "" {
		t.Fatal("missing next token")
	}
	second, err := repository.List(context.Background(), jobs.ListOptions{Types: []jobs.Type{jobs.TypePlan}, PageSize: 2, PageToken: first.NextPageToken})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{second.Records[0].Job.ID}; !reflect.DeepEqual(got, []string{"job-d"}) || second.Records == nil {
		t.Fatalf("second page=%#v", second)
	}
	if _, err := repository.Create(context.Background(), testJob("job-e", jobTestTime.Add(3*time.Minute), jobs.StatusQueued)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{Types: []jobs.Type{jobs.TypePlan}, PageSize: 2, PageToken: first.NextPageToken}); !errors.Is(err, ErrPageChanged) {
		t.Fatalf("changed snapshot error=%v", err)
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{Types: []jobs.Type{jobs.TypeApply}, PageSize: 2, PageToken: first.NextPageToken}); !errors.Is(err, ErrInvalidPageToken) {
		t.Fatalf("cross-filter token error=%v", err)
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{Types: []jobs.Type{"unknown"}}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid filter error=%v", err)
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{PageSize: MaxPageSize + 1}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid size error=%v", err)
	}
}

func TestListRejectsExcessiveFilters(t *testing.T) {
	repository, _, _ := testRepository(t)
	types := make([]jobs.Type, 17)
	for index := range types {
		types[index] = jobs.TypePlan
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{Types: types}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("types error=%v", err)
	}
	statuses := make([]jobs.Status, 17)
	for index := range statuses {
		statuses[index] = jobs.StatusQueued
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{Statuses: statuses}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("statuses error=%v", err)
	}
}

func TestListRejectsCorruptRecordAndContextCancellation(t *testing.T) {
	repository, store, _ := testRepository(t)
	if _, err := repository.Create(context.Background(), testJob("job-good", jobTestTime, jobs.StatusQueued)); err != nil {
		t.Fatal(err)
	}
	sentinel := "OIDC_TOKEN_SENTINEL_SHOULD_NOT_APPEAR"
	if err := store.WriteAtomic(statefs.JobsDir+"/job-bad.json", []byte(`{"apiVersion":"elastic-maintainer/state/v2","kind":"Job","leak":"`+sentinel+`"}`), false); err != nil {
		t.Fatal(err)
	}
	listErr := func() error {
		_, err := repository.List(context.Background(), jobs.ListOptions{})
		return err
	}()
	if !errors.Is(listErr, statefs.ErrCorrupt) {
		t.Fatalf("corrupt list error=%v", listErr)
	}
	if strings.Contains(listErr.Error(), sentinel) {
		t.Fatalf("corrupt error exposed document contents: %v", listErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.List(ctx, jobs.ListOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel list error=%v", err)
	}
	if _, err := repository.Get(ctx, "job-good"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel get error=%v", err)
	}
}

func TestCreateAcceptsOnlyQueuedAndPutLifecycle(t *testing.T) {
	repository, store, _ := testRepository(t)
	statuses := []jobs.Status{jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted}
	for index, status := range statuses {
		job := testJob(fmt.Sprintf("job-status-%d", index), jobTestTime.Add(time.Duration(index)*time.Minute), status)
		encoded, err := state.EncodeJob(job)
		if err != nil {
			t.Fatalf("encode %s: %v", status, err)
		}
		if status == jobs.StatusQueued {
			if _, err := repository.Create(context.Background(), job); err != nil {
				t.Fatalf("create %s: %v", status, err)
			}
		} else if err := store.WriteAtomic(statefs.JobsDir+"/"+job.ID+".json", encoded, false); err != nil {
			t.Fatalf("write %s fixture: %v", status, err)
		}
		record, err := repository.Get(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("read %s: %v", status, err)
		}
		if record.Job.Status != status || record.ETag == "" {
			t.Fatalf("record %s=%#v", status, record)
		}
	}
	if _, err := repository.Create(context.Background(), testJob("job-create-running-rejected", jobTestTime, jobs.StatusRunning)); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("non-queued create error=%v", err)
	}

	queued := testJob("job-queued-transition", jobTestTime, jobs.StatusQueued)
	queuedRecord, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	running := queued
	running.Status = jobs.StatusRunning
	started := jobTestTime.Add(time.Minute)
	running.StartedAt = &started
	runningRecord, err := repository.Put(context.Background(), running.ID, running, queuedRecord.ETag)
	if err != nil {
		t.Fatalf("queued to running: %v", err)
	}
	if !sameTime(running.StartedAt, runningRecord.Job.StartedAt) {
		t.Fatal("running start time was not retained")
	}

	for index, status := range []jobs.Status{jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted} {
		queued := testJob(fmt.Sprintf("job-running-transition-%d", index), jobTestTime, jobs.StatusQueued)
		queuedRecord, err := repository.Create(context.Background(), queued)
		if err != nil {
			t.Fatal(err)
		}
		job := queued
		job.Status = jobs.StatusRunning
		job.StartedAt = &started
		runningRecord, err := repository.Put(context.Background(), job.ID, job, queuedRecord.ETag)
		if err != nil {
			t.Fatalf("queued to running: %v", err)
		}
		finished := jobTestTime.Add(2 * time.Minute)
		if status == jobs.StatusInterrupted {
			if _, err := repository.Interrupt(context.Background(), job.ID, runningRecord.ETag, finished, jobrecovery.FailureCodeRunning); err != nil {
				t.Fatalf("running to %s: %v", status, err)
			}
			continue
		}
		job.Status = status
		job.FinishedAt = &finished
		if status == jobs.StatusFailed {
			job.FailureCode = "failed"
		}
		if _, err := repository.Put(context.Background(), job.ID, job, runningRecord.ETag); err != nil {
			t.Fatalf("running to %s: %v", status, err)
		}
	}
}

func TestListMaxScanBoundAndConcurrentOperations(t *testing.T) {
	repository, store, root := testRepository(t)
	encoded, err := state.EncodeJob(testJob("job-template", jobTestTime, jobs.StatusQueued))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= MaxRecordsScan; index++ {
		name := filepath.Join(root, statefs.JobsDir, fmt.Sprintf("job-%05d.json", index))
		if err := os.WriteFile(name, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repository.List(context.Background(), jobs.ListOptions{}); !errors.Is(err, ErrScanLimit) {
		t.Fatalf("scan bound error=%v", err)
	}
	_ = store.Close()

	repository, _, _ = testRepository(t)
	const workers = 8
	const jobsPerWorker = 8
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer group.Done()
			for index := 0; index < jobsPerWorker; index++ {
				id := fmt.Sprintf("concurrent-%d-%d", worker, index)
				if _, err := repository.Create(context.Background(), testJob(id, jobTestTime.Add(time.Duration(index)*time.Second), jobs.StatusQueued)); err != nil {
					t.Errorf("create %s: %v", id, err)
				}
				if _, err := repository.Get(context.Background(), id); err != nil {
					t.Errorf("get %s: %v", id, err)
				}
			}
		}(worker)
	}
	group.Wait()
	page, err := repository.List(context.Background(), jobs.ListOptions{PageSize: MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != workers*jobsPerWorker {
		t.Fatalf("concurrent record count=%d", len(page.Records))
	}
}
