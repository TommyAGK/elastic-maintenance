package jobscheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

func cancellationRequest(id string) jobs.CancellationRequest {
	return jobs.CancellationRequest{JobID: id, ActorSubject: "canceller@example.test", RequestID: "cancel-request-1"}
}

func TestSchedulerRequestCancellationQueuedRemovesPendingAndReleasesSlot(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	var queuedExecutions atomic.Int32
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())

	running := schedulerTestJob("cancel-blocking-running", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: running, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	queued := schedulerTestJob("cancel-blocked-queued", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: queued, Executor: func(context.Context, state.Job) ExecutionResult {
		queuedExecutions.Add(1)
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}

	canceled, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(queued.ID))
	if err != nil {
		t.Fatal(err)
	}
	if canceled.ID != queued.ID || canceled.Status != jobs.StatusCanceled || canceled.FinishedAt == nil || canceled.FinishedAt.Location() != time.UTC {
		t.Fatalf("canceled projection=%#v", canceled)
	}
	stored, err := repository.Get(context.Background(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Job.Status != jobs.StatusCanceled || !stored.Job.CancellationRequested {
		t.Fatalf("stored canceled=%#v", stored.Job)
	}
	if got := queuedExecutions.Load(); got != 0 {
		t.Fatalf("queued executor executions=%d", got)
	}
	assertSchedulerMarkersEmpty(t, scheduler, queued.ID)

	// The canceled pending item releases exactly its one slot even while the
	// worker remains occupied by the first job.
	after := schedulerTestJob("cancel-after-release", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: after, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
	tooMany := schedulerTestJob("cancel-after-single-release", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: tooMany, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("over-capacity executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("slot was released more than once: %v", err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitForSchedulerStatus(t, repository, running.ID, jobs.StatusCanceled)
	waitForSchedulerStatus(t, repository, after.ID, jobs.StatusCanceled)
}

func TestSchedulerQueuedCancellationUsesOneTerminalMutation(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	wrapped := &countingCancellationRepository{Repository: repository}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	blocking := schedulerTestJob("cancel-one-write-blocking", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: blocking, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	queued := schedulerTestJob("cancel-one-write-queued", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: queued, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("queued executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	wrapped.reset()
	if _, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(queued.ID)); err != nil {
		t.Fatal(err)
	}
	if got := wrapped.requestCalls.Load(); got != 0 {
		t.Fatalf("queued cancellation RequestCancellation calls=%d, want zero", got)
	}
	if got := wrapped.putCalls.Load(); got != 1 {
		t.Fatalf("queued cancellation Put calls=%d, want one", got)
	}
	if wrapped.queuedRequested.Load() {
		t.Fatal("scheduler exposed queued+cancellationRequested between writes")
	}
	stored, err := repository.Get(context.Background(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Job.Status != jobs.StatusCanceled || !stored.Job.CancellationRequested || stored.Job.FinishedAt == nil || stored.Job.FinishedAt.Location() != time.UTC {
		t.Fatalf("stored queued cancellation=%#v", stored.Job)
	}
}

func TestSchedulerRequestCancellationRunningCooperatesAndWinsExecutorResult(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	canceled := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-running", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		close(canceled)
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	projection, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Status != jobs.StatusRunning || projection.ID != job.ID {
		t.Fatalf("running cancellation projection=%#v", projection)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("executor context was not canceled")
	}
	record := waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled)
	if !record.Job.CancellationRequested || record.Job.FailureCode != "" {
		t.Fatalf("running cancellation record=%#v", record.Job)
	}
	assertSchedulerMarkersEmpty(t, scheduler, job.ID)
}

func TestSchedulerActiveTerminalCancellationRetainsOwnershipUntilFinish(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &changedTerminalGetRepository{Repository: repository}
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	wrapped.beforeRequest = func(id, _ string) {
		current, err := repository.Get(context.Background(), id)
		if err != nil {
			t.Errorf("terminal cancellation get: %v", err)
			return
		}
		requested, err := repository.RequestCancellation(context.Background(), id, current.ETag)
		if err != nil {
			t.Errorf("terminal cancellation request: %v", err)
			return
		}
		terminal := requested.Job
		terminal.Status = jobs.StatusCanceled
		finished := fixedSchedulerNow().UTC()
		terminal.FinishedAt = &finished
		if _, err := repository.Put(context.Background(), id, terminal, requested.ETag); err != nil {
			t.Errorf("terminal cancellation put: %v", err)
		}
	}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-active-terminal-ownership", jobs.TypeApply)
	wrapped.id = job.ID
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	projection, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatalf("active terminal cancellation error=%v", err)
	}
	if projection.Status != jobs.StatusCanceled {
		t.Fatalf("active terminal cancellation projection=%#v", projection)
	}
	<-canceled

	// Simulate an external append-only terminal link mutation on the next
	// durable observation, before the executor is allowed to finish.
	wrapped.mutateReportID.Store(true)
	close(release)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("active terminal replay health=%v", scheduler.Health())
	}
	assertSchedulerMarkersEmpty(t, scheduler, job.ID)
}

func TestSchedulerTerminalCancellationReplayRejectsChangedLink(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	wrapped := &changedTerminalGetRepository{Repository: repository}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	blocking := schedulerTestJob("cancel-terminal-link-blocking", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: blocking, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	job := schedulerTestJob("cancel-terminal-link", jobs.TypeApply)
	current, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("terminal replay executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if err != nil {
		t.Fatal(err)
	}
	requested, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	requested, err = repository.RequestCancellation(context.Background(), job.ID, requested.ETag)
	if err != nil {
		t.Fatal(err)
	}
	terminal := requested.Job
	terminal.Status = jobs.StatusCanceled
	finished := fixedSchedulerNow().UTC()
	terminal.FinishedAt = &finished
	if _, err := repository.Put(context.Background(), job.ID, terminal, requested.ETag); err != nil {
		t.Fatal(err)
	}
	wrapped.id = job.ID
	wrapped.mutate.Store(true)
	if current.ID != job.ID {
		t.Fatalf("accepted=%#v", current)
	}
	if _, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID)); !errors.Is(err, ErrPersistenceFailure) {
		t.Fatalf("changed-link cancellation error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("changed-link health=%v", scheduler.Health())
	}
}

func TestSchedulerRequestCancellationTerminalRaceAcceptsOwnedCompletion(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCancellationRepository{Repository: repository}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	started := make(chan struct{})
	canceled := make(chan struct{})
	job := schedulerTestJob("cancel-terminal-race", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		close(canceled)
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	wrapped.beforeRequest = func(id, _ string) {
		current, err := repository.Get(context.Background(), id)
		if err != nil {
			t.Errorf("race get: %v", err)
			return
		}
		requested, err := repository.RequestCancellation(context.Background(), id, current.ETag)
		if err != nil {
			t.Errorf("race request: %v", err)
			return
		}
		terminal := requested.Job
		terminal.Status = jobs.StatusCanceled
		finished := fixedSchedulerNow().UTC()
		terminal.FinishedAt = &finished
		if _, err := repository.Put(context.Background(), id, terminal, requested.ETag); err != nil {
			t.Errorf("race terminal put: %v", err)
		}
	}
	projection, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatalf("terminal race error=%v", err)
	}
	if projection.Status != jobs.StatusCanceled || errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("terminal race projection=%#v health=%v", projection, scheduler.Health())
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("terminal race did not cancel executor")
	}
	waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled)
}

func TestSchedulerRequestCancellationOwnedDeletionIsFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &missingGetRepository{Repository: repository}
	started := make(chan struct{})
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	blocking := schedulerTestJob("cancel-owned-delete-blocking", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: blocking, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	job := schedulerTestJob("cancel-owned-delete", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("deleted job executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	wrapped.id = job.ID
	wrapped.missing.Store(true)
	if _, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID)); !errors.Is(err, ErrPersistenceFailure) {
		t.Fatalf("owned deletion error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("owned deletion health=%v", scheduler.Health())
	}
}

func TestSchedulerFinishRejectsChangedTerminalLink(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &changedTerminalGetRepository{Repository: repository}
	job := schedulerTestJob("cancel-finish-link", jobs.TypeApply)
	wrapped.id = job.ID
	wrapped.beforeTerminalPut = func(id string) {
		current, err := repository.Get(context.Background(), id)
		if err != nil {
			t.Errorf("finish race get: %v", err)
			return
		}
		requested, err := repository.RequestCancellation(context.Background(), id, current.ETag)
		if err != nil {
			t.Errorf("finish race request: %v", err)
			return
		}
		terminal := requested.Job
		terminal.Status = jobs.StatusCanceled
		finished := fixedSchedulerNow().UTC()
		terminal.FinishedAt = &finished
		if _, err := repository.Put(context.Background(), id, terminal, requested.ETag); err != nil {
			t.Errorf("finish race terminal put: %v", err)
			return
		}
		wrapped.mutate.Store(true)
	}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("finish changed-link health=%v", scheduler.Health())
	}
}

func TestSchedulerRequestCancellationClaimRegistrationRace(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	claimed := make(chan struct{})
	release := make(chan struct{})
	wrapped := &cancellationRaceRepository{Repository: repository, claimed: claimed, release: release}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-claim-registration", jobs.TypeValidation)
	var executions atomic.Int32
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		executions.Add(1)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-claimed
	requestDone := make(chan error, 1)
	go func() {
		_, requestErr := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
		requestDone <- requestErr
	}()
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled)
	if executions.Load() != 1 {
		t.Fatalf("executor executions=%d, want one canceled cooperative invocation", executions.Load())
	}
}

func TestSchedulerTerminalCancellationReplayDoesNotPoisonActiveWorker(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-terminal-active-replay", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	current, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := repository.RequestCancellation(context.Background(), job.ID, current.ETag)
	if err != nil {
		t.Fatal(err)
	}
	finished := fixedSchedulerNow().UTC()
	terminal := requested.Job
	terminal.Status = jobs.StatusCanceled
	terminal.FinishedAt = &finished
	if _, err := repository.Put(context.Background(), job.ID, terminal, requested.ETag); err != nil {
		t.Fatal(err)
	}
	projection, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if projection.Status != jobs.StatusCanceled {
		t.Fatalf("terminal replay=%#v", projection)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(scheduler.Health(), jobs.ErrQueueClosed) {
		t.Fatalf("terminal replay health=%v", scheduler.Health())
	}
}

func TestSchedulerCancellationCompletionRacePreservesExecutorWinner(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	entered := make(chan struct{})
	release := make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, beforeTerminalPut: func(string, state.Job, string) {
		close(entered)
		<-release
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-completion-race", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-entered
	requestDone := make(chan error, 1)
	go func() {
		_, requestErr := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
		requestDone <- requestErr
	}()
	var requestErr error
	observed := false
	select {
	case requestErr = <-requestDone:
		observed = true
		t.Logf("cancellation completed before test observation: %v", requestErr)
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	if !observed {
		requestErr = <-requestDone
	}
	if !errors.Is(requestErr, jobs.ErrCancellationUnsupported) {
		t.Fatalf("completion race request error=%v", requestErr)
	}
	record := waitForSchedulerStatus(t, repository, job.ID, jobs.StatusSucceeded)
	if record.Job.CancellationRequested {
		t.Fatal("completion race persisted cancellation after executor winner")
	}
	if scheduler.Health() != nil {
		t.Fatalf("completion race health=%v", scheduler.Health())
	}
}

func TestSchedulerRequestCancellationReplayAndUnsupportedRepository(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	job := schedulerTestJob("cancel-replay", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	// Wait until the worker has claimed the record, making the first request a
	// running cancellation and the second request a durable replay.
	deadline := time.Now().Add(time.Second)
	running := false
	for time.Now().Before(deadline) {
		record, getErr := repository.Get(context.Background(), job.ID)
		if getErr == nil && record.Job.Status == jobs.StatusRunning {
			running = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !running {
		t.Fatal("worker did not claim replay test job")
	}
	if _, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID)); err != nil {
		t.Fatal(err)
	}
	terminal := waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled)
	replayed, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Status != jobs.StatusCanceled || replayed.FinishedAt == nil || replayed.FailureCode != "" {
		t.Fatalf("replay=%#v terminal=%#v", replayed, terminal.Job)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	bareRepository, cleanupBare := schedulerTestRepository(t)
	defer cleanupBare()
	bare, err := New(Options{Repository: &repositoryWithoutCancellation{Repository: bareRepository}, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Shutdown(context.Background())
	if _, err := bare.RequestCancellation(context.Background(), cancellationRequest("unsupported")); !errors.Is(err, jobs.ErrCancellationUnsupported) {
		t.Fatalf("unsupported repository error=%v", err)
	}
}

func TestSchedulerHistoricalCanceledReplayIsIdempotent(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	job := schedulerTestJob("cancel-historical-replay", jobs.TypeValidation)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := repository.RequestCancellation(context.Background(), job.ID, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	terminal := requested.Job
	terminal.Status = jobs.StatusCanceled
	finished := fixedSchedulerNow().UTC()
	terminal.FinishedAt = &finished
	if _, err := repository.Put(context.Background(), job.ID, terminal, requested.ETag); err != nil {
		t.Fatal(err)
	}
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	projection, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if err != nil {
		t.Fatalf("historical replay error=%v", err)
	}
	if projection.Status != jobs.StatusCanceled || errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("historical replay projection=%#v health=%v", projection, scheduler.Health())
	}
}

func TestSchedulerConcurrentCancellationRequestsReplaySafely(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-concurrent", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	const requests = 16
	var group sync.WaitGroup
	errorsFound := make(chan error, requests)
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, requestErr := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
			if requestErr != nil {
				errorsFound <- requestErr
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for requestErr := range errorsFound {
		t.Errorf("concurrent cancellation error=%v", requestErr)
	}
	waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled)
	if scheduler.Health() != nil {
		t.Fatalf("concurrent cancellation health=%v", scheduler.Health())
	}
}

func TestSchedulerRequestCancellationValidationShutdownAndSafeFailure(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	job := schedulerTestJob("cancel-validation", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	cases := []jobs.CancellationRequest{
		{JobID: job.ID, ActorSubject: "", RequestID: "request-1"},
		{JobID: job.ID, ActorSubject: " actor ", RequestID: "request-1"},
		{JobID: job.ID, ActorSubject: "bad\nsubject", RequestID: "request-1"},
		{JobID: job.ID, ActorSubject: strings.Repeat("a", 257), RequestID: "request-1"},
		{JobID: job.ID, ActorSubject: "actor", RequestID: "bad request"},
	}
	for _, request := range cases {
		if _, err := scheduler.RequestCancellation(context.Background(), request); !errors.Is(err, ErrInvalidCancellationRequest) {
			t.Errorf("request=%#v error=%v", request, err)
		}
	}
	if _, err := scheduler.RequestCancellation(context.Background(), jobs.CancellationRequest{JobID: "missing", ActorSubject: "actor", RequestID: "request-1"}); !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scheduler.RequestCancellation(ctx, cancellationRequest(job.ID)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request error=%v", err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID)); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("shutdown cancellation error=%v", err)
	}
}

func TestSchedulerRequestCancellationRejectsUnownedDurableWork(t *testing.T) {
	for _, status := range []jobs.Status{jobs.StatusQueued, jobs.StatusRunning} {
		t.Run(string(status), func(t *testing.T) {
			repository, cleanup := schedulerTestRepository(t)
			defer cleanup()
			job := schedulerTestJob("cancel-unowned-"+string(status), jobs.TypeValidation)
			created, err := repository.Create(context.Background(), job)
			if err != nil {
				t.Fatal(err)
			}
			if status == jobs.StatusRunning {
				running := job
				running.Status = jobs.StatusRunning
				started := job.CreatedAt.Add(time.Minute)
				running.StartedAt = &started
				if _, err := repository.Put(context.Background(), job.ID, running, created.ETag); err != nil {
					t.Fatal(err)
				}
			}
			scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
			if err != nil {
				t.Fatal(err)
			}
			defer scheduler.Shutdown(context.Background())
			_, err = scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
			if !errors.Is(err, ErrPersistenceFailure) || !errors.Is(scheduler.Health(), ErrUnhealthy) {
				t.Fatalf("status=%s error=%v health=%v", status, err, scheduler.Health())
			}
		})
	}
}

func TestSchedulerRequestCancellationUnexpectedPersistenceMakesUnhealthy(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	wrapped := &requestCancellationErrorRepository{Repository: repository, err: errors.New("CANCELLATION_STORAGE_SENTINEL")}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("cancel-storage-failure", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	_, err = scheduler.RequestCancellation(context.Background(), cancellationRequest(job.ID))
	if !errors.Is(err, ErrPersistenceFailure) || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("request error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("health=%v", scheduler.Health())
	}
}

func assertSchedulerMarkersEmpty(t *testing.T, scheduler *Scheduler, id string) {
	t.Helper()
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		t.Fatalf("acquire scheduler admission: %v", err)
	}
	defer scheduler.releaseAdmission()
	if _, ok := scheduler.active[id]; ok {
		t.Fatalf("active marker remains for %s", id)
	}
	if _, ok := scheduler.claimed[id]; ok {
		t.Fatalf("claimed marker remains for %s", id)
	}
	if _, ok := scheduler.dequeued[id]; ok {
		t.Fatalf("dequeued marker remains for %s", id)
	}
	if _, ok := scheduler.owned[id]; ok {
		t.Fatalf("owned marker remains for %s", id)
	}
}

func assertSchedulerMarkerMapsEmpty(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	if err := scheduler.acquireAdmission(context.Background()); err != nil {
		t.Fatalf("acquire scheduler admission: %v", err)
	}
	defer scheduler.releaseAdmission()
	if len(scheduler.active) != 0 || len(scheduler.claimed) != 0 || len(scheduler.dequeued) != 0 || len(scheduler.owned) != 0 {
		t.Fatalf("scheduler markers active=%d claimed=%d dequeued=%d owned=%d", len(scheduler.active), len(scheduler.claimed), len(scheduler.dequeued), len(scheduler.owned))
	}
}

type repositoryWithoutCancellation struct{ Repository }

type countingCancellationRepository struct {
	Repository
	putCalls        atomic.Int32
	requestCalls    atomic.Int32
	queuedRequested atomic.Bool
}

func (repository *countingCancellationRepository) reset() {
	repository.putCalls.Store(0)
	repository.requestCalls.Store(0)
	repository.queuedRequested.Store(false)
}

func (repository *countingCancellationRepository) Put(ctx context.Context, id string, job state.Job, etag string) (jobrecord.Record, error) {
	repository.putCalls.Add(1)
	if job.Status == jobs.StatusQueued && job.CancellationRequested {
		repository.queuedRequested.Store(true)
	}
	return repository.Repository.Put(ctx, id, job, etag)
}

func (repository *countingCancellationRepository) RequestCancellation(ctx context.Context, id, etag string) (jobrecord.Record, error) {
	repository.requestCalls.Add(1)
	return repository.Repository.(CancellationRepository).RequestCancellation(ctx, id, etag)
}

type requestCancellationErrorRepository struct {
	Repository
	err error
}

func (repository *requestCancellationErrorRepository) RequestCancellation(context.Context, string, string) (jobrecord.Record, error) {
	return jobrecord.Record{}, repository.err
}

type interceptCancellationRepository struct {
	Repository
	beforeRequest func(string, string)
	once          sync.Once
}

func (repository *interceptCancellationRepository) RequestCancellation(ctx context.Context, id, etag string) (jobrecord.Record, error) {
	repository.once.Do(func() {
		if repository.beforeRequest != nil {
			repository.beforeRequest(id, etag)
		}
	})
	return repository.Repository.(CancellationRepository).RequestCancellation(ctx, id, etag)
}

type changedTerminalGetRepository struct {
	Repository
	id                string
	mutate            atomic.Bool
	mutateReportID    atomic.Bool
	beforeRequest     func(string, string)
	requestOnce       sync.Once
	beforeTerminalPut func(string)
	terminalPutOnce   sync.Once
}

func (repository *changedTerminalGetRepository) Get(ctx context.Context, id string) (jobrecord.Record, error) {
	record, err := repository.Repository.Get(ctx, id)
	if err != nil || id != repository.id || (!repository.mutate.Load() && !repository.mutateReportID.Load()) || record.Job.Status != jobs.StatusCanceled {
		return record, err
	}
	if repository.mutateReportID.Load() {
		record.Job.ReportID = "report-changed"
	} else {
		record.Job.PlanID = "plan-changed"
	}
	encoded, err := state.EncodeJob(record.Job)
	if err != nil {
		return jobrecord.Record{}, err
	}
	digest := sha256.Sum256(encoded)
	record.ETag = hex.EncodeToString(digest[:])
	return record, nil
}

func (repository *changedTerminalGetRepository) Put(ctx context.Context, id string, job state.Job, etag string) (jobrecord.Record, error) {
	if repository.beforeTerminalPut != nil && id == repository.id && terminalStatus(job.Status) {
		repository.terminalPutOnce.Do(func() { repository.beforeTerminalPut(id) })
	}
	return repository.Repository.Put(ctx, id, job, etag)
}

func (repository *changedTerminalGetRepository) RequestCancellation(ctx context.Context, id, etag string) (jobrecord.Record, error) {
	repository.requestOnce.Do(func() {
		if repository.beforeRequest != nil {
			repository.beforeRequest(id, etag)
		}
	})
	return repository.Repository.(CancellationRepository).RequestCancellation(ctx, id, etag)
}

type missingGetRepository struct {
	Repository
	id      string
	missing atomic.Bool
}

func (repository *missingGetRepository) Get(ctx context.Context, id string) (jobrecord.Record, error) {
	if repository.missing.Load() && id == repository.id {
		return jobrecord.Record{}, jobs.ErrNotFound
	}
	return repository.Repository.Get(ctx, id)
}

func (repository *missingGetRepository) RequestCancellation(ctx context.Context, id, etag string) (jobrecord.Record, error) {
	return repository.Repository.(CancellationRepository).RequestCancellation(ctx, id, etag)
}

type cancellationRaceRepository struct {
	Repository
	claimed chan struct{}
	release chan struct{}
	once    sync.Once
}

func (repository *cancellationRaceRepository) RequestCancellation(ctx context.Context, id, etag string) (jobrecord.Record, error) {
	return repository.Repository.(CancellationRepository).RequestCancellation(ctx, id, etag)
}

func (repository *cancellationRaceRepository) Put(ctx context.Context, id string, job state.Job, etag string) (jobrecord.Record, error) {
	if job.Status == jobs.StatusRunning {
		repository.once.Do(func() {
			close(repository.claimed)
			<-repository.release
		})
	}
	return repository.Repository.Put(ctx, id, job, etag)
}
