package jobscheduler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

var schedulerTestTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestSchedulerLifecycleAndResultRules(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	now := schedulerTestTime.Add(10 * time.Minute)
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())

	job := schedulerTestJob("result-success", jobs.TypePlan)
	var got state.Job
	accepted, err := scheduler.Submit(context.Background(), Submission{
		Job: job,
		Executor: func(_ context.Context, running state.Job) ExecutionResult {
			got = running
			return ExecutionResult{Outcome: ExecutionSucceeded, PlanID: "plan-result"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ID != job.ID || accepted.Status != jobs.StatusQueued {
		t.Fatalf("accepted=%#v", accepted)
	}
	record := waitForSchedulerStatus(t, repository, job.ID, jobs.StatusSucceeded)
	if got.Status != jobs.StatusRunning || got.StartedAt == nil {
		t.Fatalf("executor did not receive defensive running copy: %#v", got)
	}
	if record.Job.PlanID != "plan-result" || !reflect.DeepEqual(record.Job.Actor, job.Actor) || record.Job.RequestID != job.RequestID || record.Job.IdempotencyKey != job.IdempotencyKey {
		t.Fatalf("metadata/link preservation: %#v", record.Job)
	}
	if record.Job.FinishedAt == nil || record.Job.FinishedAt.Location() != time.UTC || !record.Job.FinishedAt.Equal(now) {
		t.Fatalf("finish time=%v", record.Job.FinishedAt)
	}

	failed := schedulerTestJob("result-failed", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: failed, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionFailed, FailureCode: "remote_unavailable"}
	}}); err != nil {
		t.Fatal(err)
	}
	failedRecord := waitForSchedulerStatus(t, repository, failed.ID, jobs.StatusFailed)
	if failedRecord.Job.FailureCode != "remote_unavailable" || failedRecord.Job.PlanID != "" {
		t.Fatalf("failed result=%#v", failedRecord.Job)
	}

	panicJob := schedulerTestJob("result-panic", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: panicJob, Executor: func(context.Context, state.Job) ExecutionResult {
		panic("PANIC-SENTINEL")
	}}); err != nil {
		t.Fatal(err)
	}
	panicRecord := waitForSchedulerStatus(t, repository, panicJob.ID, jobs.StatusFailed)
	if panicRecord.Job.FailureCode != FailureCodeExecutorPanic || strings.Contains(panicRecord.Job.FailureCode, "PANIC-SENTINEL") {
		t.Fatalf("panic result=%#v", panicRecord.Job)
	}

	invalidJob := schedulerTestJob("result-invalid", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: invalidJob, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionOutcome(jobs.StatusCanceled), FailureCode: "secret-message"}
	}}); err != nil {
		t.Fatal(err)
	}
	invalidRecord := waitForSchedulerStatus(t, repository, invalidJob.ID, jobs.StatusFailed)
	if invalidRecord.Job.FailureCode != FailureCodeExecutorResultInvalid {
		t.Fatalf("invalid result=%#v", invalidRecord.Job)
	}

	badLinkJob := schedulerTestJob("result-bad-link", jobs.TypePlan)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: badLinkJob, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded, PlanID: ":"}
	}}); err != nil {
		t.Fatal(err)
	}
	badLinkRecord := waitForSchedulerStatus(t, repository, badLinkJob.ID, jobs.StatusFailed)
	if badLinkRecord.Job.FailureCode != FailureCodeExecutorResultInvalid || errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("bad link result=%#v health=%v", badLinkRecord.Job, scheduler.Health())
	}
}

func TestSchedulerAdmissionContextAndCapacity(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	release := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())

	first := schedulerTestJob("capacity-first", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: first, Executor: func(context.Context, state.Job) ExecutionResult {
		close(started)
		<-release
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started

	second := schedulerTestJob("capacity-second", jobs.TypeValidation)
	requestCanceled := make(chan struct{})
	requestCtx, cancel := context.WithCancel(context.Background())
	if _, err := scheduler.Submit(requestCtx, Submission{Job: second, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	cancel()
	close(requestCanceled)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("capacity-third", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third admission error=%v", err)
	}
	if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("capacity-pre-canceled", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueFull) {
		// The capacity assertion above intentionally keeps the two slots full;
		// this branch is only to avoid conflating pre-cancel behavior with a
		// slot result in this test.
		t.Fatalf("full admission error=%v", err)
	}
	close(release)
	waitForSchedulerStatus(t, repository, first.ID, jobs.StatusSucceeded)
	waitForSchedulerStatus(t, repository, second.ID, jobs.StatusSucceeded)

	preCanceled := schedulerTestJob("pre-canceled", jobs.TypeValidation)
	ctx, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	if _, err := scheduler.Submit(ctx, Submission{Job: preCanceled, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled error=%v", err)
	}
	if _, err := repository.Get(context.Background(), preCanceled.ID); !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("pre-canceled durable record error=%v", err)
	}
	_ = requestCanceled
}

func TestSchedulerDuplicateAdmissionReleasesSlot(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	duplicate := schedulerTestJob("duplicate-id", jobs.TypeValidation)
	if _, err := repository.Create(context.Background(), duplicate); err != nil {
		t.Fatal(err)
	}
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	if _, err := scheduler.Submit(context.Background(), Submission{Job: duplicate, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("duplicate executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	accepted := schedulerTestJob("after-duplicate", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: accepted, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatalf("after duplicate error=%v", err)
	}
	waitForSchedulerStatus(t, repository, accepted.ID, jobs.StatusSucceeded)
}

func TestSchedulerShutdownCancelsRunningAndQueuedAndIsIdempotent(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	running := schedulerTestJob("shutdown-running", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: running, Executor: func(ctx context.Context, _ state.Job) ExecutionResult {
		close(started)
		<-ctx.Done()
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	queued := schedulerTestJob("shutdown-queued", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: queued, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("queued executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{running.ID, queued.ID} {
		record, err := repository.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if record.Job.Status != jobs.StatusCanceled || record.Job.FailureCode != "" || record.Job.FinishedAt == nil {
			t.Fatalf("shutdown %s=%#v", id, record.Job)
		}
	}
	if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("after-close", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("after-close error=%v", err)
	}
}

func TestSchedulerWorkerConcurrency(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 2, QueueCapacity: 2, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())

	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	for index := 0; index < 4; index++ {
		job := schedulerTestJob(fmt.Sprintf("worker-bound-%d", index), jobs.TypeValidation)
		if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			started <- struct{}{}
			<-release
			active.Add(-1)
			return ExecutionResult{Outcome: ExecutionSucceeded}
		}}); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 2; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrency=%d, want 2", got)
	}
	close(release)
	for index := 0; index < 4; index++ {
		waitForSchedulerStatus(t, repository, fmt.Sprintf("worker-bound-%d", index), jobs.StatusSucceeded)
	}
}

func TestSchedulerShutdownWaitsForInFlightAdmission(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	entered := make(chan struct{})
	release := make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, createWait: func() {
		close(entered)
		<-release
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	job := schedulerTestJob("admission-shutdown", jobs.TypeValidation)
	submitDone := make(chan error, 1)
	go func() {
		_, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
			return ExecutionResult{Outcome: ExecutionSucceeded}
		}})
		submitDone <- err
	}()
	<-entered
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	shutdownErr := scheduler.Shutdown(shutdownContext)
	cancel()
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("bounded shutdown error=%v", shutdownErr)
	}
	close(release)
	if err := <-submitDone; err != nil {
		t.Fatalf("in-flight submit=%v", err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if record := waitForSchedulerStatus(t, repository, job.ID, jobs.StatusCanceled); record.Job.Status != jobs.StatusCanceled {
		t.Fatalf("admission-shutdown=%#v", record.Job)
	}
}

func TestSchedulerStaleCASDoesNotExecuteOrOverwrite(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	intercepted := make(chan struct{})
	released := make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, beforeFirstPut: func(record jobrecord.Record) {
		if record.Job.Status != jobs.StatusRunning {
			return
		}
		queued, err := repository.Get(context.Background(), record.Job.ID)
		if err != nil {
			panic(err)
		}
		external := queued.Job
		external.Status = jobs.StatusRunning
		started := fixedSchedulerNow().UTC()
		external.StartedAt = &started
		if _, err := repository.Put(context.Background(), external.ID, external, queued.ETag); err != nil {
			panic(err)
		}
		close(intercepted)
		<-released
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("stale-start", jobs.TypeValidation)
	var executions atomic.Int32
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		executions.Add(1)
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-intercepted
	close(released)
	// The external running record is authoritative; this scheduler must not
	// execute it or turn it into a terminal record.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if executions.Load() != 0 {
		t.Fatalf("stale start executions=%d", executions.Load())
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("stale start health=%v", scheduler.Health())
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusRunning {
		t.Fatalf("stale start record=%#v", record.Job)
	}
}

func TestSchedulerPersistenceFailureIsSafeAndFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCreateRepository{Repository: repository, createErr: errors.New("SECRET-PERSISTENCE-SENTINEL")}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	_, err = scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("fatal-create", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if !errors.Is(err, ErrPersistenceFailure) || strings.Contains(err.Error(), "SECRET-PERSISTENCE-SENTINEL") {
		t.Fatalf("persistence error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("health=%v", scheduler.Health())
	}
	if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("fatal-after", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("post-fatal admission=%v", err)
	}
}

func TestSchedulerCASNotFoundIsFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCreateRepository{Repository: repository, putErr: jobs.ErrNotFound}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	job := schedulerTestJob("cas-not-found", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		t.Error("CAS-not-found executor ran")
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("health=%v", scheduler.Health())
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerConcurrentSubmissions(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 8, QueueCapacity: 64, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	const count = 48
	var group sync.WaitGroup
	var accepted atomic.Int32
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			id := fmt.Sprintf("concurrent-%02d", index)
			if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob(id, jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
				return ExecutionResult{Outcome: ExecutionSucceeded}
			}}); err == nil {
				accepted.Add(1)
			} else {
				t.Errorf("submit %s: %v", id, err)
			}
		}(index)
	}
	group.Wait()
	if accepted.Load() != count {
		t.Fatalf("accepted=%d", accepted.Load())
	}
	for index := 0; index < count; index++ {
		waitForSchedulerStatus(t, repository, fmt.Sprintf("concurrent-%02d", index), jobs.StatusSucceeded)
	}
}

func TestSchedulerCanceledShutdownStillClosesAdmission(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := scheduler.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled shutdown error=%v", err)
	}
	if _, err := scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("after-canceled-shutdown", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("post-canceled-shutdown submit=%v", err)
	}
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerFinishUnderAdmissionLinearizesBeforeShutdown(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	terminalEntered := make(chan struct{})
	releaseTerminal := make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, beforeTerminalPut: func(string, state.Job, string) {
		close(terminalEntered)
		<-releaseTerminal
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("finish-before-stop", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-terminalEntered
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- scheduler.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown completed before in-flight terminal Put: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseTerminal)
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusSucceeded {
		t.Fatalf("finish-before-stop=%#v", record.Job)
	}
}

func TestSchedulerPersistenceTimeoutIsFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCreateRepository{Repository: repository, createContextWait: func(ctx context.Context) {
		<-ctx.Done()
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	_, err = scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("persistence-timeout", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if !errors.Is(err, ErrPersistenceFailure) {
		t.Fatalf("persistence timeout error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("persistence timeout health=%v", scheduler.Health())
	}
}

func TestSchedulerSubmitDeadlineIsPreserved(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCreateRepository{Repository: repository, createContextWait: func(ctx context.Context) {
		<-ctx.Done()
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err = scheduler.Submit(ctx, Submission{Job: schedulerTestJob("submit-deadline", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("submit deadline error=%v", err)
	}
	if scheduler.Health() != nil {
		t.Fatalf("submit deadline health=%v", scheduler.Health())
	}
}

func TestSchedulerCallerCancellationCannotMaskStorageFailure(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	entered, release := make(chan struct{}), make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, createWait: func() { close(entered); <-release }, createErr: errors.New("STORAGE-SENTINEL")}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, submitErr := scheduler.Submit(ctx, Submission{Job: schedulerTestJob("cancel-storage-race", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult { return ExecutionResult{Outcome: ExecutionSucceeded} }})
		result <- submitErr
	}()
	<-entered
	cancel()
	close(release)
	if err := <-result; !errors.Is(err, ErrPersistenceFailure) || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("health=%v", scheduler.Health())
	}
}

func TestSchedulerRejectsInvalidInitialLifecycleFields(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	for name, mutate := range map[string]func(*state.Job){"cancellation": func(job *state.Job) { job.CancellationRequested = true }, "validation plan link": func(job *state.Job) { job.PlanID = "plan-invalid" }} {
		t.Run(name, func(t *testing.T) {
			job := schedulerTestJob("invalid-initial-"+strings.ReplaceAll(name, " ", "-"), jobs.TypeValidation)
			mutate(&job)
			if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult { return ExecutionResult{Outcome: ExecutionSucceeded} }}); !errors.Is(err, ErrInvalidSubmission) {
				t.Fatalf("error=%v", err)
			}
			if _, err := repository.Get(context.Background(), job.ID); !errors.Is(err, jobs.ErrNotFound) {
				t.Fatalf("stored invalid job: %v", err)
			}
		})
	}
}

func TestSchedulerLifecyclePersistenceTimeoutIsFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	wrapped := &interceptCreateRepository{Repository: repository, putContextWait: func(ctx context.Context) { <-ctx.Done() }}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("lifecycle-timeout", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult { return ExecutionResult{Outcome: ExecutionSucceeded} }}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("health=%v", scheduler.Health())
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil || record.Job.Status != jobs.StatusQueued {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestSchedulerPersistenceTimeoutBounds(t *testing.T) {
	for _, timeout := range []time.Duration{time.Millisecond, time.Minute} {
		repository, cleanup := schedulerTestRepository(t)
		scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: timeout})
		if err != nil {
			cleanup()
			t.Fatalf("timeout=%v: %v", timeout, err)
		}
		if err := scheduler.Shutdown(context.Background()); err != nil {
			cleanup()
			t.Fatalf("timeout=%v shutdown: %v", timeout, err)
		}
		cleanup()
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, time.Microsecond, time.Minute + time.Nanosecond} {
		repository, cleanup := schedulerTestRepository(t)
		if _, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: timeout}); !errors.Is(err, ErrInvalidOptions) {
			cleanup()
			t.Fatalf("timeout=%v error=%v", timeout, err)
		}
		cleanup()
	}
}

func TestSchedulerLateCreateSuccessAfterTimeoutIsFatal(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: &lateCreateRepository{Repository: repository}, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow, PersistenceTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("late-create-success", jobs.TypeValidation)
	_, err = scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if !errors.Is(err, ErrPersistenceFailure) || !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("late create error=%v health=%v", err, scheduler.Health())
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusQueued {
		t.Fatalf("late create record=%#v", record.Job)
	}
}

func TestSchedulerUnknownCreateOutcomeLeavesQueuedRecordForRecovery(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	scheduler, err := New(Options{Repository: &unknownCreateOutcomeRepository{Repository: repository}, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("unknown-create-outcome", jobs.TypeValidation)
	_, err = scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}})
	if !errors.Is(err, ErrPersistenceFailure) || strings.Contains(err.Error(), "POST-RENAME-SENTINEL") {
		t.Fatalf("unknown create error=%v", err)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("unknown create health=%v", scheduler.Health())
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusQueued {
		t.Fatalf("unknown create record=%#v", record.Job)
	}
}

func TestSchedulerMalformedCreateETagIsFatal(t *testing.T) {
	for _, etag := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), "short"} {
		t.Run(fmt.Sprintf("etag-%q", etag), func(t *testing.T) {
			repository, cleanup := schedulerTestRepository(t)
			defer cleanup()
			scheduler, err := New(Options{Repository: &fixedCreateRepository{Repository: repository, etag: etag}, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
			if err != nil {
				t.Fatal(err)
			}
			defer scheduler.Shutdown(context.Background())
			_, err = scheduler.Submit(context.Background(), Submission{Job: schedulerTestJob("malformed-etag", jobs.TypeValidation), Executor: func(context.Context, state.Job) ExecutionResult {
				return ExecutionResult{Outcome: ExecutionSucceeded}
			}})
			if !errors.Is(err, ErrPersistenceFailure) || !errors.Is(scheduler.Health(), ErrUnhealthy) {
				t.Fatalf("etag=%q error=%v health=%v", etag, err, scheduler.Health())
			}
		})
	}
}

func TestSchedulerFinishETagMismatchMakesHealthUnhealthy(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	mutated := make(chan struct{})
	wrapped := &interceptCreateRepository{Repository: repository, beforeTerminalPut: func(id string, _ state.Job, _ string) {
		current, err := repository.Get(context.Background(), id)
		if err == nil {
			external := current.Job
			external.Status = jobs.StatusSucceeded
			finished := fixedSchedulerNow().UTC()
			external.FinishedAt = &finished
			_, _ = repository.Put(context.Background(), id, external, current.ETag)
		}
		close(mutated)
	}}
	scheduler, err := New(Options{Repository: wrapped, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	defer scheduler.Shutdown(context.Background())
	job := schedulerTestJob("finish-stale-etag", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-mutated
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !errors.Is(scheduler.Health(), ErrUnhealthy) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(scheduler.Health(), ErrUnhealthy) {
		t.Fatalf("stale finish health=%v", scheduler.Health())
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusSucceeded {
		t.Fatalf("stale finish record=%#v", record.Job)
	}
}

func TestSchedulerNonCooperativeExecutorShutdownCanBeRetried(t *testing.T) {
	repository, cleanup := schedulerTestRepository(t)
	defer cleanup()
	started := make(chan struct{})
	release := make(chan struct{})
	scheduler, err := New(Options{Repository: repository, Workers: 1, QueueCapacity: 1, Now: fixedSchedulerNow})
	if err != nil {
		t.Fatal(err)
	}
	job := schedulerTestJob("noncooperative-shutdown", jobs.TypeValidation)
	if _, err := scheduler.Submit(context.Background(), Submission{Job: job, Executor: func(context.Context, state.Job) ExecutionResult {
		close(started)
		<-release
		return ExecutionResult{Outcome: ExecutionSucceeded}
	}}); err != nil {
		t.Fatal(err)
	}
	<-started
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	shutdownErr := scheduler.Shutdown(shutdownContext)
	cancel()
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Fatalf("noncooperative shutdown error=%v", shutdownErr)
	}
	close(release)
	if err := scheduler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, err := repository.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Job.Status != jobs.StatusCanceled {
		t.Fatalf("noncooperative shutdown record=%#v", record.Job)
	}
}

func schedulerTestRepository(t *testing.T) (*jobrecord.FileRepository, func()) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := jobrecord.New(store)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return repository, func() { _ = store.Close() }
}

func schedulerTestJob(id string, jobType jobs.Type) state.Job {
	job := state.Job{
		APIVersion:     state.APIVersion,
		Kind:           state.KindJob,
		ID:             id,
		Type:           jobType,
		Status:         jobs.StatusQueued,
		CreatedAt:      schedulerTestTime,
		Actor:          state.Actor{Subject: "operator@example.test", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC},
		RequestID:      "request-" + id,
		IdempotencyKey: "idempotency-" + id,
		RequestDigest:  strings.Repeat("a", 64),
	}
	if jobType == jobs.TypeApply {
		job.PlanID = "plan-existing"
	}
	return job
}

func fixedSchedulerNow() time.Time { return schedulerTestTime.Add(10 * time.Minute) }

func waitForSchedulerStatus(t *testing.T, repository *jobrecord.FileRepository, id string, status jobs.Status) jobrecord.Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		record, err := repository.Get(context.Background(), id)
		if err == nil && record.Job.Status == status {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	record, err := repository.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("wait %s: %v", id, err)
	}
	t.Fatalf("wait %s status=%s want=%s", id, record.Job.Status, status)
	return jobrecord.Record{}
}

type lateCreateRepository struct {
	Repository
}

func (repository *lateCreateRepository) Create(ctx context.Context, job state.Job) (jobrecord.Record, error) {
	<-ctx.Done()
	return repository.Repository.Create(context.Background(), job)
}

type unknownCreateOutcomeRepository struct {
	Repository
}

func (repository *unknownCreateOutcomeRepository) Create(ctx context.Context, job state.Job) (jobrecord.Record, error) {
	record, err := repository.Repository.Create(ctx, job)
	if err != nil {
		return record, err
	}
	return record, errors.New("POST-RENAME-SENTINEL")
}

type fixedCreateRepository struct {
	Repository
	etag string
}

func (repository *fixedCreateRepository) Create(_ context.Context, job state.Job) (jobrecord.Record, error) {
	return jobrecord.Record{Job: job, ETag: repository.etag}, nil
}

type interceptCreateRepository struct {
	Repository
	createErr         error
	putErr            error
	createWait        func()
	createContextWait func(context.Context)
	beforeFirstPut    func(jobrecord.Record)
	beforeTerminalPut func(string, state.Job, string)
	putContextWait    func(context.Context)
	putOnce           sync.Once
	terminalPutOnce   sync.Once
}

func (repository *interceptCreateRepository) Create(ctx context.Context, job state.Job) (jobrecord.Record, error) {
	if repository.createWait != nil {
		repository.createWait()
	}
	if repository.createContextWait != nil {
		repository.createContextWait(ctx)
	}
	if repository.createErr != nil {
		return jobrecord.Record{}, repository.createErr
	}
	return repository.Repository.Create(ctx, job)
}

func (repository *interceptCreateRepository) Put(ctx context.Context, id string, job state.Job, etag string) (jobrecord.Record, error) {
	if repository.putContextWait != nil {
		repository.putContextWait(ctx)
	}
	if repository.beforeFirstPut != nil {
		var callback bool
		repository.putOnce.Do(func() { callback = true })
		if callback {
			record := jobrecord.Record{Job: job, ETag: etag}
			repository.beforeFirstPut(record)
		}
	}
	if repository.beforeTerminalPut != nil && (job.Status == jobs.StatusSucceeded || job.Status == jobs.StatusFailed || job.Status == jobs.StatusCanceled || job.Status == jobs.StatusInterrupted) {
		var callback bool
		repository.terminalPutOnce.Do(func() { callback = true })
		if callback {
			repository.beforeTerminalPut(id, job, etag)
		}
	}
	if repository.putErr != nil {
		return jobrecord.Record{}, repository.putErr
	}
	return repository.Repository.Put(ctx, id, job, etag)
}
