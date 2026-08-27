package jobrecord

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/jobrecovery"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

func TestInterruptQueuedPreservesMetadataAndClearsOnlyLifecycleFields(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-queued", jobTestTime, jobs.StatusQueued)
	queued.Type = jobs.TypeApply
	queued.PlanID = "plan-link"
	queued.CancellationRequested = false
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	finished := jobTestTime.Add(time.Minute)
	interrupted, err := repository.Interrupt(context.Background(), queued.ID, created.ETag, finished, jobrecovery.FailureCodeApplyQueued)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.Job.Status != jobs.StatusInterrupted || interrupted.Job.FailureCode != string(jobrecovery.FailureCodeApplyQueued) {
		t.Fatalf("interrupted=%#v", interrupted.Job)
	}
	if interrupted.Job.StartedAt != nil {
		t.Fatal("queued interruption claimed a start time")
	}
	if interrupted.Job.FinishedAt == nil || !interrupted.Job.FinishedAt.Equal(finished) || interrupted.Job.FinishedAt.Location() != time.UTC {
		t.Fatalf("finishedAt=%#v", interrupted.Job.FinishedAt)
	}
	want := queued
	want.Status = jobs.StatusInterrupted
	want.FinishedAt = &finished
	want.FailureCode = string(jobrecovery.FailureCodeApplyQueued)
	if !reflect.DeepEqual(interrupted.Job, want) {
		t.Fatalf("metadata changed: got=%#v want=%#v", interrupted.Job, want)
	}
	if got, err := repository.Get(context.Background(), queued.ID); err != nil || !reflect.DeepEqual(got, interrupted) {
		t.Fatalf("stored interrupted=%#v err=%v", got, err)
	}
}

func TestInterruptRunningPreservesStartedAtCancellationAndApplyLinks(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-running", jobTestTime, jobs.StatusQueued)
	queued.Type = jobs.TypeApply
	queued.PlanID = "plan-apply"
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	started := jobTestTime.Add(time.Minute)
	running := queued
	running.Status = jobs.StatusRunning
	running.StartedAt = &started
	running.CancellationRequested = true
	runningRecord, err := repository.Put(context.Background(), running.ID, running, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	bypass := running
	bypass.Status = jobs.StatusInterrupted
	bypass.FinishedAt = &started
	bypass.FailureCode = "bypass"
	if _, err := repository.Put(context.Background(), bypass.ID, bypass, runningRecord.ETag); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("direct Put interruption error=%v", err)
	}
	finished := jobTestTime.Add(2 * time.Minute)
	interrupted, err := repository.Interrupt(context.Background(), running.ID, runningRecord.ETag, finished, jobrecovery.FailureCodeApplyRunning)
	if err != nil {
		t.Fatal(err)
	}
	if interrupted.Job.Type != jobs.TypeApply || interrupted.Job.PlanID != queued.PlanID {
		t.Fatalf("apply metadata=%#v", interrupted.Job)
	}
	if interrupted.Job.StartedAt == nil || !interrupted.Job.StartedAt.Equal(started) || interrupted.Job.StartedAt.Location() != time.UTC {
		t.Fatalf("startedAt=%#v", interrupted.Job.StartedAt)
	}
	if !interrupted.Job.CancellationRequested {
		t.Fatal("Interrupt cleared cancellationRequested")
	}
}

func TestInterruptRejectsTerminalAndRepeatedCallsWithoutWrite(t *testing.T) {
	repository, store, _ := testRepository(t)
	queued := testJob("interrupt-terminal", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	started := jobTestTime.Add(time.Minute)
	running := queued
	running.Status = jobs.StatusRunning
	running.StartedAt = &started
	runningRecord, err := repository.Put(context.Background(), queued.ID, running, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	finished := jobTestTime.Add(2 * time.Minute)
	terminal := running
	terminal.Status = jobs.StatusSucceeded
	terminal.FinishedAt = &finished
	terminalRecord, err := repository.Put(context.Background(), queued.ID, terminal, runningRecord.ETag)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(statefs.JobsDir + "/" + queued.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Interrupt(context.Background(), queued.ID, terminalRecord.ETag, finished.Add(time.Minute), jobrecovery.FailureCodeQueued); !errors.Is(err, jobs.ErrInvalidTransition) {
		t.Fatalf("terminal interruption error=%v", err)
	}
	after, err := store.Read(statefs.JobsDir + "/" + queued.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("terminal interruption changed stored bytes")
	}
	if _, err := repository.Interrupt(context.Background(), queued.ID, created.ETag, finished, jobrecovery.FailureCodeQueued); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("repeated stale interruption error=%v", err)
	}
}

func TestInterruptMapsMissingAndInvalidIDsSafely(t *testing.T) {
	repository, _, _ := testRepository(t)
	for _, id := range []string{"missing", "", "../escape", "OIDC_TOKEN_SENTINEL"} {
		if _, err := repository.Interrupt(context.Background(), id, "etag", jobTestTime, jobrecovery.FailureCodeQueued); !errors.Is(err, jobs.ErrNotFound) {
			t.Errorf("id %q error=%v", id, err)
		}
	}
}

func TestInterruptRejectsTimestampAndFailureCodeBeforeWrite(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-invalid-input", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		finished time.Time
		code     string
	}{
		"zero finish":                 {finished: time.Time{}, code: string(jobrecovery.FailureCodeQueued)},
		"non UTC finish":              {finished: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("offset", 3600)), code: string(jobrecovery.FailureCodeQueued)},
		"before creation":             {finished: jobTestTime.Add(-time.Nanosecond), code: string(jobrecovery.FailureCodeQueued)},
		"empty code":                  {finished: jobTestTime, code: ""},
		"unsafe code":                 {finished: jobTestTime, code: "not a safe code"},
		"unbounded code":              {finished: jobTestTime, code: strings.Repeat("x", 129)},
		"secret-bearing invalid code": {finished: jobTestTime, code: "bad\nOIDC_TOKEN_SENTINEL"},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := repository.Interrupt(context.Background(), queued.ID, created.ETag, value.finished, jobrecovery.FailureCode(value.code))
			if !errors.Is(err, state.ErrInvalidDocument) {
				t.Fatalf("error=%v, want state validation error", err)
			}
			if strings.Contains(err.Error(), "OIDC_TOKEN_SENTINEL") {
				t.Fatalf("error exposed secret sentinel: %v", err)
			}
			got, getErr := repository.Get(context.Background(), queued.ID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if got.ETag != created.ETag || !reflect.DeepEqual(got.Job, queued) {
				t.Fatalf("invalid input changed record=%#v", got)
			}
		})
	}
}

func TestInterruptRejectsFinishBeforeRunningStart(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-before-start", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	started := jobTestTime.Add(time.Minute)
	running := queued
	running.Status = jobs.StatusRunning
	running.StartedAt = &started
	runningRecord, err := repository.Put(context.Background(), running.ID, running, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Interrupt(context.Background(), running.ID, runningRecord.ETag, started.Add(-time.Nanosecond), jobrecovery.FailureCodeRunning); !errors.Is(err, state.ErrInvalidDocument) {
		t.Fatalf("error=%v", err)
	}
}

func TestInterruptRejectsMismatchedPolicyCode(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-wrong-code", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Interrupt(context.Background(), queued.ID, created.ETag, jobTestTime, jobrecovery.FailureCodeRunning); !errors.Is(err, jobrecovery.ErrInvalidFailureCode) {
		t.Fatalf("error=%v", err)
	}
	got, err := repository.Get(context.Background(), queued.ID)
	if err != nil || got.ETag != created.ETag {
		t.Fatalf("record=%#v err=%v", got, err)
	}
}

func TestInterruptRejectsStaleETag(t *testing.T) {
	repository, _, _ := testRepository(t)
	queued := testJob("interrupt-stale", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Interrupt(context.Background(), queued.ID, "wrong", jobTestTime, jobrecovery.FailureCodeQueued); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("error=%v", err)
	}
	got, err := repository.Get(context.Background(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ETag != created.ETag || got.Job.Status != jobs.StatusQueued {
		t.Fatalf("stale ETag changed record=%#v", got)
	}
}

func TestConcurrentInterruptThroughRepositoriesHasOneWinner(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	queued := testJob("interrupt-cas", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, candidate := range []*FileRepository{repository, other} {
		candidate := candidate
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := candidate.Interrupt(context.Background(), queued.ID, created.ETag, jobTestTime, jobrecovery.FailureCodeQueued)
			results <- err
		}()
	}
	close(start)
	group.Wait()
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("CAS results=%v,%v, want one winner", first, second)
	}
	if first != nil && !errors.Is(first, jobs.ErrConflict) || second != nil && !errors.Is(second, jobs.ErrConflict) {
		t.Fatalf("CAS errors=%v,%v", first, second)
	}
	got, err := repository.Get(context.Background(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Job.Status != jobs.StatusInterrupted || got.Job.FailureCode != string(jobrecovery.FailureCodeQueued) {
		t.Fatalf("CAS winner=%#v", got)
	}
}

func TestInterruptHonorsContextGateCancellation(t *testing.T) {
	repository, _, _ := testRepository(t)
	token := <-repository.gate
	defer func() { repository.gate <- token }()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := repository.Interrupt(ctx, "interrupt-gated", "etag", jobTestTime, jobrecovery.FailureCodeQueued)
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
		t.Fatal("Interrupt gate waiter did not observe cancellation")
	}
}

func TestInterruptFailureCodeIsSerializedOnlyAfterStateValidation(t *testing.T) {
	repository, store, _ := testRepository(t)
	queued := testJob("interrupt-serialized", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Interrupt(context.Background(), queued.ID, created.ETag, jobTestTime, jobrecovery.FailureCodeQueued); err != nil {
		t.Fatal(err)
	}
	encoded, err := store.Read(statefs.JobsDir + "/" + queued.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"status":"interrupted"`) || !strings.Contains(string(encoded), `"failureCode":"job_recovery_queued"`) {
		t.Fatalf("serialized interruption=%s", encoded)
	}
	if strings.Contains(string(encoded), "OIDC_TOKEN_SENTINEL") {
		t.Fatal("serialized interruption contains secret sentinel")
	}
}
