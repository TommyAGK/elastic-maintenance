package jobrecord

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/jobrecovery"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

func TestRecoverMatrixSummaryAndTerminalBytePreservation(t *testing.T) {
	repository, store, _ := testRepository(t)
	types := []jobs.Type{jobs.TypeValidation, jobs.TypePlan, jobs.TypeApply, jobs.TypeTargetInventory}
	statuses := []jobs.Status{jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted}
	terminalBytes := make(map[string][]byte)
	for _, jobType := range types {
		for _, status := range statuses {
			id := fmt.Sprintf("recover-%s-%s", jobType, status)
			job := testJob(id, jobTestTime, status)
			job.Type = jobType
			if jobType == jobs.TypeApply {
				job.PlanID = "plan-" + id
			}
			encoded, err := state.EncodeJob(job)
			if err != nil {
				t.Fatalf("encode %s/%s: %v", jobType, status, err)
			}
			if err := store.WriteAtomic(statefs.JobsDir+"/"+id+".json", encoded, false); err != nil {
				t.Fatalf("write %s/%s: %v", jobType, status, err)
			}
			if isTerminal(status) {
				terminalBytes[id] = append([]byte(nil), encoded...)
			}
		}
	}

	finishedAt := time.Now().UTC()
	summary, err := repository.Recover(context.Background(), finishedAt)
	if err != nil {
		t.Fatal(err)
	}
	if want := (RecoverySummary{Examined: 24, Preserved: 16, Interrupted: 8}); !reflect.DeepEqual(summary, want) {
		t.Fatalf("summary=%#v want=%#v", summary, want)
	}
	for _, jobType := range types {
		for _, status := range statuses {
			id := fmt.Sprintf("recover-%s-%s", jobType, status)
			record, err := repository.Get(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			switch status {
			case jobs.StatusQueued, jobs.StatusRunning:
				if record.Job.Status != jobs.StatusInterrupted || record.Job.FailureCode != string(recoveryCode(jobType, status)) {
					t.Fatalf("recovered %s=%#v", id, record.Job)
				}
				if !record.Job.FinishedAt.Equal(finishedAt) {
					t.Fatalf("recovery timestamp for %s=%v want %v", id, record.Job.FinishedAt, finishedAt)
				}
			case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted:
				got, err := store.Read(statefs.JobsDir + "/" + id + ".json")
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, terminalBytes[id]) {
					t.Fatalf("terminal bytes changed for %s", id)
				}
			}
		}
	}

	rerunAt := time.Now().UTC()
	rerun, err := repository.Recover(context.Background(), rerunAt)
	if err != nil {
		t.Fatal(err)
	}
	if want := (RecoverySummary{Examined: 24, Preserved: 24}); !reflect.DeepEqual(rerun, want) {
		t.Fatalf("rerun summary=%#v want=%#v", rerun, want)
	}
}

func TestRecoverMalformedLaterRecordDoesNotMutateEarlierRecord(t *testing.T) {
	repository, store, _ := testRepository(t)
	good := testJob("job-a-good", jobTestTime, jobs.StatusQueued)
	encoded, err := state.EncodeJob(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/"+good.ID+".json", encoded, false); err != nil {
		t.Fatal(err)
	}
	sentinel := "RECOVERY_SECRET_SENTINEL"
	bad := []byte(`{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"Job","unknown":"` + sentinel + `"}`)
	if err := store.WriteAtomic(statefs.JobsDir+"/job-z-bad.json", bad, false); err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(statefs.JobsDir + "/" + good.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.Recover(context.Background(), time.Now().UTC())
	if !errors.Is(err, ErrRecoveryCorrupt) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "job-z-bad") {
		t.Fatalf("unsafe recovery error=%v", err)
	}
	after, err := store.Read(statefs.JobsDir + "/" + good.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("valid record was mutated before the complete snapshot was classified")
	}
}

func TestRecoverRejectsWrongFilenameWithoutMutation(t *testing.T) {
	repository, store, _ := testRepository(t)
	job := testJob("body-id", jobTestTime, jobs.StatusQueued)
	encoded, err := state.EncodeJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/filename-id.json", encoded, false); err != nil {
		t.Fatal(err)
	}
	_, err = repository.Recover(context.Background(), time.Now().UTC())
	if !errors.Is(err, ErrRecoveryCorrupt) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("error=%v", err)
	}
	if _, getErr := repository.Get(context.Background(), "filename-id"); !errors.Is(getErr, statefs.ErrCorrupt) {
		t.Fatalf("wrong filename record error=%v", getErr)
	}
}

func TestRecoverBoundsScanAndMapsFutureTimestampSafely(t *testing.T) {
	repository, _, root := testRepository(t)
	for index := 0; index <= MaxRecordsScan; index++ {
		name := filepath.Join(root, statefs.JobsDir, fmt.Sprintf("bound-%05d.json", index))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := repository.Recover(context.Background(), time.Now().UTC())
	if !errors.Is(err, ErrRecoveryScanLimit) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("scan bound error=%v", err)
	}

	repository, _, _ = testRepository(t)
	future := time.Now().UTC().Add(time.Hour)
	_, err = repository.Recover(context.Background(), future)
	if !errors.Is(err, ErrInvalidRecoveryTimestamp) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("future timestamp error=%v", err)
	}
}

func TestRecoverFailsClosedOnConcurrentCASMutation(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	queued := testJob("recover-cas", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), queued)
	if err != nil {
		t.Fatal(err)
	}
	mutated := queued
	mutated.Status = jobs.StatusRunning
	started := jobTestTime.Add(time.Minute).UTC()
	mutated.StartedAt = &started
	entered := make(chan struct{})
	continueRecovery := make(chan struct{})
	repository.recoveryBeforeWrite = func() {
		close(entered)
		<-continueRecovery
	}
	result := make(chan error, 1)
	go func() {
		_, recoverErr := repository.Recover(context.Background(), time.Now().UTC())
		result <- recoverErr
	}()
	<-entered
	if _, err := other.Put(context.Background(), mutated.ID, mutated, created.ETag); err != nil {
		t.Fatal(err)
	}
	close(continueRecovery)
	if err := <-result; !errors.Is(err, ErrRecoveryConflict) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("concurrent recovery error=%v", err)
	}
	got, err := other.Get(context.Background(), queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Job.Status != jobs.StatusRunning {
		t.Fatalf("concurrent mutation was overwritten: %#v", got.Job)
	}
}

func TestRecoverRerunsAfterPartialCASProgress(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	first := testJob("partial-a", jobTestTime, jobs.StatusQueued)
	second := testJob("partial-b", jobTestTime, jobs.StatusQueued)
	if _, err := repository.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	secondRecord, err := repository.Create(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	started := jobTestTime.Add(time.Minute)
	running := second
	running.Status = jobs.StatusRunning
	running.StartedAt = &started
	writes := 0
	repository.recoveryBeforeWrite = func() {
		writes++
		if writes != 2 {
			return
		}
		if _, putErr := other.Put(context.Background(), second.ID, running, secondRecord.ETag); putErr != nil {
			t.Fatal(putErr)
		}
	}
	finishedAt := time.Now().UTC()
	if _, err := repository.Recover(context.Background(), finishedAt); !errors.Is(err, ErrRecoveryConflict) {
		t.Fatalf("partial error=%v", err)
	}
	gotFirst, err := other.Get(context.Background(), first.ID)
	if err != nil || gotFirst.Job.Status != jobs.StatusInterrupted {
		t.Fatalf("first=%#v err=%v", gotFirst, err)
	}
	gotSecond, err := other.Get(context.Background(), second.ID)
	if err != nil || gotSecond.Job.Status != jobs.StatusRunning {
		t.Fatalf("second=%#v err=%v", gotSecond, err)
	}
	repository.recoveryBeforeWrite = nil
	runAgain, err := repository.Recover(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if want := (RecoverySummary{Examined: 2, Preserved: 1, Interrupted: 1}); runAgain != want {
		t.Fatalf("rerun=%#v want=%#v", runAgain, want)
	}
	gotSecond, err = other.Get(context.Background(), second.ID)
	if err != nil || gotSecond.Job.Status != jobs.StatusInterrupted || gotSecond.Job.FailureCode != string(jobrecovery.FailureCodeRunning) {
		t.Fatalf("recovered second=%#v err=%v", gotSecond, err)
	}
}

func TestRecoverMapsCASStorageFailureToSafeCorruption(t *testing.T) {
	repository, _, root := testRepository(t)
	queued := testJob("recover-storage", jobTestTime, jobs.StatusQueued)
	if _, err := repository.Create(context.Background(), queued); err != nil {
		t.Fatal(err)
	}
	repository.recoveryBeforeWrite = func() {
		if err := os.Chmod(filepath.Join(root, statefs.JobsDir, queued.ID+".json"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := repository.Recover(context.Background(), time.Now().UTC())
	if !errors.Is(err, ErrRecovery) || !errors.Is(err, ErrRecoveryCorrupt) {
		t.Fatalf("storage failure error=%v", err)
	}
	if strings.Contains(err.Error(), queued.ID) {
		t.Fatalf("storage failure exposed ID: %v", err)
	}
}

func TestRecoverHonorsContextCancellationAtRepositoryGate(t *testing.T) {
	repository, _, _ := testRepository(t)
	token := <-repository.gate
	defer func() { repository.gate <- token }()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, recoverErr := repository.Recover(ctx, time.Now().UTC())
		result <- recoverErr
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrRecovery) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery gate waiter did not observe cancellation")
	}
}

func recoveryCode(jobType jobs.Type, status jobs.Status) jobrecovery.FailureCode {
	if jobType == jobs.TypeApply && status == jobs.StatusQueued {
		return jobrecovery.FailureCodeApplyQueued
	}
	if jobType == jobs.TypeApply && status == jobs.StatusRunning {
		return jobrecovery.FailureCodeApplyRunning
	}
	if status == jobs.StatusQueued {
		return jobrecovery.FailureCodeQueued
	}
	return jobrecovery.FailureCodeRunning
}
