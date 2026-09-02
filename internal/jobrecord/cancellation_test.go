package jobrecord

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

func TestRequestCancellationQueuedAndRunning(t *testing.T) {
	for _, status := range []jobs.Status{jobs.StatusQueued, jobs.StatusRunning} {
		t.Run(string(status), func(t *testing.T) {
			repository, store, _ := testRepository(t)
			job := testJob("cancel-"+string(status), jobTestTime, jobs.StatusQueued)
			created, err := repository.Create(context.Background(), job)
			if err != nil {
				t.Fatal(err)
			}
			current := created
			if status == jobs.StatusRunning {
				running := job
				running.Status = jobs.StatusRunning
				started := jobTestTime.Add(time.Minute)
				running.StartedAt = &started
				current, err = repository.Put(context.Background(), running.ID, running, created.ETag)
				if err != nil {
					t.Fatal(err)
				}
			}

			requested, err := repository.RequestCancellation(context.Background(), current.Job.ID, current.ETag)
			if err != nil {
				t.Fatal(err)
			}
			want := current.Job
			want.CancellationRequested = true
			if !reflect.DeepEqual(requested.Job, want) {
				t.Fatalf("requested job=%#v want=%#v", requested.Job, want)
			}
			if requested.ETag == current.ETag {
				t.Fatal("cancellation did not change the ETag")
			}
			stored, err := repository.Get(context.Background(), current.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored, requested) {
				t.Fatalf("stored=%#v requested=%#v", stored, requested)
			}
			encoded, err := store.Read(jobPath(current.Job.ID))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(encoded, []byte(`"cancellationRequested":true`)) {
				t.Fatalf("serialized cancellation=%s", encoded)
			}
		})
	}
}

func TestRequestCancellationAlreadyRequestedIsIdempotentWithoutRewrite(t *testing.T) {
	repository, store, _ := testRepository(t)
	job := testJob("cancel-idempotent", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	first, err := repository.RequestCancellation(context.Background(), job.ID, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.RequestCancellation(context.Background(), job.ID, "stale-etag")
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("replay=%#v first=%#v", second, first)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("idempotent cancellation rewrote the document")
	}
}

func TestRequestCancellationCanceledReplayIsIdempotentWithoutRewrite(t *testing.T) {
	repository, store, _ := testRepository(t)
	job := testJob("cancel-replay", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	requested, err := repository.RequestCancellation(context.Background(), job.ID, created.ETag)
	if err != nil {
		t.Fatal(err)
	}
	canceled := requested.Job
	canceled.Status = jobs.StatusCanceled
	finished := jobTestTime.Add(time.Minute)
	canceled.FinishedAt = &finished
	terminal, err := repository.Put(context.Background(), job.ID, canceled, requested.ETag)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.RequestCancellation(context.Background(), job.ID, "stale-etag")
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed, terminal) {
		t.Fatalf("replay=%#v terminal=%#v", replayed, terminal)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("canceled replay rewrote the document")
	}
}

func TestRequestCancellationRejectsUnsupportedTerminalJobsWithoutRewrite(t *testing.T) {
	repository, store, _ := testRepository(t)
	for _, status := range []jobs.Status{jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted} {
		job := testJob("cancel-unsupported-"+string(status), jobTestTime, status)
		encoded, err := state.EncodeJob(job)
		if err != nil {
			t.Fatalf("encode %s: %v", status, err)
		}
		if err := store.WriteAtomic(jobPath(job.ID), encoded, false); err != nil {
			t.Fatal(err)
		}
		before, err := store.Read(jobPath(job.ID))
		if err != nil {
			t.Fatal(err)
		}
		_, err = repository.RequestCancellation(context.Background(), job.ID, etag(encoded))
		if !errors.Is(err, jobs.ErrCancellationUnsupported) {
			t.Errorf("status %s error=%v", status, err)
		}
		after, err := store.Read(jobPath(job.ID))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Errorf("status %s document changed", status)
		}
	}
}

func TestRequestCancellationMapsStaleMissingAndInvalidInputs(t *testing.T) {
	repository, store, _ := testRepository(t)
	job := testJob("cancel-stale", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RequestCancellation(context.Background(), job.ID, "wrong-etag"); !errors.Is(err, jobs.ErrConflict) {
		t.Fatalf("stale ETag error=%v", err)
	}
	after, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("stale ETag changed the document")
	}
	if _, err := repository.RequestCancellation(context.Background(), "missing-cancel", created.ETag); !errors.Is(err, jobs.ErrNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	for _, id := range []string{"", "../escape", "OIDC_TOKEN_SENTINEL"} {
		if _, err := repository.RequestCancellation(context.Background(), id, created.ETag); !errors.Is(err, jobs.ErrNotFound) {
			t.Errorf("invalid ID %q error=%v", id, err)
		}
	}
}

func TestRequestCancellationHonorsContextCancellation(t *testing.T) {
	repository, _, _ := testRepository(t)
	job := testJob("cancel-context", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.RequestCancellation(ctx, job.ID, created.ETag); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled error=%v", err)
	}

	token := <-repository.gate
	defer func() { repository.gate <- token }()
	ctx, cancel = context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := repository.RequestCancellation(ctx, job.ID, created.ETag)
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
		t.Fatal("RequestCancellation gate waiter did not observe cancellation")
	}
}

func TestRequestCancellationRejectsCorruptionAndStorageFailureSafely(t *testing.T) {
	repository, store, _ := testRepository(t)
	sentinel := "CANCELLATION_SECRET_SENTINEL"
	badID := "cancel-corrupt"
	bad := []byte(`{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"Job","id":"` + badID + `","secret":"` + sentinel + `"}`)
	if err := store.WriteAtomic(jobPath(badID), bad, false); err != nil {
		t.Fatal(err)
	}
	_, err := repository.RequestCancellation(context.Background(), badID, "etag")
	if !errors.Is(err, statefs.ErrCorrupt) {
		t.Fatalf("corruption error=%v", err)
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), badID) {
		t.Fatalf("corruption error exposed sensitive data: %v", err)
	}

	job := testJob("cancel-storage", jobTestTime, jobs.StatusQueued)
	created, err := repository.Create(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = repository.RequestCancellation(context.Background(), job.ID, created.ETag)
	if !errors.Is(err, statefs.ErrClosed) {
		t.Fatalf("closed store error=%v", err)
	}
}

func TestRequestCancellationPreservesImmutableBytes(t *testing.T) {
	repository, store, _ := testRepository(t)
	job := testJob("cancel-byte-preservation", jobTestTime, jobs.StatusQueued)
	job.Type = jobs.TypeApply
	job.PlanID = "plan-immutable"
	encoded, err := state.EncodeJob(job)
	if err != nil {
		t.Fatal(err)
	}
	fixture := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"cancellationRequested":false}`)...)
	if err := store.WriteAtomic(jobPath(job.ID), fixture, false); err != nil {
		t.Fatal(err)
	}
	before, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	requested, err := repository.RequestCancellation(context.Background(), job.ID, etag(before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := store.Read(jobPath(job.ID))
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := bytes.Replace(before, []byte(`"cancellationRequested":false`), []byte(`"cancellationRequested":true`), 1)
	if !bytes.Equal(after, wantBytes) {
		t.Fatalf("non-flag bytes changed: before=%s after=%s want=%s", before, after, wantBytes)
	}
	want := job
	want.CancellationRequested = true
	if !reflect.DeepEqual(requested.Job, want) {
		t.Fatalf("requested=%#v want=%#v", requested.Job, want)
	}
	if requested.ETag != etag(wantBytes) {
		t.Fatalf("returned ETag=%q want=%q", requested.ETag, etag(wantBytes))
	}
}
