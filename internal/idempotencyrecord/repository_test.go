package idempotencyrecord

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

var idempotencyTestTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

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

func testCandidate(t *testing.T, actor state.Actor, action audit.Action, key, digest string, created time.Time, outcome state.IdempotencyOutcome) state.IdempotencyRecord {
	t.Helper()
	id, err := ScopeID(actor, action, key)
	if err != nil {
		t.Fatal(err)
	}
	candidate := state.IdempotencyRecord{
		APIVersion:    state.APIVersion,
		Kind:          state.KindIdempotency,
		ID:            id,
		Key:           key,
		Actor:         actor,
		Action:        action,
		RequestDigest: digest,
		CreatedAt:     created.UTC(),
		Outcome:       outcome,
	}
	if outcome == state.IdempotencyPending {
		candidate.JobID = "job-" + key
	} else {
		candidate.Result = &state.ResultReference{Kind: state.ResultKindPlan, ID: "plan-" + key}
	}
	return candidate
}

func testActor(subject string) state.Actor {
	return state.Actor{Subject: subject, Roles: []auth.Role{auth.RolePlanner, auth.RoleViewer}, Method: auth.MethodOIDC}
}

func ptrTime(value time.Time) *time.Time { return &value }

func seedIdempotencyRecords(t *testing.T, root string, count int, created time.Time, expiredIndex int) []state.IdempotencyRecord {
	t.Helper()
	records := make([]state.IdempotencyRecord, 0, count)
	for index := 0; index < count; index++ {
		candidate := testCandidate(t, testActor(fmt.Sprintf("seed-%d@example.test", index)), audit.ActionPlanCreate, fmt.Sprintf("seed-key-%d", index), fmt.Sprintf("%064x", index), created, state.IdempotencySucceeded)
		if index == expiredIndex {
			expires := created.Add(time.Hour)
			candidate.ExpiresAt = &expires
		}
		encoded, err := state.EncodeIdempotency(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		records = append(records, candidate)
	}
	return records
}

func TestScopeIDSeparatesEveryScopeFieldButNotDigest(t *testing.T) {
	base := testActor("operator@example.test")
	id, err := ScopeID(base, audit.ActionPlanCreate, "request-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 || id != strings.ToLower(id) {
		t.Fatalf("scope id=%q", id)
	}
	cases := []struct {
		name   string
		actor  state.Actor
		action audit.Action
		key    string
	}{
		{"subject", testActor("other@example.test"), audit.ActionPlanCreate, "request-key-1"},
		{"roles", state.Actor{Subject: base.Subject, Roles: []auth.Role{auth.RoleViewer}, Method: base.Method}, audit.ActionPlanCreate, "request-key-1"},
		{"method", state.Actor{Subject: base.Subject, Roles: append([]auth.Role(nil), base.Roles...), Method: auth.MethodBearer}, audit.ActionPlanCreate, "request-key-1"},
		{"action", base, audit.ActionValidationCreate, "request-key-1"},
		{"key", base, audit.ActionPlanCreate, "request-key-2"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			other, err := ScopeID(item.actor, item.action, item.key)
			if err != nil {
				t.Fatal(err)
			}
			if other == id {
				t.Fatalf("scope dimension %s did not change id", item.name)
			}
		})
	}
	if other, err := ScopeID(base, audit.ActionPlanCreate, "request-key-1"); err != nil || other != id {
		t.Fatalf("same scope id=%q err=%v", other, err)
	}
}

func TestCreateOrReplayRequiresExplicitServiceTime(t *testing.T) {
	repository, _, _ := testRepository(t)
	candidate := testCandidate(t, testActor("time-contract@example.test"), audit.ActionPlanCreate, "time-contract-key", strings.Repeat("a", 64), idempotencyTestTime, state.IdempotencySucceeded)
	if _, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime.Add(time.Nanosecond)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("candidate/at mismatch error=%v", err)
	}
	nonUTC := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("offset", 0))
	if _, err := repository.CreateOrReplay(context.Background(), candidate, nonUTC); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("non-UTC at error=%v", err)
	}
	if _, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime); err != nil {
		t.Fatalf("canonical at error=%v", err)
	}
	if replay, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime.Add(time.Hour)); err != nil || !replay.Replay {
		t.Fatalf("replay with later observation time=%#v err=%v", replay, err)
	}
}

func TestCreateReplayLookupAndRestartStableETag(t *testing.T) {
	repository, store, root := testRepository(t)
	actor := testActor("operator@example.test")
	candidate := testCandidate(t, actor, audit.ActionPlanCreate, "request-key-1", strings.Repeat("a", 64), idempotencyTestTime, state.IdempotencyPending)
	created, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if created.Replay || created.ETag == "" {
		t.Fatalf("created=%#v", created)
	}
	before, err := os.ReadFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replay || replayed.ETag != created.ETag || !reflect.DeepEqual(replayed.Idempotency, created.Idempotency) {
		t.Fatalf("replayed=%#v created=%#v", replayed, created)
	}
	after, err := os.ReadFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("replay rewrote durable bytes")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedStore, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	reopened, err := New(reopenedStore)
	if err != nil {
		t.Fatal(err)
	}
	restartedBefore, err := os.ReadFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, restartedBefore) {
		t.Fatal("restart changed durable bytes before replay")
	}
	got, err := reopened.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Replay || got.ETag != created.ETag || !reflect.DeepEqual(got.Idempotency, created.Idempotency) {
		t.Fatalf("reopened=%#v created=%#v", got, created)
	}
	restartedAfter, err := os.ReadFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restartedBefore, restartedAfter) {
		t.Fatal("restart replay rewrote durable bytes")
	}
}

func TestDigestConflictAndIndependentScopes(t *testing.T) {
	repository, _, _ := testRepository(t)
	actor := testActor("operator@example.test")
	first := testCandidate(t, actor, audit.ActionPlanCreate, "request-key-1", strings.Repeat("a", 64), idempotencyTestTime, state.IdempotencyPending)
	if _, err := repository.CreateOrReplay(context.Background(), first, idempotencyTestTime); err != nil {
		t.Fatal(err)
	}
	changedDigest := first
	changedDigest.RequestDigest = strings.Repeat("b", 64)
	if _, err := repository.CreateOrReplay(context.Background(), changedDigest, idempotencyTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed digest error=%v", err)
	}
	otherActor := testCandidate(t, testActor("other@example.test"), first.Action, first.Key, changedDigest.RequestDigest, idempotencyTestTime, state.IdempotencyPending)
	if otherActor.ID == first.ID {
		t.Fatal("actor was omitted from scope")
	}
	if got, err := repository.CreateOrReplay(context.Background(), otherActor, idempotencyTestTime); err != nil || got.Replay {
		t.Fatalf("other actor got=%#v err=%v", got, err)
	}
	otherAction := testCandidate(t, actor, audit.ActionValidationCreate, first.Key, changedDigest.RequestDigest, idempotencyTestTime, state.IdempotencyPending)
	if _, err := repository.CreateOrReplay(context.Background(), otherAction, idempotencyTestTime); err != nil {
		t.Fatalf("other action error=%v", err)
	}
}

func TestPendingCompletionAndTerminalImmutability(t *testing.T) {
	repository, _, _ := testRepository(t)
	actor := testActor("operator@example.test")
	candidate := testCandidate(t, actor, audit.ActionPlanCreate, "request-key-1", strings.Repeat("a", 64), idempotencyTestTime, state.IdempotencyPending)
	created, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := repository.Complete(context.Background(), candidate.ID, created.ETag, state.IdempotencySucceeded, state.ResultReference{Kind: state.ResultKindJob, ID: candidate.JobID})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Idempotency.Outcome != state.IdempotencySucceeded || completed.Idempotency.Result == nil || completed.Idempotency.Result.ID != candidate.JobID {
		t.Fatalf("completed=%#v", completed)
	}
	if completed.Idempotency.CreatedAt != candidate.CreatedAt || completed.Idempotency.ExpiresAt != candidate.ExpiresAt || completed.Idempotency.JobID != candidate.JobID {
		t.Fatal("completion changed immutable fields")
	}
	if _, err := repository.Complete(context.Background(), candidate.ID, completed.ETag, state.IdempotencyFailed, state.ResultReference{Kind: state.ResultKindJob, ID: candidate.JobID}); !errors.Is(err, ErrImmutable) {
		t.Fatalf("terminal completion error=%v", err)
	}
}

func TestDirectTerminalCandidate(t *testing.T) {
	repository, _, _ := testRepository(t)
	candidate := testCandidate(t, testActor("sync@example.test"), audit.ActionCredentialUpload, "sync-key-1", strings.Repeat("c", 64), idempotencyTestTime, state.IdempotencySucceeded)
	created, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
	if err != nil || created.Replay || created.Idempotency.Result == nil {
		t.Fatalf("direct terminal=%#v err=%v", created, err)
	}
	got, err := repository.Lookup(context.Background(), candidate.Actor, candidate.Action, candidate.Key, candidate.RequestDigest, idempotencyTestTime)
	if err != nil || got.Idempotency.Outcome != state.IdempotencySucceeded {
		t.Fatalf("lookup=%#v err=%v", got, err)
	}
	direct, err := repository.Get(context.Background(), candidate.ID, candidate.RequestDigest, idempotencyTestTime)
	if err != nil || direct.ETag != created.ETag {
		t.Fatalf("direct=%#v err=%v", direct, err)
	}
	if _, err := repository.Get(context.Background(), candidate.ID, strings.Repeat("9", 64), idempotencyTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("direct digest error=%v", err)
	}
	invalidID := "not-a-scope-hash-sentinel"
	if _, err := repository.Get(context.Background(), invalidID, candidate.RequestDigest, idempotencyTestTime); !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), invalidID) {
		t.Fatalf("invalid direct id error=%v", err)
	}
}

func TestMultiRepositoryCreateAndCompletionCAS(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	candidate := testCandidate(t, testActor("race@example.test"), audit.ActionPlanCreate, "race-key-1", strings.Repeat("d", 64), idempotencyTestTime, state.IdempotencyPending)
	start := make(chan struct{})
	results := make(chan Record, 2)
	errorsCh := make(chan error, 2)
	for _, candidateRepository := range []*FileRepository{repository, other} {
		go func(candidateRepository *FileRepository) {
			<-start
			result, createErr := candidateRepository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
			results <- result
			errorsCh <- createErr
		}(candidateRepository)
	}
	close(start)
	first, second := <-results, <-results
	firstErr, secondErr := <-errorsCh, <-errorsCh
	if firstErr != nil || secondErr != nil || first.Replay == second.Replay {
		t.Fatalf("create race results=%#v/%#v errors=%v/%v", first, second, firstErr, secondErr)
	}
	created := first
	if created.Replay {
		created = second
	}
	completionStart := make(chan struct{})
	completionErrors := make(chan error, 2)
	for _, candidateRepository := range []*FileRepository{repository, other} {
		go func(candidateRepository *FileRepository) {
			<-completionStart
			_, completeErr := candidateRepository.Complete(context.Background(), candidate.ID, created.ETag, state.IdempotencySucceeded, state.ResultReference{Kind: state.ResultKindPlan, ID: "plan-race"})
			completionErrors <- completeErr
		}(candidateRepository)
	}
	close(completionStart)
	completeFirst, completeSecond := <-completionErrors, <-completionErrors
	if (completeFirst == nil) == (completeSecond == nil) || (completeFirst != nil && !errors.Is(completeFirst, ErrConflict)) || (completeSecond != nil && !errors.Is(completeSecond, ErrConflict)) {
		t.Fatalf("completion race errors=%v/%v", completeFirst, completeSecond)
	}
}

func TestExpiryBoundaryReplacementAndLookup(t *testing.T) {
	repository, _, _ := testRepository(t)
	actor := testActor("expiry@example.test")
	expires := idempotencyTestTime.Add(time.Hour)
	candidate := testCandidate(t, actor, audit.ActionPlanCreate, "expiry-key-1", strings.Repeat("e", 64), idempotencyTestTime, state.IdempotencyPending)
	candidate.ExpiresAt = &expires
	if _, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Lookup(context.Background(), actor, candidate.Action, candidate.Key, candidate.RequestDigest, expires.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("before expiry error=%v", err)
	}
	if _, err := repository.Lookup(context.Background(), actor, candidate.Action, candidate.Key, candidate.RequestDigest, expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("at expiry error=%v", err)
	}
	replacementTime := expires
	replacement := testCandidate(t, actor, candidate.Action, candidate.Key, strings.Repeat("f", 64), replacementTime, state.IdempotencySucceeded)
	replacementExpiry := replacementTime.Add(time.Hour)
	replacement.ExpiresAt = &replacementExpiry
	created, err := repository.CreateOrReplay(context.Background(), replacement, replacementTime)
	if err != nil || created.Replay || created.Idempotency.RequestDigest != replacement.RequestDigest {
		t.Fatalf("replacement=%#v err=%v", created, err)
	}
	if _, err := repository.Lookup(context.Background(), actor, candidate.Action, candidate.Key, strings.Repeat("a", 64), replacementTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement digest error=%v", err)
	}
}

func TestCompletionAfterExpiryUsesCASButExpiryHidesReplay(t *testing.T) {
	repository, _, _ := testRepository(t)
	actor := testActor("completion-expiry@example.test")
	expires := idempotencyTestTime.Add(time.Hour)
	pending := testCandidate(t, actor, audit.ActionPlanCreate, "completion-expiry-key", strings.Repeat("1", 64), idempotencyTestTime, state.IdempotencyPending)
	pending.ExpiresAt = &expires
	created, err := repository.CreateOrReplay(context.Background(), pending, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := repository.Complete(context.Background(), pending.ID, created.ETag, state.IdempotencySucceeded, state.ResultReference{Kind: state.ResultKindPlan, ID: "plan-after-expiry"})
	if err != nil {
		t.Fatalf("completion after expiry error=%v", err)
	}
	if completed.Idempotency.Outcome != state.IdempotencySucceeded {
		t.Fatalf("completion after expiry result=%#v", completed)
	}
	if _, err := repository.Lookup(context.Background(), actor, pending.Action, pending.Key, pending.RequestDigest, expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired completed lookup error=%v", err)
	}

	replacedPending := testCandidate(t, actor, audit.ActionValidationCreate, "completion-replace-key", strings.Repeat("2", 64), idempotencyTestTime, state.IdempotencyPending)
	replacedPending.ExpiresAt = &expires
	old, err := repository.CreateOrReplay(context.Background(), replacedPending, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	replacement := testCandidate(t, actor, replacedPending.Action, replacedPending.Key, strings.Repeat("3", 64), expires, state.IdempotencySucceeded)
	if _, err := repository.CreateOrReplay(context.Background(), replacement, expires); err != nil {
		t.Fatalf("replacement after expiry error=%v", err)
	}
	if _, err := repository.Complete(context.Background(), replacedPending.ID, old.ETag, state.IdempotencySucceeded, state.ResultReference{Kind: state.ResultKindPlan, ID: "stale"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("completion after replacement error=%v", err)
	}
}

func TestExpiredReplacementCASRaceHasOneWinner(t *testing.T) {
	repository, store, _ := testRepository(t)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := testActor("expiry-race@example.test")
	expires := idempotencyTestTime.Add(time.Hour)
	initial := testCandidate(t, actor, audit.ActionPlanCreate, "expiry-race-key", strings.Repeat("6", 64), idempotencyTestTime, state.IdempotencyPending)
	initial.ExpiresAt = &expires
	created, err := repository.CreateOrReplay(context.Background(), initial, idempotencyTestTime)
	if err != nil {
		t.Fatal(err)
	}
	replacementTime := expires.Add(time.Nanosecond)
	left := testCandidate(t, actor, initial.Action, initial.Key, strings.Repeat("7", 64), replacementTime, state.IdempotencySucceeded)
	right := testCandidate(t, actor, initial.Action, initial.Key, strings.Repeat("8", 64), replacementTime, state.IdempotencySucceeded)
	left.ExpiresAt = ptrTime(replacementTime.Add(time.Hour))
	right.ExpiresAt = ptrTime(replacementTime.Add(time.Hour))
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	for candidateRepository, candidate := range map[*FileRepository]state.IdempotencyRecord{repository: left, other: right} {
		go func(candidateRepository *FileRepository, candidate state.IdempotencyRecord) {
			<-start
			_, replaceErr := candidateRepository.CreateOrReplay(context.Background(), candidate, replacementTime)
			errorsCh <- replaceErr
		}(candidateRepository, candidate)
	}
	close(start)
	first, second := <-errorsCh, <-errorsCh
	if (first == nil) == (second == nil) || (first != nil && !errors.Is(first, ErrConflict)) || (second != nil && !errors.Is(second, ErrConflict)) {
		t.Fatalf("replacement race errors=%v/%v initial=%#v", first, second, created)
	}
}

func TestCapacityReclaimsOnlyExpiredRecordsAtCallerTime(t *testing.T) {
	repository, _, root := testRepository(t)
	seed := seedIdempotencyRecords(t, root, MaxRecordsScan, idempotencyTestTime, 0)
	at := idempotencyTestTime.Add(2 * time.Hour)
	candidate := testCandidate(t, testActor("reclaim@example.test"), audit.ActionPlanCreate, "reclaim-key", strings.Repeat("4", 64), at, state.IdempotencySucceeded)
	created, err := repository.CreateOrReplay(context.Background(), candidate, at)
	if err != nil || created.Replay {
		t.Fatalf("reclaimed admission=%#v err=%v", created, err)
	}
	if _, err := os.Stat(filepath.Join(root, statefs.IdempotencyDir, seed[0].ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired record remains, stat error=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, statefs.IdempotencyDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != MaxRecordsScan {
		t.Fatalf("physical records=%d, want %d", len(entries), MaxRecordsScan)
	}
}

func TestCrossRepositoryReclamationAdmitsExactlyOne(t *testing.T) {
	repository, store, root := testRepository(t)
	seed := seedIdempotencyRecords(t, root, MaxRecordsScan, idempotencyTestTime, 0)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	at := idempotencyTestTime.Add(2 * time.Hour)
	left := testCandidate(t, testActor("reclaim-capacity-left@example.test"), audit.ActionPlanCreate, "reclaim-capacity-left", strings.Repeat("9", 64), at, state.IdempotencySucceeded)
	right := testCandidate(t, testActor("reclaim-capacity-right@example.test"), audit.ActionPlanCreate, "reclaim-capacity-right", strings.Repeat("a", 64), at, state.IdempotencySucceeded)
	type result struct {
		record Record
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for candidateRepository, candidate := range map[*FileRepository]state.IdempotencyRecord{repository: left, other: right} {
		go func(candidateRepository *FileRepository, candidate state.IdempotencyRecord) {
			<-start
			record, createErr := candidateRepository.CreateOrReplay(context.Background(), candidate, at)
			results <- result{record: record, err: createErr}
		}(candidateRepository, candidate)
	}
	close(start)
	first, second := <-results, <-results
	successes, capacities := 0, 0
	for _, admission := range []result{first, second} {
		if admission.err == nil {
			successes++
		} else if errors.Is(admission.err, ErrCapacity) {
			capacities++
		} else {
			t.Fatalf("reclamation race error=%v", admission.err)
		}
	}
	if successes != 1 || capacities != 1 {
		t.Fatalf("reclamation successes=%d capacities=%d results=%#v/%#v", successes, capacities, first, second)
	}
	if _, err := os.Stat(filepath.Join(root, statefs.IdempotencyDir, seed[0].ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired record remains after cross-repository admission: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, statefs.IdempotencyDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != MaxRecordsScan {
		t.Fatalf("physical records=%d, want %d", len(entries), MaxRecordsScan)
	}
}

func TestReclamationDoesNotDeleteConcurrentCompletion(t *testing.T) {
	repository, _, root := testRepository(t)
	_ = seedIdempotencyRecords(t, root, MaxRecordsScan-1, idempotencyTestTime, -1)
	at := idempotencyTestTime.Add(2 * time.Hour)
	expires := idempotencyTestTime.Add(time.Hour)
	pending := testCandidate(t, testActor("reclaim-race@example.test"), audit.ActionPlanCreate, "reclaim-race-key", strings.Repeat("7", 64), idempotencyTestTime, state.IdempotencyPending)
	pending.ExpiresAt = &expires
	encoded, err := state.EncodeIdempotency(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, statefs.IdempotencyDir, pending.ID+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	oldETag := etag(encoded)
	ready := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	repository.capacityBeforeReclaim = func() {
		once.Do(func() {
			close(ready)
			<-proceed
		})
	}
	admission := make(chan error, 1)
	candidate := testCandidate(t, testActor("reclaim-race-new@example.test"), audit.ActionPlanCreate, "reclaim-race-new-key", strings.Repeat("8", 64), at, state.IdempotencySucceeded)
	go func() {
		_, admissionErr := repository.CreateOrReplay(context.Background(), candidate, at)
		admission <- admissionErr
	}()
	<-ready
	completed, err := repository.Complete(context.Background(), pending.ID, oldETag, state.IdempotencySucceeded, state.ResultReference{Kind: state.ResultKindJob, ID: pending.JobID})
	if err != nil {
		t.Fatalf("concurrent completion error=%v", err)
	}
	close(proceed)
	if err := <-admission; !errors.Is(err, ErrCapacity) {
		t.Fatalf("admission error=%v", err)
	}
	if completed.Idempotency.Outcome != state.IdempotencySucceeded {
		t.Fatalf("completion=%#v", completed)
	}
	if _, err := os.Stat(filepath.Join(root, statefs.IdempotencyDir, pending.ID+".json")); err != nil {
		t.Fatalf("completed record was reclaimed: %v", err)
	}
}

func TestCrossRepositoryCapacityRaceAdmitsExactlyOneAtLimit(t *testing.T) {
	repository, store, root := testRepository(t)
	_ = seedIdempotencyRecords(t, root, MaxRecordsScan-1, idempotencyTestTime, -1)
	other, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	left := testCandidate(t, testActor("capacity-race-left@example.test"), audit.ActionPlanCreate, "capacity-race-left", strings.Repeat("5", 64), idempotencyTestTime, state.IdempotencySucceeded)
	right := testCandidate(t, testActor("capacity-race-right@example.test"), audit.ActionPlanCreate, "capacity-race-right", strings.Repeat("6", 64), idempotencyTestTime, state.IdempotencySucceeded)
	type result struct {
		record Record
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for candidateRepository, candidate := range map[*FileRepository]state.IdempotencyRecord{repository: left, other: right} {
		go func(candidateRepository *FileRepository, candidate state.IdempotencyRecord) {
			<-start
			record, createErr := candidateRepository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime)
			results <- result{record: record, err: createErr}
		}(candidateRepository, candidate)
	}
	close(start)
	first, second := <-results, <-results
	successes, capacities := 0, 0
	for _, admission := range []result{first, second} {
		if admission.err == nil {
			successes++
			if admission.record.Replay {
				t.Fatal("distinct capacity admission unexpectedly replayed")
			}
		} else if errors.Is(admission.err, ErrCapacity) {
			capacities++
		} else {
			t.Fatalf("capacity race error=%v", admission.err)
		}
	}
	if successes != 1 || capacities != 1 {
		t.Fatalf("successes=%d capacities=%d results=%#v/%#v", successes, capacities, first, second)
	}
	entries, err := os.ReadDir(filepath.Join(root, statefs.IdempotencyDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != MaxRecordsScan {
		t.Fatalf("physical records=%d, want %d", len(entries), MaxRecordsScan)
	}
}

func TestCapacityKeepsDirectReplayAvailable(t *testing.T) {
	repository, store, root := testRepository(t)
	first := testCandidate(t, testActor("capacity-0@example.test"), audit.ActionPlanCreate, "capacity-key-0", strings.Repeat("0", 64), idempotencyTestTime, state.IdempotencySucceeded)
	for index := 0; index < MaxRecordsScan; index++ {
		candidate := first
		if index != 0 {
			candidate = testCandidate(t, testActor(fmt.Sprintf("capacity-%d@example.test", index)), audit.ActionPlanCreate, fmt.Sprintf("capacity-key-%d", index), fmt.Sprintf("%064x", index), idempotencyTestTime, state.IdempotencySucceeded)
		}
		encoded, err := state.EncodeIdempotency(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := repository.CreateOrReplay(context.Background(), first, idempotencyTestTime); err != nil || !got.Replay {
		t.Fatalf("capacity replay=%#v err=%v", got, err)
	}
	missing := testCandidate(t, testActor("capacity-missing@example.test"), audit.ActionPlanCreate, "capacity-key-missing", strings.Repeat("1", 64), idempotencyTestTime, state.IdempotencySucceeded)
	if _, err := repository.CreateOrReplay(context.Background(), missing, idempotencyTestTime); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity create error=%v", err)
	}
	if _, err := repository.Lookup(context.Background(), first.Actor, first.Action, first.Key, first.RequestDigest, idempotencyTestTime.Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("nil-expiry lookup at capacity error=%v", err)
	}
	_ = store
}

func TestMalformedWrongFilenameUnsafeAndErrorsDoNotEchoSentinel(t *testing.T) {
	t.Run("malformed body", func(t *testing.T) {
		repository, _, root := testRepository(t)
		sentinel := "attacker-controlled-idempotency-sentinel"
		candidate := testCandidate(t, testActor("corrupt-body@example.test"), audit.ActionPlanCreate, "corrupt-body-key", strings.Repeat("2", 64), idempotencyTestTime, state.IdempotencySucceeded)
		if err := os.WriteFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"), []byte(`{"unknown":"`+sentinel+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.Get(context.Background(), candidate.ID, strings.Repeat("2", 64), idempotencyTestTime); !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("malformed error=%v", err)
		}
		if _, err := repository.scan(context.Background()); !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("scan malformed error=%v", err)
		}
	})

	t.Run("wrong filename", func(t *testing.T) {
		repository, store, _ := testRepository(t)
		candidate := testCandidate(t, testActor("wrong-name@example.test"), audit.ActionPlanCreate, "wrong-name-key", strings.Repeat("2", 64), idempotencyTestTime, state.IdempotencySucceeded)
		wrong := strings.Repeat("3", 64)
		valid, err := state.EncodeIdempotency(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteAtomic(statefs.IdempotencyDir+"/"+wrong+".json", valid, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.scan(context.Background()); !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), candidate.ID) {
			t.Fatalf("wrong filename error=%v", err)
		}
	})

	t.Run("unsafe entry", func(t *testing.T) {
		repository, _, root := testRepository(t)
		candidate := testCandidate(t, testActor("unsafe@example.test"), audit.ActionPlanCreate, "unsafe-key", strings.Repeat("2", 64), idempotencyTestTime, state.IdempotencySucceeded)
		if err := os.Symlink(filepath.Join(root, "not-a-real-file"), filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json")); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.Get(context.Background(), candidate.ID, strings.Repeat("2", 64), idempotencyTestTime); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("unsafe error=%v", err)
		}
	})
}

func TestOperationalStorageErrorsMapToUnavailable(t *testing.T) {
	for _, operational := range []error{statefs.ErrInsufficientFree, statefs.ErrFreeSpaceUnavailable, statefs.ErrWriteFailed, statefs.ErrDurabilityUnknown, statefs.ErrFileUnavailable, statefs.ErrLockUnavailable, statefs.ErrClosed} {
		t.Run(operational.Error(), func(t *testing.T) {
			mapped := mapStoreError(operational)
			if !errors.Is(mapped, ErrUnavailable) || errors.Is(mapped, ErrCorrupt) {
				t.Fatalf("mapped=%v", mapped)
			}
		})
	}
	for _, unsafe := range []error{statefs.ErrCorrupt, statefs.ErrSymlink, statefs.ErrHardLinked, statefs.ErrUnsafeFile, statefs.ErrNotRegular} {
		t.Run("unsafe-"+unsafe.Error(), func(t *testing.T) {
			mapped := mapStoreError(unsafe)
			if !errors.Is(mapped, ErrCorrupt) || errors.Is(mapped, ErrUnavailable) {
				t.Fatalf("mapped=%v", mapped)
			}
		})
	}
}

func TestContextGateCancellationAndCanonicalValidation(t *testing.T) {
	repository, _, _ := testRepository(t)
	token := <-repository.gate
	defer func() { repository.gate <- token }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.Lookup(ctx, testActor("cancel@example.test"), audit.ActionPlanCreate, "cancel-key-1", strings.Repeat("4", 64), idempotencyTestTime); !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup cancellation=%v", err)
	}
	if _, err := ScopeID(state.Actor{Subject: " unsafely spaced ", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}, audit.ActionPlanCreate, "cancel-key-1"); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("unsafe actor error=%v", err)
	}
	nonUTC := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("not-utc", 0))
	if _, err := repository.Lookup(context.Background(), testActor("cancel@example.test"), audit.ActionPlanCreate, "cancel-key-1", strings.Repeat("4", 64), nonUTC); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("non-UTC timestamp error=%v", err)
	}
}

func TestSerializedCandidateUsesStrictStateCodec(t *testing.T) {
	repository, _, root := testRepository(t)
	candidate := testCandidate(t, testActor("codec@example.test"), audit.ActionPlanCreate, "codec-key-1", strings.Repeat("5", 64), idempotencyTestTime, state.IdempotencySucceeded)
	if _, err := repository.CreateOrReplay(context.Background(), candidate, idempotencyTestTime); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, statefs.IdempotencyDir, candidate.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := state.DecodeIdempotency(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, candidate) {
		t.Fatalf("decoded=%#v candidate=%#v", decoded, candidate)
	}
	if strings.Contains(string(encoded), "credentialValue") || strings.Contains(string(encoded), "requestBody") {
		t.Fatalf("serialized bytes contain prohibited field: %s", encoded)
	}
}
