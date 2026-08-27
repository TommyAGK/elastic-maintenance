package jobrecovery

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

func TestClassifyMatrix(t *testing.T) {
	types := []jobs.Type{jobs.TypeValidation, jobs.TypePlan, jobs.TypeApply, jobs.TypeTargetInventory}
	statuses := []jobs.Status{jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted}
	for _, jobType := range types {
		for _, status := range statuses {
			decision, err := Classify(jobType, status)
			if err != nil {
				t.Fatalf("Classify(%q, %q): %v", jobType, status, err)
			}
			switch status {
			case jobs.StatusQueued:
				want := FailureCodeQueued
				if jobType == jobs.TypeApply {
					want = FailureCodeApplyQueued
				}
				if decision != (Decision{Action: ActionInterrupt, FailureCode: want}) {
					t.Errorf("Classify(%q, %q)=%#v, want interrupt %q", jobType, status, decision, want)
				}
			case jobs.StatusRunning:
				want := FailureCodeRunning
				if jobType == jobs.TypeApply {
					want = FailureCodeApplyRunning
				}
				if decision != (Decision{Action: ActionInterrupt, FailureCode: want}) {
					t.Errorf("Classify(%q, %q)=%#v, want interrupt %q", jobType, status, decision, want)
				}
			default:
				if decision != (Decision{Action: ActionPreserve}) {
					t.Errorf("Classify(%q, %q)=%#v, want preserve", jobType, status, decision)
				}
			}
		}
	}
}

func TestClassifyRejectsInvalidValuesWithSafeSentinels(t *testing.T) {
	if _, err := Classify(jobs.Type("unknown-SECRET"), jobs.StatusQueued); !errors.Is(err, ErrInvalidJob) || !errors.Is(err, ErrInvalidType) {
		t.Fatalf("invalid type error=%v", err)
	}
	if _, err := Classify(jobs.TypePlan, jobs.Status("unknown-SECRET")); !errors.Is(err, ErrInvalidJob) || !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("invalid status error=%v", err)
	}
	for _, err := range []error{
		func() error { _, err := Classify(jobs.Type("OIDC_TOKEN_SENTINEL"), jobs.StatusQueued); return err }(),
		func() error { _, err := Classify(jobs.TypePlan, jobs.Status("API_KEY_SENTINEL")); return err }(),
	} {
		if strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("classification error exposed input: %v", err)
		}
	}
}

func TestClassifyJobIsPureAndDoesNotAlias(t *testing.T) {
	job := state.Job{Type: jobs.TypeApply, Status: jobs.StatusRunning}
	before := job
	decision, err := ClassifyJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != ActionInterrupt || decision.FailureCode != FailureCodeApplyRunning {
		t.Fatalf("decision=%#v", decision)
	}
	if !reflect.DeepEqual(job, before) {
		t.Fatalf("ClassifyJob mutated input: before=%#v after=%#v", before, job)
	}
}
