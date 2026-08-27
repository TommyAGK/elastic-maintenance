// Package jobrecovery defines the fail-closed policy used when a durable job
// is found without an approved execution-resume contract. It has no
// filesystem, clock, scheduler, or execution dependencies.
package jobrecovery

import (
	"errors"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

// Action is the only recovery action currently defined. Recovery deliberately
// has no resume action until a job type has a complete, approved durable input
// and side-effect contract.
type Action string

const (
	ActionPreserve  Action = "preserve"
	ActionInterrupt Action = "interrupt"
)

// Failure codes are bounded, constant, and safe to persist. Non-apply jobs
// distinguish whether work had started; apply jobs use separate codes because
// an apply can have remote mutation side effects and is never resumable here.
const (
	FailureCodeQueued       FailureCode = "job_recovery_queued"
	FailureCodeRunning      FailureCode = "job_recovery_running"
	FailureCodeApplyQueued  FailureCode = "job_recovery_apply_queued"
	FailureCodeApplyRunning FailureCode = "job_recovery_apply_running"
)

var (
	// ErrInvalidJob is returned (via errors.Is) for an invalid type or status.
	// Its messages and wrapped errors contain no caller-controlled values.
	ErrInvalidJob         = errors.New("invalid job recovery input")
	ErrInvalidType        = errors.New("invalid job recovery type")
	ErrInvalidStatus      = errors.New("invalid job recovery status")
	ErrInvalidFailureCode = errors.New("invalid job recovery failure code")
)

// Decision is the deterministic policy result for one job type/status pair.
// FailureCode is empty for Preserve decisions and one of the constants above
// for Interrupt decisions.
type FailureCode string

type Decision struct {
	Action      Action
	FailureCode FailureCode
}

// Classify returns the fail-closed recovery decision for a valid job type and
// status. All terminal statuses are preserved. Queued and running jobs of
// every currently supported type are interrupted because no type currently
// persists complete approved resume inputs; apply receives an apply-specific
// code.
func Classify(jobType jobs.Type, status jobs.Status) (Decision, error) {
	switch jobType {
	case jobs.TypeValidation, jobs.TypePlan, jobs.TypeApply, jobs.TypeTargetInventory:
	default:
		return Decision{}, invalidInput(ErrInvalidType)
	}
	if !status.Valid() {
		return Decision{}, invalidInput(ErrInvalidStatus)
	}

	switch status {
	case jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted:
		return Decision{Action: ActionPreserve}, nil
	case jobs.StatusQueued:
		if jobType == jobs.TypeApply {
			return Decision{Action: ActionInterrupt, FailureCode: FailureCodeApplyQueued}, nil
		}
		return Decision{Action: ActionInterrupt, FailureCode: FailureCodeQueued}, nil
	case jobs.StatusRunning:
		if jobType == jobs.TypeApply {
			return Decision{Action: ActionInterrupt, FailureCode: FailureCodeApplyRunning}, nil
		}
		return Decision{Action: ActionInterrupt, FailureCode: FailureCodeRunning}, nil
	default:
		// Valid currently exhausts the switch above. Keep the default fail
		// closed so adding a status without updating policy cannot preserve or
		// resume it accidentally.
		return Decision{}, invalidInput(ErrInvalidStatus)
	}
}

// ClassifyJob applies Classify to a durable state job. Other fields are
// intentionally ignored: recovery policy classifies only type and status and
// never mutates or aliases the supplied job.
func ClassifyJob(job state.Job) (Decision, error) {
	return Classify(job.Type, job.Status)
}

func invalidInput(kind error) error {
	return errors.Join(ErrInvalidJob, kind)
}
