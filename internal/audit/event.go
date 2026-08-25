package audit

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

type Action string

const (
	ActionLogin                 Action = "auth.login"
	ActionBreakGlassLogin       Action = "auth.break_glass.login"
	ActionLogout                Action = "auth.logout"
	ActionCredentialUpload      Action = "credentials.upload"
	ActionCredentialRotate      Action = "credentials.rotate"
	ActionCredentialDelete      Action = "credentials.delete"
	ActionValidationCreate      Action = "validations.create"
	ActionTargetInventoryCreate Action = "targets.inventory.create"
	ActionPlanCreate            Action = "plans.create"
	ActionPlanApply             Action = "plans.apply"
)

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeDenied    Outcome = "denied"
	OutcomeFailed    Outcome = "failed"
)

var (
	auditCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	knownActions     = map[Action]struct{}{
		ActionLogin: {}, ActionBreakGlassLogin: {}, ActionLogout: {},
		ActionCredentialUpload: {}, ActionCredentialRotate: {}, ActionCredentialDelete: {},
		ActionValidationCreate: {}, ActionTargetInventoryCreate: {}, ActionPlanCreate: {}, ActionPlanApply: {},
	}
)

type Event struct {
	OccurredAt time.Time
	Actor      *auth.Actor
	RequestID  string
	Action     Action
	Outcome    Outcome
	TargetID   string
	PlanID     string
	JobID      string
	ReasonCode string
}

func (event Event) Validate() error {
	if event.OccurredAt.IsZero() {
		return errors.New("audit event occurrence time is required")
	}
	if event.Actor == nil {
		if event.Outcome == OutcomeSucceeded {
			return errors.New("successful audit event actor is required")
		}
	} else if _, err := event.Actor.Normalized(); err != nil {
		return errors.New("audit event actor is invalid")
	}
	if !auditCodePattern.MatchString(event.RequestID) {
		return errors.New("audit event request ID is invalid")
	}
	if _, ok := knownActions[event.Action]; !ok {
		return errors.New("audit event action is invalid")
	}
	if event.Outcome != OutcomeSucceeded && event.Outcome != OutcomeDenied && event.Outcome != OutcomeFailed {
		return errors.New("audit event outcome is invalid")
	}
	optionalCodes := []struct {
		field string
		value string
	}{
		{field: "target ID", value: event.TargetID},
		{field: "plan ID", value: event.PlanID},
		{field: "job ID", value: event.JobID},
		{field: "reason code", value: event.ReasonCode},
	}
	for _, item := range optionalCodes {
		if item.value != "" && !auditCodePattern.MatchString(item.value) {
			return errors.New("audit event " + item.field + " is invalid")
		}
	}
	return nil
}

type Recorder interface {
	Record(context.Context, Event) error
}

type NopRecorder struct{}

func (NopRecorder) Record(context.Context, Event) error { return nil }

type LogRecorder struct{ Logger *slog.Logger }

func (recorder LogRecorder) Record(ctx context.Context, event Event) error {
	if recorder.Logger == nil {
		return errors.New("audit logger is required")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	actor := ""
	method := ""
	if event.Actor != nil {
		actor = event.Actor.Subject
		method = string(event.Actor.Method)
	}
	record := slog.NewRecord(event.OccurredAt, slog.LevelWarn, "Security audit event", 0)
	record.AddAttrs(slog.Any("action", event.Action), slog.Any("outcome", event.Outcome), slog.String("reason_code", event.ReasonCode), slog.String("request_id", event.RequestID), slog.String("actor", actor), slog.String("authentication_method", method), slog.String("target_id", event.TargetID), slog.String("plan_id", event.PlanID), slog.String("job_id", event.JobID))
	return recorder.Logger.Handler().Handle(ctx, record)
}
