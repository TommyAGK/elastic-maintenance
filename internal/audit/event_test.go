package audit

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

func TestEventValidate(t *testing.T) {
	event := Event{
		OccurredAt: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
		Actor: &auth.Actor{
			Subject: "user-1",
			Roles:   []auth.Role{auth.RoleAdministrator},
			Method:  auth.MethodSession,
		},
		RequestID: "request-1",
		Action:    ActionCredentialRotate,
		Outcome:   OutcomeSucceeded,
		TargetID:  "production-default",
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEventValidateRejectsMissingRequiredFields(t *testing.T) {
	validActor := &auth.Actor{Subject: "user-1", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodBearer}
	validTime := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	for name, event := range map[string]Event{
		"time":    {Actor: validActor, RequestID: "request", Action: ActionPlanCreate, Outcome: OutcomeSucceeded},
		"actor":   {OccurredAt: validTime, RequestID: "request", Action: ActionPlanCreate, Outcome: OutcomeSucceeded},
		"request": {OccurredAt: validTime, Actor: validActor, Action: ActionPlanCreate, Outcome: OutcomeSucceeded},
		"action":  {OccurredAt: validTime, Actor: validActor, RequestID: "request", Outcome: OutcomeSucceeded},
		"outcome": {OccurredAt: validTime, Actor: validActor, RequestID: "request", Action: ActionPlanCreate},
	} {
		t.Run(name, func(t *testing.T) {
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestEventAllowsAnonymousDeniedAuthentication(t *testing.T) {
	event := Event{
		OccurredAt: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
		RequestID:  "request-1",
		Action:     ActionLogin,
		Outcome:    OutcomeDenied,
		ReasonCode: "authentication_required",
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEventRejectsFreeFormAuditCodes(t *testing.T) {
	base := Event{
		OccurredAt: time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
		Actor:      &auth.Actor{Subject: "user-1", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodBearer},
		RequestID:  "request-1",
		Action:     ActionPlanCreate,
		Outcome:    OutcomeFailed,
	}
	for name, change := range map[string]func(*Event){
		"unknown action": func(event *Event) { event.Action = "credentials.read-secret" },
		"reason message": func(event *Event) { event.ReasonCode = "remote error contained secret" },
		"target newline": func(event *Event) { event.TargetID = "target\nforged" },
	} {
		t.Run(name, func(t *testing.T) {
			event := base
			change(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}

func TestEventHasNoCredentialValueFields(t *testing.T) {
	eventType := reflect.TypeOf(Event{})
	var fieldNames []string
	for index := 0; index < eventType.NumField(); index++ {
		fieldNames = append(fieldNames, eventType.Field(index).Name)
	}
	joined := strings.ToLower(strings.Join(fieldNames, " "))
	for _, forbidden := range []string{"password", "token", "cookie", "apikey", "certificate", "secretvalue"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("audit event includes forbidden field category %q", forbidden)
		}
	}
}

type failingAuditHandler struct{}

func (failingAuditHandler) Enabled(context.Context, slog.Level) bool { return true }
func (failingAuditHandler) Handle(context.Context, slog.Record) error {
	return errors.New("sink unavailable")
}
func (handler failingAuditHandler) WithAttrs([]slog.Attr) slog.Handler { return handler }
func (handler failingAuditHandler) WithGroup(string) slog.Handler      { return handler }

func TestLogRecorderPropagatesSinkFailure(t *testing.T) {
	event := Event{OccurredAt: time.Now(), Actor: &auth.Actor{Subject: "user", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}, RequestID: "request-1", Action: ActionLogin, Outcome: OutcomeSucceeded}
	if err := (LogRecorder{Logger: slog.New(failingAuditHandler{})}).Record(context.Background(), event); err == nil {
		t.Fatal("Record error=nil")
	}
}

func TestNopRecorder(t *testing.T) {
	if err := (NopRecorder{}).Record(context.Background(), Event{}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
}
