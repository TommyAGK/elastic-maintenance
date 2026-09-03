package state

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

func auditTestEvent() audit.Event {
	return audit.Event{
		OccurredAt: time.Date(2026, time.January, 2, 4, 4, 5, 0, time.FixedZone("CET", 60*60)),
		Actor: &auth.Actor{
			Subject:          " operator ",
			DisplayName:      "Operator TOKEN-SENTINEL",
			Roles:            []auth.Role{auth.RoleViewer, auth.RoleAdministrator, auth.RoleViewer},
			Method:           auth.MethodBearer,
			SessionExpiresAt: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
			CSRFToken:        "CSRF-SENTINEL",
		},
		RequestID:  "request-1",
		Action:     audit.ActionPlanCreate,
		Outcome:    audit.OutcomeSucceeded,
		TargetID:   "target-1",
		PlanID:     "plan-1",
		JobID:      "job-1",
		ReasonCode: "http_201",
	}
}

func TestNewAuditEventProjectsAndNormalizes(t *testing.T) {
	value, err := NewAuditEvent("audit-1", auditTestEvent())
	if err != nil {
		t.Fatal(err)
	}
	if value.APIVersion != APIVersion || value.Kind != KindAuditEvent || value.ID != "audit-1" {
		t.Fatalf("header = %#v", value)
	}
	if value.OccurredAt.Location() != time.UTC || !value.OccurredAt.Equal(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("occurredAt = %v", value.OccurredAt)
	}
	if value.Actor == nil {
		t.Fatal("actor was dropped")
	}
	wantActor := Actor{Subject: "operator", Roles: []auth.Role{auth.RoleAdministrator, auth.RoleViewer}, Method: auth.MethodBearer}
	if !reflect.DeepEqual(*value.Actor, wantActor) {
		t.Fatalf("actor = %#v, want %#v", *value.Actor, wantActor)
	}
	encoded, err := EncodeAuditEvent(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"displayName", "TOKEN-SENTINEL", "sessionExpiresAt", "CSRF-SENTINEL", "csrfToken"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("projection contains %q: %s", forbidden, encoded)
		}
	}
}

func TestNewAuditEventAcceptsAllActionsOutcomesRolesAndMethods(t *testing.T) {
	actions := []audit.Action{
		audit.ActionLogin, audit.ActionBreakGlassLogin, audit.ActionLogout,
		audit.ActionCredentialUpload, audit.ActionCredentialRotate, audit.ActionCredentialDelete,
		audit.ActionValidationCreate, audit.ActionTargetInventoryCreate, audit.ActionPlanCreate,
		audit.ActionPlanApply, audit.ActionJobCancel, "future.namespace-operation",
	}
	for _, action := range actions {
		for _, outcome := range []audit.Outcome{audit.OutcomeSucceeded, audit.OutcomeDenied, audit.OutcomeFailed} {
			for _, method := range []auth.Method{auth.MethodSession, auth.MethodOIDC, auth.MethodBearer, auth.MethodBreakGlass} {
				event := auditTestEvent()
				event.Action, event.Outcome = action, outcome
				event.Actor.Method = method
				if _, err := NewAuditEvent("audit-1", event); err != nil {
					t.Fatalf("action=%q outcome=%q method=%q: %v", action, outcome, method, err)
				}
			}
		}
	}
	for _, outcome := range []audit.Outcome{audit.OutcomeDenied, audit.OutcomeFailed} {
		event := auditTestEvent()
		event.Actor = nil
		event.Outcome = outcome
		if value, err := NewAuditEvent("audit-1", event); err != nil || value.Actor != nil {
			t.Fatalf("anonymous %q: value=%#v err=%v", outcome, value, err)
		}
	}
	anonymousSuccess := auditTestEvent()
	anonymousSuccess.Actor = nil
	if _, err := NewAuditEvent("audit-1", anonymousSuccess); !errors.Is(err, ErrInvalidAuditEvent) {
		t.Fatalf("anonymous success error = %v", err)
	}
	for _, roles := range [][]auth.Role{
		{auth.RoleViewer}, {auth.RolePlanner}, {auth.RoleApplier}, {auth.RoleAdministrator},
		{auth.RoleViewer, auth.RolePlanner, auth.RoleApplier, auth.RoleAdministrator},
	} {
		event := auditTestEvent()
		event.Actor.Roles = roles
		if _, err := NewAuditEvent("audit-1", event); err != nil {
			t.Fatalf("roles=%v: %v", roles, err)
		}
	}
}

func TestNewAuditEventReturnsSafeSentinelErrors(t *testing.T) {
	const sentinel = "CREDENTIAL-TOKEN-CERT-BODY-SENTINEL"
	base := auditTestEvent()
	cases := []struct {
		name string
		call func() (AuditEvent, error)
	}{
		{"id", func() (AuditEvent, error) { return NewAuditEvent(sentinel+"\n", base) }},
		{"request", func() (AuditEvent, error) {
			event := base
			event.RequestID = sentinel + "\n"
			return NewAuditEvent("audit-1", event)
		}},
		{"action", func() (AuditEvent, error) {
			event := base
			event.Action = audit.Action(sentinel + "\n")
			return NewAuditEvent("audit-1", event)
		}},
		{"target", func() (AuditEvent, error) {
			event := base
			event.TargetID = sentinel + "\n"
			return NewAuditEvent("audit-1", event)
		}},
		{"plan", func() (AuditEvent, error) {
			event := base
			event.PlanID = sentinel + "\n"
			return NewAuditEvent("audit-1", event)
		}},
		{"job", func() (AuditEvent, error) {
			event := base
			event.JobID = "job.with.dot"
			return NewAuditEvent("audit-1", event)
		}},
		{"reason", func() (AuditEvent, error) {
			event := base
			event.ReasonCode = sentinel + "\n"
			return NewAuditEvent("audit-1", event)
		}},
		{"role", func() (AuditEvent, error) {
			event := base
			event.Actor.Roles = []auth.Role{auth.Role(sentinel)}
			return NewAuditEvent("audit-1", event)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.call()
			if !errors.Is(err, ErrInvalidAuditEvent) || !reflect.DeepEqual(value, AuditEvent{}) {
				t.Fatalf("value=%#v err=%v", value, err)
			}
			if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("unsafe constructor error: %q", err)
			}
		})
	}
}

func TestAuditEventValidationBoundsAndOptionalFields(t *testing.T) {
	valid := auditTestEvent()
	for name, change := range map[string]func(*audit.Event){
		"empty id":           func(event *audit.Event) {},
		"empty request":      func(event *audit.Event) { event.RequestID = "" },
		"empty action":       func(event *audit.Event) { event.Action = "" },
		"unscoped action":    func(event *audit.Event) { event.Action = "future" },
		"uppercase action":   func(event *audit.Event) { event.Action = "Future.action" },
		"action punctuation": func(event *audit.Event) { event.Action = "future..action" },
		"invalid target":     func(event *audit.Event) { event.TargetID = "target/id" },
		"invalid reason":     func(event *audit.Event) { event.ReasonCode = "reason with spaces" },
		"invalid outcome":    func(event *audit.Event) { event.Outcome = "unknown" },
		"zero time":          func(event *audit.Event) { event.OccurredAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			event := valid
			change(&event)
			id := "audit-1"
			if name == "empty id" {
				id = ""
			}
			if _, err := NewAuditEvent(id, event); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
	for _, field := range []string{"TargetID", "PlanID", "JobID", "ReasonCode"} {
		event := valid
		switch field {
		case "TargetID":
			event.TargetID = ""
		case "PlanID":
			event.PlanID = ""
		case "JobID":
			event.JobID = ""
		case "ReasonCode":
			event.ReasonCode = ""
		}
		value, err := NewAuditEvent("audit-1", event)
		if err != nil {
			t.Fatalf("empty %s: %v", field, err)
		}
		encoded, err := EncodeAuditEvent(value)
		if err != nil {
			t.Fatal(err)
		}
		jsonField := map[string]string{"TargetID": "targetID", "PlanID": "planID", "JobID": "jobID", "ReasonCode": "reasonCode"}[field]
		if bytes.Contains(encoded, []byte(`"`+jsonField+`"`)) {
			t.Fatalf("non-canonical key found for %s: %s", field, encoded)
		}
	}
	valid.Action = audit.Action(strings.Repeat("a", 126) + ".b")
	if _, err := NewAuditEvent("audit-1", valid); err != nil {
		t.Fatalf("128-byte action rejected: %v", err)
	}
	valid.Action = audit.Action(strings.Repeat("a", 127) + ".b")
	if _, err := NewAuditEvent("audit-1", valid); err == nil {
		t.Fatal("129-byte action accepted")
	}
	tooLong := valid
	tooLong.Action = audit.ActionPlanCreate
	tooLong.ReasonCode = strings.Repeat("a", 129)
	if _, err := NewAuditEvent("audit-1", tooLong); err == nil {
		t.Fatal("overlong reason accepted")
	}
	tooLong.ReasonCode = "ok"
	if _, err := NewAuditEvent(strings.Repeat("a", 129), tooLong); err == nil {
		t.Fatal("overlong event ID accepted")
	}
	tooLong = valid
	tooLong.JobID = strings.Repeat("a", 65)
	if _, err := NewAuditEvent("audit-1", tooLong); err == nil {
		t.Fatal("overlong job ID accepted")
	}
	badTime := valid
	badTime.Action = audit.ActionPlanCreate
	badTime.OccurredAt = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("PST", -8*60*60))
	if _, err := NewAuditEvent("audit-1", badTime); err != nil {
		t.Fatal("constructor failed to normalize offset time", err)
	}
}

func TestAuditEventExactJSONAndStrictDecode(t *testing.T) {
	event := auditTestEvent()
	event.Actor = nil
	event.TargetID, event.PlanID, event.JobID, event.ReasonCode = "", "", "", ""
	event.Outcome = audit.OutcomeDenied
	value, err := NewAuditEvent("audit-1", event)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeAuditEvent(value)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"audit-1","occurredAt":"2026-01-02T03:04:05Z","requestId":"request-1","action":"plans.create","outcome":"denied"}`
	if string(encoded) != want {
		t.Fatalf("JSON = %s, want %s", encoded, want)
	}
	decoded, err := DecodeAuditEvent(encoded)
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("round trip value=%#v err=%v", decoded, err)
	}
	document, err := DecodeDocument(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := document.(AuditEvent); !ok {
		t.Fatalf("DecodeDocument type = %T", document)
	}
	for _, suffix := range []string{
		`,"requestId":"request-1"} {}`,
		`,"unexpected":true}`,
	} {
		bad := append([]byte(nil), encoded[:len(encoded)-1]...)
		bad = append(bad, []byte(suffix)...)
		if _, err := DecodeAuditEvent(bad); err == nil {
			t.Fatalf("accepted malformed audit JSON %s", bad)
		}
	}
	duplicate := append([]byte(nil), encoded[:len(encoded)-1]...)
	duplicate = append(duplicate, []byte(`,"id":"other"}`)...)
	if _, err := DecodeAuditEvent(duplicate); !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate error = %v", err)
	}
	for _, replacement := range []struct{ old, new []byte }{
		{[]byte(APIVersion), []byte("elastic-maintainer/state/v2")},
		{[]byte(`"AuditEvent"`), []byte(`"Job"`)},
	} {
		bad := bytes.Replace(encoded, replacement.old, replacement.new, 1)
		if _, err := DecodeAuditEvent(bad); err == nil {
			t.Fatalf("accepted wrong header %s", bad)
		}
	}
	if _, err := DecodeAuditEvent(append(encoded, []byte(` {}`)...)); !errors.Is(err, ErrTrailingJSON) {
		t.Fatalf("trailing error = %v", err)
	}
}

func TestAuditEventV1CompatibilityForLegacyOptionalValues(t *testing.T) {
	// The original v1 decoder treated explicit null optionals as absent and
	// allowed the shared safe-code grammar for job references. Preserve that
	// read contract until an explicit complete state-set migration.
	legacy := `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"audit-1","occurredAt":"2026-01-02T03:04:05Z","actor":null,"requestId":"request-1","action":"plans.create","outcome":"denied","targetID":null,"planID":null,"jobID":"job.legacy:v1","reasonCode":null}`
	value, err := DecodeAuditEvent([]byte(legacy))
	if err != nil {
		t.Fatalf("legacy v1 decode: %v", err)
	}
	if value.Actor != nil || value.TargetID != "" || value.PlanID != "" || value.JobID != "job.legacy:v1" || value.ReasonCode != "" {
		t.Fatalf("legacy projection = %#v", value)
	}
	canonical, err := EncodeAuditEvent(value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("null")) {
		t.Fatalf("legacy re-encode was not canonical: %s", canonical)
	}

	event := auditTestEvent()
	event.JobID = "job.legacy:v1"
	if _, err := NewAuditEvent("audit-1", event); !errors.Is(err, ErrInvalidAuditEvent) {
		t.Fatalf("constructor accepted impossible current job reference: %v", err)
	}
}

func TestAuditEventCodecBoundAndSentinelSafety(t *testing.T) {
	if _, err := DecodeAuditEvent(bytes.Repeat([]byte("x"), MaxDocumentBytes+1)); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}
	const sentinel = "TOKEN-CERT-BODY-REQUEST-SECRET-SENTINEL"
	base := auditTestEvent()
	for _, change := range []func(*audit.Event){
		func(event *audit.Event) { event.Actor.DisplayName = sentinel + "\n" },
		func(event *audit.Event) { event.RequestID = sentinel + "\n" },
		func(event *audit.Event) { event.TargetID = sentinel + "\n" },
		func(event *audit.Event) { event.PlanID = sentinel + "\n" },
		func(event *audit.Event) { event.ReasonCode = sentinel + "\n" },
	} {
		event := base
		actor := *base.Actor
		event.Actor = &actor
		change(&event)
		_, err := NewAuditEvent("audit-1", event)
		if err == nil || strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "\n") {
			t.Fatalf("unsafe constructor result: %v", err)
		}
	}
	encoded := mustEncode(t, baseAuditStateEvent())
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "TOKEN") || strings.Contains(string(encoded), "CERT") {
		t.Fatalf("sentinel-like data encoded: %s", encoded)
	}
}

func baseAuditStateEvent() AuditEvent {
	value, err := NewAuditEvent("audit-1", auditTestEvent())
	if err != nil {
		panic(err)
	}
	return value
}
