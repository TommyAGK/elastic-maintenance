package auditenvelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

func fullEvent() audit.Event {
	return audit.Event{
		OccurredAt: time.Date(2026, time.January, 2, 4, 4, 5, 0, time.FixedZone("CET", 60*60)),
		Actor: &auth.Actor{
			Subject:          " operator ",
			DisplayName:      "Operator display text",
			Roles:            []auth.Role{auth.RoleViewer, auth.RoleAdministrator, auth.RoleViewer},
			Method:           auth.MethodBearer,
			SessionExpiresAt: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
			CSRFToken:        "csrf-transient-value",
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

func minimalEvent() audit.Event {
	return audit.Event{
		OccurredAt: time.Date(2026, time.January, 2, 4, 4, 5, 0, time.FixedZone("CET", 60*60)),
		RequestID:  "request-1",
		Action:     audit.ActionLogin,
		Outcome:    audit.OutcomeDenied,
	}
}

func mustEnvelope(t *testing.T, id string, event audit.Event) Envelope {
	t.Helper()
	envelope, err := New(id, event)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return envelope
}

func TestNewProducesExactCanonicalAuditEventBytes(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		event audit.Event
		want  string
	}{
		{
			name:  "full",
			id:    "audit-1",
			event: fullEvent(),
			want:  `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"audit-1","occurredAt":"2026-01-02T03:04:05Z","actor":{"subject":"operator","roles":["administrator","viewer"],"authMethod":"bearer"},"requestId":"request-1","action":"plans.create","outcome":"succeeded","targetID":"target-1","planID":"plan-1","jobID":"job-1","reasonCode":"http_201"}`,
		},
		{
			name:  "minimal",
			id:    "audit-2",
			event: minimalEvent(),
			want:  `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"audit-2","occurredAt":"2026-01-02T03:04:05Z","requestId":"request-1","action":"auth.login","outcome":"denied"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := mustEnvelope(t, test.id, test.event)
			if got := string(envelope.Bytes()); got != test.want {
				t.Fatalf("Bytes() = %s, want %s", got, test.want)
			}
			if err := envelope.Validate(); err != nil {
				t.Fatalf("Envelope.Validate() error = %v", err)
			}
			decoded, err := state.DecodeAuditEvent([]byte(test.want))
			if err != nil {
				t.Fatalf("state.DecodeAuditEvent() error = %v", err)
			}
			if err := decoded.Validate(); err != nil {
				t.Fatalf("decoded AuditEvent.Validate() error = %v", err)
			}
			if !bytes.Equal(envelope.Bytes(), []byte(test.want)) {
				t.Fatal("envelope bytes did not remain canonical after validation")
			}
		})
	}
}

func TestNewStructurallyAllowListsSafeMetadata(t *testing.T) {
	envelope := mustEnvelope(t, "audit-1", fullEvent())
	encoded := envelope.Bytes()
	for _, retained := range []string{
		`"subject":"operator"`,
		`"roles":["administrator","viewer"]`,
		`"authMethod":"bearer"`,
		`"requestId":"request-1"`,
		`"action":"plans.create"`,
		`"outcome":"succeeded"`,
		`"targetID":"target-1"`,
		`"planID":"plan-1"`,
		`"jobID":"job-1"`,
		`"reasonCode":"http_201"`,
	} {
		if !bytes.Contains(encoded, []byte(retained)) {
			t.Fatalf("canonical bytes omitted retained metadata %q: %s", retained, encoded)
		}
	}
	for _, excluded := range []string{
		"displayName", "Operator display text", "sessionExpiresAt", "csrfToken", "csrf-transient-value",
	} {
		if bytes.Contains(encoded, []byte(excluded)) {
			t.Fatalf("canonical bytes retained transient field %q: %s", excluded, encoded)
		}
	}

	// audit.Event has no body, header, cookie, token, API-key, or PEM fields.
	// Those values therefore cannot cross this structural allowlist boundary;
	// the producer must never place them in a safe metadata field.
}

func TestGrammarValidSecretLookingReasonCodeIsNotHeuristicallyRejected(t *testing.T) {
	event := fullEvent()
	// This is a producer-owned reason code, not a credential or secret value.
	// The envelope validates grammar and structure; it is deliberately not a
	// substring-based secret detector.
	event.ReasonCode = "token_redacted"
	envelope := mustEnvelope(t, "audit-1", event)
	decoded, err := state.DecodeAuditEvent(envelope.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ReasonCode != "token_redacted" {
		t.Fatalf("reason code = %q, want token_redacted", decoded.ReasonCode)
	}
}

func TestEnvelopeDefensivelyCopiesConstructorInput(t *testing.T) {
	event := fullEvent()
	envelope := mustEnvelope(t, "audit-1", event)
	want := envelope.Bytes()

	event.Actor.Subject = "changed"
	event.Actor.Roles[0] = auth.RolePlanner
	event.RequestID = "changed-request"
	event.TargetID = "changed-target"
	event.ReasonCode = "changed-reason"

	if got := envelope.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("constructor input mutation changed envelope: got %s, want %s", got, want)
	}
}

func TestEnvelopeDefensivelyCopiesBytesOutput(t *testing.T) {
	envelope := mustEnvelope(t, "audit-1", fullEvent())
	want := envelope.Bytes()
	first := envelope.Bytes()
	first[0] ^= 0xff
	first[len(first)-1] ^= 0xff
	second := envelope.Bytes()
	if !bytes.Equal(second, want) {
		t.Fatalf("Bytes() output mutation changed envelope: got %s, want %s", second, want)
	}
	if &first[0] == &second[0] {
		t.Fatal("Bytes() returned aliased storage")
	}
}

func TestEnvelopeValidateRejectsZeroAndNonCanonicalValues(t *testing.T) {
	if err := (Envelope{}).Validate(); err != ErrInvalidEnvelope {
		t.Fatalf("zero envelope error = %v, want ErrInvalidEnvelope", err)
	}

	canonical := mustEnvelope(t, "audit-1", minimalEvent()).Bytes()
	cases := map[string][]byte{
		"whitespace": append(append([]byte(nil), canonical...), ' '),
		"explicit null optional": bytes.Replace(canonical,
			[]byte(`"outcome":"denied"}`),
			[]byte(`"outcome":"denied","reasonCode":null}`), 1),
		"malformed": []byte(`{"apiVersion":`),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			err := (Envelope{canonical: encoded}).Validate()
			if err != ErrInvalidEnvelope {
				t.Fatalf("Validate() error = %v, want ErrInvalidEnvelope", err)
			}
		})
	}

	decoded, err := state.DecodeAuditEvent(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := state.EncodeAuditEvent(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Envelope{canonical: reencoded}).Validate(); err != nil {
		t.Fatalf("canonical state bytes rejected: %v", err)
	}
}

func TestEnvelopeValidateInheritsStateDocumentBound(t *testing.T) {
	overLimit := bytes.Repeat([]byte("x"), state.MaxDocumentBytes+1)
	if err := (Envelope{canonical: overLimit}).Validate(); err != ErrInvalidEnvelope {
		t.Fatalf("oversized envelope error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestNewAcceptsCurrentAndFutureActionsOutcomesAndAnonymousFailures(t *testing.T) {
	actions := []audit.Action{
		audit.ActionLogin, audit.ActionBreakGlassLogin, audit.ActionLogout,
		audit.ActionCredentialUpload, audit.ActionCredentialRotate, audit.ActionCredentialDelete,
		audit.ActionValidationCreate, audit.ActionTargetInventoryCreate, audit.ActionPlanCreate,
		audit.ActionPlanApply, audit.ActionJobCancel, "future.namespace_operation",
	}
	for _, action := range actions {
		for _, outcome := range []audit.Outcome{audit.OutcomeSucceeded, audit.OutcomeDenied, audit.OutcomeFailed} {
			event := fullEvent()
			event.Action = action
			event.Outcome = outcome
			if _, err := New("audit-1", event); err != nil {
				t.Fatalf("action=%q outcome=%q: %v", action, outcome, err)
			}
		}
	}
	for _, outcome := range []audit.Outcome{audit.OutcomeDenied, audit.OutcomeFailed} {
		event := fullEvent()
		event.Actor = nil
		event.Outcome = outcome
		if _, err := New("audit-1", event); err != nil {
			t.Fatalf("anonymous outcome=%q: %v", outcome, err)
		}
	}
	anonymousSuccess := fullEvent()
	anonymousSuccess.Actor = nil
	if err := func() error {
		_, err := New("audit-1", anonymousSuccess)
		return err
	}(); err != ErrInvalidEnvelope {
		t.Fatalf("anonymous success error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestNewRejectsUnsafeInputWithOnlyFixedSentinel(t *testing.T) {
	const sentinel = "TOKEN-CERT-BODY-REQUEST-SECRET-SENTINEL"
	cases := map[string]func(*audit.Event, *string){
		"id":                 func(_ *audit.Event, id *string) { *id = sentinel + "\n" },
		"request ID newline": func(event *audit.Event, _ *string) { event.RequestID = sentinel + "\n" },
		"action":             func(event *audit.Event, _ *string) { event.Action = audit.Action(sentinel) },
		"reason":             func(event *audit.Event, _ *string) { event.ReasonCode = sentinel + "\n" },
		"body":               func(event *audit.Event, _ *string) { event.ReasonCode = `{"body":"sentinel"}` },
		"header":             func(event *audit.Event, _ *string) { event.ReasonCode = "Authorization: Bearer sentinel" },
		"cookie":             func(event *audit.Event, _ *string) { event.ReasonCode = "Cookie: session=sentinel" },
		"PEM":                func(event *audit.Event, _ *string) { event.ReasonCode = "-----BEGIN CERTIFICATE-----" },
		"newline":            func(event *audit.Event, _ *string) { event.TargetID = "target\nforged" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			event := fullEvent()
			id := "audit-1"
			change(&event, &id)
			_, err := New(id, event)
			if err != ErrInvalidEnvelope {
				t.Fatalf("New() error = %v, want ErrInvalidEnvelope", err)
			}
			if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("unsafe input appeared in error: %q", err)
			}
		})
	}
}

func TestNewRejectsInvalidIdentifiersAndReasonCodes(t *testing.T) {
	cases := map[string]func(*audit.Event){
		"empty request ID": func(event *audit.Event) { event.RequestID = "" },
		"unsafe target ID": func(event *audit.Event) { event.TargetID = "target/id" },
		"unsafe plan ID":   func(event *audit.Event) { event.PlanID = "plan id" },
		"unsafe job ID":    func(event *audit.Event) { event.JobID = "job.with.dot" },
		"unscoped action":  func(event *audit.Event) { event.Action = "future" },
		"uppercase action": func(event *audit.Event) { event.Action = "Future.action" },
		"empty action":     func(event *audit.Event) { event.Action = "" },
		"unsafe reason":    func(event *audit.Event) { event.ReasonCode = "reason with spaces" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			event := fullEvent()
			change(&event)
			if err := func() error {
				_, err := New("audit-1", event)
				return err
			}(); err != ErrInvalidEnvelope {
				t.Fatalf("New() error = %v, want ErrInvalidEnvelope", err)
			}
		})
	}
}

func TestNewRejectsInvalidActorMetadata(t *testing.T) {
	event := fullEvent()
	event.Actor.Subject = " actor\nforged"
	if err := func() error {
		_, err := New("audit-1", event)
		return err
	}(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("invalid actor error = %v, want ErrInvalidEnvelope", err)
	}
}
