package state

import "github.com/TommyAGK/elastic-maintenance/internal/audit"

// NewAuditEvent projects a transient audit event into its durable, non-secret
// state representation. The caller supplies the durable ID; this boundary
// does not generate IDs, persist anything, or attempt to redact arbitrary
// input. Authentication metadata is narrowed through ActorFromAuth, so
// display/session/CSRF/token-bearing fields cannot cross the boundary.
//
// The transient audit package has a finite action registry for its current
// hooks. Durable state intentionally validates the broader bounded
// namespaced syntax so a new hook action does not require a state-schema
// change.
func NewAuditEvent(id string, event audit.Event) (AuditEvent, error) {
	value := AuditEvent{
		APIVersion: APIVersion,
		Kind:       KindAuditEvent,
		ID:         id,
		OccurredAt: event.OccurredAt.UTC(),
		RequestID:  event.RequestID,
		Action:     event.Action,
		Outcome:    event.Outcome,
		TargetID:   event.TargetID,
		PlanID:     event.PlanID,
		JobID:      event.JobID,
		ReasonCode: event.ReasonCode,
	}
	if event.Actor != nil {
		actor, err := ActorFromAuth(*event.Actor)
		if err != nil {
			return AuditEvent{}, ErrInvalidAuditEvent
		}
		value.Actor = &actor
	}
	// Newly projected references must name a possible current durable job.
	// DecodeAuditEvent deliberately retains the wider v1 safe-code grammar so
	// previously valid persisted documents remain readable without migration.
	if value.JobID != "" && !jobIDPattern.MatchString(value.JobID) {
		return AuditEvent{}, ErrInvalidAuditEvent
	}
	if err := value.Validate(); err != nil {
		return AuditEvent{}, ErrInvalidAuditEvent
	}
	return value, nil
}
