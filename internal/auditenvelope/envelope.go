// Package auditenvelope provides the immutable, safe boundary between
// transient audit events and storage. It retains only canonical AuditEvent
// bytes produced by the state projection and exposes no mutable event value.
//
// The state grammar is intentionally not a secret detector. Callers must pass
// only producer-owned metadata such as bounded reason codes; syntactically
// valid text that merely resembles a secret is not evidence that it is safe.
package auditenvelope

import (
	"bytes"
	"errors"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

// ErrInvalidEnvelope is the only error exposed by this package. It contains
// no caller-controlled diagnostics.
var ErrInvalidEnvelope = errors.New("invalid audit envelope")

// Envelope is an immutable, pre-storage audit event. Its canonical bytes are
// intentionally unexported; callers can obtain only defensive copies.
type Envelope struct {
	canonical []byte
}

// New projects event through the safe state boundary, encodes the resulting
// AuditEvent canonically, and copies the encoded bytes before retaining them.
// It does not generate IDs, redact arbitrary text, or persist the event.
func New(id string, event audit.Event) (Envelope, error) {
	projected, err := state.NewAuditEvent(id, event)
	if err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	canonical, err := state.EncodeAuditEvent(projected)
	if err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	if len(canonical) == 0 {
		return Envelope{}, ErrInvalidEnvelope
	}
	return Envelope{canonical: append([]byte(nil), canonical...)}, nil
}

// Bytes returns a defensive copy of the canonical AuditEvent bytes.
func (envelope Envelope) Bytes() []byte {
	return append([]byte(nil), envelope.canonical...)
}

// Validate verifies that the envelope contains one strictly decoded,
// canonically re-encoded AuditEvent. It rejects the zero value, non-canonical
// encodings, and every malformed value with the fixed sentinel.
func (envelope Envelope) Validate() error {
	if len(envelope.canonical) == 0 {
		return ErrInvalidEnvelope
	}
	projected, err := state.DecodeAuditEvent(envelope.canonical)
	if err != nil {
		return ErrInvalidEnvelope
	}
	canonical, err := state.EncodeAuditEvent(projected)
	if err != nil || !bytes.Equal(canonical, envelope.canonical) {
		return ErrInvalidEnvelope
	}
	return nil
}
