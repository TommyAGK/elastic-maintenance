package state

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidDocument    = errors.New("invalid state document")
	ErrUnsupportedVersion = errors.New("unsupported state document version")
	ErrUnsupportedKind    = errors.New("unsupported state document kind")
	ErrNilDestination     = errors.New("state decode destination is nil")
	ErrTrailingJSON       = errors.New("state document has trailing JSON")
	ErrDuplicateField     = errors.New("state document contains a duplicate JSON field")
	ErrDocumentTooLarge   = errors.New("state document exceeds the size limit")
	ErrMigrationRequired  = errors.New("state document requires explicit migration")
	// ErrInvalidAuditEvent is the safe constructor boundary error. It deliberately
	// does not include any caller-controlled field or validation diagnostic.
	ErrInvalidAuditEvent = errors.New("invalid audit event")
)

const (
	// MaxDocumentBytes bounds both decoding and encoding. Filesystem persistence
	// is deliberately out of scope, but every later writer can use this same
	// limit before touching a state directory.
	MaxDocumentBytes = 4 << 20
	maxJSONDepth     = 64
	maxJSONObject    = 100_000
	maxJSONArray     = 100_000
	maxJSONNodes     = 500_000
	maxJSONString    = 1 << 20
	maxIDLength      = 128
	maxTextLength    = 64 << 10
)

type versionError struct {
	Got  string
	Want string
}

func (err *versionError) Error() string {
	return fmt.Sprintf("%v: got %q, want %q", ErrUnsupportedVersion, err.Got, err.Want)
}

func (err *versionError) Unwrap() error { return ErrUnsupportedVersion }

func (err *versionError) Is(target error) bool {
	return target == ErrUnsupportedVersion || target == ErrMigrationRequired
}

type kindError struct {
	Got Kind
}

func (err *kindError) Error() string {
	return fmt.Sprintf("%v: got %q", ErrUnsupportedKind, err.Got)
}

func (err *kindError) Unwrap() error { return ErrUnsupportedKind }

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidDocument, fmt.Sprintf(format, args...))
}

func invalidField(field, format string, args ...any) error {
	return invalid("%s: %s", field, fmt.Sprintf(format, args...))
}

func checkHeader(apiVersion string, kind Kind, expected Kind) error {
	if apiVersion != APIVersion {
		return &versionError{Got: apiVersion, Want: APIVersion}
	}
	if kind != expected {
		return &kindError{Got: kind}
	}
	return nil
}

func supportedKind(kind Kind) bool {
	switch kind {
	case KindSourceSnapshot, KindOwnershipInventory, KindPreMutationJournal, KindPlan, KindJob, KindReport, KindIdempotency, KindAuditEvent:
		return true
	default:
		return false
	}
}

// MigrationPolicy documents an intentionally non-automatic policy. A future
// version must be handled by an explicit offline converter and written as a
// new document; Decode never rewrites or downgrades data.
func MigrationPolicy() string {
	return "No silent migration. State versions are immutable; only an explicit offline migration to a newly reviewed version may read and rewrite a document."
}

// RequiresMigration reports whether a document header names a different
// version. It is useful to make startup/reporting errors explicit without
// performing migration.
func RequiresMigration(apiVersion string) bool {
	return apiVersion != APIVersion
}
