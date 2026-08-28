// Package statefs provides Linux-only, single-writer persistence primitives
// for the maintainer's non-secret state directory. It assumes a trusted
// process boundary: observed symlinks, hard links, and unsafe metadata are
// rejected, but malicious same-UID actors and PVC/storage administrators are
// outside the replacement-integrity threat model.
package statefs

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupportedPlatform  = errors.New("state filesystem is unsupported on this platform")
	ErrInvalidOptions       = errors.New("invalid state directory options")
	ErrInvalidStateDir      = errors.New("invalid state directory")
	ErrStateDirNotFound     = errors.New("state directory is unavailable")
	ErrStateDirIsRoot       = errors.New("state directory must not be the filesystem root")
	ErrStateDirNotDirectory = errors.New("state directory is not a directory")
	ErrUnsafePermissions    = errors.New("state directory has unsafe permissions")
	ErrUnsafeOwnership      = errors.New("state directory has unsafe ownership")
	ErrSymlink              = errors.New("state directory path contains a symlink")
	ErrUnexpectedEntry      = errors.New("state directory contains an unexpected entry")
	ErrInsufficientFree     = errors.New("state directory does not have enough free space")
	ErrFreeSpaceUnavailable = errors.New("state directory free-space check is unavailable")
	ErrFileUnavailable      = errors.New("state document is unavailable")
	ErrWriteFailed          = errors.New("state document write failed")
	ErrDurabilityUnknown    = errors.New("state document durability is unknown")
	ErrAlreadyLocked        = errors.New("state directory is already locked")
	ErrLockConflict         = errors.New("state lock is already held")
	ErrLockLost             = errors.New("state process lock is no longer safely linked")
	ErrLockUnavailable      = errors.New("state lock is unavailable")
	ErrClosed               = errors.New("state directory is closed")
	ErrInvalidRelativePath  = errors.New("invalid state-relative path")
	ErrNotFound             = errors.New("state document is unavailable")
	ErrNotRegular           = errors.New("state document is not a regular file")
	ErrHardLinked           = errors.New("state document has multiple hard links")
	ErrUnsafeFile           = errors.New("state document has unsafe ownership or permissions")
	ErrDocumentTooLarge     = errors.New("state document exceeds the size limit")
	ErrDestinationExists    = errors.New("state document already exists")
	ErrCorrupt              = errors.New("state document is corrupt")
	ErrTooManyDocuments     = errors.New("state document directory has too many entries")
	ErrAggregateTooLarge    = errors.New("state document directory exceeds the aggregate size limit")
	ErrETagMismatch         = errors.New("state document ETag does not match")
	ErrInvalidReadBounds    = errors.New("invalid state document read bounds")
)

// LockConflictError identifies a non-blocking lock conflict without exposing
// process metadata or other potentially sensitive details.
type LockConflictError struct {
	Kind LockKind
	ID   string
}

func (e *LockConflictError) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("%v: %s lock", ErrLockConflict, e.Kind)
	}
	return fmt.Sprintf("%v: %s %q", ErrLockConflict, e.Kind, e.ID)
}

func (e *LockConflictError) Unwrap() error { return ErrLockConflict }
func (e *LockConflictError) Is(target error) bool {
	return target == ErrLockConflict || (e.Kind == LockKindProcess && target == ErrAlreadyLocked)
}

// InvalidPathError retains only the safe, caller-supplied path reason. It does
// not include an OS path or any file contents in an error string.
type InvalidPathError struct{ Reason string }

func (e *InvalidPathError) Error() string {
	if e.Reason == "" {
		return ErrInvalidRelativePath.Error()
	}
	return fmt.Sprintf("%v: %s", ErrInvalidRelativePath, e.Reason)
}
func (e *InvalidPathError) Unwrap() error { return ErrInvalidRelativePath }

// FreeSpaceError reports a failed free-space check without embedding a path.
type FreeSpaceError struct {
	Required  uint64
	Available uint64
}

func (e *FreeSpaceError) Error() string {
	return fmt.Sprintf("%v: required=%d available=%d", ErrInsufficientFree, e.Required, e.Available)
}
func (e *FreeSpaceError) Unwrap() error { return ErrInsufficientFree }

// DirectoryName constants are the only directories this package creates.
const (
	ConfigSnapshotsDir = "config-snapshots"
	SourcesDir         = "sources"
	InventoriesDir     = "inventories"
	JournalsDir        = "journals"
	PlansDir           = "plans"
	JobsDir            = "jobs"
	ReportsDir         = "reports"
	AuditDir           = "audit"
	IdempotencyDir     = "idempotency"
	LocksDir           = "locks"
)

var controlledDirectories = [...]string{
	ConfigSnapshotsDir,
	SourcesDir,
	InventoriesDir,
	JournalsDir,
	PlansDir,
	JobsDir,
	ReportsDir,
	AuditDir,
	IdempotencyDir,
	LocksDir,
}

// ControlledDirectories returns a copy of the fixed directory set.
func ControlledDirectories() []string {
	result := make([]string, len(controlledDirectories))
	copy(result, controlledDirectories[:])
	return result
}

const (
	// MaxDocumentBytes is the package-level upper bound for a state document.
	// The schema package uses the same limit.
	MaxDocumentBytes = 4 << 20

	// DefaultMinFreeBytes is the advisory free-space reserve used by the
	// production runtime before state writes. It is a preflight guard, not a
	// filesystem quota: individual writes can still fail for other reasons.
	DefaultMinFreeBytes = 64 << 20
)
