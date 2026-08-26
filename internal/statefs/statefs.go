package statefs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

const (
	maxLockMetadataBytes = 4096
	maxRelativePathBytes = 512
	maxComponentBytes    = 255
)

type fileMetadata struct {
	mode  uint32
	uid   int
	nlink uint64
	isDir bool
	isReg bool
}

// LockKind identifies the scope of an advisory lock.
type LockKind string

const (
	LockKindProcess LockKind = "process"
	LockKindJob     LockKind = "job"
	LockKindTarget  LockKind = "target"
)

// LockMetadata is the bounded, non-secret diagnostic projection stored in a
// lock file. Callers may supply InstanceID, Hostname, and StartedAt; zero
// process fields are filled from the current process.
type LockMetadata struct {
	PID        int       `json:"pid"`
	UID        int       `json:"uid"`
	Hostname   string    `json:"hostname,omitempty"`
	InstanceID string    `json:"instanceID,omitempty"`
	Kind       LockKind  `json:"kind"`
	ID         string    `json:"id,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
}

// hooks are narrowly scoped failure-injection points for filesystem tests.
// Nil hooks use the real system calls. Hooks must preserve the semantics of
// the corresponding operation; in particular Write may return a short write.
type hooks struct {
	StatFS          func(*os.File) (uint64, error)
	Write           func(*os.File, []byte) (int, error)
	Fsync           func(*os.File) error
	FsyncDir        func(*os.File) error
	Rename          func(*os.File, string, string, bool) error
	RenameNoReplace func(*os.File, string, string) error
	RenameReplace   func(*os.File, string, string) error
	Remove          func(*os.File, string) error
}

// Options controls opening a pre-existing state directory. StateDir must be
// absolute and must already exist; this package never creates the mount point.
type Options struct {
	StateDir string
	// ExpectedOwnerUID defaults to the effective UID when nil.
	ExpectedOwnerUID *int

	// MinFreeBytes is a preflight/advisory threshold. A write can still fail
	// because data or metadata blocks, quotas, or filesystem policy consume
	// space differently than this estimate.
	MinFreeBytes     uint64
	MaxDocumentBytes int64
	LockMetadata     LockMetadata
}

// Store owns the state-root descriptor and the process lock. It is safe for
// concurrent reads/writes, but only one Store may be open for a state root.
// When both mutexes are needed, the order is Store.mu before Lock.mu.
type Store struct {
	mu                sync.Mutex
	root              *os.File
	dirs              map[string]*os.File
	processLock       *Lock
	namedLocks        map[*Lock]struct{}
	rootProcessLocked bool
	ownerUID          int
	minFree           uint64
	maxBytes          int64
	hooks             hooks
	metadata          LockMetadata
	closed            bool
}

// Open validates and opens an existing state directory, acquires its
// non-blocking process lock, and creates only the fixed controlled subdirs.
func Open(options Options) (*Store, error) {
	return openWithHooks(options, hooks{})
}

// openWithHooks is intentionally unexported: failure injection is available
// only to same-package tests and is not part of the production API.
func openWithHooks(options Options, testHooks hooks) (*Store, error) {
	if err := platformCheck(); err != nil {
		return nil, err
	}
	path, err := optionPath(options)
	if err != nil {
		return nil, err
	}
	owner, err := optionOwnerUID(options)
	if err != nil {
		return nil, err
	}
	minFree := options.MinFreeBytes
	maxBytes := options.MaxDocumentBytes
	if maxBytes == 0 {
		maxBytes = MaxDocumentBytes
	}
	if maxBytes < 1 || maxBytes > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: max document bytes must be between 1 and %d", ErrInvalidOptions, MaxDocumentBytes)
	}

	root, err := openStateRoot(path)
	if err != nil {
		return nil, wrapRootOpenError(err)
	}
	store := &Store{
		root:       root,
		dirs:       make(map[string]*os.File, len(controlledDirectories)),
		namedLocks: make(map[*Lock]struct{}),
		ownerUID:   owner,
		minFree:    minFree,
		maxBytes:   maxBytes,
		hooks:      testHooks,
	}
	cleanup := func(openErr error) (*Store, error) {
		store.closeFiles()
		return nil, openErr
	}

	meta, err := inspectFile(root)
	if err != nil {
		return cleanup(fmt.Errorf("%w: inspect root: %v", ErrInvalidStateDir, err))
	}
	if !meta.isDir {
		return cleanup(ErrStateDirNotDirectory)
	}
	if err := validateDirectoryMetadata(meta, owner); err != nil {
		return cleanup(err)
	}
	if err := validateRootEntries(root); err != nil {
		return cleanup(err)
	}
	if err := store.checkFreeSpace(0); err != nil {
		return cleanup(err)
	}
	// Lock the root directory descriptor as the authoritative process guard.
	// This prevents a same-UID process from bypassing the lock by unlinking or
	// replacing the human-readable process.lock pathname.
	if err := lockFile(root); err != nil {
		if isLockConflict(err) {
			return cleanup(ErrAlreadyLocked)
		}
		return cleanup(fmt.Errorf("%w: root process lock: %v", ErrLockUnavailable, err))
	}
	store.rootProcessLocked = true

	// locks is the sole directory needed before acquiring the process lock.
	locks, err := openChildDir(root, LocksDir, true)
	if err != nil {
		return cleanup(wrapControlledDirError(LocksDir, err))
	}
	store.dirs[LocksDir] = locks
	if metadata, inspectErr := inspectFile(locks); inspectErr != nil {
		return cleanup(fmt.Errorf("%w: inspect %s: %v", ErrInvalidStateDir, LocksDir, inspectErr))
	} else if err := validateDirectoryMetadata(metadata, owner); err != nil {
		return cleanup(fmt.Errorf("%s: %w", LocksDir, err))
	}

	processFile, err := openLockFile(locks, "process.lock")
	if err != nil {
		return cleanup(wrapLockOpenError(LockKindProcess, "", err))
	}
	processMetadata := makeLockMetadata(options, LockKindProcess, "", owner)
	process := &Lock{file: processFile, kind: LockKindProcess, metadata: processMetadata}
	if metadata, inspectErr := inspectFile(processFile); inspectErr != nil {
		_ = processFile.Close()
		return cleanup(fmt.Errorf("%w: inspect process lock: %v", ErrInvalidStateDir, inspectErr))
	} else if err := validateLockMetadata(metadata, owner); err != nil {
		_ = processFile.Close()
		return cleanup(err)
	}
	if err := lockFile(processFile); err != nil {
		_ = processFile.Close()
		if isLockConflict(err) {
			return cleanup(ErrAlreadyLocked)
		}
		return cleanup(fmt.Errorf("%w: process lock: %v", ErrLockUnavailable, err))
	}
	if err := process.writeMetadata(store.hooks); err != nil {
		_ = process.release()
		return cleanup(wrapOperationError(ErrLockUnavailable, "process lock metadata", err))
	}
	store.processLock = process
	store.metadata = processMetadata

	// The process lock protects directory initialization and all subsequent
	// state operations. Existing controlled directories are validated rather
	// than silently repaired.
	for _, name := range controlledDirectories {
		if name == LocksDir {
			continue
		}
		directory, dirErr := openChildDir(root, name, true)
		if dirErr != nil {
			return cleanup(wrapControlledDirError(name, dirErr))
		}
		metadata, inspectErr := inspectFile(directory)
		if inspectErr != nil {
			_ = directory.Close()
			return cleanup(fmt.Errorf("%w: inspect %s: %v", ErrInvalidStateDir, name, inspectErr))
		}
		if metadataErr := validateDirectoryMetadata(metadata, owner); metadataErr != nil {
			_ = directory.Close()
			return cleanup(fmt.Errorf("%s: %w", name, metadataErr))
		}
		store.dirs[name] = directory
	}
	if err := store.cleanupTemporaryFiles(); err != nil {
		return cleanup(err)
	}
	if err := store.syncDirectory(root); err != nil {
		return cleanup(wrapOperationError(ErrInvalidStateDir, "sync state directory", err))
	}
	return store, nil
}

func optionPath(options Options) (string, error) {
	path := options.StateDir
	if path == "" {
		return "", fmt.Errorf("%w: state directory is required", ErrInvalidOptions)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w: state directory must be absolute", ErrInvalidStateDir)
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) || clean == "." {
		return "", ErrStateDirIsRoot
	}
	if len(clean) > maxRelativePathBytes*4 {
		return "", fmt.Errorf("%w: state directory path is too long", ErrInvalidStateDir)
	}
	return clean, nil
}

func optionOwnerUID(options Options) (int, error) {
	if options.ExpectedOwnerUID != nil {
		if *options.ExpectedOwnerUID < 0 {
			return 0, fmt.Errorf("%w: owner UID cannot be negative", ErrInvalidOptions)
		}
		return *options.ExpectedOwnerUID, nil
	}
	return os.Geteuid(), nil
}

func wrapRootOpenError(err error) error {
	switch {
	case errors.Is(err, ErrUnsupportedPlatform):
		return ErrUnsupportedPlatform
	case isSpaceError(err):
		return fmt.Errorf("%w: %w", ErrInsufficientFree, err)
	case errors.Is(err, ErrStateDirIsRoot):
		return ErrStateDirIsRoot
	case errors.Is(err, ErrSymlink), isSymlinkError(err):
		return ErrSymlink
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %v", ErrStateDirNotFound, err)
	case isNotDirectoryError(err):
		return ErrStateDirNotDirectory
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w: %v", ErrUnsafePermissions, err)
	default:
		return fmt.Errorf("%w: %v", ErrInvalidStateDir, err)
	}
}

func wrapControlledDirError(name string, err error) error {
	if isSpaceError(err) {
		return fmt.Errorf("%w: %s: %w", ErrInsufficientFree, name, err)
	}
	if errors.Is(err, ErrSymlink) || isSymlinkError(err) {
		return fmt.Errorf("%s: %w", name, ErrSymlink)
	}
	if isNotDirectoryError(err) {
		return fmt.Errorf("%s: %w", name, ErrStateDirNotDirectory)
	}
	return fmt.Errorf("%w: %s: %v", ErrInvalidStateDir, name, err)
}

func wrapLockOpenError(kind LockKind, id string, err error) error {
	if isSpaceError(err) {
		return fmt.Errorf("%w: %s lock: %w", ErrInsufficientFree, kind, err)
	}
	if errors.Is(err, ErrSymlink) || isSymlinkError(err) {
		return fmt.Errorf("%w: %s lock", ErrSymlink, kind)
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: %v", ErrUnsafePermissions, err)
	}
	return fmt.Errorf("%w: %s lock: %v", ErrLockUnavailable, kind, err)
}

func validateRootEntries(root *os.File) error {
	if _, err := root.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: reset root enumeration: %v", ErrInvalidStateDir, err)
	}
	allowed := make(map[string]struct{}, len(controlledDirectories))
	for _, name := range controlledDirectories {
		allowed[name] = struct{}{}
	}
	entries, err := root.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("%w: enumerate root: %v", ErrInvalidStateDir, err)
	}
	for _, name := range entries {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%w: %q", ErrUnexpectedEntry, name)
		}
	}
	return nil
}

func validateDirectoryMetadata(metadata fileMetadata, owner int) error {
	if !metadata.isDir {
		return ErrStateDirNotDirectory
	}
	if metadata.uid != owner {
		return fmt.Errorf("%w: expected=%d", ErrUnsafeOwnership, owner)
	}
	// State is deliberately owner-only. This is stronger than merely
	// rejecting group/other write bits and prevents other users from reading or
	// replacing non-secret state while preserving its integrity.
	if metadata.mode&0077 != 0 || metadata.mode&0700 != 0700 || metadata.mode&07000 != 0 {
		return ErrUnsafePermissions
	}
	return nil
}

func validateLockMetadata(metadata fileMetadata, owner int) error {
	if !metadata.isReg {
		return ErrNotRegular
	}
	if metadata.nlink != 1 {
		return ErrHardLinked
	}
	if metadata.uid != owner {
		return ErrUnsafeOwnership
	}
	if metadata.mode&0077 != 0 || metadata.mode&0700 != 0600 || metadata.mode&07000 != 0 {
		return ErrUnsafePermissions
	}
	return nil
}

func validateDocumentMetadata(metadata fileMetadata, owner int) error {
	if !metadata.isReg {
		return ErrNotRegular
	}
	if metadata.nlink != 1 {
		return ErrHardLinked
	}
	if metadata.uid != owner {
		return ErrUnsafeOwnership
	}
	if metadata.mode&0777 != 0600 || metadata.mode&07000 != 0 {
		return ErrUnsafeFile
	}
	return nil
}

func makeLockMetadata(options Options, kind LockKind, id string, owner int) LockMetadata {
	metadata := options.LockMetadata
	if metadata.PID == 0 {
		metadata.PID = os.Getpid()
	}
	// The metadata describes the verified owner, never an independently
	// supplied identity that could make diagnostics misleading.
	metadata.UID = owner
	if metadata.Hostname == "" {
		metadata.Hostname, _ = os.Hostname()
	}
	if metadata.StartedAt.IsZero() {
		metadata.StartedAt = time.Now().UTC()
	} else {
		metadata.StartedAt = metadata.StartedAt.UTC()
	}
	metadata.Kind = kind
	metadata.ID = id
	return metadata
}

func (metadata LockMetadata) validate() error {
	if metadata.PID <= 0 || metadata.UID < 0 || metadata.StartedAt.IsZero() {
		return fmt.Errorf("%w: incomplete lock metadata", ErrInvalidOptions)
	}
	for field, value := range map[string]string{"hostname": metadata.Hostname, "instanceID": metadata.InstanceID} {
		if len(value) > 256 || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("%w: invalid lock metadata %s", ErrInvalidOptions, field)
		}
	}
	if metadata.Kind != LockKindProcess && metadata.Kind != LockKindJob && metadata.Kind != LockKindTarget {
		return fmt.Errorf("%w: invalid lock metadata kind", ErrInvalidOptions)
	}
	if metadata.ID != "" {
		if _, err := CanonicalID(metadata.ID); err != nil {
			return err
		}
	}
	return nil
}

func (lock *Lock) writeMetadata(hooks hooks) error {
	if err := lock.metadata.validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(lock.metadata)
	if err != nil || len(encoded) > maxLockMetadataBytes {
		return fmt.Errorf("%w: lock metadata is too large", ErrInvalidOptions)
	}
	encoded = append(encoded, '\n')
	if err := lock.file.Truncate(0); err != nil {
		return mapSpaceError(err)
	}
	if _, err := lock.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := writeComplete(lock.file, encoded, hooks.Write); err != nil {
		return mapSpaceError(err)
	}
	if hooks.Fsync != nil {
		return mapSpaceError(hooks.Fsync(lock.file))
	}
	return mapSpaceError(lock.file.Sync())
}

func writeComplete(file *os.File, data []byte, writeFn func(*os.File, []byte) (int, error)) error {
	for len(data) != 0 {
		var n int
		var err error
		if writeFn != nil {
			n, err = writeFn(file, data)
		} else {
			n, err = file.Write(data)
		}
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Lock is a held nonblocking flock. Close releases it; it is safe to call
// Close more than once.
//
// Mutex order is Store.mu, then Lock.mu. Any operation that updates a store's
// named-lock registry takes Store.mu before touching a Lock; Lock.Close also
// follows that order. No lock removal is performed while Lock.mu is held.
type Lock struct {
	mu       sync.Mutex
	file     *os.File
	kind     LockKind
	metadata LockMetadata
	owner    *Store
	closed   bool
}

func (lock *Lock) release() error {
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.closed {
		return nil
	}
	unlockErr := unlockFile(lock.file)
	closeErr := lock.file.Close()
	lock.closed = true
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

// Close releases the advisory lock.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	if lock.owner == nil {
		return lock.release()
	}

	// Lock.Close must not acquire Store.mu after Lock.mu. Store.Close takes
	// Store.mu while releasing locks, so taking it first prevents the inverse
	// lock-order deadlock.
	lock.owner.mu.Lock()
	defer lock.owner.mu.Unlock()
	err := lock.release()
	delete(lock.owner.namedLocks, lock)
	return err
}

func (lock *Lock) Kind() LockKind {
	if lock == nil {
		return ""
	}
	return lock.kind
}

func (lock *Lock) Metadata() LockMetadata {
	if lock == nil {
		return LockMetadata{}
	}
	return lock.metadata
}

func (store *Store) checkOpenLocked() error {
	if store.closed || store.root == nil {
		return ErrClosed
	}
	return nil
}

func mapSpaceError(err error) error {
	if err != nil && isInsufficientFreeError(err) {
		return fmt.Errorf("%w: %w", ErrInsufficientFree, err)
	}
	return err
}

func isSpaceError(err error) bool {
	return errors.Is(err, ErrInsufficientFree) || isInsufficientFreeError(err)
}

func wrapOperationError(fallback error, operation string, err error) error {
	if isSpaceError(err) {
		return fmt.Errorf("%w: %s: %w", ErrInsufficientFree, operation, err)
	}
	return fmt.Errorf("%w: %s: %v", fallback, operation, err)
}

func (store *Store) checkFreeSpace(extra int) error {
	if extra < 0 {
		return fmt.Errorf("%w: negative write size", ErrInvalidOptions)
	}
	if uint64(extra) > ^uint64(0)-store.minFree {
		return &FreeSpaceError{Required: ^uint64(0), Available: 0}
	}
	required := store.minFree + uint64(extra)
	var available uint64
	var err error
	if store.hooks.StatFS != nil {
		available, err = store.hooks.StatFS(store.root)
	} else {
		available, err = freeBytes(store.root)
	}
	if err != nil {
		return fmt.Errorf("%w: statfs: %v", ErrFreeSpaceUnavailable, err)
	}
	if available < required {
		return &FreeSpaceError{Required: required, Available: available}
	}
	return nil
}

func (store *Store) syncFile(file *os.File) error {
	if store.hooks.Fsync != nil {
		return store.hooks.Fsync(file)
	}
	return file.Sync()
}

func (store *Store) syncDirectory(directory *os.File) error {
	if store.hooks.FsyncDir != nil {
		return store.hooks.FsyncDir(directory)
	}
	return directory.Sync()
}

func (store *Store) closeFiles() {
	if store.processLock != nil {
		_ = store.processLock.release()
		store.processLock = nil
	}
	if store.rootProcessLocked && store.root != nil {
		_ = unlockFile(store.root)
		store.rootProcessLocked = false
	}
	for name, directory := range store.dirs {
		_ = directory.Close()
		delete(store.dirs, name)
	}
	if store.root != nil {
		_ = store.root.Close()
		store.root = nil
	}
	store.closed = true
}

// Close releases the process lock and closes all descriptors.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	var result error
	for lock := range store.namedLocks {
		if err := lock.release(); err != nil && result == nil {
			result = err
		}
		delete(store.namedLocks, lock)
	}
	if store.processLock != nil {
		if err := store.processLock.release(); err != nil && result == nil {
			result = err
		}
		store.processLock = nil
	}
	if store.rootProcessLocked && store.root != nil {
		if err := unlockFile(store.root); err != nil && result == nil {
			result = err
		}
		store.rootProcessLocked = false
	}
	for name, directory := range store.dirs {
		if err := directory.Close(); err != nil && result == nil {
			result = err
		}
		delete(store.dirs, name)
	}
	if err := store.root.Close(); err != nil && result == nil {
		result = err
	}
	store.root = nil
	store.closed = true
	return result
}

// Check rechecks ownership, mode, and free-space readiness while retaining
// the original process lock.
func (store *Store) Check() error {
	if store == nil {
		return ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return err
	}
	metadata, err := inspectFile(store.root)
	if err != nil {
		return fmt.Errorf("%w: inspect root: %v", ErrInvalidStateDir, err)
	}
	if err := validateDirectoryMetadata(metadata, store.ownerUID); err != nil {
		return err
	}
	if err := validateRootEntries(store.root); err != nil {
		return err
	}
	for _, name := range controlledDirectories {
		directory := store.dirs[name]
		if directory == nil {
			return fmt.Errorf("%w: controlled directory %s is missing", ErrInvalidStateDir, name)
		}
		metadata, inspectErr := inspectFile(directory)
		if inspectErr != nil {
			return fmt.Errorf("%w: inspect %s: %v", ErrInvalidStateDir, name, inspectErr)
		}
		if metadataErr := validateDirectoryMetadata(metadata, store.ownerUID); metadataErr != nil {
			return fmt.Errorf("%s: %w", name, metadataErr)
		}
	}
	if !store.rootProcessLocked || store.processLock == nil || store.processLock.file == nil {
		return ErrLockLost
	}
	lockMetadata, inspectErr := inspectFile(store.processLock.file)
	if inspectErr != nil {
		return fmt.Errorf("%w: inspect process lock: %v", ErrLockLost, inspectErr)
	}
	if lockMetadata.nlink != 1 {
		return ErrLockLost
	}
	if err := validateLockMetadata(lockMetadata, store.ownerUID); err != nil {
		return fmt.Errorf("%w: %v", ErrLockLost, err)
	}
	return store.checkFreeSpace(0)
}

func (store *Store) validateControlledDirectory(directory *os.File) error {
	metadata, err := inspectFile(directory)
	if err != nil {
		return fmt.Errorf("%w: inspect document directory: %v", ErrInvalidStateDir, err)
	}
	return validateDirectoryMetadata(metadata, store.ownerUID)
}

func (store *Store) cleanupTemporaryFiles() error {
	for _, name := range controlledDirectories {
		if name == LocksDir {
			continue
		}
		directory := store.dirs[name]
		entries, err := directory.Readdirnames(-1)
		if err != nil {
			return fmt.Errorf("%w: enumerate %s: %v", ErrInvalidStateDir, name, err)
		}
		removed := false
		for _, entry := range entries {
			if !strings.HasPrefix(entry, ".statefs-tmp-") {
				continue
			}
			file, openErr := openDocumentFile(directory, entry)
			if openErr != nil {
				return fmt.Errorf("%w: inspect stale temporary file: %v", ErrInvalidStateDir, openErr)
			}
			metadata, inspectErr := inspectFile(file)
			_ = file.Close()
			if inspectErr != nil {
				return fmt.Errorf("%w: inspect stale temporary file: %v", ErrInvalidStateDir, inspectErr)
			}
			if err := validateStaleTemporaryMetadata(metadata, store.ownerUID); err != nil {
				return fmt.Errorf("%w: stale temporary file: %v", ErrInvalidStateDir, err)
			}
			if store.hooks.Remove != nil {
				err = store.hooks.Remove(directory, entry)
			} else {
				err = removeAt(directory, entry)
			}
			if err != nil {
				return wrapOperationError(ErrInvalidStateDir, "remove stale temporary file", err)
			}
			removed = true
		}
		if removed {
			if err := store.syncDirectory(directory); err != nil {
				return wrapOperationError(ErrInvalidStateDir, "sync "+name+" after temporary cleanup", err)
			}
		}
	}
	return nil
}

// Read reads one direct child document under a fixed controlled directory.
func (store *Store) Read(relative string) ([]byte, error) {
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return nil, err
	}
	directory, name, err := store.documentLocation(relative)
	if err != nil {
		return nil, err
	}
	if err := store.validateControlledDirectory(directory); err != nil {
		return nil, err
	}
	file, err := openDocumentFile(directory, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		if errors.Is(err, ErrSymlink) || isSymlinkError(err) {
			return nil, ErrSymlink
		}
		return nil, fmt.Errorf("%w: %v", ErrFileUnavailable, err)
	}
	defer file.Close()
	metadata, err := inspectFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect document: %v", ErrCorrupt, err)
	}
	if err := validateDocumentMetadata(metadata, store.ownerUID); err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: stat document: %v", ErrCorrupt, err)
	}
	if info.Size() < 0 || info.Size() > store.maxBytes {
		return nil, ErrDocumentTooLarge
	}
	limited := io.LimitReader(file, store.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: read document: %v", ErrCorrupt, err)
	}
	if int64(len(data)) > store.maxBytes {
		return nil, ErrDocumentTooLarge
	}
	return data, nil
}

// WriteAtomic atomically writes data. The replace argument directly selects
// replace versus rename-no-replace behavior.
func (store *Store) WriteAtomic(relative string, data []byte, replace bool) error {
	return store.writeAtomic(relative, data, replace)
}

func (store *Store) writeAtomic(relative string, data []byte, replace bool) (result error) {
	if store == nil {
		return ErrClosed
	}
	if int64(len(data)) > MaxDocumentBytes {
		return ErrDocumentTooLarge
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return err
	}
	if int64(len(data)) > store.maxBytes {
		return ErrDocumentTooLarge
	}
	directory, name, err := store.documentLocation(relative)
	if err != nil {
		return err
	}
	if err := store.validateControlledDirectory(directory); err != nil {
		return err
	}
	if err := store.checkFreeSpace(len(data)); err != nil {
		return err
	}
	// Statefs assumes a single-writer trusted-process boundary. It rejects an
	// observed symlink, hard link, special file, or unsafe metadata before a
	// replacement, and performs the rename relative to the opened directory.
	// It does not claim to defend against a malicious same-UID process or PVC /
	// storage administrator replacing an inode after these checks; that is out
	// of scope.
	if existing, openErr := openDocumentFile(directory, name); openErr == nil {
		metadata, inspectErr := inspectFile(existing)
		_ = existing.Close()
		if inspectErr != nil {
			return fmt.Errorf("%w: inspect destination: %v", ErrCorrupt, inspectErr)
		}
		if validateErr := validateDocumentMetadata(metadata, store.ownerUID); validateErr != nil {
			return validateErr
		}
	} else if !errors.Is(openErr, os.ErrNotExist) {
		if isSpaceError(openErr) {
			return fmt.Errorf("%w: inspect destination: %w", ErrInsufficientFree, openErr)
		}
		if errors.Is(openErr, ErrSymlink) || isSymlinkError(openErr) {
			return ErrSymlink
		}
		if !replace && errors.Is(openErr, os.ErrExist) {
			return ErrDestinationExists
		}
		return fmt.Errorf("%w: inspect destination: %v", ErrCorrupt, openErr)
	} else if !replace {
		// No destination is the normal no-replace case.
	}

	tempName, err := uniqueTempName()
	if err != nil {
		return fmt.Errorf("%w: temporary name: %v", ErrInvalidStateDir, err)
	}
	temporary, err := createTempFile(directory, tempName)
	if err != nil {
		return wrapOperationError(ErrInvalidStateDir, "create temporary document", err)
	}
	cleanupTemp := true
	defer func() {
		if !cleanupTemp {
			return
		}
		var cleanupErr error
		if store.hooks.Remove != nil {
			cleanupErr = store.hooks.Remove(directory, tempName)
		} else {
			cleanupErr = removeAt(directory, tempName)
		}
		if cleanupErr == nil {
			cleanupErr = store.syncDirectory(directory)
		}
		if cleanupErr != nil {
			cleanupErr = wrapOperationError(ErrCorrupt, "cleanup temporary document", cleanupErr)
			if result == nil {
				result = cleanupErr
			} else {
				result = fmt.Errorf("%w; cleanup temporary document: %w", result, cleanupErr)
			}
		}
	}()
	if metadata, inspectErr := inspectFile(temporary); inspectErr != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: inspect temporary document: %v", ErrCorrupt, inspectErr)
	} else if validateErr := validateTemporaryMetadata(metadata, store.ownerUID); validateErr != nil {
		_ = temporary.Close()
		return validateErr
	}
	if err := writeComplete(temporary, data, store.hooks.Write); err != nil {
		_ = temporary.Close()
		return wrapOperationError(ErrCorrupt, "write temporary document", err)
	}
	if err := store.syncFile(temporary); err != nil {
		_ = temporary.Close()
		return wrapOperationError(ErrCorrupt, "fsync temporary document", err)
	}
	if err := temporary.Close(); err != nil {
		return wrapOperationError(ErrCorrupt, "close temporary document", mapSpaceError(err))
	}
	if err := store.rename(directory, tempName, name, replace); err != nil {
		if errors.Is(err, ErrDestinationExists) || errors.Is(err, os.ErrExist) || isAlreadyExists(err) {
			return ErrDestinationExists
		}
		return wrapOperationError(ErrCorrupt, "rename temporary document", err)
	}
	cleanupTemp = false
	if err := store.syncDirectory(directory); err != nil {
		return wrapOperationError(ErrDurabilityUnknown, "fsync document directory", err)
	}
	return nil
}

func validateTemporaryMetadata(metadata fileMetadata, owner int) error {
	if !metadata.isReg {
		return ErrNotRegular
	}
	if metadata.nlink != 1 {
		return ErrHardLinked
	}
	if metadata.uid != owner {
		return ErrUnsafeOwnership
	}
	if metadata.mode&0777 != 0600 || metadata.mode&07000 != 0 {
		return ErrUnsafeFile
	}
	return nil
}

func validateStaleTemporaryMetadata(metadata fileMetadata, owner int) error {
	if !metadata.isReg {
		return ErrNotRegular
	}
	// nlink=2 is possible only when a crash occurred during the Linux
	// link+unlink no-replace fallback. Removing the reserved temp name leaves
	// the destination's single link intact. More links are never accepted.
	if metadata.nlink < 1 || metadata.nlink > 2 {
		return ErrHardLinked
	}
	if metadata.uid != owner {
		return ErrUnsafeOwnership
	}
	if metadata.mode&0777 != 0600 || metadata.mode&07000 != 0 {
		return ErrUnsafeFile
	}
	return nil
}

func (store *Store) rename(directory *os.File, oldName, newName string, replace bool) error {
	if replace && store.hooks.RenameReplace != nil {
		return store.hooks.RenameReplace(directory, oldName, newName)
	}
	if !replace && store.hooks.RenameNoReplace != nil {
		return store.hooks.RenameNoReplace(directory, oldName, newName)
	}
	if store.hooks.Rename != nil {
		return store.hooks.Rename(directory, oldName, newName, replace)
	}
	return renameAt(directory, oldName, newName, replace)
}

func uniqueTempName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".statefs-tmp-" + hex.EncodeToString(random[:]), nil
}

func (store *Store) documentLocation(relative string) (*os.File, string, error) {
	parts, err := validateRelativePath(relative)
	if err != nil {
		return nil, "", err
	}
	directory, ok := store.dirs[parts[0]]
	if !ok || parts[0] == LocksDir {
		return nil, "", &InvalidPathError{Reason: "path is outside controlled document directories"}
	}
	return directory, parts[1], nil
}

func validateRelativePath(relative string) ([]string, error) {
	if relative == "" || len(relative) > maxRelativePathBytes || filepath.IsAbs(relative) || strings.ContainsRune(relative, '\x00') || strings.Contains(relative, "\\") {
		return nil, &InvalidPathError{Reason: "path must be a bounded relative slash path"}
	}
	if relative != filepath.ToSlash(relative) {
		return nil, &InvalidPathError{Reason: "path uses an unsupported separator"}
	}
	parts := strings.Split(relative, "/")
	if len(parts) != 2 {
		return nil, &InvalidPathError{Reason: "path must contain one controlled directory and one file"}
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > maxComponentBytes || strings.IndexFunc(part, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return nil, &InvalidPathError{Reason: "path contains an unsafe component"}
		}
		if index == 1 && strings.HasPrefix(part, ".statefs-tmp-") {
			return nil, &InvalidPathError{Reason: "temporary names are reserved"}
		}
		if index == 0 {
			valid := false
			for _, name := range controlledDirectories {
				if part == name && name != LocksDir {
					valid = true
					break
				}
			}
			if !valid {
				return nil, &InvalidPathError{Reason: "path is outside controlled document directories"}
			}
		}
	}
	return parts, nil
}

// CanonicalID validates an already canonical lock/document identity. It does
// not trim or normalize: callers must use the returned form consistently.
func CanonicalID(value string) (string, error) {
	if value == "" || len(value) > 128 || value == "." || value == ".." || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("%w: ID must be 1-128 canonical characters", ErrInvalidRelativePath)
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '.' && character != ':' {
			return "", fmt.Errorf("%w: ID contains an unsafe character", ErrInvalidRelativePath)
		}
	}
	return value, nil
}

// CanonicalTargetID derives a bounded, deterministic target lock ID from
// state/name/url/space components. Hashing avoids putting URL syntax in a
// filename while preserving exact identity distinctions.
func CanonicalTargetID(components ...string) (string, error) {
	if len(components) == 0 {
		return "", fmt.Errorf("%w: target identity is required", ErrInvalidRelativePath)
	}
	var builder strings.Builder
	for _, component := range components {
		if component == "" || len(component) > 4096 || strings.IndexByte(component, 0) >= 0 {
			return "", fmt.Errorf("%w: target identity component is invalid", ErrInvalidRelativePath)
		}
		fmt.Fprintf(&builder, "%d:", len(component))
		builder.WriteString(component)
	}
	digest := fmt.Sprintf("%x", sha256Sum([]byte(builder.String())))
	return digest, nil
}

// SortCanonicalIDs validates and returns a lexicographically sorted copy.
func SortCanonicalIDs(values []string) ([]string, error) {
	result := append([]string(nil), values...)
	for index, value := range result {
		canonical, err := CanonicalID(value)
		if err != nil {
			return nil, err
		}
		result[index] = canonical
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, fmt.Errorf("%w: duplicate lock ID", ErrInvalidRelativePath)
		}
	}
	return result, nil
}

// AcquireJobLock obtains a nonblocking job lock for a canonical job ID. It
// does not impose an order relative to other locks; callers that need several
// locks must use AcquireLocks.
func (store *Store) AcquireJobLock(id string) (*Lock, error) {
	return store.acquireNamedLock(LockKindJob, id)
}

// AcquireTargetLock obtains a nonblocking target lock for a canonical target
// ID. It does not impose an order relative to other locks; callers that need
// several locks must use AcquireLocks.
func (store *Store) AcquireTargetLock(id string) (*Lock, error) {
	return store.acquireNamedLock(LockKindTarget, id)
}

func (store *Store) acquireNamedLock(kind LockKind, id string) (*Lock, error) {
	canonical, err := CanonicalID(id)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return nil, err
	}
	return store.acquireNamedLockLocked(kind, canonical)
}

func (store *Store) acquireNamedLockLocked(kind LockKind, canonical string) (*Lock, error) {
	name := string(kind) + "-" + canonical + ".lock"
	file, err := openLockFile(store.dirs[LocksDir], name)
	if err != nil {
		return nil, wrapLockOpenError(kind, canonical, err)
	}
	metadata, inspectErr := inspectFile(file)
	if inspectErr != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: inspect %s lock: %v", ErrLockUnavailable, kind, inspectErr)
	}
	if metadataErr := validateLockMetadata(metadata, store.ownerUID); metadataErr != nil {
		_ = file.Close()
		return nil, metadataErr
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		if isLockConflict(err) || errors.Is(err, ErrLockConflict) {
			return nil, &LockConflictError{Kind: kind, ID: canonical}
		}
		return nil, fmt.Errorf("%w: %s %q: %v", ErrLockUnavailable, kind, canonical, err)
	}
	lock := &Lock{file: file, kind: kind, owner: store, metadata: makeLockMetadata(Options{LockMetadata: store.metadata}, kind, canonical, store.ownerUID)}
	if err := lock.writeMetadata(store.hooks); err != nil {
		_ = lock.release()
		return nil, wrapOperationError(ErrLockUnavailable, fmt.Sprintf("%s lock metadata", kind), err)
	}
	store.namedLocks[lock] = struct{}{}
	return lock, nil
}

// AcquireLocks obtains multiple locks in deterministic order for this call:
// jobs precede targets, and IDs within each kind are canonical and ascending.
// Already-acquired locks are released on any conflict or failure. Individual
// AcquireJobLock and AcquireTargetLock calls deliberately do not participate
// in this ordering; their flock is simply nonblocking and reports conflict.
func (store *Store) AcquireLocks(jobIDs, targetIDs []string) ([]*Lock, error) {
	jobs, err := SortCanonicalIDs(jobIDs)
	if err != nil {
		return nil, err
	}
	targets, err := SortCanonicalIDs(targetIDs)
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return nil, err
	}
	locks := make([]*Lock, 0, len(jobs)+len(targets))
	for _, id := range jobs {
		lock, lockErr := store.acquireNamedLockLocked(LockKindJob, id)
		if lockErr != nil {
			store.closeNamedLocks(locks)
			return nil, lockErr
		}
		locks = append(locks, lock)
	}
	for _, id := range targets {
		lock, lockErr := store.acquireNamedLockLocked(LockKindTarget, id)
		if lockErr != nil {
			store.closeNamedLocks(locks)
			return nil, lockErr
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func closeLocks(locks []*Lock) {
	for index := len(locks) - 1; index >= 0; index-- {
		_ = locks[index].Close()
	}
}

func (store *Store) closeNamedLocks(locks []*Lock) {
	for index := len(locks) - 1; index >= 0; index-- {
		_ = locks[index].release()
		delete(store.namedLocks, locks[index])
	}
}

// WriteStateDocument encodes a validated state document and atomically stores
// it. The relative path remains the caller's responsibility and is checked by
// the same path policy as raw writes.
func (store *Store) WriteStateDocument(relative string, document state.Document, replace bool) error {
	if document == nil {
		return state.ErrNilDestination
	}
	encoded, err := state.Encode(document)
	if err != nil {
		return err
	}
	return store.WriteAtomic(relative, encoded, replace)
}

// ReadStateDocument reads and strictly validates one persisted state document.
func (store *Store) ReadStateDocument(relative string) (state.Document, error) {
	encoded, err := store.Read(relative)
	if err != nil {
		return nil, err
	}
	document, err := state.DecodeDocument(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	return document, nil
}

// Remove atomically removes a regular, owner-only, single-link document and
// fsyncs its containing directory.
func (store *Store) Remove(relative string) error {
	if store == nil {
		return ErrClosed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.checkOpenLocked(); err != nil {
		return err
	}
	directory, name, err := store.documentLocation(relative)
	if err != nil {
		return err
	}
	if err := store.validateControlledDirectory(directory); err != nil {
		return err
	}
	file, err := openDocumentFile(directory, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	metadata, inspectErr := inspectFile(file)
	_ = file.Close()
	if inspectErr != nil {
		return inspectErr
	}
	if err := validateDocumentMetadata(metadata, store.ownerUID); err != nil {
		return err
	}
	if store.hooks.Remove != nil {
		err = store.hooks.Remove(directory, name)
	} else {
		err = removeAt(directory, name)
	}
	if err != nil {
		return mapSpaceError(err)
	}
	if err := store.syncDirectory(directory); err != nil {
		return wrapOperationError(ErrDurabilityUnknown, "fsync document directory", err)
	}
	return nil
}

// sha256Sum is kept local to avoid exposing a digest API from this filesystem
// package.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}
