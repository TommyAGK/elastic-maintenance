//go:build linux

package statefs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"golang.org/x/sys/unix"
)

func testOptions(path string) Options {
	return Options{StateDir: path, MinFreeBytes: 1}
}

func openTestStore(t *testing.T, path string, hooks hooks) *Store {
	t.Helper()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	options := testOptions(path)
	store, err := openWithHooks(options, hooks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestOpenHardenedStateDirectory(t *testing.T) {
	t.Run("requires existing absolute non-root directory", func(t *testing.T) {
		if _, err := Open(Options{StateDir: "relative"}); !errors.Is(err, ErrInvalidStateDir) {
			t.Fatalf("relative path error = %v", err)
		}
		if _, err := Open(Options{StateDir: "/"}); !errors.Is(err, ErrStateDirIsRoot) {
			t.Fatalf("root path error = %v", err)
		}
		file := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StateDir: file}); !errors.Is(err, ErrStateDirNotDirectory) {
			t.Fatalf("file path error = %v", err)
		}
		if _, err := Open(Options{StateDir: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, ErrStateDirNotFound) {
			t.Fatalf("missing path error = %v", err)
		}
	})

	t.Run("rejects symlink traversal", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(realDir, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StateDir: link}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlink root error = %v", err)
		}
		stateDir := filepath.Join(realDir, "state")
		if err := os.Mkdir(stateDir, 0700); err != nil {
			t.Fatal(err)
		}
		childLink := filepath.Join(stateDir, LocksDir)
		if err := os.Symlink(base, childLink); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StateDir: stateDir}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlink controlled dir error = %v", err)
		}
	})

	t.Run("rejects unsafe modes ownership and entries", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0750); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StateDir: dir}); !errors.Is(err, ErrUnsafePermissions) {
			t.Fatalf("group-readable root error = %v", err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		wrong := os.Geteuid() + 1
		if _, err := Open(Options{StateDir: dir, ExpectedOwnerUID: &wrong}); !errors.Is(err, ErrUnsafeOwnership) {
			t.Fatalf("wrong owner error = %v", err)
		}
		unexpected := filepath.Join(dir, "unexpected")
		if err := os.WriteFile(unexpected, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Options{StateDir: dir}); !errors.Is(err, ErrUnexpectedEntry) {
			t.Fatalf("unexpected entry error = %v", err)
		}
	})

	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, dir, hooks{})
	for _, name := range controlledDirectories {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("controlled directory %s mode=%v info=%#v", name, info.Mode(), info)
		}
	}
	if info, err := os.Stat(filepath.Join(dir, LocksDir, "process.lock")); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("process lock mode=%v", info.Mode())
	}
	if err := store.Check(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, PlansDir), 0750); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("unsafe child directory check = %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, PlansDir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unexpected-later"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Check(); !errors.Is(err, ErrUnexpectedEntry) {
		t.Fatalf("unexpected root entry check = %v", err)
	}
}

func TestRestrictiveUmaskDoesNotWeakenControlledModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	previous := unix.Umask(0777)
	defer unix.Umask(previous)
	store, err := Open(Options{StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, name := range controlledDirectories {
		info, statErr := os.Stat(filepath.Join(dir, name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("directory %s mode=%o", name, info.Mode().Perm())
		}
	}
	if info, statErr := os.Stat(filepath.Join(dir, LocksDir, "process.lock")); statErr != nil {
		t.Fatal(statErr)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("process lock mode=%o", info.Mode().Perm())
	}
}

func TestStaleTemporaryFilesAreCleanedAtOpen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	plans := filepath.Join(dir, PlansDir)
	if err := os.Mkdir(plans, 0700); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(plans, ".statefs-tmp-crashed")
	if err := os.WriteFile(temporary, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, dir, hooks{})
	if _, err := os.Stat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp stat error = %v", err)
	}
	_ = store.Close()

	fallbackDir := t.TempDir()
	if err := os.Chmod(fallbackDir, 0700); err != nil {
		t.Fatal(err)
	}
	fallbackPlans := filepath.Join(fallbackDir, PlansDir)
	if err := os.Mkdir(fallbackPlans, 0700); err != nil {
		t.Fatal(err)
	}
	fallbackTemp := filepath.Join(fallbackPlans, ".statefs-tmp-fallback")
	fallbackDestination := filepath.Join(fallbackPlans, "recovered.json")
	if err := os.WriteFile(fallbackTemp, []byte("recovered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fallbackTemp, fallbackDestination); err != nil {
		t.Fatal(err)
	}
	fallbackStore := openTestStore(t, fallbackDir, hooks{})
	if _, err := os.Stat(fallbackTemp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fallback stale temp stat error = %v", err)
	}
	if got, err := fallbackStore.Read("plans/recovered.json"); err != nil || string(got) != "recovered" {
		t.Fatalf("recovered fallback data=%q err=%v", got, err)
	}
	_ = fallbackStore.Close()
}

func TestProcessAndScopedLockContention(t *testing.T) {
	dir := t.TempDir()
	first := openTestStore(t, dir, hooks{})
	if _, err := Open(Options{StateDir: dir}); !errors.Is(err, ErrAlreadyLocked) {
		t.Fatalf("second process error = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, LocksDir, "process.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{StateDir: dir}); !errors.Is(err, ErrAlreadyLocked) {
		t.Fatalf("second process after lock-path removal error = %v", err)
	}
	job, err := first.AcquireJobLock("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.AcquireJobLock("job-1"); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("same job error = %v", err)
	}
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	job, err = first.AcquireJobLock("job-1")
	if err != nil {
		t.Fatal(err)
	}
	_ = job.Close()
	// Individual lock calls are nonblocking operations, not a global ordering
	// protocol. Canonical ordering is enforced only by AcquireLocks.
	highJob, err := first.AcquireJobLock("job-b")
	if err != nil {
		t.Fatal(err)
	}
	lowJob, err := first.AcquireJobLock("job-a")
	if err != nil {
		t.Fatalf("individual canonical-order acquisition: %v", err)
	}
	_ = lowJob.Close()
	_ = highJob.Close()
	if _, err := first.AcquireTargetLock("../escape"); !errors.Is(err, ErrInvalidRelativePath) {
		t.Fatalf("unsafe target ID error = %v", err)
	}
	target, err := first.AcquireTargetLock("target-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.AcquireTargetLock("target-1"); !errors.Is(err, ErrLockConflict) {
		t.Fatalf("same target error = %v", err)
	}
	jobAfterTarget, err := first.AcquireJobLock("job-after-target")
	if err != nil {
		t.Fatalf("individual job lock after target error = %v", err)
	}
	_ = jobAfterTarget.Close()
	_ = target.Close()

	locks, err := first.AcquireLocks([]string{"job-b", "job-a"}, []string{"target-b", "target-a"})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{locks[0].Metadata().ID, locks[1].Metadata().ID, locks[2].Metadata().ID, locks[3].Metadata().ID}; fmt.Sprint(got) != "[job-a job-b target-a target-b]" {
		t.Fatalf("lock order = %v", got)
	}
	closeLocks(locks)
	if _, err := first.AcquireLocks([]string{"same", "same"}, nil); !errors.Is(err, ErrInvalidRelativePath) {
		t.Fatalf("duplicate lock ID error = %v", err)
	}
	active, err := first.AcquireJobLock("active")
	if err != nil {
		t.Fatal(err)
	}
	if active == nil {
		t.Fatal("active lock is nil")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(Options{StateDir: dir})
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	_ = second.Close()
}

func TestAtomicWriteSafetyAndVisibility(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	if err := store.WriteAtomic("plans/plan.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic("plans/plan.json", []byte("new"), false); !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("no-replace error = %v", err)
	}
	if got, err := store.Read("plans/plan.json"); err != nil || string(got) != "old" {
		t.Fatalf("preserved no-replace data=%q err=%v", got, err)
	}
	if err := store.WriteAtomic("plans/plan.json", []byte("new"), true); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Read("plans/plan.json"); err != nil || string(got) != "new" {
		t.Fatalf("replacement data=%q err=%v", got, err)
	}

	for _, path := range []string{"../escape", "/absolute", "plans/../escape", "plans/a/b", "locks/lock", "unknown/x"} {
		if _, err := store.Read(path); !errors.Is(err, ErrInvalidRelativePath) {
			t.Errorf("Read(%q) error = %v", path, err)
		}
		if err := store.WriteAtomic(path, []byte("x"), true); !errors.Is(err, ErrInvalidRelativePath) {
			t.Errorf("Write(%q) error = %v", path, err)
		}
	}

	var writes atomic.Int64
	shortDir := t.TempDir()
	shortStore := openTestStore(t, shortDir, hooks{
		Write: func(file *os.File, data []byte) (int, error) {
			writes.Add(1)
			n := 1
			if len(data) < n {
				n = len(data)
			}
			return file.Write(data[:n])
		},
	})
	if err := shortStore.WriteAtomic("plans/short.json", []byte("short write loop"), false); err != nil {
		t.Fatal(err)
	}
	if writes.Load() < 2 {
		t.Fatalf("write hook called %d times", writes.Load())
	}
	shortStore.Close()
}

func TestReadStateDocumentRedactsDecoderDiagnostics(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	sentinel := "OIDC_TOKEN_SENTINEL_MUST_NOT_ESCAPE"
	data := []byte(`{"apiVersion":"` + sentinel + `","kind":"Job"}`)
	if err := store.WriteAtomic("plans/bad.json", data, false); err != nil {
		t.Fatal(err)
	}
	_, err := store.ReadStateDocument("plans/bad.json")
	if !errors.Is(err, ErrCorrupt) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("redacted state error=%v", err)
	}
	if !errors.Is(err, state.ErrUnsupportedVersion) || !errors.Is(err, state.ErrMigrationRequired) {
		t.Fatalf("state error class=%v", err)
	}
}

func TestAtomicCompareAndSwapRequiresMatchingExistingContent(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	if err := store.WriteAtomic("plans/state.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomicIfMatch("plans/missing.json", []byte("new"), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CAS error=%v", err)
	}
	if err := store.WriteAtomicIfMatch("plans/state.json", []byte("new"), "wrong"); !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("mismatched CAS error=%v", err)
	}
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "old" {
		t.Fatalf("mismatched CAS changed document=%q err=%v", got, err)
	}
	digest := sha256.Sum256([]byte("old"))
	if err := store.WriteAtomicIfMatch("plans/state.json", []byte("new"), hex.EncodeToString(digest[:])); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "new" {
		t.Fatalf("successful CAS document=%q err=%v", got, err)
	}
}

func TestRemoveIfMatchIsDescriptorRelativeAndCASSafe(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	if err := store.WriteAtomic("plans/state.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	oldETag := sha256.Sum256([]byte("old"))
	oldETagText := hex.EncodeToString(oldETag[:])
	if err := store.RemoveIfMatch("plans/missing.json", oldETagText); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing conditional remove error=%v", err)
	}
	if err := store.RemoveIfMatch("plans/state.json", "wrong"); !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("mismatched conditional remove error=%v", err)
	}
	if err := store.WriteAtomic("plans/state.json", []byte("new"), true); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveIfMatch("plans/state.json", oldETagText); !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("changed conditional remove error=%v", err)
	}
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "new" {
		t.Fatalf("changed document=%q err=%v", got, err)
	}
	newETag := sha256.Sum256([]byte("new"))
	if err := store.RemoveIfMatch("plans/state.json", hex.EncodeToString(newETag[:])); err != nil {
		t.Fatalf("successful conditional remove error=%v", err)
	}
	if _, err := store.Read("plans/state.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed document read error=%v", err)
	}
}

func TestRemoveRetainsHardenedValidation(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	if err := store.Remove("plans/missing.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing remove error=%v", err)
	}
	if err := store.WriteAtomic("plans/state.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("plans/state.json"); err != nil {
		t.Fatalf("remove error=%v", err)
	}
	if _, err := store.Read("plans/state.json"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed document read error=%v", err)
	}
	oversizedPath := filepath.Join(dir, PlansDir, "oversized.json")
	if err := os.WriteFile(oversizedPath, make([]byte, MaxDocumentBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("plans/oversized.json"); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("oversized remove error=%v", err)
	}
	if _, err := os.Stat(oversizedPath); err != nil {
		t.Fatalf("unsafe oversized document was removed: %v", err)
	}
}

func TestInterruptedWritesPreserveOldDocumentAndCleanTemp(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int64
	store := openTestStore(t, dir, hooks{Write: func(file *os.File, data []byte) (int, error) {
		if calls.Add(1) == 1 {
			return file.Write(data)
		}
		n := len(data) / 2
		if n == 0 {
			n = 1
		}
		_, _ = file.Write(data[:n])
		return n, errors.New("injected interrupted write")
	}})
	calls.Store(0)
	if err := store.WriteAtomic("plans/state.json", []byte("before"), false); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic("plans/state.json", []byte("after"), true); !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("interrupted write error = %v", err)
	}
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "before" {
		t.Fatalf("old data=%q err=%v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, PlansDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".statefs-tmp-") {
			t.Fatalf("temporary file was not cleaned: %s", entry.Name())
		}
	}
}

func TestFsyncRenameAndFreeSpaceFailures(t *testing.T) {
	dir := t.TempDir()
	var statCalls atomic.Int64
	store := openTestStore(t, dir, hooks{StatFS: func(*os.File) (uint64, error) {
		if statCalls.Add(1) == 1 {
			return 1 << 30, nil
		}
		return 0, nil
	}})
	if err := store.WriteAtomic("plans/state.json", []byte("data"), false); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("free-space error = %v", err)
	}
	store.Close()

	var fsyncCalls atomic.Int64
	fsyncDir := t.TempDir()
	store = openTestStore(t, fsyncDir, hooks{
		Fsync: func(file *os.File) error {
			if fsyncCalls.Add(1) >= 3 {
				return errors.New("injected fsync failure")
			}
			return file.Sync()
		},
	})
	if err := store.WriteAtomic("plans/state.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic("plans/state.json", []byte("new"), true); !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("fsync error = %v", err)
	}
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "old" {
		t.Fatalf("fsync preservation data=%q err=%v", got, err)
	}
	store.Close()

	var removed atomic.Int64
	renameDir := t.TempDir()
	store = openTestStore(t, renameDir, hooks{
		Rename: func(*os.File, string, string, bool) error { return errors.New("injected rename failure") },
		Remove: func(dir *os.File, name string) error {
			removed.Add(1)
			return removeAt(dir, name)
		},
	})
	if err := store.WriteAtomic("plans/state.json", []byte("data"), false); !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("rename error = %v", err)
	}
	if removed.Load() != 1 {
		t.Fatalf("cleanup calls=%d", removed.Load())
	}
	entries, err := os.ReadDir(filepath.Join(renameDir, PlansDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("left files after rename failure: %v", entries)
	}
	_ = store.Close()

	boundedDir := t.TempDir()
	if err := os.Chmod(boundedDir, 0700); err != nil {
		t.Fatal(err)
	}
	bounded, err := Open(Options{StateDir: boundedDir, MaxDocumentBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := bounded.WriteAtomic("plans/bounded.json", []byte("1234"), false); err != nil {
		t.Fatal(err)
	}
	if err := bounded.WriteAtomic("plans/too-large.json", []byte("12345"), false); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("write size error = %v", err)
	}
	_ = bounded.Close()

	statErrorDir := t.TempDir()
	if err := os.Chmod(statErrorDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := openWithHooks(Options{StateDir: statErrorDir}, hooks{StatFS: func(*os.File) (uint64, error) {
		return 0, errors.New("injected statfs failure")
	}}); !errors.Is(err, ErrFreeSpaceUnavailable) {
		t.Fatalf("statfs error = %v", err)
	}
}

func TestSpaceErrorsMapToInsufficientFree(t *testing.T) {
	var fail atomic.Bool

	writeStore := openTestStore(t, t.TempDir(), hooks{Write: func(file *os.File, data []byte) (int, error) {
		if fail.Load() {
			return 0, unix.ENOSPC
		}
		return file.Write(data)
	}})
	fail.Store(true)
	if err := writeStore.WriteAtomic("plans/write-space.json", []byte("data"), false); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("write ENOSPC = %v", err)
	}
	_ = writeStore.Close()

	fail.Store(false)
	fsyncStore := openTestStore(t, t.TempDir(), hooks{Fsync: func(file *os.File) error {
		if fail.Load() {
			return unix.EDQUOT
		}
		return file.Sync()
	}})
	fail.Store(true)
	if err := fsyncStore.WriteAtomic("plans/fsync-space.json", []byte("data"), false); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("fsync EDQUOT = %v", err)
	}
	_ = fsyncStore.Close()

	fail.Store(false)
	lockStore := openTestStore(t, t.TempDir(), hooks{Fsync: func(file *os.File) error {
		if fail.Load() {
			return unix.ENOSPC
		}
		return file.Sync()
	}})
	fail.Store(true)
	if _, err := lockStore.AcquireJobLock("lock-space"); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("lock metadata ENOSPC = %v", err)
	}
	_ = lockStore.Close()

	renameStore := openTestStore(t, t.TempDir(), hooks{Rename: func(*os.File, string, string, bool) error {
		return unix.ENOSPC
	}})
	if err := renameStore.WriteAtomic("plans/rename-space.json", []byte("data"), false); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("rename ENOSPC = %v", err)
	}
	_ = renameStore.Close()

	fail.Store(false)
	directoryStore := openTestStore(t, t.TempDir(), hooks{FsyncDir: func(directory *os.File) error {
		if fail.Load() {
			return unix.EDQUOT
		}
		return directory.Sync()
	}})
	fail.Store(true)
	if err := directoryStore.WriteAtomic("plans/directory-space.json", []byte("data"), false); !errors.Is(err, ErrInsufficientFree) {
		t.Fatalf("directory fsync EDQUOT = %v", err)
	}
	_ = directoryStore.Close()
}

func TestDirectoryFsyncFailureReportsDurabilityUnknown(t *testing.T) {
	dir := t.TempDir()
	var fail atomic.Bool
	store := openTestStore(t, dir, hooks{FsyncDir: func(directory *os.File) error {
		if fail.Load() {
			return errors.New("injected directory fsync failure")
		}
		return directory.Sync()
	}})
	if err := store.WriteAtomic("plans/state.json", []byte("old"), false); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := store.WriteAtomic("plans/state.json", []byte("new"), true); !errors.Is(err, ErrDurabilityUnknown) {
		t.Fatalf("directory fsync error = %v", err)
	}
	// The rename has already become visible; callers must not assume the old
	// value survived after a durability failure.
	if got, err := store.Read("plans/state.json"); err != nil || string(got) != "new" {
		t.Fatalf("post-rename value=%q err=%v", got, err)
	}
}

func TestReadRejectsSymlinksHardLinksSpecialFilesAndOversize(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	plans := filepath.Join(dir, PlansDir)
	target := filepath.Join(plans, "target.json")
	if err := os.WriteFile(target, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(plans, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("plans/link.json"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("document symlink read error = %v", err)
	}
	if err := store.RemoveIfMatch("plans/link.json", "anything"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("document symlink conditional remove error = %v", err)
	}
	if err := store.WriteAtomic("plans/link.json", []byte("x"), true); !errors.Is(err, ErrSymlink) {
		t.Fatalf("document symlink write error = %v", err)
	}

	if err := os.Chmod(target, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("plans/target.json"); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("unsafe file mode error = %v", err)
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(plans, "hard.json")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("plans/hard.json"); !errors.Is(err, ErrHardLinked) {
		t.Fatalf("hard link read error = %v", err)
	}
	if err := store.RemoveIfMatch("plans/hard.json", "anything"); !errors.Is(err, ErrHardLinked) {
		t.Fatalf("hard link conditional remove error = %v", err)
	}
	if err := store.WriteAtomic("plans/hard.json", []byte("x"), true); !errors.Is(err, ErrHardLinked) {
		t.Fatalf("hard link write error = %v", err)
	}

	special := filepath.Join(plans, "dir.json")
	if err := os.Mkdir(special, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read("plans/dir.json"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory read error = %v", err)
	}
	if err := store.RemoveIfMatch("plans/dir.json", "anything"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory conditional remove error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(plans, "big.json"), []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	store.maxBytes = 4
	if _, err := store.Read("plans/big.json"); !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("oversize read error = %v", err)
	}
	store.maxBytes = MaxDocumentBytes
	if err := os.WriteFile(filepath.Join(plans, "corrupt.json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadStateDocument("plans/corrupt.json"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt document error = %v", err)
	}
}

func TestConcurrentLockAcquireAndCloseNoDeadlock(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})

	const workers = 8
	const iterations = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				job, err := store.AcquireJobLock(fmt.Sprintf("job-%d", iteration%4))
				if err == nil {
					_ = job.Close()
				} else if !errors.Is(err, ErrLockConflict) {
					t.Errorf("AcquireJobLock: %v", err)
				}

				locks, err := store.AcquireLocks(
					[]string{fmt.Sprintf("batch-job-%d", worker)},
					[]string{fmt.Sprintf("batch-target-%d", iteration%4)},
				)
				if err == nil {
					for _, lock := range locks {
						_ = lock.Close()
					}
				} else if !errors.Is(err, ErrLockConflict) {
					t.Errorf("AcquireLocks: %v", err)
				}
			}
		}(worker)
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent lock acquire/close did not complete")
	}
}

func TestConcurrentStoreAndLockCloseNoDeadlock(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	locks, err := store.AcquireLocks([]string{"close-job-a", "close-job-b"}, []string{"close-target-a", "close-target-b"})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, lock := range locks {
		wg.Add(1)
		go func(lock *Lock) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				_ = lock.Close()
			}
		}(lock)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = store.Close()
	}()
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Store.Close and Lock.Close did not complete")
	}
}

func TestAtomicReplacementNeverExposesPartialData(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, hooks{})
	if err := store.WriteAtomic("plans/visible.json", []byte(strings.Repeat("A", 4096)), false); err != nil {
		t.Fatal(err)
	}
	var bad atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for index := 0; index < 100; index++ {
			value := byte('A')
			if index%2 != 0 {
				value = 'B'
			}
			if err := store.WriteAtomic("plans/visible.json", []byte(strings.Repeat(string(value), 4096)), true); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for index := 0; index < 100; index++ {
			data, err := os.ReadFile(filepath.Join(dir, PlansDir, "visible.json"))
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if len(data) != 4096 || (data[0] != 'A' && data[0] != 'B') || strings.Trim(string(data), string(data[0])) != "" {
				bad.Add(1)
			}
		}
	}()
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("observed %d partial documents", bad.Load())
	}
}
