//go:build linux

package statefs

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func platformCheck() error { return nil }

func openStateRoot(path string) (*os.File, error) {
	// Openat2 makes the no-symlink/no-magic-link policy explicit. The
	// component-by-component fallback below has the same policy on kernels
	// without openat2 (or when a sandbox blocks the syscall).
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(rootFD), "statefs-root-base")
	if root == nil {
		_ = unix.Close(rootFD)
		return nil, errors.New("cannot create root descriptor")
	}
	relative := strings.TrimPrefix(filepath.ToSlash(path), "/")
	if relative == "" {
		_ = root.Close()
		return nil, ErrStateDirIsRoot
	}

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, openErr := unix.Openat2(int(root.Fd()), relative, how)
	if openErr == nil {
		_ = root.Close()
		return os.NewFile(uintptr(fd), path), nil
	}
	// ENOSYS is the normal old-kernel case. EINVAL/EPERM cover old x/sys/kernel
	// combinations and seccomp policies. All other errors are real path errors
	// and are returned rather than weakened by a fallback.
	if !errors.Is(openErr, unix.ENOSYS) && !errors.Is(openErr, unix.EINVAL) && !errors.Is(openErr, unix.EPERM) {
		_ = root.Close()
		return nil, openErr
	}

	current := root
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = current.Close()
			return nil, ErrSymlink
		}
		fd, err := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		next := os.NewFile(uintptr(fd), part)
		_ = current.Close()
		current = next
	}
	return current, nil
}

func openChildDir(parent *os.File, name string, create bool) (*os.File, error) {
	created := false
	if create {
		err := unix.Mkdirat(int(parent.Fd()), name, 0700)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		created = err == nil
	}

	// This check gives callers a stable symlink-specific diagnostic. The
	// descriptor open below remains authoritative and is protected by
	// O_NOFOLLOW, so this observation is not used as a security check.
	if err := rejectSymlinkAt(parent, name); err != nil {
		return nil, err
	}

	// O_NOFOLLOW and O_DIRECTORY bind the descriptor to the directory inode
	// before any metadata repair. For a newly created directory, chmod the
	// opened descriptor rather than the pathname; Fchmodat on parent/name would
	// reintroduce a path replacement race. The fallback below targets only this
	// already-open descriptor. Existing directories are validated, never repaired.
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		directory := os.NewFile(uintptr(fd), name)
		if created {
			if chmodErr := unix.Fchmod(fd, 0700); chmodErr != nil {
				_ = directory.Close()
				_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
				return nil, chmodErr
			}
		}
		return directory, nil
	}
	if !created || !errors.Is(err, unix.EACCES) {
		return nil, err
	}

	// A maximally restrictive umask can remove search permission before the
	// first open. O_PATH still gives us an inode descriptor; AT_EMPTY_PATH
	// applies Fchmod to that descriptor without reopening a pathname, after
	// which the ordinary directory descriptor can be obtained.
	pathFD, pathErr := unix.Openat(int(parent.Fd()), name, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if pathErr != nil {
		return nil, pathErr
	}
	pathFile := os.NewFile(uintptr(pathFD), name)
	var pathStat unix.Stat_t
	if statErr := unix.Fstat(pathFD, &pathStat); statErr != nil {
		_ = pathFile.Close()
		_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		return nil, statErr
	}
	if pathStat.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = pathFile.Close()
		_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		return nil, ErrSymlink
	}
	if pathStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = pathFile.Close()
		_ = unix.Unlinkat(int(parent.Fd()), name, 0)
		return nil, unix.ENOTDIR
	}
	chmodErr := unix.Fchmodat(pathFD, "", 0700, unix.AT_EMPTY_PATH)
	if errors.Is(chmodErr, unix.ENOSYS) || errors.Is(chmodErr, unix.EOPNOTSUPP) || errors.Is(chmodErr, unix.EPERM) || errors.Is(chmodErr, unix.EINVAL) {
		// Kernels before fchmodat2 do not implement AT_EMPTY_PATH. The procfd
		// symlink names this already-open inode, so this fallback cannot race
		// with a replacement of parent/name; it is not a state path lookup.
		chmodErr = unix.Fchmodat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(pathFD), 0700, 0)
	}
	if chmodErr != nil {
		_ = pathFile.Close()
		_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		return nil, chmodErr
	}
	fd, err = unix.Openat(pathFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	_ = pathFile.Close()
	if err != nil {
		_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openLockFile(dir *os.File, name string) (*os.File, error) {
	var before unix.Stat_t
	statErr := unix.Fstatat(int(dir.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW)
	if statErr == nil && before.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, ErrSymlink
	}
	if statErr != nil && !errors.Is(statErr, unix.ENOENT) {
		return nil, statErr
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if statErr != nil && errors.Is(statErr, unix.ENOENT) {
		// O_CREAT is affected by umask. Do not repair an existing lock's mode,
		// but make a lock created by a restrictive umask exactly 0600.
		if err := unix.Fchmod(fd, 0600); err != nil {
			_ = file.Close()
			_ = unix.Unlinkat(int(dir.Fd()), name, 0)
			return nil, err
		}
	}
	return file, nil
}

func openDocumentFile(dir *os.File, name string) (*os.File, error) {
	if err := rejectSymlinkAt(dir, name); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func createTempFile(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := unix.Fchmod(fd, 0600); err != nil {
		_ = file.Close()
		_ = unix.Unlinkat(int(dir.Fd()), name, 0)
		return nil, err
	}
	return file, nil
}

func removeAt(dir *os.File, name string) error {
	return unix.Unlinkat(int(dir.Fd()), name, 0)
}

func renameAt(dir *os.File, oldName, newName string, replace bool) error {
	if replace {
		return unix.Renameat(int(dir.Fd()), oldName, int(dir.Fd()), newName)
	}
	if err := unix.Renameat2(int(dir.Fd()), oldName, int(dir.Fd()), newName, unix.RENAME_NOREPLACE); err == nil {
		return nil
	} else if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
		return err
	}
	// link+unlink is an atomic no-replace fallback on ordinary local Unix
	// filesystems. linkat fails with EEXIST if the destination appeared first.
	if err := unix.Linkat(int(dir.Fd()), oldName, int(dir.Fd()), newName, 0); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(dir.Fd()), oldName, 0); err != nil {
		// Best effort cleanup. Returning the error leaves the destination intact,
		// which is safer than deleting either name after a successful link.
		return err
	}
	return nil
}

func lockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func freeBytes(file *os.File) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("invalid filesystem block size")
	}
	blockSize := uint64(stat.Bsize)
	// Linux exposes Bavail as unsigned, but reject values that would be a
	// negative signed result rather than treating a sentinel as free space.
	if stat.Bavail > uint64(1<<63-1) {
		return 0, errors.New("negative filesystem available block count")
	}
	if stat.Bavail > ^uint64(0)/blockSize {
		return 0, errors.New("filesystem free-space calculation overflow")
	}
	return stat.Bavail * blockSize, nil
}

func inspectFile(file *os.File) (fileMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fileMetadata{}, err
	}
	return fileMetadata{
		mode:  uint32(stat.Mode),
		uid:   int(stat.Uid),
		nlink: uint64(stat.Nlink),
		isDir: stat.Mode&unix.S_IFMT == unix.S_IFDIR,
		isReg: stat.Mode&unix.S_IFMT == unix.S_IFREG,
	}, nil
}

func rejectSymlinkAt(dir *os.File, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	return nil
}

func isSymlinkError(err error) bool      { return errors.Is(err, unix.ELOOP) }
func isNotDirectoryError(err error) bool { return errors.Is(err, unix.ENOTDIR) }
func isLockConflict(err error) bool {
	return errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)
}
func isAlreadyExists(err error) bool { return errors.Is(err, unix.EEXIST) }
func isInsufficientFreeError(err error) bool {
	return errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)
}
