//go:build !linux

package statefs

import (
	"errors"
	"os"
)

// Non-Linux builds intentionally contain compilation stubs only. The state
// directory implementation relies on Linux descriptor-relative primitives;
// silently falling back to path-based operations or process-local locks would
// make Open appear safe when it is not.
func platformCheck() error { return ErrUnsupportedPlatform }

func openStateRoot(string) (*os.File, error) { return nil, ErrUnsupportedPlatform }

func openChildDir(*os.File, string, bool) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func openLockFile(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func openDocumentFile(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func createTempFile(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}

func removeAt(*os.File, string) error { return ErrUnsupportedPlatform }

func renameAt(*os.File, string, string, bool) error { return ErrUnsupportedPlatform }

func lockFile(*os.File) error { return ErrUnsupportedPlatform }

func unlockFile(*os.File) error { return ErrUnsupportedPlatform }

func isSymlinkError(err error) bool      { return errors.Is(err, ErrSymlink) }
func isNotDirectoryError(err error) bool { return errors.Is(err, ErrStateDirNotDirectory) }
func isLockConflict(error) bool          { return false }
func isAlreadyExists(err error) bool     { return errors.Is(err, os.ErrExist) }
func isInsufficientFreeError(error) bool { return false }

func inspectFile(*os.File) (fileMetadata, error) {
	return fileMetadata{}, ErrUnsupportedPlatform
}
