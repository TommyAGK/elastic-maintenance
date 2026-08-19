//go:build !linux

package secretmount

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Non-Linux production is unsupported. This fallback requires an administrator-
// controlled immutable mount root and verifies the resolved path before opening.
func openMountedFile(root, relative string) (*os.File, error) {
	candidate := filepath.Join(root, relative)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || !pathWithin(root, resolved) {
		return nil, errors.New("mounted secret key is unavailable")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, errors.New("mounted secret key is unavailable")
	}
	return file, nil
}
func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && relative != "."
}
