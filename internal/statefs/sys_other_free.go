//go:build !linux && !(darwin || dragonfly || freebsd || openbsd || aix)

package statefs

import (
	"errors"
	"os"
)

// freeBytes is a compilation stub because non-Linux Open calls fail closed.
func freeBytes(*os.File) (uint64, error) {
	return 0, errors.New("statfs is unavailable on unsupported platform")
}
