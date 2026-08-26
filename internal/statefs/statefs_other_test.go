//go:build !linux

package statefs

import (
	"errors"
	"testing"
)

func TestOpenFailsClosedOutsideLinux(t *testing.T) {
	if _, err := Open(Options{}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Open error = %v, want %v", err, ErrUnsupportedPlatform)
	}
}
