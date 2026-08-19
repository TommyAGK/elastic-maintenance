package secretmount

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

func TestMountedReaderReadsBoundedKeyAndSupportsProjectedSymlink(t *testing.T) {
	root := t.TempDir()
	version := filepath.Join(root, "..2026_01")
	if err := os.Mkdir(version, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, "session-key"), []byte("value"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "namespace", "secret")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "..2026_01", "session-key"), filepath.Join(directory, "session-key")); err != nil {
		t.Fatal(err)
	}
	reader, err := NewMountedReader(root, 64)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := reader.Read(context.Background(), config.SecretKeyRef{Namespace: "namespace", Name: "secret", Key: "session-key"})
	if err != nil || string(contents) != "value" {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
}
func TestMountedReaderRejectsEscapeInvalidAndOversizedKeys(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "ns", "name")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "large"), []byte(strings.Repeat("x", 65)), 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewMountedReader(root, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []config.SecretKeyRef{{Namespace: "ns", Name: "name", Key: "escape"}, {Namespace: "ns", Name: "name", Key: "large"}, {Namespace: "..", Name: "name", Key: "escape"}} {
		if _, err := reader.Read(context.Background(), ref); err == nil {
			t.Errorf("Read(%#v) succeeded", ref)
		}
	}
}
