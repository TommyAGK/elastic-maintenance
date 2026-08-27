//go:build linux

package statefs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestListDocumentsEnumeratesValidatedJSONAndResetsOffset(t *testing.T) {
	directory := t.TempDir()
	store := openTestStore(t, directory, hooks{})
	for _, name := range []string{"z.json", "a.json", "middle.json"} {
		if err := store.WriteAtomic("plans/"+name, []byte("{}"), false); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"a.json", "middle.json", "z.json"}
	for attempt := 0; attempt < 2; attempt++ {
		got, err := store.ListDocuments(PlansDir)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("attempt %d names=%v, want %v", attempt, got, want)
		}
	}
	if _, err := store.ListDocuments(LocksDir); !errors.Is(err, ErrInvalidRelativePath) {
		t.Fatalf("locks directory error=%v", err)
	}
	if _, err := store.ListDocuments("plans/"); !errors.Is(err, ErrInvalidRelativePath) {
		t.Fatalf("non-exact directory error=%v", err)
	}
}

func TestListDocumentsRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		setup func(string, string) error
		want  error
	}{
		{name: "temporary", setup: func(directory, name string) error {
			return os.WriteFile(filepath.Join(directory, name), []byte("x"), 0600)
		}, want: ErrUnexpectedEntry},
		{name: "non-json", setup: func(directory, name string) error {
			return os.WriteFile(filepath.Join(directory, name), []byte("x"), 0600)
		}, want: ErrUnexpectedEntry},
		{name: "symlink", setup: func(directory, name string) error {
			return os.Symlink(filepath.Join(directory, "target.json"), filepath.Join(directory, name))
		}, want: ErrSymlink},
		{name: "hardlink", setup: func(directory, name string) error {
			return os.Link(filepath.Join(directory, "target.json"), filepath.Join(directory, name))
		}, want: ErrHardLinked},
		{name: "special directory", setup: func(directory, name string) error { return os.Mkdir(filepath.Join(directory, name), 0700) }, want: ErrNotRegular},
		{name: "unsafe mode", setup: func(directory, name string) error {
			return os.WriteFile(filepath.Join(directory, name), []byte("x"), 0640)
		}, want: ErrUnsafeFile},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store := openTestStore(t, root, hooks{})
			plans := filepath.Join(root, PlansDir)
			if test.name == "symlink" || test.name == "hardlink" {
				if err := os.WriteFile(filepath.Join(plans, "target.json"), []byte("target"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			name := "unsafe.json"
			if test.name == "temporary" {
				name = ".statefs-tmp-leftover.json"
			}
			if test.name == "non-json" {
				name = "unexpected.txt"
			}
			if err := test.setup(plans, name); err != nil {
				t.Fatal(err)
			}
			_, err := store.ListDocuments(PlansDir)
			if !errors.Is(err, test.want) {
				t.Fatalf("ListDocuments error=%v, want %v", err, test.want)
			}
		})
	}
}

func TestReadDocumentsReturnsSortedDefensiveSnapshotAndBounds(t *testing.T) {
	root := t.TempDir()
	store := openTestStore(t, root, hooks{})
	for name, value := range map[string]string{"z.json": "z", "a.json": "a"} {
		if err := store.WriteAtomic(PlansDir+"/"+name, []byte(value), false); err != nil {
			t.Fatal(err)
		}
	}
	documents, err := store.ReadDocuments(PlansDir, 10, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{documents[0].Name, documents[1].Name}; !reflect.DeepEqual(got, []string{"a.json", "z.json"}) {
		t.Fatalf("document names=%v", got)
	}
	documents[0].Data[0] = 'x'
	if got, err := store.Read(PlansDir + "/a.json"); err != nil || string(got) != "a" {
		t.Fatalf("defensive snapshot changed store=%q err=%v", got, err)
	}
	if _, err := store.ReadDocuments(PlansDir, 1, 32<<20); !errors.Is(err, ErrTooManyDocuments) {
		t.Fatalf("count bound error=%v", err)
	}
	if _, err := store.ReadDocuments(PlansDir, 10, 1); !errors.Is(err, ErrAggregateTooLarge) {
		t.Fatalf("aggregate bound error=%v", err)
	}
}

func TestListDocumentsRejectsOversizedDocumentWithoutExposingContents(t *testing.T) {
	root := t.TempDir()
	store := openTestStore(t, root, hooks{})
	store.maxBytes = 4
	sentinel := "API_KEY_SENTINEL_SHOULD_NOT_APPEAR"
	if err := os.WriteFile(filepath.Join(root, PlansDir, "large.json"), []byte(strings.Repeat("x", 5)+sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := store.ListDocuments(PlansDir)
	if !errors.Is(err, ErrDocumentTooLarge) {
		t.Fatalf("ListDocuments error=%v", err)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error exposed document contents: %v", err)
	}
}
