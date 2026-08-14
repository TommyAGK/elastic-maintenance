package source

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDiscoverReadsYAMLInLexicalOrderWithSafeLocations(t *testing.T) {
	mountRoot := t.TempDir()
	resourceRoot := filepath.Join(mountRoot, "production")
	mustMkdirAll(t, filepath.Join(resourceRoot, "nested"))
	mustWrite(t, filepath.Join(resourceRoot, "z.yml"), "kind: z\n")
	mustWrite(t, filepath.Join(resourceRoot, "a.yaml"), "kind: a\n")
	mustWrite(t, filepath.Join(resourceRoot, "nested", "b.yaml"), "kind: b\n")
	mustWrite(t, filepath.Join(resourceRoot, "ignored.json"), `{"ignored":true}`)
	mustWrite(t, filepath.Join(resourceRoot, ".source-revision"), "  feature/safe-discovery  \n")

	discoverer := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits())
	result, err := discoverer.Discover("production", resourceRoot, ".source-revision")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.ID != "production" || result.Revision != "feature/safe-discovery" {
		t.Fatalf("resource set metadata = %#v", result)
	}
	if len(result.Files) != 3 {
		t.Fatalf("len(Files) = %d", len(result.Files))
	}
	wantPaths := []string{"a.yaml", "nested/b.yaml", "z.yml"}
	wantContents := []string{"kind: a\n", "kind: b\n", "kind: z\n"}
	for index, file := range result.Files {
		if file.Location != (Location{ResourceSetID: "production", RelativePath: wantPaths[index]}) {
			t.Errorf("Files[%d].Location = %#v", index, file.Location)
		}
		if string(file.Contents) != wantContents[index] {
			t.Errorf("Files[%d].Contents = %q", index, file.Contents)
		}
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), mountRoot) || strings.Contains(string(encoded), "kind: a") {
		t.Fatalf("serialized discovery result leaked an absolute path or source body: %s", encoded)
	}
}

func TestDiscoverResolvesAssignedRootOnceWithinMountBoundary(t *testing.T) {
	mountRoot := t.TempDir()
	actualRoot := filepath.Join(mountRoot, "actual")
	mustMkdirAll(t, actualRoot)
	mustWrite(t, filepath.Join(actualRoot, "resource.yaml"), "kind: safe\n")
	assignedRoot := filepath.Join(mountRoot, "assigned")
	if err := os.Symlink(actualRoot, assignedRoot); err != nil {
		t.Fatal(err)
	}

	result, err := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits()).Discover("set-1", assignedRoot, "")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Files) != 1 || result.Files[0].Location.RelativePath != "resource.yaml" {
		t.Fatalf("Files = %#v", result.Files)
	}
}

func TestDiscoverRejectsAssignedRootEscape(t *testing.T) {
	parent := t.TempDir()
	mountRoot := filepath.Join(parent, "mount")
	outsideRoot := filepath.Join(parent, "outside")
	mustMkdirAll(t, mountRoot)
	mustMkdirAll(t, outsideRoot)
	mustWrite(t, filepath.Join(outsideRoot, "resource.yaml"), "kind: escaped\n")
	assignedRoot := filepath.Join(mountRoot, "escaped")
	if err := os.Symlink(outsideRoot, assignedRoot); err != nil {
		t.Fatal(err)
	}

	_, err := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits()).Discover("set-1", assignedRoot, "")
	assertDiscoveryCode(t, err, "root_escape")
	if strings.Contains(err.Error(), parent) {
		t.Fatalf("error leaked an absolute path: %v", err)
	}
}

func TestDiscoverRejectsSymlinksAnywhereInResourceSet(t *testing.T) {
	mountRoot, resourceRoot := newResourceRoot(t)
	mustWrite(t, filepath.Join(resourceRoot, "actual.yaml"), "kind: safe\n")
	if err := os.Symlink("actual.yaml", filepath.Join(resourceRoot, "linked.yaml")); err != nil {
		t.Fatal(err)
	}

	_, err := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits()).Discover("set-1", resourceRoot, "")
	assertDiscoveryCode(t, err, "symlink_not_allowed")
	assertRelativePath(t, err, "linked.yaml")
}

func TestDiscoverRejectsSpecialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets are not available")
	}
	mountRoot, resourceRoot := newResourceRoot(t)
	listener, err := net.Listen("unix", filepath.Join(resourceRoot, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	_, err = newTestDiscoverer(t, []string{mountRoot}, DefaultLimits()).Discover("set-1", resourceRoot, "")
	assertDiscoveryCode(t, err, "special_file_not_allowed")
	assertRelativePath(t, err, "socket")
}

func TestDiscoverRejectsUnsafeResourceSetIDs(t *testing.T) {
	mountRoot, resourceRoot := newResourceRoot(t)
	discoverer := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits())
	for _, id := range []string{"", "bad\nset", "contains.dot", strings.Repeat("a", 65)} {
		if _, err := discoverer.Discover(id, resourceRoot, ""); err == nil || !strings.Contains(err.Error(), "resource set ID is invalid") {
			t.Fatalf("Discover(%q) error = %v", id, err)
		}
	}
}

func TestDiscoverBoundsIgnoredEntriesAndDepth(t *testing.T) {
	t.Run("ignored entries", func(t *testing.T) {
		mountRoot, resourceRoot := newResourceRoot(t)
		mustWrite(t, filepath.Join(resourceRoot, "a.txt"), "ignored")
		mustWrite(t, filepath.Join(resourceRoot, "b.txt"), "ignored")
		limits := Limits{MaxFiles: 1, MaxEntries: 1, MaxDepth: 2, MaxFileBytes: 4, MaxTotalBytes: 4, MaxRevisionBytes: 4}
		_, err := newTestDiscoverer(t, []string{mountRoot}, limits).Discover("set-1", resourceRoot, "")
		assertDiscoveryCode(t, err, "too_many_entries")
	})
	t.Run("depth", func(t *testing.T) {
		mountRoot, resourceRoot := newResourceRoot(t)
		mustMkdirAll(t, filepath.Join(resourceRoot, "one", "two"))
		limits := Limits{MaxFiles: 1, MaxEntries: 4, MaxDepth: 1, MaxFileBytes: 4, MaxTotalBytes: 4, MaxRevisionBytes: 4}
		_, err := newTestDiscoverer(t, []string{mountRoot}, limits).Discover("set-1", resourceRoot, "")
		assertDiscoveryCode(t, err, "depth_exceeded")
	})
}

func TestDiscoverEnforcesResourceBounds(t *testing.T) {
	for name, testCase := range map[string]struct {
		files    map[string]string
		limits   Limits
		wantCode string
	}{
		"file size": {
			files:    map[string]string{"large.yaml": "12345"},
			limits:   Limits{MaxFiles: 2, MaxFileBytes: 4, MaxTotalBytes: 8, MaxRevisionBytes: 4},
			wantCode: "file_too_large",
		},
		"file count": {
			files:    map[string]string{"a.yaml": "1", "b.yaml": "2"},
			limits:   Limits{MaxFiles: 1, MaxFileBytes: 4, MaxTotalBytes: 8, MaxRevisionBytes: 4},
			wantCode: "too_many_files",
		},
		"total size": {
			files:    map[string]string{"a.yaml": "1234", "b.yaml": "5678"},
			limits:   Limits{MaxFiles: 2, MaxFileBytes: 4, MaxTotalBytes: 6, MaxRevisionBytes: 4},
			wantCode: "total_size_exceeded",
		},
	} {
		t.Run(name, func(t *testing.T) {
			mountRoot, resourceRoot := newResourceRoot(t)
			for path, contents := range testCase.files {
				mustWrite(t, filepath.Join(resourceRoot, path), contents)
			}
			_, err := newTestDiscoverer(t, []string{mountRoot}, testCase.limits).Discover("set-1", resourceRoot, "")
			assertDiscoveryCode(t, err, testCase.wantCode)
		})
	}
}

func TestDiscoverValidatesRevisionMetadata(t *testing.T) {
	for name, testCase := range map[string]struct {
		contents []byte
		limits   Limits
		wantCode string
	}{
		"missing": {
			limits:   DefaultLimits(),
			wantCode: "revision_not_found",
		},
		"too large": {
			contents: []byte("12345"),
			limits:   Limits{MaxFiles: 1, MaxFileBytes: 4, MaxTotalBytes: 4, MaxRevisionBytes: 4},
			wantCode: "revision_too_large",
		},
		"multiple lines": {
			contents: []byte("first\nsecond"),
			limits:   DefaultLimits(),
			wantCode: "invalid_revision",
		},
		"invalid UTF-8": {
			contents: []byte{0xff, 0xfe},
			limits:   DefaultLimits(),
			wantCode: "invalid_revision",
		},
		"display control": {
			contents: []byte("feature/\u202eevil"),
			limits:   DefaultLimits(),
			wantCode: "invalid_revision",
		},
	} {
		t.Run(name, func(t *testing.T) {
			mountRoot, resourceRoot := newResourceRoot(t)
			if testCase.contents != nil {
				if err := os.WriteFile(filepath.Join(resourceRoot, ".revision"), testCase.contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := newTestDiscoverer(t, []string{mountRoot}, testCase.limits).Discover("set-1", resourceRoot, ".revision")
			assertDiscoveryCode(t, err, testCase.wantCode)
		})
	}
}

func TestDiscoverRejectsRevisionDirectoryAndTraversal(t *testing.T) {
	mountRoot, resourceRoot := newResourceRoot(t)
	mustMkdirAll(t, filepath.Join(resourceRoot, ".revision"))
	discoverer := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits())

	_, err := discoverer.Discover("set-1", resourceRoot, ".revision")
	assertDiscoveryCode(t, err, "invalid_revision")
	_, err = discoverer.Discover("set-1", resourceRoot, "../revision")
	assertDiscoveryCode(t, err, "invalid_revision_path")
}

func TestDiscoverDoesNotModifyReadOnlySourceFiles(t *testing.T) {
	mountRoot, resourceRoot := newResourceRoot(t)
	path := filepath.Join(resourceRoot, "resource.yaml")
	mustWrite(t, path, "kind: immutable\n")
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := newTestDiscoverer(t, []string{mountRoot}, DefaultLimits()).Discover("set-1", resourceRoot, "")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode() != after.Mode() || string(result.Files[0].Contents) != "kind: immutable\n" {
		t.Fatal("discovery modified a read-only source file")
	}
}

func TestNewDiscovererRejectsMountRootResolvingToFilesystemRoot(t *testing.T) {
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(string(filepath.Separator), link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDiscoverer([]string{link}, DefaultLimits()); err == nil || !strings.Contains(err.Error(), "must not resolve to the filesystem root") {
		t.Fatalf("NewDiscoverer() error = %v", err)
	}
}

func TestNewDiscovererRejectsUnsafeConfiguration(t *testing.T) {
	mountRoot := t.TempDir()
	for name, testCase := range map[string]struct {
		roots  []string
		limits Limits
	}{
		"no roots":      {roots: nil, limits: DefaultLimits()},
		"relative root": {roots: []string{"relative"}, limits: DefaultLimits()},
		"duplicate root": {
			roots:  []string{mountRoot, mountRoot},
			limits: DefaultLimits(),
		},
		"invalid limits": {roots: []string{mountRoot}, limits: Limits{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewDiscoverer(testCase.roots, testCase.limits); err == nil {
				t.Fatal("NewDiscoverer() error = nil")
			}
		})
	}
}

func newResourceRoot(t *testing.T) (string, string) {
	t.Helper()
	mountRoot := t.TempDir()
	resourceRoot := filepath.Join(mountRoot, "set")
	mustMkdirAll(t, resourceRoot)
	return mountRoot, resourceRoot
}

func newTestDiscoverer(t *testing.T, roots []string, limits Limits) *Discoverer {
	t.Helper()
	discoverer, err := NewDiscoverer(roots, limits)
	if err != nil {
		t.Fatalf("NewDiscoverer() error = %v", err)
	}
	return discoverer
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertDiscoveryCode(t *testing.T, err error, code string) {
	t.Helper()
	var discoveryErr *DiscoveryError
	if !errors.As(err, &discoveryErr) {
		t.Fatalf("error = %v, want DiscoveryError", err)
	}
	if discoveryErr.Code != code {
		t.Fatalf("DiscoveryError.Code = %q, want %q (error: %v)", discoveryErr.Code, code, err)
	}
}

func assertRelativePath(t *testing.T, err error, path string) {
	t.Helper()
	var discoveryErr *DiscoveryError
	if !errors.As(err, &discoveryErr) {
		t.Fatalf("error = %v, want DiscoveryError", err)
	}
	if discoveryErr.RelativePath != path {
		t.Fatalf("DiscoveryError.RelativePath = %q, want %q", discoveryErr.RelativePath, path)
	}
}
