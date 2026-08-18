package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultMaxFiles         = 10_000
	DefaultMaxEntries       = 100_000
	DefaultMaxDepth         = 64
	DefaultMaxFileBytes     = 4 << 20
	DefaultMaxTotalBytes    = 64 << 20
	DefaultMaxRevisionBytes = 1024
)

type Limits struct {
	MaxFiles         int
	MaxEntries       int
	MaxDepth         int
	MaxFileBytes     int64
	MaxTotalBytes    int64
	MaxRevisionBytes int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxFiles:         DefaultMaxFiles,
		MaxEntries:       DefaultMaxEntries,
		MaxDepth:         DefaultMaxDepth,
		MaxFileBytes:     DefaultMaxFileBytes,
		MaxTotalBytes:    DefaultMaxTotalBytes,
		MaxRevisionBytes: DefaultMaxRevisionBytes,
	}
}

type Location struct {
	ResourceSetID string `json:"resourceSetID"`
	RelativePath  string `json:"relativePath"`
	Document      int    `json:"document,omitempty"`
	Line          int    `json:"line,omitempty"`
	Column        int    `json:"column,omitempty"`
}

type File struct {
	Location Location
	Contents []byte `json:"-"`
}

type RawFileDigest struct {
	RelativePath string `json:"relativePath"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
}

func (file File) RawDigest() RawFileDigest {
	digest := sha256.Sum256(file.Contents)
	return RawFileDigest{RelativePath: file.Location.RelativePath, SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(file.Contents))}
}

type ResourceSet struct {
	ID       string
	Revision string
	Files    []File
}

func (set ResourceSet) RawFileDigests() []RawFileDigest {
	files := append([]File(nil), set.Files...)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Location.RelativePath < files[j].Location.RelativePath })
	result := make([]RawFileDigest, 0, len(files))
	for _, file := range files {
		result = append(result, file.RawDigest())
	}
	return result
}

type DiscoveryError struct {
	Code          string
	ResourceSetID string
	RelativePath  string
	Err           error
}

func (err *DiscoveryError) Error() string {
	location := fmt.Sprintf("resource set %q", err.ResourceSetID)
	if err.RelativePath != "" {
		location += fmt.Sprintf(" file %q", err.RelativePath)
	}
	if err.Err == nil {
		return location + ": " + err.Code
	}
	return location + ": " + err.Code + ": " + err.Err.Error()
}

func (err *DiscoveryError) Unwrap() error { return err.Err }

type Discoverer struct {
	mountRoots []string
	limits     Limits
}

func NewDiscoverer(mountRoots []string, limits Limits) (*Discoverer, error) {
	if limits.MaxEntries == 0 {
		limits.MaxEntries = DefaultMaxEntries
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = DefaultMaxDepth
	}
	if len(mountRoots) == 0 {
		return nil, errors.New("at least one mount root is required")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}

	resolvedRoots := make([]string, 0, len(mountRoots))
	seen := map[string]struct{}{}
	for index, root := range mountRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
			return nil, fmt.Errorf("mount root %d must be a clean absolute path other than the filesystem root", index)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("resolve mount root %d: %w", index, sanitizePathError(err))
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return nil, fmt.Errorf("inspect mount root %d: %w", index, sanitizePathError(err))
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("mount root %d is not a directory", index)
		}
		resolved = filepath.Clean(resolved)
		if resolved == string(filepath.Separator) {
			return nil, fmt.Errorf("mount root %d must not resolve to the filesystem root", index)
		}
		if _, duplicate := seen[resolved]; duplicate {
			return nil, fmt.Errorf("mount roots %d resolves to a duplicate directory", index)
		}
		seen[resolved] = struct{}{}
		resolvedRoots = append(resolvedRoots, resolved)
	}
	return &Discoverer{mountRoots: resolvedRoots, limits: limits}, nil
}

func (limits Limits) Validate() error {
	if limits.MaxFiles <= 0 {
		return errors.New("maximum resource file count must be positive")
	}
	if limits.MaxEntries <= 0 {
		return errors.New("maximum source entry count must be positive")
	}
	if limits.MaxDepth <= 0 {
		return errors.New("maximum source depth must be positive")
	}
	if limits.MaxFileBytes <= 0 {
		return errors.New("maximum resource file size must be positive")
	}
	if limits.MaxTotalBytes < limits.MaxFileBytes {
		return errors.New("maximum total resource size must be at least the per-file limit")
	}
	if limits.MaxRevisionBytes <= 0 {
		return errors.New("maximum revision size must be positive")
	}
	return nil
}

func (discoverer *Discoverer) Discover(resourceSetID, root, revisionFile string) (*ResourceSet, error) {
	return discoverer.DiscoverContext(context.Background(), resourceSetID, root, revisionFile)
}

func (discoverer *Discoverer) DiscoverContext(ctx context.Context, resourceSetID, root, revisionFile string) (*ResourceSet, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if discoverer == nil {
		return nil, errors.New("source discoverer is nil")
	}
	if !resourceSetIdentifierPattern.MatchString(resourceSetID) {
		return nil, errors.New("resource set ID is invalid")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, discoveryError("invalid_root", resourceSetID, "", nil)
	}
	if revisionFile != "" && !isCleanRelativePath(revisionFile) {
		return nil, discoveryError("invalid_revision_path", resourceSetID, filepath.ToSlash(revisionFile), nil)
	}

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, discoveryError("root_unavailable", resourceSetID, "", sanitizePathError(err))
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	mountRoot, ok := containingMountRoot(resolvedRoot, discoverer.mountRoots)
	if !ok {
		return nil, discoveryError("root_escape", resourceSetID, "", nil)
	}

	result, err := discoverResourceSetContents(ctx, resourceSetID, mountRoot, resolvedRoot, revisionFile, discoverer.limits)
	if err != nil {
		return nil, err
	}
	sort.Slice(result.Files, func(left, right int) bool {
		return result.Files[left].Location.RelativePath < result.Files[right].Location.RelativePath
	})
	return result, nil
}

var (
	errSizeLimit                 = errors.New("size limit exceeded")
	resourceSetIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)
)

func readBoundedRegularFile(path string, before fs.FileInfo, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed during discovery")
	}
	return readBoundedOpenFile(file, after, limit)
}

func readBoundedOpenFile(file *os.File, before fs.FileInfo, limit int64) ([]byte, error) {
	if before.Size() > limit {
		return nil, errSizeLimit
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, errSizeLimit
	}
	final, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if final.Size() != before.Size() || !final.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("file changed during discovery")
	}
	return contents, nil
}

func ValidateRevisionMetadata(value string) error {
	validated, err := validateRevision([]byte(value))
	if err != nil {
		return err
	}
	if validated != value {
		return errors.New("revision metadata must not contain surrounding whitespace")
	}
	return nil
}

func validateRevision(contents []byte) (string, error) {
	if !utf8.Valid(contents) {
		return "", errors.New("revision metadata must be valid UTF-8")
	}
	revision := strings.TrimSpace(string(contents))
	if revision == "" {
		return "", errors.New("revision metadata must not be empty")
	}
	for _, character := range revision {
		if unicode.Is(unicode.Categories["C"], character) || unicode.Is(unicode.Categories["Zl"], character) || unicode.Is(unicode.Categories["Zp"], character) {
			return "", errors.New("revision metadata must be one printable line")
		}
	}
	return revision, nil
}

func isCleanRelativePath(path string) bool {
	clean := filepath.Clean(path)
	return path != "" && !filepath.IsAbs(path) && clean == path && clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func withinAny(path string, roots []string) bool {
	_, ok := containingMountRoot(path, roots)
	return ok
}

func containingMountRoot(path string, roots []string) (string, bool) {
	var selected string
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && len(root) > len(selected) {
			selected = root
		}
	}
	return selected, selected != ""
}

func relativeDisplayPath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." {
		return ""
	}
	return filepath.ToSlash(relative)
}

func discoveryError(code, resourceSetID, relativePath string, err error) *DiscoveryError {
	return &DiscoveryError{Code: code, ResourceSetID: resourceSetID, RelativePath: relativePath, Err: err}
}

func readErrorCode(err error, sizeCode string) string {
	if errors.Is(err, errSizeLimit) {
		return sizeCode
	}
	return "unreadable_file"
}

func sanitizePathError(err error) error {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return errors.New(pathError.Err.Error())
	}
	return err
}
