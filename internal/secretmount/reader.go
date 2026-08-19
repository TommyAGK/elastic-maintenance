package secretmount

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

const DefaultMaxBytes int64 = 64 << 10

var componentPattern = regexp.MustCompile(`^[-._A-Za-z0-9]+$`)

type Reader interface {
	Read(context.Context, config.SecretKeyRef) ([]byte, error)
}

type MountedReader struct {
	root     string
	resolved string
	maxBytes int64
}

func NewMountedReader(root string, maxBytes int64) (*MountedReader, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("secret mount root is invalid")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("secret mount root is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, errors.New("secret mount root is unavailable")
	}
	if maxBytes <= 0 || maxBytes > DefaultMaxBytes {
		return nil, errors.New("secret mount byte limit is invalid")
	}
	return &MountedReader{root: root, resolved: filepath.Clean(resolved), maxBytes: maxBytes}, nil
}

func (reader *MountedReader) Read(ctx context.Context, ref config.SecretKeyRef) ([]byte, error) {
	if reader == nil || !validRef(ref) {
		return nil, errors.New("secret reference is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relative := filepath.Join(ref.Namespace, ref.Name, ref.Key)
	file, err := openMountedFile(reader.resolved, relative)
	if err != nil {
		return nil, errors.New("mounted secret key is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > reader.maxBytes {
		return nil, errors.New("mounted secret key is invalid")
	}
	contents, err := io.ReadAll(io.LimitReader(file, reader.maxBytes+1))
	if err != nil || int64(len(contents)) > reader.maxBytes {
		return nil, errors.New("mounted secret key is invalid")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	final, err := file.Stat()
	if err != nil || final.Size() != opened.Size() || !final.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("mounted secret key changed while reading")
	}
	return contents, nil
}

func validRef(ref config.SecretKeyRef) bool {
	return componentPattern.MatchString(ref.Namespace) && componentPattern.MatchString(ref.Name) && componentPattern.MatchString(ref.Key) && !strings.ContainsAny(ref.Namespace+ref.Name+ref.Key, `/\\`)
}
