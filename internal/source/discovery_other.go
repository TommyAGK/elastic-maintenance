//go:build !linux

package source

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func discoverResourceSetContents(ctx context.Context, resourceSetID, _ string, resolvedRoot, revisionFile string, limits Limits) (*ResourceSet, error) {
	result := &ResourceSet{ID: resourceSetID}
	var entries int
	var totalBytes int64
	revisionFound := false
	err := filepath.WalkDir(resolvedRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative := relativeDisplayPath(resolvedRoot, path)
		if walkErr != nil {
			return discoveryError("unreadable_path", resourceSetID, relative, sanitizePathError(walkErr))
		}
		if path == resolvedRoot {
			return nil
		}
		entries++
		if entries > limits.MaxEntries {
			return discoveryError("too_many_entries", resourceSetID, relative, nil)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return discoveryError("symlink_not_allowed", resourceSetID, relative, nil)
		}
		info, err := entry.Info()
		if err != nil {
			return discoveryError("unreadable_path", resourceSetID, relative, sanitizePathError(err))
		}
		isRevision := revisionFile != "" && relative == filepath.ToSlash(revisionFile)
		if info.IsDir() {
			if isRevision {
				return discoveryError("invalid_revision", resourceSetID, relative, errors.New("revision metadata must be a regular file"))
			}
			if strings.Count(relative, "/")+1 > limits.MaxDepth {
				return discoveryError("depth_exceeded", resourceSetID, relative, nil)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return discoveryError("special_file_not_allowed", resourceSetID, relative, nil)
		}
		if isRevision {
			contents, err := readBoundedRegularFile(path, info, limits.MaxRevisionBytes)
			if err != nil {
				return discoveryError(readErrorCode(err, "revision_too_large"), resourceSetID, relative, sanitizePathError(err))
			}
			revision, err := validateRevision(contents)
			if err != nil {
				return discoveryError("invalid_revision", resourceSetID, relative, err)
			}
			result.Revision = revision
			revisionFound = true
			return nil
		}
		extension := filepath.Ext(entry.Name())
		if extension != ".yaml" && extension != ".yml" {
			return nil
		}
		if len(result.Files) >= limits.MaxFiles {
			return discoveryError("too_many_files", resourceSetID, relative, nil)
		}
		contents, err := readBoundedRegularFile(path, info, limits.MaxFileBytes)
		if err != nil {
			return discoveryError(readErrorCode(err, "file_too_large"), resourceSetID, relative, sanitizePathError(err))
		}
		totalBytes += int64(len(contents))
		if totalBytes > limits.MaxTotalBytes {
			return discoveryError("total_size_exceeded", resourceSetID, relative, nil)
		}
		result.Files = append(result.Files, File{
			Location: Location{ResourceSetID: resourceSetID, RelativePath: relative},
			Contents: contents,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if revisionFile != "" && !revisionFound {
		return nil, discoveryError("revision_not_found", resourceSetID, filepath.ToSlash(revisionFile), nil)
	}
	return result, nil
}
