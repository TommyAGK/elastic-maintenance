//go:build linux

package source

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxWalkState struct {
	resourceSetID string
	revisionFile  string
	limits        Limits
	result        *ResourceSet
	entries       int
	totalBytes    int64
	revisionFound bool
}

func discoverResourceSetContents(resourceSetID, mountRoot, resolvedRoot, revisionFile string, limits Limits) (*ResourceSet, error) {
	mount, err := openAbsoluteDirectoryNoFollow(mountRoot)
	if err != nil {
		return nil, discoveryError("root_unavailable", resourceSetID, "", err)
	}
	defer mount.Close()
	relativeRoot, err := filepath.Rel(mountRoot, resolvedRoot)
	if err != nil || relativeRoot == ".." || strings.HasPrefix(relativeRoot, ".."+string(filepath.Separator)) {
		return nil, discoveryError("root_escape", resourceSetID, "", nil)
	}
	root, err := openRelativeDirectoryNoFollow(mount, relativeRoot)
	if err != nil {
		return nil, discoveryError("root_unavailable", resourceSetID, "", err)
	}
	defer root.Close()

	state := &linuxWalkState{
		resourceSetID: resourceSetID,
		revisionFile:  filepath.ToSlash(revisionFile),
		limits:        limits,
		result:        &ResourceSet{ID: resourceSetID},
	}
	if err := state.walkDirectory(root, "", 0); err != nil {
		return nil, err
	}
	if revisionFile != "" && !state.revisionFound {
		return nil, discoveryError("revision_not_found", resourceSetID, filepath.ToSlash(revisionFile), nil)
	}
	return state.result, nil
}

func openAbsoluteDirectoryNoFollow(path string) (*os.File, error) {
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(rootFD), "filesystem-root")
	if current == nil {
		unix.Close(rootFD)
		return nil, errors.New("could not open filesystem root")
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		next, err := openDirectoryAt(current, component)
		if err != nil {
			current.Close()
			return nil, err
		}
		if err := current.Close(); err != nil {
			next.Close()
			return nil, err
		}
		current = next
	}
	return current, nil
}

func openRelativeDirectoryNoFollow(root *os.File, relative string) (*os.File, error) {
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	current := os.NewFile(uintptr(fd), "resource-set-root")
	if current == nil {
		unix.Close(fd)
		return nil, errors.New("could not duplicate mount root")
	}
	if relative == "." {
		return current, nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, errors.New("invalid relative resource-set root")
		}
		next, err := openDirectoryAt(current, component)
		if err != nil {
			current.Close()
			return nil, err
		}
		if err := current.Close(); err != nil {
			next.Close()
			return nil, err
		}
		current = next
	}
	return current, nil
}

func openDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "source-directory")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("could not open source directory")
	}
	return file, nil
}

func (state *linuxWalkState) walkDirectory(directory *os.File, parent string, depth int) error {
	remaining := state.limits.MaxEntries - state.entries
	entries := make([]os.DirEntry, 0, min(remaining, 256))
	for {
		batchSize := min(remaining-len(entries)+1, 256)
		if batchSize < 1 {
			batchSize = 1
		}
		batch, err := directory.ReadDir(batchSize)
		entries = append(entries, batch...)
		if len(entries) > remaining {
			relative := entries[len(entries)-1].Name()
			if parent != "" {
				relative = parent + "/" + relative
			}
			return discoveryError("too_many_entries", state.resourceSetID, relative, nil)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return discoveryError("unreadable_path", state.resourceSetID, parent, sanitizePathError(err))
		}
	}
	state.entries += len(entries)
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })

	for _, entry := range entries {
		relative := entry.Name()
		if parent != "" {
			relative = parent + "/" + entry.Name()
		}

		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return discoveryError("unreadable_path", state.resourceSetID, relative, err)
		}
		mode := stat.Mode & unix.S_IFMT
		isRevision := state.revisionFile != "" && relative == state.revisionFile
		switch mode {
		case unix.S_IFLNK:
			return discoveryError("symlink_not_allowed", state.resourceSetID, relative, nil)
		case unix.S_IFDIR:
			if isRevision {
				return discoveryError("invalid_revision", state.resourceSetID, relative, errors.New("revision metadata must be a regular file"))
			}
			if depth >= state.limits.MaxDepth {
				return discoveryError("depth_exceeded", state.resourceSetID, relative, nil)
			}
			childFD, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return discoveryError("unreadable_path", state.resourceSetID, relative, err)
			}
			child := os.NewFile(uintptr(childFD), "resource-set-directory")
			if child == nil {
				unix.Close(childFD)
				return discoveryError("unreadable_path", state.resourceSetID, relative, errors.New("could not open directory"))
			}
			var opened unix.Stat_t
			if err := unix.Fstat(childFD, &opened); err != nil || !sameFileIdentity(stat, opened) {
				child.Close()
				if err == nil {
					err = errors.New("directory changed during discovery")
				}
				return discoveryError("unreadable_path", state.resourceSetID, relative, err)
			}
			err = state.walkDirectory(child, relative, depth+1)
			closeErr := child.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return discoveryError("unreadable_path", state.resourceSetID, relative, closeErr)
			}
		case unix.S_IFREG:
			if err := state.readRegularFile(directory, entry.Name(), relative, isRevision, stat); err != nil {
				return err
			}
		default:
			return discoveryError("special_file_not_allowed", state.resourceSetID, relative, nil)
		}
	}
	return nil
}

func sameFileIdentity(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func (state *linuxWalkState) readRegularFile(directory *os.File, name, relative string, isRevision bool, expected unix.Stat_t) error {
	isResource := filepath.Ext(name) == ".yaml" || filepath.Ext(name) == ".yml"
	if !isRevision && !isResource {
		return nil
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return discoveryError("unreadable_file", state.resourceSetID, relative, err)
	}
	file := os.NewFile(uintptr(fd), "resource-set-file")
	if file == nil {
		unix.Close(fd)
		return discoveryError("unreadable_file", state.resourceSetID, relative, errors.New("could not open file"))
	}
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameFileIdentity(expected, opened) {
		if err == nil {
			err = errors.New("file changed during discovery")
		}
		return discoveryError("unreadable_file", state.resourceSetID, relative, err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		if err == nil {
			err = errors.New("file changed during discovery")
		}
		return discoveryError("unreadable_file", state.resourceSetID, relative, sanitizePathError(err))
	}

	limit := state.limits.MaxFileBytes
	sizeCode := "file_too_large"
	if isRevision {
		limit = state.limits.MaxRevisionBytes
		sizeCode = "revision_too_large"
	}
	contents, err := readBoundedOpenFile(file, info, limit)
	if err != nil {
		return discoveryError(readErrorCode(err, sizeCode), state.resourceSetID, relative, sanitizePathError(err))
	}
	if isRevision {
		revision, err := validateRevision(contents)
		if err != nil {
			return discoveryError("invalid_revision", state.resourceSetID, relative, err)
		}
		state.result.Revision = revision
		state.revisionFound = true
		return nil
	}
	if len(state.result.Files) >= state.limits.MaxFiles {
		return discoveryError("too_many_files", state.resourceSetID, relative, nil)
	}
	state.totalBytes += int64(len(contents))
	if state.totalBytes > state.limits.MaxTotalBytes {
		return discoveryError("total_size_exceeded", state.resourceSetID, relative, nil)
	}
	state.result.Files = append(state.result.Files, File{
		Location: Location{ResourceSetID: state.resourceSetID, RelativePath: relative},
		Contents: contents,
	})
	return nil
}
