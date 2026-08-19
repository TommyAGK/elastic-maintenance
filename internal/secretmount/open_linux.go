//go:build linux

package secretmount

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openMountedFile(root, relative string) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errors.New("mounted secret root is unavailable")
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errors.New("mounted secret key is unavailable")
	}
	return os.NewFile(uintptr(fd), "mounted-secret"), nil
}
