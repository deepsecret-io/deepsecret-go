// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openNoFollow opens path for reading without following a symbolic link in
// its last element. O_NONBLOCK keeps a FIFO swapped in from blocking the
// open, and O_NOCTTY a terminal swapped in from becoming the controlling
// one; O_NONBLOCK is cleared once the file is open.
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errLink
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
