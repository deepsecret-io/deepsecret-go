// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disk

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// CreateIn creates the file name inside root, which must not exist, for
// writing, with mode (the umask applies). root resolves every folder on
// the way inside it in the kernel, and O_EXCL never opens what is already
// at name, a link included.
func CreateIn(root *os.Root, name string, mode os.FileMode) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
}

// MkdirIn creates the folder name inside root with perm (the umask
// applies).
func MkdirIn(root *os.Root, name string, perm os.FileMode) error {
	return root.Mkdir(name, perm.Perm())
}

// OpenDirIn opens the folder name inside root, to set its metadata
// through the handle, and refuses a link or anything else at name that is
// not a folder. O_DIRECTORY fails on anything else before opening it, so
// a FIFO swapped in cannot block the open. It checks name after the open,
// so a link swapped in for the folder, and back, is refused too.
func OpenDirIn(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err == nil {
		var info os.FileInfo
		if info, err = root.Lstat(name); err == nil && (!opened.IsDir() || !info.IsDir() || !os.SameFile(opened, info)) {
			err = &os.PathError{Op: "open", Path: name, Err: errors.New("not a folder, or it changed while it was opened")}
		}
	}
	if err != nil {
		_ = f.Close() // opened only to read its metadata
		return nil, err
	}
	return f, nil
}

// SetTimes sets the access and modification times of the open file f to
// mtime, through its descriptor.
func SetTimes(f *os.File, mtime time.Time) error {
	tv := unix.NsecToTimeval(mtime.UnixNano())
	return unix.Futimes(int(f.Fd()), []unix.Timeval{tv, tv}) // #nosec G115 -- a file descriptor fits in an int.
}
