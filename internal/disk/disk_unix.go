// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disk

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// FreeBytes reports the bytes an unprivileged user can still write in
// the filesystem holding dir.
func FreeBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil || st.Bsize <= 0 {
		return 0, false
	}
	return blocksToBytes(st.Bavail, uint64(st.Bsize)), true // #nosec G115 -- Bsize is positive here (int64 on Linux, uint32 on macOS).
}

// CreateNew creates path, which must not exist, for writing, with mode
// (the umask applies). O_NOFOLLOW makes the kernel refuse a symlink at
// path; folders above path are still followed.
func CreateNew(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode) // #nosec G304 -- callers pass a path they checked; O_NOFOLLOW refuses a link at its leaf.
}

// CreateTemp creates a new file in dir for writing, private to this user
// (0600): it is os.CreateTemp.
func CreateTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

// Mkdir creates the folder path with perm (the umask applies).
func Mkdir(path string, perm os.FileMode) error {
	return os.Mkdir(path, perm)
}

// MkdirPrivate creates dir and any missing parents, each private to this
// user (0700), as os.MkdirAll does: folders already there keep their mode.
func MkdirPrivate(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

// ReadPrivate reads the file path, and refuses one that another user owns
// or that anyone but its owner may open, as the Windows build does: a key
// or a credential in it is no longer private, and someone else may have
// put it there. The check and the read use one descriptor, so the file
// cannot be swapped in between.
func ReadPrivate(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass the path of a file they keep.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read only.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%s belongs to another user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (run: chmod 600 %s)", path, path)
	}
	return io.ReadAll(f)
}

// CheckPrivateDir refuses dir unless it is a real directory, not a
// symlink, owned by this user and closed to everyone else, so no other
// user can read, replace or redirect what is kept in it.
func CheckPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s belongs to another user", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to other users (run: chmod 700 %s)", dir, dir)
	}
	return nil
}

// Lock takes an exclusive lock on f without waiting, and returns
// ErrLocked when another open file holds it. Closing f releases it, and so
// does the process ending.
func Lock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) // #nosec G115 -- a file descriptor fits in an int.
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}
