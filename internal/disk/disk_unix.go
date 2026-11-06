// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disk

import (
	"errors"
	"fmt"
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
