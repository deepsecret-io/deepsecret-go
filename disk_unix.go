// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package sdk

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// freeDiskBytes reports the bytes an unprivileged user can still write in
// the filesystem holding dir.
func freeDiskBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}

// checkPrivateDir refuses dir unless it is a real directory, not a
// symlink, owned by this user and closed to everyone else, so no other
// user can read, replace or redirect what is kept in it.
func checkPrivateDir(dir string) error {
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
