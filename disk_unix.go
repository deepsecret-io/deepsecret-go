// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package sdk

import "golang.org/x/sys/unix"

// freeDiskBytes reports the bytes an unprivileged user can still write in
// the filesystem holding dir.
func freeDiskBytes(dir string) (int64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}
