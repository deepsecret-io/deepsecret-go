// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"fmt"
	"os"
	"syscall"
)

// safeOpenForWrite opens target with O_CREATE|O_WRONLY|O_NOFOLLOW plus
// either O_EXCL (default) or O_TRUNC (allowOverwrite). O_NOFOLLOW makes the
// kernel reject the open if the leaf component is a symlink — closing the
// symlink-swap race window that ensureInsideDir's pre-flight TOCTOU check
// otherwise leaves open. Intermediate path components are still resolved
// through symlinks; deeper hardening would require openat-style traversal
// which Go does not expose portably.
func safeOpenForWrite(target string, mode os.FileMode, allowOverwrite bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | syscall.O_NOFOLLOW
	if allowOverwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(target, flags, mode)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("destination already exists: %s", target)
		}
		return nil, fmt.Errorf("open %s: %w", target, err)
	}
	return f, nil
}
