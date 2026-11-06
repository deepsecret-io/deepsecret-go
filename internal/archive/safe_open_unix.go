// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"fmt"
	"os"
	"syscall"
)

// safeCreate creates target with O_CREATE|O_EXCL|O_WRONLY|O_NOFOLLOW, so it
// never opens a file that is already there. O_NOFOLLOW makes the kernel
// reject the open if the leaf component is a symlink, closing the
// symlink-swap race window that ensureInsideDir's pre-flight TOCTOU check
// otherwise leaves open. Intermediate path components are still resolved
// through symlinks; deeper hardening would require openat-style traversal
// which Go does not expose portably. The file gets mode with the umask
// applied.
func safeCreate(target string, mode os.FileMode) (*os.File, error) {
	// #nosec G304 -- callers check target is inside the output directory (ensureInsideDir), and O_NOFOLLOW refuses a symlink at its leaf.
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("destination already exists: %s", target)
		}
		return nil, fmt.Errorf("open %s: %w", target, err)
	}
	return f, nil
}
