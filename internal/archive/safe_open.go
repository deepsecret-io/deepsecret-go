// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"fmt"
	"os"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
)

// safeCreate creates target, which must not exist, for writing
// (disk.CreateNew): it never opens a file that is already there, and it
// refuses a link at target (O_NOFOLLOW on Unix, an open that does not
// follow reparse points on Windows), which closes the link-swap race that
// ensureInsideDir's earlier check leaves open. Folders above target are
// still followed. On Unix the file gets mode with the umask applied; on
// Windows it is private to this user.
func safeCreate(target string, mode os.FileMode) (*os.File, error) {
	f, err := disk.CreateNew(target, mode)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("destination already exists: %s", target)
		}
		return nil, fmt.Errorf("open %s: %w", target, err)
	}
	return f, nil
}
