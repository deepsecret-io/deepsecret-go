// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package archive

import (
	"fmt"
	"os"
)

// safeCreate creates target with O_CREATE|O_EXCL|O_WRONLY on Windows, so it
// never opens a file that is already there. Windows has no O_NOFOLLOW;
// reparse-point hardening would require GetFileAttributes-style inspection
// that we do not implement. Operators who need the strongest guarantees
// should run extraction on a Unix host.
func safeCreate(target string, mode os.FileMode) (*os.File, error) {
	// #nosec G304 -- callers check target is inside the output directory (ensureInsideDir); see above for reparse points.
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("destination already exists: %s", target)
		}
		return nil, fmt.Errorf("open %s: %w", target, err)
	}
	return f, nil
}
