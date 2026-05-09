// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package archive

import (
	"fmt"
	"os"
)

// safeOpenForWrite opens target with O_CREATE|O_WRONLY plus either O_EXCL
// (default) or O_TRUNC (allowOverwrite) on Windows. Windows has no
// O_NOFOLLOW; reparse-point hardening would require GetFileAttributes-style
// inspection that we do not implement. Operators who need the strongest
// guarantees should run extraction on a Unix host.
func safeOpenForWrite(target string, mode os.FileMode, allowOverwrite bool) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY
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
