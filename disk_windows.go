// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package sdk

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// freeDiskBytes reports the bytes the caller can still write in the volume
// holding dir.
func freeDiskBytes(dir string) (int64, bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, nil, nil); err != nil {
		return 0, false
	}
	return int64(free), true
}

// checkPrivateDir refuses dir unless it is a real directory, not a
// symlink or junction. Access is left to the folder's ACL.
func checkPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}
