// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package sdk

import (
	"errors"
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
	return blocksToBytes(free, 1), true
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

// lockFile takes an exclusive lock on f without waiting, and returns
// errLocked when another open file holds it. Closing f releases it, and so
// does the process ending. It locks one byte far past the end of any
// payload, so the lock never stands in the way of reading or writing the
// payload itself.
func lockFile(f *os.File) error {
	at := &windows.Overlapped{Offset: 0xFFFFFFFF, OffsetHigh: 0x7FFFFFFF}
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, at)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return errLocked
	}
	return err
}
