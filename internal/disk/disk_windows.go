// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disk

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// FreeBytes reports the bytes the caller can still write in the volume
// holding dir.
func FreeBytes(dir string) (int64, bool) {
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

// CheckPrivateDir refuses dir unless it is a real directory, not a
// symlink or junction, that only this user, SYSTEM and Administrators own
// and may open (see private_windows.go), so no other user can read,
// replace or redirect what is kept in it. It reads the folder through one
// handle that does not follow a link.
func CheckPrivateDir(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }() // read only.
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &os.PathError{Op: "stat", Path: dir, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return checkPrivate(h, dir, true)
}

// Lock takes an exclusive lock on f without waiting, and returns
// ErrLocked when another open file holds it. Closing f releases it, and so
// does the process ending. It locks one byte far past the end of any
// payload, so the lock never stands in the way of reading or writing the
// payload itself.
func Lock(f *os.File) error {
	at := &windows.Overlapped{Offset: 0xFFFFFFFF, OffsetHigh: 0x7FFFFFFF}
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, at)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}
