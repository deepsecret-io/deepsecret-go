// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disk

// os.Root creates files and folders with the ACL they inherit from the
// folder above, not the private one this package gives what it creates
// (private_windows.go). So CreateIn and MkdirIn open the folder above the
// name through the root, which resolves every folder on the way inside it
// in the kernel, and create the name's last part relative to that
// folder's handle with NtCreateFile and the private security descriptor,
// without following a link there. Only a last part that Windows keeps as
// it is written reaches NtCreateFile, so it names the same file os.Root
// would.
//
// The CLI (github.com/deepsecret-io/cli) has no copy of this file: it
// writes decrypted files only through the SDK.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateIn creates the file name inside root, which must not exist, for
// writing, private to this user whatever mode says; a mode without the
// owner's write bit makes it read-only, as os.OpenFile does.
func CreateIn(root *os.Root, name string, mode os.FileMode) (*os.File, error) {
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if mode&0o200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY
	}
	h, err := createIn(root, name, false, windows.FILE_GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES, attrs,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), filepath.Join(root.Name(), name)), nil
}

// MkdirIn creates the folder name inside root, private to this user
// whatever the permission bits say.
func MkdirIn(root *os.Root, name string, _ os.FileMode) error {
	h, err := createIn(root, name, true, windows.FILE_LIST_DIRECTORY, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	return windows.CloseHandle(h)
}

// OpenDirIn opens the folder name inside root, to set its times through
// the handle, and refuses a link or anything else at name that is not a
// folder: the open itself does not follow a link at name, and does not
// open a file.
func OpenDirIn(root *os.Root, name string) (*os.File, error) {
	parent, leaf, err := openParent(root, name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	defer func() { _ = parent.Close() }() // only read; open until the call below returns
	h, err := ntCreate(parent, leaf, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h) // opened only to set its times
		if err == nil {
			err = errors.New("a link, not a folder")
		}
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), filepath.Join(root.Name(), name)), nil
}

// SetTimes sets the access and modification times of the open file f to
// mtime, through its handle.
func SetTimes(f *os.File, mtime time.Time) error {
	ft := windows.NsecToFiletime(mtime.UnixNano())
	return windows.SetFileTime(windows.Handle(f.Fd()), nil, &ft, &ft)
}

// createIn creates name inside root, which must not exist, private to
// this user (privateAttrs), and returns its handle.
func createIn(root *os.Root, name string, folder bool, access, attrs, share, options uint32) (windows.Handle, error) {
	sa, err := privateAttrs(folder)
	if err != nil {
		return 0, err
	}
	parent, leaf, err := openParent(root, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = parent.Close() }() // only read; open until the call below returns
	return ntCreate(parent, leaf, access, sa.SecurityDescriptor, attrs, share, windows.FILE_CREATE, options|windows.FILE_OPEN_REPARSE_POINT)
}

// openParent opens, through root, the folder that holds name, and returns
// it with name's last part. It refuses a last part Windows would not keep
// as written (keptAsWritten).
func openParent(root *os.Root, name string) (*os.File, string, error) {
	dir, leaf := filepath.Split(name)
	if !keptAsWritten(leaf) {
		return nil, "", windows.ERROR_INVALID_NAME
	}
	dir = strings.TrimRight(dir, `\/`)
	if dir == "" {
		dir = "."
	}
	parent, err := root.Open(dir)
	if err != nil {
		return nil, "", err
	}
	return parent, leaf, nil
}

// keptAsWritten reports whether leaf, one part of a name, is one Windows
// keeps as it is written, the way os.Root reads it: not empty, "." or
// "..", no separator, no colon (which names a stream of another file), no
// device name such as NUL (filepath.IsLocal asks this Windows, so NUL.txt
// is refused before Windows 11 and is a plain file name since), and no
// trailing dot or space, which the Win32 layer strips.
func keptAsWritten(leaf string) bool {
	return leaf != "" && leaf != "." && leaf != ".." && filepath.IsLocal(leaf) &&
		!strings.ContainsAny(leaf, `/\:`) && !strings.HasSuffix(leaf, ".") && !strings.HasSuffix(leaf, " ")
}

// ntCreate opens or creates leaf relative to the folder parent with
// NtCreateFile, comparing names without case as Windows does, and with sd
// as the security of what it creates.
func ntCreate(parent *os.File, leaf string, access uint32, sd *windows.SECURITY_DESCRIPTOR, attrs, share, disposition, options uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return 0, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory:      windows.Handle(parent.Fd()),
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: sd,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	var h windows.Handle
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, oa, &windows.IO_STATUS_BLOCK{}, nil, attrs, share,
		disposition, options|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if status, ok := errors.AsType[windows.NTStatus](err); ok {
		// As a Win32 error, so errors.Is(err, os.ErrExist) and
		// os.ErrNotExist work.
		return 0, status.Errno()
	}
	if err != nil {
		return 0, err
	}
	return h, nil
}
