// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"os"
	"time"
)

// sysFileInfo is the per-file metadata we need beyond what os.FileInfo
// exposes portably: owner uid/gid for tar headers, and (dev, ino) for hard
// link detection. Fields are -1 / 0 when unavailable on the host platform
// (e.g. Windows). Always populated through sysStat so call sites stay
// portable.
type sysFileInfo struct {
	UID   int    // -1 if unavailable
	GID   int    // -1 if unavailable
	Dev   uint64 // 0 if unavailable
	Ino   uint64 // 0 if unavailable
	Nlink uint64 // 1 if unavailable
}

// hardLinkKey returns the (Dev, Ino) pair that identifies a file, for map
// lookup. ok is false without inode info (Windows, or hard links not
// applicable); callers should not dedupe in that case. The pair is kept
// whole: a combined number could make two different files collide, and the
// second would be archived as a link to the first.
func (s sysFileInfo) hardLinkKey() (key [2]uint64, ok bool) {
	if s.Ino == 0 {
		return key, false
	}
	return [2]uint64{s.Dev, s.Ino}, true
}

// Platform-specific functions: see sysattrs_unix.go and sysattrs_windows.go.
//
//   sysStat(info)           : pull uid/gid/dev/ino/nlink out of os.FileInfo.Sys()
//   readXattrs(path)        : list+get xattrs on the leaf file (Llistxattr)
//   writeXattr(path, k, v)  : Lsetxattr-style write (does not follow symlinks)
//   lchtimes(path, mtime)   : set mtime without following symlinks
//   lchown(path, uid, gid)  : chown without following symlinks (best-effort)
//
// Windows builds compile to no-ops where the concept doesn't exist.

var (
	_ = readXattrs
	_ = writeXattr
	_ = lchtimes
	_ = lchown
	_ = sysStat
	_ time.Time
	_ os.FileInfo
)
