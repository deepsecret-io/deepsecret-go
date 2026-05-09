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
	Uid   int    // -1 if unavailable
	Gid   int    // -1 if unavailable
	Dev   uint64 // 0 if unavailable
	Ino   uint64 // 0 if unavailable
	Nlink uint64 // 1 if unavailable
}

// hardLinkKey returns a stable identifier for a (Dev, Ino) pair, suitable
// for map lookup. Zero value means "no inode info" (Windows or hard links
// not applicable); callers should not dedupe in that case.
func (s sysFileInfo) hardLinkKey() (uint64, bool) {
	if s.Ino == 0 {
		return 0, false
	}
	// Combine dev + ino. They're independent monotonic counters per FS, so
	// xor with a shift gives a low-collision composite.
	return s.Dev<<32 ^ s.Ino, true
}

// Platform-specific functions — see sysattrs_unix.go and sysattrs_windows.go.
//
//   sysStat(info)            — pull uid/gid/dev/ino/nlink out of os.FileInfo.Sys()
//   readXattrs(path)         — list+get xattrs on the leaf file (Llistxattr)
//   writeXattr(path, k, v)   — Lsetxattr-style write (does not follow symlinks)
//   lchtimes(path, mtime)    — set mtime without following symlinks
//   lchown(path, uid, gid)   — chown without following symlinks (best-effort)
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
