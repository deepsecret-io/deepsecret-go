// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package archive

import (
	"os"
	"time"
)

// Windows doesn't expose Unix-style uid/gid/inode through os.FileInfo.Sys
// in any portable way. Hard-link detection via stat is also unreliable
// (NTFS hard links exist but are rarely used in dev workflows). The
// archive format still carries owner/uid/gid fields; on Windows we just
// don't populate them and don't try to restore them.
func sysStat(info os.FileInfo) sysFileInfo {
	return sysFileInfo{Uid: -1, Gid: -1, Nlink: 1}
}

// Windows has NTFS Alternate Data Streams (rough analogue of xattrs) but
// they're rarely used and have a very different API. We treat archives
// produced on Windows as having no xattrs, and skip applying xattrs from
// archives produced on other platforms when extracting on Windows.
func readXattrs(path string) (map[string]string, error) { return nil, nil }
func writeXattr(path, name, value string) error         { return nil }

// Windows doesn't have a portable lchtimes equivalent. Symlinks created
// by os.Symlink inherit the current time; we accept that fidelity gap on
// Windows in exchange for a portable codebase.
func lchtimes(path string, mtime time.Time) error { return nil }

// Windows ignores Unix uid/gid; chown is a no-op.
func lchown(path string, uid, gid int) error { return nil }
