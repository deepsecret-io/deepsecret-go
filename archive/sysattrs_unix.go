// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func sysStat(info os.FileInfo) sysFileInfo {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return sysFileInfo{Uid: -1, Gid: -1, Nlink: 1}
	}
	return sysFileInfo{
		Uid:   int(s.Uid),
		Gid:   int(s.Gid),
		Dev:   uint64(s.Dev), // #nosec G115 -- int32 on macOS: an identity compared only for equality, so the bit pattern matters, not the value.
		Ino:   uint64(s.Ino),
		Nlink: uint64(s.Nlink),
	}
}

// readXattrs reads every extended attribute on path without following
// symlinks. Returns a map of name -> raw bytes (as string) suitable for
// embedding in PAX SCHILY.xattr.<name> records.
//
// Errors during enumeration return what we have so far; per-attribute read
// errors are skipped silently. xattrs are best-effort metadata, not
// critical to round-trip the file's content.
func readXattrs(path string) (map[string]string, error) {
	sz, err := unix.Llistxattr(path, nil)
	if err != nil || sz == 0 {
		// ENOTSUP / ENOSYS / empty all map to "no xattrs"
		return nil, nil
	}
	buf := make([]byte, sz)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return nil, nil
	}
	out := map[string]string{}
	for _, name := range parseNullList(buf[:n]) {
		// Probe size, then read.
		vsz, err := unix.Lgetxattr(path, name, nil)
		if err != nil || vsz < 0 {
			continue
		}
		val := make([]byte, vsz)
		n, err := unix.Lgetxattr(path, name, val)
		if err != nil {
			continue
		}
		out[name] = string(val[:n])
	}
	return out, nil
}

// writeXattr applies a single xattr to path without following symlinks.
// Errors are returned to the caller, which decides whether to log or fail.
// In practice xattr writes can fail because:
//   - destination FS doesn't support them (ENOTSUP)
//   - cross-platform names (com.apple.* on Linux) are rejected
//   - missing capabilities (security.* needs CAP_SYS_ADMIN)
//
// Callers should treat per-xattr errors as warnings, not fatal.
func writeXattr(path, name, value string) error {
	return unix.Lsetxattr(path, name, []byte(value), 0)
}

// lchtimes sets mtime (and atime to the same value) on a path without
// following symlinks. macOS, Linux, *BSD all support AT_SYMLINK_NOFOLLOW
// on utimensat/UtimesNanoAt.
func lchtimes(path string, mtime time.Time) error {
	ts := []unix.Timespec{
		unix.NsecToTimespec(mtime.UnixNano()),
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	return unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// lchown chowns a path without following symlinks. Best-effort: most
// non-root callers can only chown to their own uid/gid, and cross-machine
// uid/gid mappings rarely line up. Caller treats failures as soft.
func lchown(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

// parseNullList splits a NUL-terminated buffer (the format Llistxattr
// returns) into its constituent strings.
func parseNullList(buf []byte) []string {
	var out []string
	start := 0
	for i, b := range buf {
		if b == 0 {
			if i > start {
				out = append(out, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(buf) {
		// rare — listxattr always NUL-terminates, but be defensive
		if name := strings.TrimRight(string(buf[start:]), "\x00"); name != "" {
			out = append(out, name)
		}
	}
	return out
}
