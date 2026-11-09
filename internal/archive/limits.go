// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import "os"

// Limits controls resource bounds for extraction and decompression operations.
// All fields are enforced during extraction. A nil Limits pointer uses
// DefaultLimits().
type Limits struct {
	// MaxEntries is the maximum number of entries (files) in an archive.
	// Zero means use default.
	MaxEntries int

	// MaxEntrySize is the maximum uncompressed size of a single entry in bytes.
	// Zero means use default.
	MaxEntrySize int64

	// MaxTotalSize is the maximum total uncompressed size across all entries.
	// Zero means use default.
	MaxTotalSize int64

	// AllowOverwrite permits extraction to replace existing files. Default
	// (false) rejects writes to a destination that already exists; symlink
	// hardening (O_NOFOLLOW on Unix) is always enforced regardless of this
	// flag. Set true when the caller intentionally wants to clobber.
	AllowOverwrite bool

	// MaxNameLen bounds one entry's path, and MaxNameBytes all entries'
	// paths together. Zero means 4096 bytes and 64 MiB.
	MaxNameLen   int
	MaxNameBytes int64

	// KeepSpecialModes keeps setuid, setgid and sticky bits. By default
	// they are dropped, so an archive cannot plant a setuid file. The
	// permission bits are private either way (privatePerm).
	KeepSpecialModes bool

	// KeepOwnership restores each entry's owner and group from the
	// archive, which takes effect when extracting as root. By default
	// entries belong to whoever extracts them.
	KeepOwnership bool
}

// DefaultLimits returns conservative default limits suitable for SDK use.
//
//   - MaxEntries:   10,000 files
//   - MaxEntrySize: 512 MB per file
//   - MaxTotalSize: 2 GB total
//   - MaxNameLen:   4096 bytes per path
//   - MaxNameBytes: 64 MiB of paths in all
func DefaultLimits() *Limits {
	return &Limits{
		MaxEntries:   10_000,
		MaxEntrySize: 512 * 1024 * 1024,      // 512 MB
		MaxTotalSize: 2 * 1024 * 1024 * 1024, // 2 GB
		MaxNameLen:   4096,
		MaxNameBytes: 64 << 20,
	}
}

// privatePerm is the permission extraction gives what it creates, whatever
// the archive or payload asks for: 0700 for a directory, and for a file
// 0600, or 0700 when perm has the owner's execute bit. The sender does not
// choose who else may read, change or list a decrypted secret, and cannot
// lock its owner out of it either. The umask still applies on top, as
// open(2) and mkdir(2) apply it.
func privatePerm(perm os.FileMode, dir bool) os.FileMode {
	if dir || perm&0o100 != 0 {
		return 0o700
	}
	return 0o600
}

// entryMode is an archive entry's mode as extraction applies it: the
// private permission bits (privatePerm), plus the entry's setuid, setgid
// and sticky bits with KeepSpecialModes.
func (l *Limits) entryMode(hdrMode int64, dir bool) os.FileMode {
	mode := unixModeToGo(hdrMode & modeBits)
	perm := privatePerm(mode.Perm(), dir)
	if l.KeepSpecialModes {
		return perm | mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
	}
	return perm
}

// resolve returns the effective limits, filling zero values with defaults.
func (l *Limits) resolve() *Limits {
	d := DefaultLimits()
	if l == nil {
		return d
	}
	out := *l
	if out.MaxEntries <= 0 {
		out.MaxEntries = d.MaxEntries
	}
	if out.MaxEntrySize <= 0 {
		out.MaxEntrySize = d.MaxEntrySize
	}
	if out.MaxTotalSize <= 0 {
		out.MaxTotalSize = d.MaxTotalSize
	}
	if out.MaxNameLen <= 0 {
		out.MaxNameLen = d.MaxNameLen
	}
	if out.MaxNameBytes <= 0 {
		out.MaxNameBytes = d.MaxNameBytes
	}
	return &out
}
