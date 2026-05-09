// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

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
}

// DefaultLimits returns conservative default limits suitable for SDK use.
//
//   - MaxEntries:   10,000 files
//   - MaxEntrySize: 512 MB per file
//   - MaxTotalSize: 2 GB total
func DefaultLimits() *Limits {
	return &Limits{
		MaxEntries:   10_000,
		MaxEntrySize: 512 * 1024 * 1024,      // 512 MB
		MaxTotalSize: 2 * 1024 * 1024 * 1024, // 2 GB
	}
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
	return &out
}
