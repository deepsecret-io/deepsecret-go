// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package compress

// Limits controls resource bounds for decompression operations.
// A nil Limits pointer uses [DefaultLimits].
type Limits struct {
	// MaxOutputSize is the maximum decompressed output size in bytes.
	// Zero means use default.
	MaxOutputSize int64
}

// DefaultLimits returns the default limits used when no explicit Limits
// is passed. Sized to match the maximum encrypted payload the SDK is
// expected to handle (Organization tier upload cap of 50 GiB plus
// compression-overhead headroom).
//
//   - MaxOutputSize: 100 GiB
func DefaultLimits() *Limits {
	return &Limits{
		MaxOutputSize: 100 * 1024 * 1024 * 1024,
	}
}

// resolve returns the effective limits, filling zero values with defaults.
func (l *Limits) resolve() *Limits {
	d := DefaultLimits()
	if l == nil {
		return d
	}
	out := *l
	if out.MaxOutputSize <= 0 {
		out.MaxOutputSize = d.MaxOutputSize
	}
	return &out
}
