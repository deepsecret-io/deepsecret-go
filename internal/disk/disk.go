// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package disk holds the file system checks the SDK relies on: free space,
// folders private to this user, and file locks.
package disk

import (
	"errors"
	"math"
)

// ErrLocked is a file whose lock another open file holds (Lock).
var ErrLocked = errors.New("locked by another process")

// blocksToBytes is blocks of size bytes each, capped at math.MaxInt64:
// some network and FUSE filesystems report more free space than an int64
// holds, which would otherwise wrap to a small or negative number and
// refuse a write that fits.
func blocksToBytes(blocks, size uint64) int64 {
	if size != 0 && blocks > math.MaxInt64/size {
		return math.MaxInt64
	}
	return int64(blocks * size) // #nosec G115 -- the check above keeps the product within int64.
}
