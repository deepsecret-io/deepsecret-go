// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"math"
	"testing"
)

// Free space too large for an int64, which some network and FUSE
// filesystems report, is capped rather than wrapped to a small or negative
// number that would refuse a write that fits.
func TestBlocksToBytes(t *testing.T) {
	for _, c := range []struct {
		blocks, size uint64
		want         int64
	}{
		{10, 4096, 40960},
		{0, 4096, 0},
		{10, 0, 0},
		{1 << 62, 4096, math.MaxInt64},
		{math.MaxUint64, 1, math.MaxInt64},
		{math.MaxInt64, 1, math.MaxInt64},
	} {
		if got := blocksToBytes(c.blocks, c.size); got != c.want {
			t.Errorf("blocksToBytes(%d, %d) = %d, want %d", c.blocks, c.size, got, c.want)
		}
	}
}
