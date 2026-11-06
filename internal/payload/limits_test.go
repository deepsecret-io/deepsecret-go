// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package payload

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// The total size check holds when the limits are as large as an int64
// gets, instead of wrapping around and letting a file through.
func TestDecodeFilesTotalSizeDoesNotOverflow(t *testing.T) {
	var buf bytes.Buffer
	e := &streamEncoder{w: bufio.NewWriter(&buf)}
	sum := sha256.Sum256([]byte("hello"))
	e.head(majorMap, 2)
	e.text("type")
	e.text("files")
	e.text("files")
	e.head(majorArray, 2)
	e.head(majorMap, 5)
	e.text("data")
	e.head(majorBytes, 5)
	e.raw([]byte("hello"))
	e.text("mode")
	e.head(majorUint, 0o600)
	e.text("name")
	e.text("a.txt")
	e.text("size")
	e.head(majorUint, 5)
	e.text("sha256")
	e.text(hex.EncodeToString(sum[:]))
	// The second file declares math.MaxInt64-2 bytes; its data never follows.
	e.head(majorMap, 5)
	e.text("data")
	e.head(majorBytes, math.MaxInt64-2)
	if e.err != nil {
		t.Fatal(e.err)
	}
	if err := e.w.Flush(); err != nil {
		t.Fatal(err)
	}

	lim := DecodeLimits{MaxFileSize: math.MaxInt64, MaxTotalSize: math.MaxInt64}
	if _, err := DecodeFiles(&buf, lim, nil); err == nil || !strings.Contains(err.Error(), "total size limit") {
		t.Errorf("decode: %v, want the total size limit", err)
	}
}
