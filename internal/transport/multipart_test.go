// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"testing"
)

// partMD5 hashes exactly the part, and refuses a source that ends early.
func TestPartMD5(t *testing.T) {
	src := bytes.NewReader([]byte("abcdef"))
	want := md5.Sum([]byte("cdef"))
	if sum, err := partMD5(src, uploadPart{Number: 1, Offset: 2, Size: 4}); err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("full part: %x, %v", sum, err)
	}
	if _, err := partMD5(src, uploadPart{Number: 2, Offset: 4, Size: 4}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short part: %v", err)
	}
}
