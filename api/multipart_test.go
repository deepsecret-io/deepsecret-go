// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// readFull refuses a short read, even one that ends at EOF.
func TestReadFull(t *testing.T) {
	src := bytes.NewReader([]byte("abcdef"))
	buf := make([]byte, 4)
	if err := readFull(src, buf, 2); err != nil || string(buf) != "cdef" {
		t.Fatalf("full read: %q, %v", buf, err)
	}
	if err := readFull(src, buf, 4); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read: %v", err)
	}
}
