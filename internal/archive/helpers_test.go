// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"fmt"
	"io"
	"os"
	"testing"
)

// writeOrFatal writes a file or fails the test.
func writeOrFatal(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

// mkdirOrFatal creates a directory or fails the test.
func mkdirOrFatal(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

// failWriter fails after writing n bytes.
type failWriter struct {
	n       int
	written int
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.n {
		allowed := w.n - w.written
		if allowed > 0 {
			w.written += allowed
			return allowed, fmt.Errorf("injected write failure at byte %d", w.written)
		}
		return 0, fmt.Errorf("injected write failure at byte %d", w.written)
	}
	w.written += len(p)
	return len(p), nil
}

// repeatingReader produces an infinite stream of a single byte.
type repeatingReader struct{ b byte }

func (r *repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// ensure imports are used
var (
	_           = fmt.Sprintf
	_ io.Reader = (*repeatingReader)(nil)
)
