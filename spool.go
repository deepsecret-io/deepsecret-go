// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// TempDirEnv names the environment variable that sets where sends and
// decrypts keep their temporary ciphertext file when the options set no
// TempDir.
const TempDirEnv = "DEEPSECRET_TMPDIR"

// spool holds one ciphertext: in a private temporary file, or in memory for
// payloads small enough to need no disk. Only ciphertext is ever written
// to it.
type spool struct {
	dir  string   // the private directory, "" in memory
	file *os.File // nil in memory
	buf  []byte
	size int64
}

// newSpool creates a private directory (0700) under base, or under
// $DEEPSECRET_TMPDIR or the system temp directory when base is empty, and
// a ciphertext file (0600) inside it. When need is positive and the
// filesystem reports its free space, it refuses up front if fewer than
// need bytes are free.
func newSpool(base string, need int64) (*spool, error) {
	if base == "" {
		base = os.Getenv(TempDirEnv)
	}
	if base == "" {
		base = os.TempDir()
	}
	if err := checkFreeSpace(base, need, "the encrypted payload", "set "+TempDirEnv+" or the TempDir option to use another directory"); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "deepsecret-")
	if err != nil {
		return nil, fmt.Errorf("create temporary directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("protect temporary directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "payload"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("create temporary file: %w", err)
	}
	return &spool{dir: dir, file: f}, nil
}

// newMemSpool holds a ciphertext in memory, preallocated to size bytes
// when it is known.
func newMemSpool(size int64) *spool {
	return &spool{buf: make([]byte, size), size: size}
}

// Write appends to the ciphertext.
func (s *spool) Write(p []byte) (int, error) {
	if s.file != nil {
		n, err := s.file.Write(p)
		s.size += int64(n)
		return n, err
	}
	s.buf = append(s.buf[:s.size], p...)
	s.size += int64(len(p))
	return len(p), nil
}

// WriteAt writes at an offset within the ciphertext's size.
func (s *spool) WriteAt(p []byte, off int64) (int, error) {
	if s.file != nil {
		return s.file.WriteAt(p, off)
	}
	if off < 0 || off+int64(len(p)) > int64(len(s.buf)) {
		return 0, fmt.Errorf("write past the end of the payload")
	}
	return copy(s.buf[off:], p), nil
}

// ReadAt reads from the ciphertext.
func (s *spool) ReadAt(p []byte, off int64) (int, error) {
	if s.file != nil {
		return s.file.ReadAt(p, off)
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := copy(p, s.buf[off:s.size])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// reader reads the first size bytes from the start, independently of any
// other reader.
func (s *spool) reader(size int64) *io.SectionReader {
	return io.NewSectionReader(s, 0, size)
}

// Close closes the file and removes the directory with it.
func (s *spool) Close() error {
	if s.file == nil {
		s.buf = nil
		return nil
	}
	s.file.Close()
	return os.RemoveAll(s.dir)
}

// spoolNeed is the free space a ciphertext of about plaintextSize bytes
// needs: its exact size plus 1% headroom.
func spoolNeed(plaintextSize int64) int64 {
	chunks := plaintextSize/(1<<20) + 1
	ciphertext := plaintextSize + chunks*16
	return ciphertext + ciphertext/100
}

// checkFreeSpace refuses when the filesystem holding dir, or its nearest
// existing parent, reports fewer than need bytes free; hint, when set, says
// what to do. It does nothing when need is not positive or the platform
// reports no free space.
func checkFreeSpace(dir string, need int64, what, hint string) error {
	if need <= 0 {
		return nil
	}
	probe := dir
	for {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return nil
		}
		probe = parent
	}
	if free, ok := freeDiskBytes(probe); ok && free < need {
		msg := fmt.Sprintf("not enough free space in %s for %s: %s needed, %s free", dir, what, humanBytes(need), humanBytes(free))
		if hint != "" {
			msg += " (" + hint + ")"
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// ctxReader stops reading once ctx is done, so a cancel stops a long
// encrypt or decrypt.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
