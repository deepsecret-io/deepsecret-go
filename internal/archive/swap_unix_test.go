// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
)

// These tests play another local account that may rename inside the output
// directory, or inside the folder above it, and swaps a folder for a
// symlink while a write is under way, after every check on it has passed.
// No write may leave the output directory through that link.

// swapForLink moves the folder dir aside, to dir+".moved", and puts a
// symlink to target in its place.
func swapForLink(t *testing.T, dir, target string) {
	t.Helper()
	if err := os.Rename(dir, dir+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
}

// swapReader reads r, and before the first read after ready reports true
// it calls swap, once. Extraction reads an entry's data after creating its
// file, so a swap there comes after every check on the entry.
type swapReader struct {
	r       io.Reader
	ready   func() bool
	swap    func()
	swapped bool
}

func (s *swapReader) Read(p []byte) (int, error) {
	if !s.swapped && s.ready() {
		s.swapped = true
		s.swap()
	}
	// Small reads, so the swap lands while the entry's data is still
	// being written.
	return s.r.Read(p[:min(len(p), 4096)])
}

// exists reports whether something is at path.
func exists(path string) func() bool {
	return func() bool {
		_, err := os.Lstat(path)
		return err == nil
	}
}

// victim makes <base>/outside/f, the file another account wants the write
// to reach, and returns base, the output directory <base>/out and the
// victim's path.
func victim(t *testing.T) (base, out, f string) {
	t.Helper()
	base = t.TempDir()
	out = filepath.Join(base, "out")
	f = filepath.Join(base, "outside", "f")
	mkdirOrFatal(t, out)
	mkdirOrFatal(t, filepath.Dir(f))
	writeOrFatal(t, f, []byte("victim"))
	old := time.Date(2024, 2, 2, 2, 2, 2, 0, time.UTC)
	if err := os.Chtimes(f, old, old); err != nil {
		t.Fatal(err)
	}
	return base, out, f
}

// assertUntouched fails unless the victim at path still holds "victim"
// with its old mtime, and nothing else appeared beside it.
func assertUntouched(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("the file outside the output directory is gone: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "victim" {
		t.Errorf("the file outside holds %q, want victim", got)
	}
	if want := time.Date(2024, 2, 2, 2, 2, 2, 0, time.UTC); !info.ModTime().Equal(want) {
		t.Errorf("the mtime of the file outside changed to %v", info.ModTime())
	}
	if got := tree(t, filepath.Dir(path)); strings.Join(got, ",") != filepath.Base(path) {
		t.Errorf("the folder outside holds %v, want %s alone", got, filepath.Base(path))
	}
}

// A subfolder of the output directory swapped for a link while its file is
// written: restoring the file's mtime, and removing it when extraction
// then fails, act on the file extraction created, never on one the link
// leads to.
func TestExtractTarSubfolderSwappedForLink(t *testing.T) {
	_, out, f := victim(t)
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "sub/", mode: 0o700},
		tarTestEntry{typ: tar.TypeReg, name: "sub/f", mode: 0o600, data: bytes.Repeat([]byte("x"), 1<<20),
			mtime: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)},
		// Refused: extraction fails after sub/f, and removes what it made.
		tarTestEntry{typ: tar.TypeFifo, name: "fifo"},
	)
	r := &swapReader{r: bytes.NewReader(data), ready: exists(filepath.Join(out, "sub", "f")),
		swap: func() { swapForLink(t, filepath.Join(out, "sub"), "../outside") }}
	if _, err := ExtractTarReader(r, out, compress.None, nil); err == nil {
		t.Fatal("extraction of a FIFO succeeded")
	}
	if !r.swapped {
		t.Fatal("the subfolder was never swapped")
	}
	assertUntouched(t, f)
}

// With overwrite, the new file is renamed over the old one. A subfolder
// swapped for a link while the new file is written must not let the rename
// replace a file the link leads to with one another account put there.
func TestWriteFileOverwriteSubfolderSwappedForLink(t *testing.T) {
	base, out, f := victim(t)
	sub := filepath.Join(out, "sub")
	mkdirOrFatal(t, sub)
	writeOrFatal(t, filepath.Join(sub, "f"), []byte("old"))
	r := &swapReader{r: strings.NewReader("new"), ready: func() bool { return true }, swap: func() {
		temps, err := filepath.Glob(filepath.Join(sub, ".deepsecret-*.partial"))
		if err != nil || len(temps) != 1 {
			t.Fatalf("temporary file: %v, %v", temps, err)
		}
		swapForLink(t, sub, "../outside")
		// The new file's temporary name, in the folder the link leads to.
		writeOrFatal(t, filepath.Join(base, "outside", filepath.Base(temps[0])), []byte("planted"))
	}}
	_, _, _ = writeOne(out, "sub/f", 0o600, r, 100, true)
	if !r.swapped {
		t.Fatal("the subfolder was never swapped")
	}
	if got, _ := os.ReadFile(f); string(got) != "victim" {
		t.Errorf("the file outside was replaced: it holds %q", got)
	}
}

// The output directory itself swapped for a link while a file is
// extracted: a hard link entry after it is still made inside the output
// directory, never beside a file the link leads to.
func TestExtractTarHardLinkAfterOutputDirSwapped(t *testing.T) {
	base, out, f := victim(t)
	outside := filepath.Dir(f)
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeReg, name: "f", mode: 0o600, data: bytes.Repeat([]byte("x"), 1<<20)},
		tarTestEntry{typ: tar.TypeLink, name: "l", link: "f"},
		tarTestEntry{typ: tar.TypeReg, name: "g", mode: 0o600, data: []byte("g")},
	)
	r := &swapReader{r: bytes.NewReader(data), ready: exists(filepath.Join(out, "f")),
		swap: func() { swapForLink(t, out, outside) }}
	_, _ = ExtractTarReader(r, out, compress.None, nil)
	if !r.swapped {
		t.Fatal("the output directory was never swapped")
	}
	assertUntouched(t, f)
	if got := tree(t, filepath.Join(base, "out.moved")); strings.Join(got, ",") != "f,g,l" {
		t.Errorf("the output directory holds %v, want f, g and l", got)
	}
}
