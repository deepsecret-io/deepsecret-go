// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
)

func sampleTree(t *testing.T) []ExpandedFile {
	t.Helper()
	root := t.TempDir()
	mkdirOrFatal(t, filepath.Join(root, "src", "nested"))
	writeOrFatal(t, filepath.Join(root, "src", "a.txt"), []byte("hello"))
	writeOrFatal(t, filepath.Join(root, "src", "nested", "b.bin"), bytes.Repeat([]byte{7}, 70000))
	writeOrFatal(t, filepath.Join(root, "src", "empty"), nil)
	if err := os.Symlink("a.txt", filepath.Join(root, "src", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "src", "a.txt"), filepath.Join(root, "src", "hard")); err != nil {
		t.Fatal(err)
	}
	files, err := ExpandPaths([]string{filepath.Join(root, "src")}, false)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// A Tar's Size is the exact length Write writes, known before any file is
// read, so the payload can declare it first.
func TestTarSizeMatchesWrite(t *testing.T) {
	tarball, err := NewTar(sampleTree(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tarball.Write(&buf, compress.None); err != nil {
		t.Fatal(err)
	}
	if tarball.Size != int64(buf.Len()) {
		t.Fatalf("Size %d, Write wrote %d", tarball.Size, buf.Len())
	}
}

// ValidateTarReader accepts what WriteTar writes and lists its entries.
func TestValidateTarReaderAcceptsWriteTar(t *testing.T) {
	files := sampleTree(t)
	for _, algo := range []compress.Algorithm{compress.None, compress.Zstd} {
		var buf bytes.Buffer
		if err := WriteTar(&buf, files, algo); err != nil {
			t.Fatal(err)
		}
		names, total, err := ValidateTarReader(&buf, algo, nil)
		if err != nil {
			t.Fatalf("%q: %v", algo, err)
		}
		// Every entry but the two directories creates a file or a link.
		// Without inode numbers, Windows archives the hard link as a copy
		// of a.txt.
		want := int64(5 + 70000)
		if runtime.GOOS == "windows" {
			want += 5
		}
		if len(names) != len(files)-2 || total != want {
			t.Fatalf("%q: %d names for %d entries, %d bytes: %v", algo, len(names), len(files), total, names)
		}
	}
}

func rawTar(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			tw.Write(bytes.Repeat([]byte{'x'}, int(h.Size)))
		}
	}
	tw.Close()
	return buf.Bytes()
}

// ValidateTarReader refuses what extraction would refuse, before anything
// is written.
func TestValidateTarReaderRefusesHostileArchives(t *testing.T) {
	reg := func(name string, size int64) *tar.Header {
		return &tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o644}
	}
	cases := map[string]struct {
		data []byte
		lim  *Limits
		want string
	}{
		"parent escape":  {rawTar(t, reg("../evil", 1)), nil, "'..' segment"},
		"absolute path":  {rawTar(t, reg("/etc/passwd", 1)), nil, "empty segment"},
		"duplicate":      {rawTar(t, reg("a", 1), reg("a", 1)), nil, "duplicate"},
		"device":         {rawTar(t, &tar.Header{Typeflag: tar.TypeChar, Name: "dev"}), nil, "unsupported tar entry type"},
		"dangling link":  {rawTar(t, &tar.Header{Typeflag: tar.TypeLink, Name: "l", Linkname: "missing"}), nil, "not an earlier file"},
		"entry too big":  {rawTar(t, reg("a", 10)), &Limits{MaxEntrySize: 5}, "exceeding limit 5"},
		"total too big":  {rawTar(t, reg("a", 4), reg("b", 4)), &Limits{MaxTotalSize: 6}, "total size limit 6"},
		"too many":       {rawTar(t, reg("a", 1), reg("b", 1)), &Limits{MaxEntries: 1}, "maximum entry count"},
		"empty symlink":  {rawTar(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "s"}), nil, "symlink target is empty"},
		"not a tar file": {bytes.Repeat([]byte{0xff}, 1024), nil, "tar read"},
		"under a symlink": {rawTar(t, reg("first", 1), &tar.Header{Typeflag: tar.TypeSymlink, Name: "s", Linkname: "/outside"}, reg("s/x", 1)), nil,
			"which is not a directory"},
		"under a file": {rawTar(t, reg("f", 1), reg("f/x", 1)), nil, "which is not a directory"},
		"long name":    {rawTar(t, reg(strings.Repeat("n", 300), 1)), &Limits{MaxNameLen: 255}, "the limit is 255"},
		"names in all": {rawTar(t, reg("aaaa", 1), reg("bbbb", 1)), &Limits{MaxNameBytes: 6}, "6 bytes in all"},
	}
	for name, c := range cases {
		if _, _, err := ValidateTarReader(bytes.NewReader(c.data), compress.None, c.lim); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// WriteFile writes inside the output directory only, and replaces nothing
// unless told to.
func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path, n, err := WriteFile(dir, "sub/a.txt", 0o640, strings.NewReader("hello"), 100, false, nil)
	if err != nil || n != 5 || path != filepath.Join(dir, "sub", "a.txt") {
		t.Fatalf("write: %s %d %v", path, n, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "hello" {
		t.Fatalf("content %q", got)
	}
	if _, _, err := WriteFile(dir, "sub/a.txt", 0o640, strings.NewReader("x"), 100, false, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite without permission: %v", err)
	}
	if _, _, err := WriteFile(dir, "sub/a.txt", 0o640, strings.NewReader("x"), 100, true, nil); err != nil {
		t.Fatalf("overwrite with permission: %v", err)
	}
	if _, _, err := WriteFile(dir, "../escape", 0o640, strings.NewReader("x"), 100, false, nil); err == nil {
		t.Fatal("wrote outside the output directory")
	}
	if _, _, err := WriteFile(dir, "big", 0o640, strings.NewReader("too long"), 3, false, nil); err == nil {
		t.Fatal("wrote past the size limit")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteFile(dir, "out/x", 0o640, strings.NewReader("x"), 100, false, nil); err == nil || !strings.Contains(err.Error(), "escape") {
		t.Fatalf("wrote through a symlink out of the directory: %v", err)
	}
}
