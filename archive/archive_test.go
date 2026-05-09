// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk/compress"
)

// extractedFile is a flattened view of a tar entry on disk, used by tests
// that previously introspected ExtractTarToMemory output.
type extractedFile struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// extractToTreeReader extracts a compressed tar from r into a temp dir and
// returns the regular files as a sorted slice. Directory entries are folded
// into the file paths. This replaces the dropped ExtractTarToMemoryReader
// helper for test introspection only.
func extractToTreeReader(t *testing.T, r io.Reader, algo compress.Algorithm, lim *Limits) ([]extractedFile, error) {
	t.Helper()
	dir := t.TempDir()
	if _, err := ExtractTarReader(r, dir, algo, lim); err != nil {
		return nil, err
	}
	return readDirTree(t, dir)
}

func extractToTree(t *testing.T, data []byte, algo compress.Algorithm, lim *Limits) ([]extractedFile, error) {
	t.Helper()
	return extractToTreeReader(t, bytes.NewReader(data), algo, lim)
}

func readDirTree(t *testing.T, root string) ([]extractedFile, error) {
	t.Helper()
	var out []extractedFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, extractedFile{
			Name: filepath.ToSlash(rel),
			Data: data,
			Mode: info.Mode().Perm(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// stable order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Name > out[j].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

// ── ValidateArchivePath ─────────────────────────────────────────────────────

func TestValidateArchivePath(t *testing.T) {
	valid := []struct {
		input string
		want  string
	}{
		{"file.go", "file.go"},
		{"dir/file.go", "dir/file.go"},
		{"a/b/c/d.txt", "a/b/c/d.txt"},
		{"hello.tar.zst", "hello.tar.zst"},
	}
	for _, tt := range valid {
		t.Run("valid_"+tt.input, func(t *testing.T) {
			got, err := ValidateArchivePath(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	invalid := []string{
		"",                   // empty
		".",                  // dot segment
		"..",                 // dotdot segment
		"../evil.txt",        // traversal
		"a/../b",             // internal traversal
		"/etc/passwd",        // absolute
		"a//b",               // double slash
		"a/",                 // trailing slash
		"/a",                 // leading slash
		"a\\b",               // backslash
		"a/./b",              // dot segment inside
		"a\x00b",             // null byte
		"a/../../etc/passwd", // deep traversal
	}
	for _, input := range invalid {
		t.Run("invalid_"+input, func(t *testing.T) {
			_, err := ValidateArchivePath(input)
			if err == nil {
				t.Errorf("expected error for %q", input)
			}
		})
	}
}

func TestNormalizeToArchivePath(t *testing.T) {
	// Backslash conversion (Windows path)
	got, err := NormalizeToArchivePath("a\\b\\c.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a/b/c.txt" {
		t.Errorf("got %q, want %q", got, "a/b/c.txt")
	}

	// Still rejects invalid after normalization
	_, err = NormalizeToArchivePath("..\\evil.txt")
	if err == nil {
		t.Error("should reject traversal after backslash normalization")
	}
}

// ── ExpandPaths ─────────────────────────────────────────────────────────────

func TestExpandPaths_Files(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "a.txt"), []byte("a"))
	writeOrFatal(t, filepath.Join(tmpDir, "b.txt"), []byte("b"))

	files, err := ExpandPaths([]string{
		filepath.Join(tmpDir, "a.txt"),
		filepath.Join(tmpDir, "b.txt"),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Errorf("got %d files, want 2", len(files))
	}
}

func TestExpandPaths_Sorted(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "z.txt"), []byte("z"))
	writeOrFatal(t, filepath.Join(tmpDir, "a.txt"), []byte("a"))
	writeOrFatal(t, filepath.Join(tmpDir, "m.txt"), []byte("m"))

	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(files); i++ {
		if files[i].RelPath < files[i-1].RelPath {
			t.Errorf("not sorted: %q before %q", files[i-1].RelPath, files[i].RelPath)
		}
	}
}

func TestExpandPaths_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	sub := filepath.Join(tmpDir, "sub")
	mkdirOrFatal(t, sub)
	writeOrFatal(t, filepath.Join(tmpDir, "root.txt"), []byte("r"))
	writeOrFatal(t, filepath.Join(sub, "nested.txt"), []byte("n"))

	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Two files + two directory entries (root + sub).
	if len(files) != 4 {
		t.Errorf("got %d entries, want 4 (2 files + 2 dirs)", len(files))
	}
	var fileCount, dirCount int
	for _, f := range files {
		if strings.Contains(f.RelPath, "\\") {
			t.Errorf("archive path contains backslash: %q", f.RelPath)
		}
		if f.IsDir {
			dirCount++
		} else {
			fileCount++
		}
	}
	if fileCount != 2 || dirCount != 2 {
		t.Errorf("got %d files / %d dirs, want 2 / 2", fileCount, dirCount)
	}
}

func TestExpandPaths_SkipHidden(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "visible.txt"), []byte("v"))
	writeOrFatal(t, filepath.Join(tmpDir, ".hidden"), []byte("h"))
	hiddenDir := filepath.Join(tmpDir, ".git")
	mkdirOrFatal(t, hiddenDir)
	writeOrFatal(t, filepath.Join(hiddenDir, "config"), []byte("c"))

	visible, _ := ExpandPaths([]string{tmpDir}, true)
	// 1 visible file + 1 walk-root dir entry.
	var fileCount, dirCount int
	for _, f := range visible {
		if f.IsDir {
			dirCount++
		} else {
			fileCount++
		}
	}
	if fileCount != 1 {
		t.Errorf("got %d visible files, want 1", fileCount)
	}
	if dirCount != 1 {
		t.Errorf("got %d dir entries, want 1 (root only; .git skipped)", dirCount)
	}
}

func TestExpandPaths_Dedup(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "file.txt")
	writeOrFatal(t, f, []byte("x"))

	files, err := ExpandPaths([]string{f, f, f}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("got %d files, want 1 (dedup)", len(files))
	}
}

func TestExpandPaths_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || !files[0].IsDir {
		t.Errorf("empty directory should yield exactly one dir entry, got %+v", files)
	}
}

func TestExpandPaths_Nonexistent(t *testing.T) {
	_, err := ExpandPaths([]string{"/nonexistent/path"}, false)
	if err == nil {
		t.Error("nonexistent path should return error")
	}
}

func TestExpandPaths_RejectsSymlinkRoot(t *testing.T) {
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real.txt")
	writeOrFatal(t, realFile, []byte("x"))
	linkFile := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	_, err := ExpandPaths([]string{linkFile}, false)
	if err == nil {
		t.Error("should reject symlinked input root")
	}
}

// ── Tar ─────────────────────────────────────────────────────────────────────

func TestCreateTarExtractRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "file1.txt"), []byte("content one"))
	sub := filepath.Join(tmpDir, "sub")
	mkdirOrFatal(t, sub)
	writeOrFatal(t, filepath.Join(sub, "file2.txt"), []byte("content two"))

	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, algo := range []compress.Algorithm{compress.None, compress.Zstd} {
		t.Run(string(algo), func(t *testing.T) {
			data, err := CreateTar(files, algo)
			if err != nil {
				t.Fatal(err)
			}
			extractDir := t.TempDir()
			count, err := ExtractTar(data, extractDir, algo, nil)
			if err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Errorf("extracted %d files, want 2", count)
			}
		})
	}
}

func TestCreateTarFromBytesRoundtrip(t *testing.T) {
	entries := []TarEntry{
		{Name: "hello.txt", Data: []byte("hello"), Mode: 0644},
		{Name: "sub/world.txt", Data: []byte("world"), Mode: 0755},
	}

	data, err := CreateTarFromBytes(entries, compress.Zstd)
	if err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTree(t, data, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 2 {
		t.Fatalf("got %d entries, want 2", len(extracted))
	}
}

func TestCreateTarFromBytes_Sorted(t *testing.T) {
	entries := []TarEntry{
		{Name: "z.txt", Data: []byte("z"), Mode: 0644},
		{Name: "a.txt", Data: []byte("a"), Mode: 0644},
	}

	data, _ := CreateTarFromBytes(entries, compress.None)
	extracted, _ := extractToTree(t, data, compress.None, nil)

	if extracted[0].Name != "a.txt" {
		t.Errorf("first entry should be a.txt (sorted), got %q", extracted[0].Name)
	}
}

func TestCreateTarFromBytes_RejectsDuplicate(t *testing.T) {
	entries := []TarEntry{
		{Name: "same.txt", Data: []byte("a"), Mode: 0644},
		{Name: "same.txt", Data: []byte("b"), Mode: 0644},
	}

	_, err := CreateTarFromBytes(entries, compress.None)
	if err == nil {
		t.Error("should reject duplicate archive names")
	}
}

func TestCreateTarFromBytes_RejectsInvalidPath(t *testing.T) {
	entries := []TarEntry{
		{Name: "../evil.txt", Data: []byte("x"), Mode: 0644},
	}

	_, err := CreateTarFromBytes(entries, compress.None)
	if err == nil {
		t.Error("should reject traversal in archive name")
	}
}

func TestCreateTar_RejectsEmpty(t *testing.T) {
	_, err := CreateTar(nil, compress.None)
	if err == nil {
		t.Error("should reject empty file list")
	}
}

// ── Extraction security ─────────────────────────────────────────────────────

func TestExtractTar_RejectsPathTraversal(t *testing.T) {
	// Create raw tar with malicious entry (bypassing CreateTarFromBytes validation)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "../evil.txt", Size: 5})
	tw.Write([]byte("pwned"))
	tw.Close()

	extractDir := t.TempDir()
	_, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		t.Error("path traversal should be rejected")
	}
}

func TestExtractTar_PreservesAbsoluteSymlinkTarget(t *testing.T) {
	// Absolute symlink targets are stored verbatim — the link is just a
	// string in the inode. ensureInsideDir + O_NOFOLLOW prevent any actual
	// write from escaping through the link.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "link.txt",
		Linkname: "/Users/me/.cache/foo",
	})
	tw.Close()

	extractDir := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil); err != nil {
		t.Fatalf("absolute symlink target should round-trip: %v", err)
	}
	got, err := os.Readlink(filepath.Join(extractDir, "link.txt"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if got != "/Users/me/.cache/foo" {
		t.Errorf("got target %q, want absolute target preserved", got)
	}
}

func TestExtractTar_BlocksWriteThroughEscapingSymlink(t *testing.T) {
	// A symlink with an escaping target is fine on its own; the safety
	// guarantee is that subsequent writes can't go *through* it. Here we
	// create the link and then try to write a file at link/escaped.txt;
	// ensureInsideDir must reject the write.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "escape",
		Linkname: "../..",
	})
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "escape/pwned.txt", Size: 1})
	tw.Write([]byte("x"))
	tw.Close()

	extractDir := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil); err == nil {
		t.Error("write through escaping symlink should be rejected")
	}
}

func TestExtractTar_AcceptsInTreeSymlink(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// A real file in the archive...
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "real.txt", Size: 5, Mode: 0644})
	tw.Write([]byte("hello"))
	// ...and a symlink pointing at it.
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeSymlink,
		Name:     "link.txt",
		Linkname: "real.txt",
	})
	tw.Close()

	extractDir := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil); err != nil {
		t.Fatalf("expected in-tree symlink to extract: %v", err)
	}
	link := filepath.Join(extractDir, "link.txt")
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "real.txt" {
		t.Errorf("got target %q, want %q", target, "real.txt")
	}
}

func TestExtractTar_HardlinkRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "real.txt", Size: 5, Mode: 0644})
	tw.Write([]byte("hello"))
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "link.txt", Linkname: "real.txt"})
	tw.Close()

	extractDir := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil); err != nil {
		t.Fatalf("hardlink should extract: %v", err)
	}
	a, err := os.Stat(filepath.Join(extractDir, "real.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(extractDir, "link.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Errorf("real.txt and link.txt should share inode")
	}
}

func TestExtractTar_RejectsHardlinkEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "evil", Linkname: "../escape"})
	tw.Close()

	if _, err := ExtractTar(buf.Bytes(), t.TempDir(), compress.None, nil); err == nil {
		t.Error("hardlink with escaping target should be rejected")
	}
}

func TestExtractTar_RejectsAbsolutePath(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "/etc/passwd", Size: 4})
	tw.Write([]byte("root"))
	tw.Close()

	extractDir := t.TempDir()
	_, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		t.Error("absolute path should be rejected")
	}
}

func TestExtractTar_RejectsBackslashPath(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "a\\b.txt", Size: 1})
	tw.Write([]byte("x"))
	tw.Close()

	extractDir := t.TempDir()
	_, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		t.Error("backslash path should be rejected")
	}
}

func TestExtractTar_RejectsEmptyName(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "", Size: 1})
	tw.Write([]byte("x"))
	tw.Close()

	extractDir := t.TempDir()
	_, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		t.Error("empty name should be rejected")
	}
}

func TestExtractTar_TruncatedArchive(t *testing.T) {
	entries := []TarEntry{{Name: "test.txt", Data: bytes.Repeat([]byte("x"), 1000), Mode: 0644}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	// Truncate at various points
	for _, cutAt := range []int{10, 50, len(data) / 2} {
		_, err := ExtractTar(data[:cutAt], t.TempDir(), compress.None, nil)
		if err == nil {
			t.Errorf("should reject truncated archive at byte %d", cutAt)
		}
	}
}

// ── Extraction limits ───────────────────────────────────────────────────────

func TestExtractTar_EntryCountLimit(t *testing.T) {
	var entries []TarEntry
	for i := 0; i < 20; i++ {
		entries = append(entries, TarEntry{
			Name: fmt.Sprintf("file%03d.txt", i),
			Data: []byte("data"),
			Mode: 0644,
		})
	}
	data, _ := CreateTarFromBytes(entries, compress.None)

	limits := &Limits{MaxEntries: 5}
	_, err := ExtractTar(data, t.TempDir(), compress.None, limits)
	if err == nil {
		t.Error("should reject archive exceeding entry count limit")
	}
}

func TestExtractTar_EntrySizeLimit(t *testing.T) {
	entries := []TarEntry{
		{Name: "big.txt", Data: bytes.Repeat([]byte("x"), 10_000), Mode: 0644},
	}
	data, _ := CreateTarFromBytes(entries, compress.None)

	limits := &Limits{MaxEntrySize: 1000}
	_, err := ExtractTar(data, t.TempDir(), compress.None, limits)
	if err == nil {
		t.Error("should reject entry exceeding size limit")
	}
}

func TestExtractTar_TotalSizeLimit(t *testing.T) {
	var entries []TarEntry
	for i := 0; i < 5; i++ {
		entries = append(entries, TarEntry{
			Name: fmt.Sprintf("file%d.txt", i),
			Data: bytes.Repeat([]byte("x"), 5000),
			Mode: 0644,
		})
	}
	data, _ := CreateTarFromBytes(entries, compress.None)

	// Total uncompressed = 25000, set limit below that
	limits := &Limits{MaxTotalSize: 10_000}
	_, err := ExtractTar(data, t.TempDir(), compress.None, limits)
	if err == nil {
		t.Error("should reject archive exceeding total size limit")
	}
}

func TestExtractTar_Limits(t *testing.T) {
	entries := []TarEntry{
		{Name: "big.txt", Data: bytes.Repeat([]byte("x"), 10_000), Mode: 0644},
	}
	data, _ := CreateTarFromBytes(entries, compress.None)

	limits := &Limits{MaxEntrySize: 1000}
	_, err := extractToTree(t, data, compress.None, limits)
	if err == nil {
		t.Error("should reject entry exceeding size limit in memory extraction")
	}
}

// ── Determinism ─────────────────────────────────────────────────────────────

func TestCreateTarFromBytes_Deterministic(t *testing.T) {
	entries := []TarEntry{
		{Name: "z.txt", Data: []byte("z"), Mode: 0644},
		{Name: "a.txt", Data: []byte("a"), Mode: 0644},
		{Name: "m.txt", Data: []byte("m"), Mode: 0644},
	}

	// Create twice — should produce identical output
	data1, _ := CreateTarFromBytes(entries, compress.None)
	data2, _ := CreateTarFromBytes(entries, compress.None)

	if !bytes.Equal(data1, data2) {
		t.Error("CreateTarFromBytes should be deterministic")
	}
}

// ── Duplicate entry on extract ───────────────────────────────────────────────

func TestExtractTar_RejectsDuplicateEntry(t *testing.T) {
	// Manually create tar with duplicate names (bypasses CreateTarFromBytes validation)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "dup.txt", Size: 1})
	tw.Write([]byte("a"))
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "dup.txt", Size: 1})
	tw.Write([]byte("b"))
	tw.Close()

	_, err := ExtractTar(buf.Bytes(), t.TempDir(), compress.None, nil)
	if err == nil {
		t.Error("should reject duplicate entry names on extract")
	}
}

// ── Negative size ───────────────────────────────────────────────────────────

func TestExtractTar_AcceptsZeroSizeEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "empty.txt", Size: 0})
	tw.Close()

	count, err := ExtractTar(buf.Bytes(), t.TempDir(), compress.None, nil)
	if err != nil {
		t.Fatalf("Size=0 should be valid: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 file, got %d", count)
	}
}

// ── Mode normalization ──────────────────────────────────────────────────────

func TestCreateTarFromBytes_NormalizesMode(t *testing.T) {
	entries := []TarEntry{
		{Name: "setuid.txt", Data: []byte("x"), Mode: 0o4755}, // setuid bit
	}
	data, err := CreateTarFromBytes(entries, compress.None)
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := extractToTree(t, data, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Mode should have setuid stripped
	if extracted[0].Mode&0o7000 != 0 {
		t.Errorf("setuid/setgid/sticky bits should be stripped, got %o", extracted[0].Mode)
	}
}

// ── Device/fifo entry rejection ─────────────────────────────────────────────

func TestExtractTar_RejectsDeviceEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeChar,
		Name:     "dev",
	})
	tw.Close()

	_, err := ExtractTar(buf.Bytes(), t.TempDir(), compress.None, nil)
	if err == nil {
		t.Error("should reject device entry")
	}
}

func TestExtractTar_RejectsFifoEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeFifo,
		Name:     "pipe",
	})
	tw.Close()

	_, err := ExtractTar(buf.Bytes(), t.TempDir(), compress.None, nil)
	if err == nil {
		t.Error("should reject fifo entry")
	}
}

// ── Special filename edge cases ─────────────────────────────────────────────

func TestValidateArchivePath_SpecialNames(t *testing.T) {
	// These should be valid (just unusual)
	valid := []string{
		"a",
		"a/b",
		"file with spaces.txt",
		"file-with-dashes.txt",
		"ALLCAPS.TXT",
		"unicode-café.txt",
		"deep/nested/path/to/file.txt",
	}
	for _, name := range valid {
		if _, err := ValidateArchivePath(name); err != nil {
			t.Errorf("should accept %q: %v", name, err)
		}
	}
}

// ── Overwrite behavior ──────────────────────────────────────────────────────

func TestExtractTar_RejectsExistingFileByDefault(t *testing.T) {
	extractDir := t.TempDir()

	target := filepath.Join(extractDir, "file.txt")
	writeOrFatal(t, target, []byte("old content"))

	entries := []TarEntry{{Name: "file.txt", Data: []byte("new content"), Mode: 0644}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	if _, err := ExtractTar(data, extractDir, compress.None, nil); err == nil {
		t.Fatal("expected error when destination exists without AllowOverwrite")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old content" {
		t.Errorf("file should be untouched, got %q", string(got))
	}
}

func TestExtractTar_OverwritesWithAllowOverwrite(t *testing.T) {
	extractDir := t.TempDir()

	target := filepath.Join(extractDir, "file.txt")
	writeOrFatal(t, target, []byte("old content"))

	entries := []TarEntry{{Name: "file.txt", Data: []byte("new content"), Mode: 0644}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	count, err := ExtractTar(data, extractDir, compress.None, &Limits{AllowOverwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	got, _ := os.ReadFile(target)
	if string(got) != "new content" {
		t.Errorf("file should be overwritten, got %q", string(got))
	}
}

// ── Zero mode semantics ─────────────────────────────────────────────────────

func TestExtractTar_ZeroModeDefaultsTo0644(t *testing.T) {
	entries := []TarEntry{{Name: "zero.txt", Data: []byte("x"), Mode: 0}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	extractDir := t.TempDir()
	_, err := ExtractTar(data, extractDir, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(extractDir, "zero.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Should default to 0644 (not 0000)
	if info.Mode().Perm() != 0644 {
		t.Errorf("mode = %o, want 0644", info.Mode().Perm())
	}
}

// ── Long path names ─────────────────────────────────────────────────────────

func TestCreateTarFromBytes_LongPaths(t *testing.T) {
	// 100+ byte path (requires PAX format)
	longDir := strings.Repeat("a", 50)
	longName := longDir + "/" + strings.Repeat("b", 50) + "/" + strings.Repeat("c", 50) + ".txt"

	entries := []TarEntry{{Name: longName, Data: []byte("long"), Mode: 0644}}
	data, err := CreateTarFromBytes(entries, compress.None)
	if err != nil {
		t.Fatalf("should handle long paths via PAX: %v", err)
	}

	extracted, err := extractToTree(t, data, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if extracted[0].Name != longName {
		t.Errorf("long path roundtrip failed: got %q", extracted[0].Name)
	}
}

// ── Partial extraction cleanup ──────────────────────────────────────────────

func TestExtractTar_PartialExtractionOnError(t *testing.T) {
	// Valid first entry, then a FIFO (named pipe) — an unsupported tar
	// type the extractor rejects, so we can verify the first file landed.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "good.txt", Size: 4})
	tw.Write([]byte("good"))
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeFifo, Name: "bad.fifo"})
	tw.Close()

	extractDir := t.TempDir()
	count, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		t.Error("should fail on fifo entry")
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (partial extraction)", count)
	}
	if _, statErr := os.Stat(filepath.Join(extractDir, "good.txt")); statErr != nil {
		t.Error("first file should exist after partial extraction")
	}
}

// ── ExpandPaths error propagation ───────────────────────────────────────────

func TestExpandPaths_PropagatesWalkErrors(t *testing.T) {
	tmpDir := t.TempDir()
	sub := filepath.Join(tmpDir, "unreadable")
	mkdirOrFatal(t, sub)
	writeOrFatal(t, filepath.Join(sub, "file.txt"), []byte("x"))
	// Make directory unreadable
	os.Chmod(sub, 0000)
	defer os.Chmod(sub, 0755) // restore for cleanup

	_, err := ExpandPaths([]string{tmpDir}, false)
	if err == nil {
		t.Error("should propagate permission error from walk")
	}
}

// ── Streaming APIs ──────────────────────────────────────────────────────────

func TestWriteTar_StreamingRoundtrip(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "a.txt"), []byte("aaa"))
	writeOrFatal(t, filepath.Join(tmpDir, "b.txt"), []byte("bbb"))

	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Stream create
	var buf bytes.Buffer
	if err := WriteTar(&buf, files, compress.Zstd); err != nil {
		t.Fatal(err)
	}

	// Stream extract
	extractDir := t.TempDir()
	count, err := ExtractTarReader(&buf, extractDir, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("extracted %d, want 2", count)
	}
}

func TestWriteTarFromBytes_StreamingRoundtrip(t *testing.T) {
	entries := []TarEntry{
		{Name: "hello.txt", Data: []byte("hello"), Mode: 0644},
		{Name: "world.txt", Data: []byte("world"), Mode: 0644},
	}

	var buf bytes.Buffer
	if err := WriteTarFromBytes(&buf, entries, compress.Zstd); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 2 {
		t.Errorf("got %d, want 2", len(extracted))
	}
}

func TestStreamingConsistencyWithByteAPIs(t *testing.T) {
	entries := []TarEntry{
		{Name: "z.txt", Data: []byte("z"), Mode: 0644},
		{Name: "a.txt", Data: []byte("a"), Mode: 0644},
	}

	// []byte API
	bytesResult, err := CreateTarFromBytes(entries, compress.None)
	if err != nil {
		t.Fatal(err)
	}

	// Streaming API
	var buf bytes.Buffer
	if err := WriteTarFromBytes(&buf, entries, compress.None); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bytesResult, buf.Bytes()) {
		t.Error("streaming and []byte APIs should produce identical output")
	}
}

// ── outputDir behavior ──────────────────────────────────────────────────────

func TestExtractTar_CreatesOutputDir(t *testing.T) {
	entries := []TarEntry{{Name: "file.txt", Data: []byte("x"), Mode: 0644}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	// Use a non-existent nested path
	extractDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	count, err := ExtractTar(data, extractDir, compress.None, nil)
	if err != nil {
		t.Fatalf("should create output dir: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	// Verify file was written
	if _, err := os.Stat(filepath.Join(extractDir, "file.txt")); err != nil {
		t.Error("file should exist in created output dir")
	}
}

func TestExtractTar_RejectsOutputDirAsFile(t *testing.T) {
	entries := []TarEntry{{Name: "file.txt", Data: []byte("x"), Mode: 0644}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	// Create a file where outputDir should be
	outputPath := filepath.Join(t.TempDir(), "not-a-dir")
	writeOrFatal(t, outputPath, []byte("i am a file"))

	_, err := ExtractTar(data, outputPath, compress.None, nil)
	if err == nil {
		t.Error("should reject output path that is a file")
	}
}

// ── Total-size overflow cleanup ─────────────────────────────────────────────

func TestExtractTar_TotalSizeOverflowDoesNotLeaveFile(t *testing.T) {
	// Create two entries: first fits in budget, second would exceed
	entries := []TarEntry{
		{Name: "small.txt", Data: bytes.Repeat([]byte("a"), 100), Mode: 0644},
		{Name: "toobig.txt", Data: bytes.Repeat([]byte("b"), 200), Mode: 0644},
	}
	data, _ := CreateTarFromBytes(entries, compress.None)

	extractDir := t.TempDir()
	limits := &Limits{MaxTotalSize: 150} // first fits (100), second (200) would exceed
	count, err := ExtractTar(data, extractDir, compress.None, limits)
	if err == nil {
		t.Error("should fail on total size overflow")
	}
	// First file should have been extracted
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	// Second file should NOT exist (rejected before writing)
	if _, statErr := os.Stat(filepath.Join(extractDir, "toobig.txt")); statErr == nil {
		t.Error("oversized file should not be written to disk")
	}
}

// ── Direct-file basename collision ──────────────────────────────────────────

func TestExpandPaths_DirectFileBaseCollision(t *testing.T) {
	tmpDir := t.TempDir()
	dirA := filepath.Join(tmpDir, "a")
	dirB := filepath.Join(tmpDir, "b")
	mkdirOrFatal(t, dirA)
	mkdirOrFatal(t, dirB)
	writeOrFatal(t, filepath.Join(dirA, "config.yaml"), []byte("a"))
	writeOrFatal(t, filepath.Join(dirB, "config.yaml"), []byte("b"))

	_, err := ExpandPaths([]string{
		filepath.Join(dirA, "config.yaml"),
		filepath.Join(dirB, "config.yaml"),
	}, false)
	if err == nil {
		t.Error("should reject direct-file basename collision")
	}
}

// ── Memory extraction mode normalization ────────────────────────────────────

func TestExtractTar_NormalizesZeroMode(t *testing.T) {
	entries := []TarEntry{{Name: "zero.txt", Data: []byte("x"), Mode: 0}}
	data, _ := CreateTarFromBytes(entries, compress.None)

	extracted, err := extractToTree(t, data, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if extracted[0].Mode != 0644 {
		t.Errorf("mode = %o, want 0644 (normalized from 0)", extracted[0].Mode)
	}
}

// ── Streaming large file ────────────────────────────────────────────────────

func TestWriteTar_LargeFileStreaming(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a 1MB file
	bigFile := filepath.Join(tmpDir, "big.bin")
	bigData := bytes.Repeat([]byte("ABCDEFGHIJ"), 100_000) // 1MB
	writeOrFatal(t, bigFile, bigData)

	files, err := ExpandPaths([]string{bigFile}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Stream create
	var buf bytes.Buffer
	if err := WriteTar(&buf, files, compress.Zstd); err != nil {
		t.Fatal(err)
	}

	// Stream extract
	extractDir := t.TempDir()
	count, err := ExtractTarReader(&buf, extractDir, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	// Verify content
	got, _ := os.ReadFile(filepath.Join(extractDir, "big.bin"))
	if !bytes.Equal(got, bigData) {
		t.Error("large file content mismatch after streaming roundtrip")
	}
}

// ── WriteTarStream ──────────────────────────────────────────────────────────

func TestWriteTarStream_Roundtrip(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "a.txt", Size: 5, Mode: 0644, Reader: strings.NewReader("hello")},
		{Name: "b.txt", Size: 5, Mode: 0644, Reader: strings.NewReader("world")},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.Zstd); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 2 {
		t.Fatalf("got %d entries, want 2", len(extracted))
	}
	if string(extracted[0].Data) != "hello" {
		t.Errorf("first = %q, want %q", string(extracted[0].Data), "hello")
	}
	if string(extracted[1].Data) != "world" {
		t.Errorf("second = %q, want %q", string(extracted[1].Data), "world")
	}
}

func TestWriteTarStream_SizeMismatch(t *testing.T) {
	// Reader provides fewer bytes than declared Size
	entries := []TarStreamEntry{
		{Name: "short.txt", Size: 100, Mode: 0644, Reader: strings.NewReader("only 10 ch")},
	}

	var buf bytes.Buffer
	err := WriteTarStream(&buf, entries, compress.None)
	if err == nil {
		t.Error("should fail when reader provides fewer bytes than declared size")
	}
}

func TestWriteTarStream_RejectsDuplicate(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "dup.txt", Size: 1, Mode: 0644, Reader: strings.NewReader("a")},
		{Name: "dup.txt", Size: 1, Mode: 0644, Reader: strings.NewReader("b")},
	}

	var buf bytes.Buffer
	err := WriteTarStream(&buf, entries, compress.None)
	if err == nil {
		t.Error("should reject duplicate entry names")
	}
}

func TestWriteTarStream_RejectsInvalidPath(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "../evil.txt", Size: 1, Mode: 0644, Reader: strings.NewReader("x")},
	}

	var buf bytes.Buffer
	err := WriteTarStream(&buf, entries, compress.None)
	if err == nil {
		t.Error("should reject traversal path")
	}
}

func TestWriteTarStream_MoreBytesThanSize(t *testing.T) {
	// Reader has more data than declared Size — only Size bytes should be written
	entries := []TarStreamEntry{
		{Name: "truncated.txt", Size: 5, Mode: 0644,
			Reader: strings.NewReader("hello world this is extra data")},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.None); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted[0].Data) != "hello" {
		t.Errorf("got %q, want %q (truncated to Size=5)", string(extracted[0].Data), "hello")
	}
}

func TestWriteTarStream_ZeroSizeEntry(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "empty.txt", Size: 0, Mode: 0644, Reader: strings.NewReader("")},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.None); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 1 {
		t.Fatalf("got %d entries, want 1", len(extracted))
	}
	if len(extracted[0].Data) != 0 {
		t.Errorf("got %d bytes, want 0", len(extracted[0].Data))
	}
}

func TestWriteTarStream_NilReader(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "nil.txt", Size: 10, Mode: 0644, Reader: nil},
	}

	var buf bytes.Buffer
	err := WriteTarStream(&buf, entries, compress.None)
	if err == nil {
		t.Error("should reject nil reader")
	}
}

func TestWriteTarStream_NegativeSize(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "neg.txt", Size: -1, Mode: 0644, Reader: strings.NewReader("x")},
	}

	var buf bytes.Buffer
	err := WriteTarStream(&buf, entries, compress.None)
	if err == nil {
		t.Error("should reject negative size")
	}
}

func TestWriteTarStream_LargeStreaming(t *testing.T) {
	// 1MB entry streamed without buffering the full content
	size := int64(1_000_000)
	reader := io.LimitReader(
		&repeatingReader{b: byte('X')},
		size,
	)

	entries := []TarStreamEntry{
		{Name: "large.bin", Size: size, Mode: 0644, Reader: reader},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.Zstd); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(extracted[0].Data)) != size {
		t.Errorf("got %d bytes, want %d", len(extracted[0].Data), size)
	}
}

func TestWriteTarStream_ZeroSizeLeavesReaderUnread(t *testing.T) {
	// Size=0 should read zero bytes, leaving the reader's content unread
	underlying := strings.NewReader("should not be read")
	entries := []TarStreamEntry{
		{Name: "empty.txt", Size: 0, Mode: 0644, Reader: underlying},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.None); err != nil {
		t.Fatal(err)
	}

	// The reader should still have all its bytes
	remaining, _ := io.ReadAll(underlying)
	if string(remaining) != "should not be read" {
		t.Errorf("reader content consumed: remaining = %q", string(remaining))
	}
}

func TestWriteTarStream_MultiEntryExcessBytesIsolated(t *testing.T) {
	// Each entry has its own reader. First entry has more data than Size.
	// Second entry should still work correctly — excess from first reader
	// must not leak into the second entry.
	entries := []TarStreamEntry{
		{Name: "a.txt", Size: 3, Mode: 0644, Reader: strings.NewReader("abcXXXextra")},
		{Name: "b.txt", Size: 5, Mode: 0644, Reader: strings.NewReader("hello")},
	}

	var buf bytes.Buffer
	if err := WriteTarStream(&buf, entries, compress.None); err != nil {
		t.Fatal(err)
	}

	extracted, err := extractToTreeReader(t, &buf, compress.None, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 2 {
		t.Fatalf("got %d entries, want 2", len(extracted))
	}
	if string(extracted[0].Data) != "abc" {
		t.Errorf("first = %q, want %q", string(extracted[0].Data), "abc")
	}
	if string(extracted[1].Data) != "hello" {
		t.Errorf("second = %q, want %q", string(extracted[1].Data), "hello")
	}
}

// ── Error propagation tests ─────────────────────────────────────────────────

func TestWriteTar_FailMidStream(t *testing.T) {
	tmpDir := t.TempDir()
	writeOrFatal(t, filepath.Join(tmpDir, "a.txt"), []byte("aaa"))
	writeOrFatal(t, filepath.Join(tmpDir, "b.txt"), []byte(strings.Repeat("x", 10000)))

	files, err := ExpandPaths([]string{tmpDir}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Fail after a small number of bytes (mid-stream)
	err = WriteTar(&failWriter{n: 50}, files, compress.None)
	if err == nil {
		t.Error("should propagate writer error")
	}
}

func TestWriteTarFromBytes_FailMidStream(t *testing.T) {
	entries := []TarEntry{
		{Name: "big.txt", Data: bytes.Repeat([]byte("x"), 10000), Mode: 0644},
	}
	err := WriteTarFromBytes(&failWriter{n: 50}, entries, compress.None)
	if err == nil {
		t.Error("should propagate writer error")
	}
}

func TestWriteTarStream_FailMidStream(t *testing.T) {
	entries := []TarStreamEntry{
		{Name: "big.txt", Size: 10000, Mode: 0644,
			Reader: io.LimitReader(&repeatingReader{b: 'X'}, 10000)},
	}
	err := WriteTarStream(&failWriter{n: 50}, entries, compress.None)
	if err == nil {
		t.Error("should propagate writer error")
	}
}

// ── Symlink parent escape test ──────────────────────────────────────────────

func TestExtractTar_SymlinkedParentDir(t *testing.T) {
	extractDir := t.TempDir()

	// Create a symlink inside extractDir that points outside
	outsideDir := t.TempDir()
	symlinkDir := filepath.Join(extractDir, "escape")
	if err := os.Symlink(outsideDir, symlinkDir); err != nil {
		t.Skip("cannot create symlink on this platform")
	}

	// Create an archive with a file under "escape/secret.txt"
	// If extraction follows the symlink, the file lands in outsideDir
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "escape/secret.txt", Size: 6})
	tw.Write([]byte("pwned!"))
	tw.Close()

	_, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil)
	if err == nil {
		// Check if the file escaped
		if _, statErr := os.Stat(filepath.Join(outsideDir, "secret.txt")); statErr == nil {
			t.Error("file escaped through symlinked parent directory!")
		}
		// Even if no error, the file should NOT be in outsideDir
	}
	// Either an error or the file stays inside extractDir — both acceptable
	if _, statErr := os.Stat(filepath.Join(outsideDir, "secret.txt")); statErr == nil {
		t.Error("file should not exist outside extraction directory")
	}
}

// ── Late-close failure ──────────────────────────────────────────────────────

func TestWriteTarStream_FailOnFinalWrite(t *testing.T) {
	// Writer that succeeds for small writes but fails during tar finalization
	// (tar.Close writes 1024 bytes of zero padding). A writer that allows
	// only the first ~600 bytes will fail during Close.
	entries := []TarStreamEntry{
		{Name: "file.txt", Size: 5, Mode: 0644, Reader: strings.NewReader("hello")},
	}
	err := WriteTarStream(&failWriter{n: 600}, entries, compress.None)
	if err == nil {
		t.Error("should propagate error during tar finalization")
	}
}

func TestWriteTarFromBytes_FailOnFinalWrite(t *testing.T) {
	entries := []TarEntry{
		{Name: "file.txt", Data: []byte("hello"), Mode: 0644},
	}
	err := WriteTarFromBytes(&failWriter{n: 600}, entries, compress.None)
	if err == nil {
		t.Error("should propagate error during tar finalization")
	}
}

func TestExtractTar_RestoresMTime(t *testing.T) {
	mtime := time.Date(2022, 6, 15, 10, 30, 0, 0, time.UTC)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{
		Format:   tar.FormatPAX,
		Typeflag: tar.TypeReg,
		Name:     "stamped.txt",
		Size:     5,
		Mode:     0644,
		ModTime:  mtime,
	})
	tw.Write([]byte("hello"))
	tw.Close()

	extractDir := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), extractDir, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(extractDir, "stamped.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := info.ModTime().UTC().Truncate(time.Second)
	if !got.Equal(mtime) {
		t.Errorf("file mtime = %s, want %s", got, mtime)
	}
}

func TestExtractTar_RoundTripsXattrs(t *testing.T) {
	if runtimeOS := os.Getenv("GOOS"); runtimeOS == "windows" {
		t.Skip("xattrs are not supported on Windows")
	}
	tmpSrc := t.TempDir()
	srcFile := filepath.Join(tmpSrc, "tagged.txt")
	if err := os.WriteFile(srcFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	// Try to set a user-namespace xattr; bail out if the FS doesn't
	// support them (some CI tmpfs / overlayfs setups don't).
	if err := writeXattr(srcFile, "user.ds_test", "v1"); err != nil {
		t.Skipf("filesystem does not support user xattrs: %v", err)
	}

	files, err := ExpandPaths([]string{srcFile}, false)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteTar(&buf, files, compress.None); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), dst, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	got, err := readXattrs(filepath.Join(dst, "tagged.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got["user.ds_test"] != "v1" {
		t.Errorf("xattr did not round-trip: got %#v", got)
	}
}

func TestExtractTar_RoundTripsSetuidBit(t *testing.T) {
	tmpSrc := t.TempDir()
	srcFile := filepath.Join(tmpSrc, "setuid.bin")
	if err := os.WriteFile(srcFile, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	// Set setuid via Go's FileMode flag (bit 23), which os.Chmod
	// translates to the Unix S_ISUID bit on disk.
	if err := os.Chmod(srcFile, 0o755|os.ModeSetuid); err != nil {
		t.Skipf("filesystem doesn't honor setuid: %v", err)
	}
	srcInfo, _ := os.Stat(srcFile)
	if srcInfo.Mode()&os.ModeSetuid == 0 {
		t.Skip("filesystem does not preserve setuid (e.g. tmpfs with nosuid)")
	}

	files, _ := ExpandPaths([]string{srcFile}, false)
	var buf bytes.Buffer
	if err := WriteTar(&buf, files, compress.None); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	if _, err := ExtractTar(buf.Bytes(), dst, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dst, "setuid.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Errorf("setuid bit not preserved: mode = %s", info.Mode())
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("perm bits = %o, want 0755", info.Mode().Perm())
	}
}
