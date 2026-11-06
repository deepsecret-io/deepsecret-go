// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/deepsecret-io/sdk/internal/compress"
)

// tree lists every path under dir, relative and slash-separated, with a
// trailing slash on directories.
func tree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			rel += "/"
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// preexisting fills out with what a user already had there.
func preexisting(t *testing.T, out string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(out, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"keep.txt": "mine", "existing/old.txt": "mine too"} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// An extraction that fails midway removes what it created, files, links
// and directories, and leaves everything that was there before.
func TestExtractTarFailureRemovesWhatItCreated(t *testing.T) {
	out := t.TempDir()
	preexisting(t, out)
	before := tree(t, out)
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "newdir/", mode: 0o755},
		tarTestEntry{typ: tar.TypeReg, name: "newdir/a.txt", mode: 0o644, data: []byte("a")},
		tarTestEntry{typ: tar.TypeReg, name: "deep/er/b.txt", mode: 0o644, data: []byte("b")},
		tarTestEntry{typ: tar.TypeReg, name: "existing/c.txt", mode: 0o644, data: []byte("c")},
		tarTestEntry{typ: tar.TypeSymlink, name: "link", link: "keep.txt"},
		tarTestEntry{typ: tar.TypeReg, name: "d.txt", mode: 0o644, data: []byte("d")},
		tarTestEntry{typ: tar.TypeLink, name: "hard", link: "d.txt"},
		// A FIFO is refused: extraction fails here, after the entries above.
		tarTestEntry{typ: tar.TypeFifo, name: "fifo"},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err == nil || !strings.Contains(err.Error(), "unsupported tar entry type") {
		t.Fatalf("extract: %v, want the refused entry", err)
	}
	if got := tree(t, out); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Errorf("after the failure the output holds %v, want what was there before: %v", got, before)
	}
	for name, want := range map[string]string{"keep.txt": "mine", "existing/old.txt": "mine too"} {
		if got, err := os.ReadFile(filepath.Join(out, name)); err != nil || string(got) != want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

// A failed extraction also removes the output directory when it made it.
func TestExtractTarFailureRemovesOutputDirItMade(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "new", "out")
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeReg, name: "a.txt", mode: 0o644, data: []byte("a")},
		tarTestEntry{typ: tar.TypeFifo, name: "fifo"},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err == nil {
		t.Fatal("extraction of a FIFO succeeded")
	}
	if got := tree(t, parent); len(got) != 0 {
		t.Errorf("the failed extraction left %v", got)
	}
}

// With AllowOverwrite, a failed extraction removes the files it replaced
// too, since their old content is gone, and still leaves the rest.
func TestExtractTarFailureRemovesOverwrittenFiles(t *testing.T) {
	out := t.TempDir()
	preexisting(t, out)
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeReg, name: "existing/old.txt", mode: 0o600, data: []byte("replaced")},
		tarTestEntry{typ: tar.TypeFifo, name: "fifo"},
	)
	if _, err := ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true}); err == nil {
		t.Fatal("extraction of a FIFO succeeded")
	}
	if got := tree(t, out); strings.Join(got, ",") != "existing/,keep.txt" {
		t.Errorf("the output holds %v, want existing/ and keep.txt", got)
	}
}

// Removing a directory the write made leaves it when someone else put a
// file in it meanwhile, and reports it.
func TestUndoKeepsAndReportsWhatOthersAdded(t *testing.T) {
	out := t.TempDir()
	var undo Undo
	dir := filepath.Join(out, "made", "here")
	if err := undo.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := undo.MkdirAll(dir, 0o700); err != nil { // already there: nothing more recorded
		t.Fatal(err)
	}
	theirs := filepath.Join(out, "made", "theirs.txt")
	if err := os.WriteFile(theirs, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := undo.Remove(nil)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(out, "made")+" is left behind") {
		t.Errorf("err = %v, want made/ reported", err)
	}
	if got := tree(t, out); strings.Join(got, ",") != "made/,made/theirs.txt" {
		t.Errorf("the output holds %v, want made/ with the other file", got)
	}
}

// With overwrite, the new file replaces the old one: it gets the entry's
// mode, not the old file's, and a link at its path is replaced, never
// written through.
func TestOverwriteReplacesFileAndMode(t *testing.T) {
	out := t.TempDir()
	old := filepath.Join(out, "secret.txt")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(old, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteFile(out, "secret.txt", 0o600, strings.NewReader("new"), 100, true, nil); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, old, "new")

	// Extraction with AllowOverwrite does the same.
	data := buildTar(t, tarTestEntry{typ: tar.TypeReg, name: "secret.txt", mode: 0o600, data: []byte("newer")})
	if err := os.Chmod(old, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true}); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, old, "newer")

	// A link at the path, pointing at another file in the output, is
	// replaced; the file it pointed at is untouched.
	other := filepath.Join(out, "other.txt")
	if err := os.WriteFile(other, []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other.txt", old); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := WriteFile(out, "secret.txt", 0o600, strings.NewReader("newest"), 100, true, nil); err != nil {
		t.Fatal(err)
	}
	assertPrivateFile(t, old, "newest")
	if got, _ := os.ReadFile(other); string(got) != "other" {
		t.Errorf("the link's target was written: %q", got)
	}
	if got := tree(t, out); strings.Join(got, ",") != "other.txt,secret.txt" {
		t.Errorf("the output holds %v; a temporary file was left", got)
	}
}

// runtimeHasModes is false on Windows, where files have no Unix modes.
var runtimeHasModes = runtime.GOOS != "windows"

func assertPrivateFile(t *testing.T, path, want string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s is %v, want a regular file", path, info.Mode())
	}
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Errorf("%s holds %q, want %q", path, got, want)
	}
	if runtimeHasModes && info.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %o, want 0600", path, info.Mode().Perm())
	}
}
