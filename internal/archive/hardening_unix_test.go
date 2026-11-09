// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package archive

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
)

// assertModes fails unless each path has exactly the mode it maps to:
// permission bits and setuid, setgid and sticky.
func assertModes(t *testing.T, want map[string]os.FileMode) {
	t.Helper()
	for path, mode := range want {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		mask := os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		if got := info.Mode() & mask; got != mode {
			t.Errorf("%s: mode %v, want %v", path, got, mode)
		}
	}
}

// Everything extraction creates is private to the user who extracts it,
// whatever modes the archive asks for: a sender does not choose who else
// may read, change or list a decrypted secret, nor lock its owner out of
// it. Only the owner's execute bit is kept. The umask is cleared, so the
// modes cannot come from it.
func TestExtractTarCreatesPrivateEntries(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	out := t.TempDir()
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "shared/", mode: 0o777},
		tarTestEntry{typ: tar.TypeDir, name: "sticky/", mode: 0o1777},
		tarTestEntry{typ: tar.TypeDir, name: "locked/", mode: 0o500},
		tarTestEntry{typ: tar.TypeDir, name: "zero/", mode: 0},
		tarTestEntry{typ: tar.TypeReg, name: "locked/inside.txt", mode: 0o644, data: []byte("i")},
		tarTestEntry{typ: tar.TypeReg, name: "shared/secret.txt", mode: 0o666, data: []byte("s")},
		tarTestEntry{typ: tar.TypeReg, name: "shared/run.sh", mode: 0o777, data: []byte("r")},
		tarTestEntry{typ: tar.TypeLink, name: "shared/run-link.sh", link: "shared/run.sh"},
		tarTestEntry{typ: tar.TypeReg, name: "shared/others-exec", mode: 0o011, data: []byte("o")},
		tarTestEntry{typ: tar.TypeReg, name: "shared/write-only", mode: 0o200, data: []byte("w")},
		tarTestEntry{typ: tar.TypeReg, name: "shared/zero", mode: 0, data: []byte("z")},
		tarTestEntry{typ: tar.TypeReg, name: "shared/setuid", mode: 0o4777, data: []byte("u")},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	assertModes(t, map[string]os.FileMode{
		filepath.Join(out, "shared"):                0o700,
		filepath.Join(out, "sticky"):                0o700,
		filepath.Join(out, "locked"):                0o700,
		filepath.Join(out, "zero"):                  0o700,
		filepath.Join(out, "locked", "inside.txt"):  0o600,
		filepath.Join(out, "shared", "secret.txt"):  0o600,
		filepath.Join(out, "shared", "run.sh"):      0o700,
		filepath.Join(out, "shared", "run-link.sh"): 0o700,
		filepath.Join(out, "shared", "others-exec"): 0o600,
		filepath.Join(out, "shared", "write-only"):  0o600,
		filepath.Join(out, "shared", "zero"):        0o600,
		filepath.Join(out, "shared", "setuid"):      0o700,
	})
}

// KeepSpecialModes adds an entry's special bits to the private permission
// bits, and never widens them.
func TestExtractTarKeepSpecialModesStaysPrivate(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	out := t.TempDir()
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "sticky/", mode: 0o1777},
		tarTestEntry{typ: tar.TypeReg, name: "sticky/data", mode: 0o1666, data: []byte("d")},
	)
	if _, err := ExtractTar(data, out, compress.None, &Limits{KeepSpecialModes: true}); err != nil {
		t.Fatal(err)
	}
	assertModes(t, map[string]os.FileMode{
		filepath.Join(out, "sticky"): 0o700 | os.ModeSticky,
	})
	// A regular file's sticky bit is refused by some systems (EFTYPE on
	// macOS for non-root), so only its permission bits are checked.
	if info, err := os.Stat(filepath.Join(out, "sticky", "data")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("sticky/data: %v, %v; want 0600 permission bits", info, err)
	}
}

// WriteFile, which writes a payload's single files, follows the same
// rule: the file is private, executable only when mode has the owner's
// execute bit, also when it replaces an old file.
func TestWriteFileCreatesPrivateFiles(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	out := t.TempDir()
	want := map[string]os.FileMode{}
	for name, tc := range map[string]struct {
		mode os.FileMode
		want os.FileMode
	}{
		"shared.txt":  {0o666, 0o600},
		"run.sh":      {0o755, 0o700},
		"zero":        {0, 0o600},
		"write-only":  {0o200, 0o600},
		"setuid":      {0o777 | os.ModeSetuid, 0o700},
		"sub/dir-bit": {0o644 | os.ModeDir, 0o600},
	} {
		path, _, err := WriteFile(out, name, tc.mode, strings.NewReader("x"), 1, false, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want[path] = tc.want
	}
	if err := os.Chmod(filepath.Join(out, "shared.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteFile(out, "shared.txt", 0o666, strings.NewReader("y"), 1, true, nil); err != nil {
		t.Fatal(err)
	}
	want[filepath.Join(out, "sub")] = 0o700
	assertModes(t, want)
}

// Directories extraction creates without an entry of their own, the
// output directory among them, are private.
func TestExtractTarCreatesPrivateDirectories(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	data := buildTar(t, tarTestEntry{typ: tar.TypeReg, name: "sub/file.txt", mode: 0o644, data: []byte("f")})
	if _, err := ExtractTar(data, out, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteFile(out, "other/file.txt", 0o600, strings.NewReader("o"), 1, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{out, filepath.Join(out, "sub"), filepath.Join(out, "other")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s: mode %o, want 0700", dir, got)
		}
	}
}

// leftoverReader makes dir read-only on its first read, so the file being
// written can no longer be removed, then yields data.
type leftoverReader struct {
	dir  string
	data *strings.Reader
	done bool
}

func (r *leftoverReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if err := os.Chmod(r.dir, 0o500); err != nil {
			return 0, err
		}
	}
	return r.data.Read(p)
}

// A file that fails its size check and cannot be removed is reported, not
// left behind silently.
func TestWriteFileReportsFileLeftBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove files from a read-only directory")
	}
	out := t.TempDir()
	sub := filepath.Join(out, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o700) })
	r := &leftoverReader{dir: sub, data: strings.NewReader("too long")}
	_, _, err := WriteFile(out, "sub/a.txt", 0o600, r, 3, false, nil)
	if err == nil || !strings.Contains(err.Error(), "size limit") || !strings.Contains(err.Error(), "left behind") {
		t.Errorf("write: %v, want the size error and the file left behind", err)
	}
}

// outsideVictim makes <base>/victim/f outside the output directory
// <base>/out and returns both paths.
func outsideVictim(t *testing.T) (out, victim string) {
	t.Helper()
	base := t.TempDir()
	out = filepath.Join(base, "out")
	victim = filepath.Join(base, "victim", "f")
	mkdirOrFatal(t, out)
	mkdirOrFatal(t, filepath.Dir(victim))
	writeOrFatal(t, victim, []byte("victim"))
	old := time.Date(2024, 2, 2, 2, 2, 2, 0, time.UTC)
	if err := os.Chtimes(victim, old, old); err != nil {
		t.Fatal(err)
	}
	return out, victim
}

// With AllowOverwrite, an archive that writes through one of its own
// symlinks, retargets that symlink outside and then fails must not make
// the cleanup delete the file the retargeted path now names.
func TestExtractTarCleanupStaysInsideOutputDir(t *testing.T) {
	out, victim := outsideVictim(t)
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "c/", mode: 0o755},
		tarTestEntry{typ: tar.TypeDir, name: "a/", mode: 0o755},
		tarTestEntry{typ: tar.TypeSymlink, name: "a/b", link: "../c"},
		tarTestEntry{typ: tar.TypeReg, name: "a/b/f", mode: 0o644, data: []byte("inside")},
		tarTestEntry{typ: tar.TypeSymlink, name: "l2", link: "a"},
		tarTestEntry{typ: tar.TypeSymlink, name: "l2/b", link: "../../victim"},
		tarTestEntry{typ: tar.TypeSymlink, name: "dot", link: "."},
		tarTestEntry{typ: tar.TypeSymlink, name: "dot/l2", link: "zzz"},
		tarTestEntry{typ: tar.TypeFifo, name: "trigger"},
	)
	if _, err := ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true}); err == nil {
		t.Fatal("extraction through an in-archive symlink succeeded")
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "victim" {
		t.Fatalf("file outside the output directory: %q, %v", got, err)
	}
}

// Directory times are restored only on real directories: a symlink an
// archive put on a recorded directory path cannot redirect the restore.
func TestExtractTarDirectoryTimesStayInside(t *testing.T) {
	out, victim := outsideVictim(t)
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "real/", mode: 0o755},
		tarTestEntry{typ: tar.TypeSymlink, name: "link", link: "real"},
		tarTestEntry{typ: tar.TypeDir, name: "link/sub/", mode: 0o755, mtime: time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC)},
		tarTestEntry{typ: tar.TypeSymlink, name: "real/sub", link: "../../victim/f"},
	)
	_, _ = ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true})
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime of the file outside changed from %v to %v", before.ModTime(), after.ModTime())
	}
}

// An entry is never created through a symlink, whether the archive made it
// or it was already in the output directory.
func TestExtractTarRefusesEntriesThroughSymlinks(t *testing.T) {
	out, _ := outsideVictim(t)
	mkdirOrFatal(t, filepath.Join(out, "real"))
	if err := os.Symlink("real", filepath.Join(out, "link")); err != nil {
		t.Fatal(err)
	}
	data := buildTar(t, tarTestEntry{typ: tar.TypeReg, name: "link/f", mode: 0o644, data: []byte("x")})
	_, err := ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true})
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("entry through an existing symlink: %v, want a refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(out, "real", "f")); !os.IsNotExist(err) {
		t.Errorf("file was written through the symlink: %v", err)
	}
}

// With AllowOverwrite a symlink may replace a file but never a directory.
func TestExtractTarNeverReplacesDirectories(t *testing.T) {
	out, _ := outsideVictim(t)
	mkdirOrFatal(t, filepath.Join(out, "d"))
	data := buildTar(t, tarTestEntry{typ: tar.TypeSymlink, name: "d", link: "elsewhere"})
	_, err := ExtractTar(data, out, compress.None, &Limits{AllowOverwrite: true})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("symlink over a directory: %v, want a refusal", err)
	}
	if info, err := os.Lstat(filepath.Join(out, "d")); err != nil || !info.IsDir() {
		t.Errorf("directory was replaced: %v", err)
	}
}
