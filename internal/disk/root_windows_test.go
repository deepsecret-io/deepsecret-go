// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disk

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
)

// openRoot opens dir as a root, closed when the test ends.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// What CreateIn and MkdirIn create inside a root is private from the
// moment it exists, as what CreateTemp and Mkdir create on a path is, even
// in a folder others may open: os.Root alone would give it the folder's
// inherited ACL.
func TestCreateInIsPrivate(t *testing.T) {
	dir := t.TempDir()
	root := openRoot(t, dir)
	if err := MkdirIn(root, "sub", 0o755); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, filepath.Join(dir, "sub"))
	disktest.SetDACL(t, filepath.Join(dir, "sub"), "D:P(A;OICI;FA;;;"+disktest.CurrentUser(t).String()+")(A;OICI;FR;;;BU)")

	name := filepath.Join("sub", "entry.txt")
	f, err := CreateIn(root, name, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("plaintext"); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2003, 3, 3, 3, 3, 3, 0, time.UTC)
	if err := SetTimes(f, mtime); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, filepath.Join(dir, name))
	if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.ModTime().Equal(mtime) {
		t.Errorf("file mtime: %v, %v; want %v", info, err, mtime)
	}
	if _, err := CreateIn(root, name, 0o600); !os.IsExist(err) {
		t.Errorf("a file already there: %v, want exist", err)
	}
	if err := MkdirIn(root, filepath.Join("sub", "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, filepath.Join(dir, "sub", "inner"))

	readOnly := filepath.Join("sub", "read-only.txt")
	f, err = CreateIn(root, readOnly, 0o444)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, readOnly)); err != nil || info.Mode().Perm()&0o200 != 0 {
		t.Errorf("a 0444 file: %v, %v; want the read-only attribute", info, err)
	}
	if err := os.Chmod(filepath.Join(dir, readOnly), 0o600); err != nil { // so t.TempDir can remove it
		t.Fatal(err)
	}
}

// A name Windows would not keep as written is refused: a stream of
// another file, a device, or a trailing dot or space the Win32 layer
// strips, which os.Root would read as another name.
func TestCreateInRefusesNamesWindowsRewrites(t *testing.T) {
	dir := t.TempDir()
	root := openRoot(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt:stream", "NUL", "COM1.txt", "dot.", "space ", `..\escape`} {
		if f, err := CreateIn(root, name, 0o600); err == nil {
			f.Close()
			t.Errorf("CreateIn(%q) succeeded", name)
		}
		if err := MkdirIn(root, name, 0o700); err == nil {
			t.Errorf("MkdirIn(%q) succeeded", name)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "a" {
		t.Errorf("a.txt holds %q", got)
	}
}

// OpenDirIn opens a folder and refuses a file or a link to a folder.
func TestOpenDirInRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	root := openRoot(t, dir)
	if err := MkdirIn(root, "sub", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDirIn(root, "sub")
	if err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2003, 3, 3, 3, 3, 3, 0, time.UTC)
	if err := SetTimes(d, mtime); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "sub")); err != nil || !info.ModTime().Equal(mtime) {
		t.Errorf("folder mtime: %v, %v; want %v", info, err, mtime)
	}
	if f, err := OpenDirIn(root, "file"); err == nil {
		f.Close()
		t.Error("a file opened as a folder")
	}
	if err := os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
	}
	if f, err := OpenDirIn(root, "link"); err == nil {
		f.Close()
		t.Error("a link to a folder opened as a folder")
	}
}
