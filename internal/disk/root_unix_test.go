// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disk

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

// CreateIn and MkdirIn create new files and folders with the mode asked
// for, never open what is already at the name, a link included, and never
// create anything outside the root.
func TestCreateInStaysInsideTheRoot(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	base := t.TempDir()
	dir, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, d := range []string{dir, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root := openRoot(t, dir)

	if err := MkdirIn(root, "sub", 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := CreateIn(root, filepath.Join("sub", "f"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{filepath.Join(dir, "sub"): 0o700, filepath.Join(dir, "sub", "f"): 0o600} {
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v, %v; want mode %v", path, info, err, want)
		}
	}
	if _, err := CreateIn(root, filepath.Join("sub", "f"), 0o600); !os.IsExist(err) {
		t.Errorf("a file already there: %v, want exist", err)
	}
	if err := MkdirIn(root, "sub", 0o700); !os.IsExist(err) {
		t.Errorf("a folder already there: %v, want exist", err)
	}

	// A dangling link at the name: refused, its target not created.
	if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateIn(root, "link", 0o600); !os.IsExist(err) {
		t.Errorf("a link at the name: %v, want exist", err)
	}
	// A folder on the way that leads out of the root.
	if err := os.Symlink("../outside", filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateIn(root, filepath.Join("out", "f"), 0o600); err == nil {
		t.Error("created a file through a link out of the root")
	}
	if err := MkdirIn(root, filepath.Join("out", "d"), 0o700); err == nil {
		t.Error("created a folder through a link out of the root")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Errorf("the folder outside holds %v, %v", entries, err)
	}
}

// OpenDirIn opens a folder for its metadata and refuses a link to one, or
// a file; SetTimes sets the times through the handle.
func TestOpenDirInRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := openRoot(t, dir)
	for _, name := range []string{"link", "file", "missing"} {
		if f, err := OpenDirIn(root, name); err == nil {
			f.Close()
			t.Errorf("%s opened as a folder", name)
		}
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
		t.Errorf("folder mtime: %v, %v; want %v", info.ModTime(), err, mtime)
	}
}

// A FIFO swapped in for a folder makes OpenDirIn fail at once, instead of
// blocking until someone opens the FIFO's other end.
func TestOpenDirInDoesNotBlockOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	root := openRoot(t, dir)
	done := make(chan error, 1)
	go func() {
		f, err := OpenDirIn(root, "fifo")
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO opened as a folder")
		}
	case <-time.After(5 * time.Second):
		// Unblock the open so the test can end.
		if w, err := os.OpenFile(filepath.Join(dir, "fifo"), os.O_WRONLY, 0); err == nil {
			w.Close()
		}
		t.Fatal("OpenDirIn blocked on a FIFO")
	}
}
