// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
)

// overflowingTar holds a 5-byte file and then the header of one declaring
// math.MaxInt64-2 bytes, whose data never follows: with limits at
// math.MaxInt64, adding the two sizes would wrap around.
func overflowingTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Format: tar.FormatPAX, Typeflag: tar.TypeReg, Name: "a.txt", Size: 5, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Format: tar.FormatPAX, Typeflag: tar.TypeReg, Name: "b.txt", Size: math.MaxInt64 - 2, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The total size check holds when the limits are as large as an int64
// gets, instead of wrapping around and letting the entry through.
func TestTotalSizeLimitDoesNotOverflow(t *testing.T) {
	lim := &Limits{MaxEntrySize: math.MaxInt64, MaxTotalSize: math.MaxInt64}
	data := overflowingTar(t)
	if _, _, err := ValidateTarReader(bytes.NewReader(data), compress.None, lim); err == nil || !strings.Contains(err.Error(), "total size limit") {
		t.Errorf("validate: %v, want the total size limit", err)
	}
	if _, err := ExtractTar(data, t.TempDir(), compress.None, lim); err == nil || !strings.Contains(err.Error(), "total size limit") {
		t.Errorf("extract: %v, want the total size limit", err)
	}
}

// A size limit of math.MaxInt64 writes the whole file, rather than
// overflowing the one-byte-past-the-limit probe and writing nothing.
func TestWriteFileWithLargestLimit(t *testing.T) {
	dir := t.TempDir()
	path, n, err := WriteFile(dir, "a.txt", 0o600, strings.NewReader("hello"), math.MaxInt64, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "hello" || n != 5 {
		t.Errorf("wrote %d bytes, file %q, %v; want hello", n, got, err)
	}
}

// Extraction leaves out the xattr namespaces that carry privileges or
// access: file capabilities, SELinux labels and ACLs.
func TestRestorableXattr(t *testing.T) {
	for name, want := range map[string]bool{
		"user.ds_test":            true,
		"com.apple.FinderInfo":    true,
		"security.capability":     false,
		"security.selinux":        false,
		"trusted.overlay.opaque":  false,
		"system.posix_acl_access": false,
	} {
		if got := restorableXattr(name); got != want {
			t.Errorf("restorableXattr(%q) = %v, want %v", name, got, want)
		}
	}
}

// Two files on different devices whose (dev, ino) pairs combined into one
// number used to collide get distinct keys, so neither is archived as a
// link to the other.
func TestHardLinkKeyKeepsDevAndIno(t *testing.T) {
	a := sysFileInfo{Dev: 1, Ino: 1<<32 | 5}
	b := sysFileInfo{Dev: 0, Ino: 5}
	ka, okA := a.hardLinkKey()
	kb, okB := b.hardLinkKey()
	if !okA || !okB || ka == kb {
		t.Errorf("keys %v (%v) and %v (%v) must differ", ka, okA, kb, okB)
	}
	if _, ok := (sysFileInfo{Dev: 1}).hardLinkKey(); ok {
		t.Error("a file without an inode number has no key")
	}
}

// buildTar builds an uncompressed tar of entries in order, each a header
// and, for a regular file, its data.
func buildTar(t *testing.T, entries ...tarTestEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Format: tar.FormatPAX, Typeflag: e.typ, Name: e.name, Linkname: e.link, Mode: e.mode, Size: int64(len(e.data)), ModTime: e.mtime, PAXRecords: e.pax}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarTestEntry struct {
	typ   byte
	name  string
	link  string // a symlink's or hard link's target
	mode  int64
	data  []byte
	pax   map[string]string
	mtime time.Time
}

// A directory entry that names a directory already there leaves it as it
// is: an archive cannot change the mode of what it did not create.
func TestExtractTarLeavesExistingDirectoriesAlone(t *testing.T) {
	out := t.TempDir()
	keep := filepath.Join(out, "keep")
	if err := os.Mkdir(keep, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keep, 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(keep)
	if err != nil {
		t.Fatal(err)
	}
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "keep/", mode: 0o777},
		tarTestEntry{typ: tar.TypeReg, name: "keep/a.txt", mode: 0o600, data: []byte("a")},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(keep)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Errorf("existing directory mode %v became %v", before.Mode(), after.Mode())
	}
}

// A directory entry over an existing file is refused rather than skipped.
func TestExtractTarRefusesDirectoryOverFile(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "taken"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := buildTar(t, tarTestEntry{typ: tar.TypeDir, name: "taken/", mode: 0o755})
	if _, err := ExtractTar(data, out, compress.None, nil); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("extract: %v, want a refusal", err)
	}
}
