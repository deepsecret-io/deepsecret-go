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

	"github.com/deepsecret-io/sdk/compress"
)

// Extraction applies the umask to the archive's modes, as open(2) and
// mkdir(2) do, instead of setting the sender's modes exactly: a user with
// umask 077 keeps decrypted files private whatever the archive says.
func TestExtractTarAppliesUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	out := t.TempDir()
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "shared/", mode: 0o777},
		tarTestEntry{typ: tar.TypeReg, name: "shared/secret.txt", mode: 0o666, data: []byte("s")},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(out, "shared"):               0o700,
		filepath.Join(out, "shared", "secret.txt"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", path, got, want)
		}
	}
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
