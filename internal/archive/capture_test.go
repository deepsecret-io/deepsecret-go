// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
	"github.com/deepsecret-io/deepsecret-go/internal/payload"
)

// fullPath is the path on disk of the entry archived as rel.
func fullPath(t *testing.T, files []ExpandedFile, rel string) string {
	t.Helper()
	for _, f := range files {
		if strings.HasSuffix(f.RelPath, rel) {
			return f.FullPath
		}
	}
	t.Fatalf("no entry %s", rel)
	return ""
}

// A file that changes after NewTar captured it fails Write with an error
// that names the file, however it changed: a log that grows, a file cut
// short, one replaced or removed (log rotation), or one swapped for a link
// to another file, whose bytes must not go out under the captured name.
func TestTarWriteNamesAChangedFile(t *testing.T) {
	changes := map[string]func(t *testing.T, path string){
		"grew": func(t *testing.T, path string) {
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteString("one more line\n"); err != nil {
				t.Fatal(err)
			}
		},
		"shrank": func(t *testing.T, path string) {
			if err := os.Truncate(path, 1); err != nil {
				t.Fatal(err)
			}
		},
		"replaced": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeOrFatal(t, path+".new", b) // the same bytes, as another file
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	}
	if runtime.GOOS != "windows" {
		changes["swapped for a link"] = func(t *testing.T, path string) {
			other := filepath.Join(filepath.Dir(path), "other")
			writeOrFatal(t, other, bytes.Repeat([]byte{7}, 70000))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			files := sampleTree(t)
			path := fullPath(t, files, "nested/b.bin")
			tarball, err := NewTar(files)
			if err != nil {
				t.Fatal(err)
			}
			change(t, path)
			err = tarball.Write(io.Discard, compress.None)
			if !errors.Is(err, payload.ErrFileChanged) {
				t.Fatalf("Write: %v, want a changed-file error", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the error does not name %s: %v", path, err)
			}
		})
	}
}

// Changed lists, in capture order, the files that are no longer as
// captured: grown, removed or replaced. An untouched file is not listed.
func TestChanged(t *testing.T) {
	dir := t.TempDir()
	var files []Captured
	for _, name := range []string{"a.log", "b.log", "c.log", "d.log"} {
		path := filepath.Join(dir, name)
		writeOrFatal(t, path, []byte("one line\n"))
		info, err := Capture(path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, Captured{Path: path, Info: info})
	}
	f, err := os.OpenFile(files[0].Path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("two lines\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := os.Remove(files[2].Path); err != nil {
		t.Fatal(err)
	}
	writeOrFatal(t, files[3].Path+".new", []byte("one line\n"))
	if err := os.Rename(files[3].Path+".new", files[3].Path); err != nil {
		t.Fatal(err)
	}

	got := Changed(files, false)
	want := []string{files[0].Path, files[2].Path, files[3].Path}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Changed: %v, want %v", got, want)
	}
	// In a snapshot, a file that only grew is no change.
	got = Changed(files, true)
	want = []string{files[2].Path, files[3].Path}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Changed in a snapshot: %v, want %v", got, want)
	}
}

// A snapshot archive sends a file that grew after the capture with the
// bytes it had then; a file cut short still stops it, naming the file.
func TestTarSnapshot(t *testing.T) {
	files := sampleTree(t)
	path := fullPath(t, files, "nested/b.bin")
	tarball, err := NewTar(files)
	if err != nil {
		t.Fatal(err)
	}
	tarball.Snapshot = true
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("one more line\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	var buf bytes.Buffer
	if err := tarball.Write(&buf, compress.None); err != nil {
		t.Fatalf("a snapshot of a grown file: %v", err)
	}
	if tarball.Size != int64(buf.Len()) {
		t.Fatalf("Size %d, Write wrote %d", tarball.Size, buf.Len())
	}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("no nested/b.bin in the archive: %v", err)
		}
		if strings.HasSuffix(hdr.Name, "nested/b.bin") {
			data, err := io.ReadAll(tr)
			if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{7}, 70000)) {
				t.Fatalf("b.bin went out as %d bytes (%v), want its 70000 captured bytes", len(data), err)
			}
			break
		}
	}

	if err := os.Truncate(path, 1); err != nil {
		t.Fatal(err)
	}
	if err := tarball.Write(io.Discard, compress.None); !errors.Is(err, payload.ErrFileChanged) || !strings.Contains(err.Error(), path) {
		t.Fatalf("a snapshot of a file cut short: %v", err)
	}
}

// A Tar's Captured lists its regular files, the ones Write reads.
func TestTarCaptured(t *testing.T) {
	files := sampleTree(t)
	tarball, err := NewTar(files)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range tarball.Captured() {
		got = append(got, filepath.Base(c.Path))
	}
	// Without inode numbers, Windows archives the hard link as a copy.
	want := "a.txt,empty,b.bin"
	if runtime.GOOS == "windows" {
		want = "a.txt,empty,hard,b.bin"
	}
	if strings.Join(got, ",") != want {
		t.Fatalf("Captured: %v, want %s", got, want)
	}
}

// OpenCaptured opens the file it captured, and refuses a path that now
// holds another file.
func TestOpenCaptured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeOrFatal(t, path, []byte("abc"))
	info, err := Capture(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := OpenCaptured(path, info)
	if err != nil {
		t.Fatalf("the captured file: %v", err)
	}
	_ = f.Close()

	writeOrFatal(t, path+".new", []byte("abc"))
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCaptured(path, info); !errors.Is(err, payload.ErrFileChanged) || !strings.Contains(err.Error(), path) {
		t.Fatalf("a replaced file: %v", err)
	}
}
