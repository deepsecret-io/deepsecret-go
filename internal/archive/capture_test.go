// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
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
