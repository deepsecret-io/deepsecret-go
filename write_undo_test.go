// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/deepsecret-io/sdk/payload"
)

// stopWhen is a context that reports itself cancelled once stop says so,
// to fail a write at a chosen point.
type stopWhen struct {
	context.Context
	stop func() bool
}

func (s stopWhen) Err() error {
	if s.stop() {
		return context.Canceled
	}
	return nil
}

// complete reports whether path holds size bytes, a file fully written.
func complete(path string, size int64) func() bool {
	return func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() == size
	}
}

// listTree lists every path under dir, relative and slash-separated.
func listTree(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err == nil && path != dir {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func randomEntry(t *testing.T, name string, size int) payload.FileEntry {
	data := randomBytes(t, size)
	sum := sha256.Sum256(data)
	return payload.FileEntry{Name: name, Data: data, Size: int64(size), SHA256: hex.EncodeToString(sum[:]), Mode: 0o600}
}

// A write that fails midway, after a file is fully on disk, removes what it
// created (files, directories, files it overwrote) and leaves what was
// there before.
func TestWriteFilesFailureRemovesWhatItCreated(t *testing.T) {
	const size = 1 << 20
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	bob := f.client("bob@example.com")
	id := sendRaw(t, f, payload.Payload{Type: "files", Files: []payload.FileEntry{
		randomEntry(t, "new/a.bin", size), randomEntry(t, "b.bin", size),
	}})

	for _, overwrite := range []bool{false, true} {
		out := t.TempDir()
		writeFile(t, filepath.Join(out, "keep.txt"), []byte("mine"), 0o644)
		if overwrite {
			writeFile(t, filepath.Join(out, "new", "a.bin"), []byte("old"), 0o644)
		}
		opened, err := bob.OpenSecret(id, DecryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		opened.ctx = stopWhen{context.Background(), complete(filepath.Join(out, "new", "a.bin"), size)}
		_, err = opened.WriteFiles(out, WriteOptions{Overwrite: overwrite})
		opened.Close()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("overwrite=%v: %v, want the write stopped", overwrite, err)
		}
		want := "keep.txt" // a.bin it overwrote is gone, as is new/ when it made it
		if overwrite {
			want = "keep.txt,new"
		}
		if got := listTree(t, out); got != want {
			t.Errorf("overwrite=%v: the output holds %s, want %s", overwrite, got, want)
		}
		assertFile(t, filepath.Join(out, "keep.txt"), []byte("mine"), 0o644)
	}
}

// The same holds for an archive stopped after its first file is written.
func TestWriteFilesArchiveFailureRemovesWhatItCreated(t *testing.T) {
	const size = 1 << 20
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "tree")
	writeFile(t, filepath.Join(src, "one.bin"), randomBytes(t, size), 0o600)
	writeFile(t, filepath.Join(src, "two.bin"), randomBytes(t, size), 0o600)
	res, err := f.client("alice@example.com").EncryptPaths([]string{"bob@example.com"}, []string{src},
		EncryptOptions{Name: "bundle", Archive: true, Compress: CompressZstd})
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	writeFile(t, filepath.Join(out, "keep.txt"), []byte("mine"), 0o644)
	opened, err := f.client("bob@example.com").OpenSecret(res.Secret.ID, DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	opened.ctx = stopWhen{context.Background(), complete(filepath.Join(out, "tree", "one.bin"), size)}
	if _, err := opened.WriteFiles(out, WriteOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v, want the write stopped", err)
	}
	if got := listTree(t, out); got != "keep.txt" {
		t.Errorf("the output holds %s, want keep.txt alone", got)
	}
}
