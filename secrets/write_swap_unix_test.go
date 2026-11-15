// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package secrets_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/payload"
	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// swapWhen is a context that, the first time it is asked whether it is
// done once ready says so, runs swap: a hook into the middle of a write,
// since decryption asks between chunks.
type swapWhen struct {
	context.Context
	ready func() bool
	swap  func()
	once  *sync.Once
}

func (s swapWhen) Err() error {
	if s.ready() {
		s.once.Do(s.swap)
	}
	return nil
}

// Another account that may rename in the folder above the output directory
// swaps the output directory for a symlink while the first file is being
// written, after every check has passed. The rest of the write still lands
// in the output directory that was checked, never where the link leads.
func TestWriteFilesStayInOutputDirSwappedForLink(t *testing.T) {
	const size = 1 << 20
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	id := sendRaw(t, f, payload.Payload{Type: "files", Files: []payload.FileEntry{
		randomEntry(t, "a.bin", size), randomEntry(t, "b.bin", size),
	}})
	base := t.TempDir()
	out, outside := filepath.Join(base, "out"), filepath.Join(base, "outside")
	for _, dir := range []string{out, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	opened, err := f.client("bob@example.com").Secrets.Open(context.Background(), id, secrets.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	swapped := false
	ctx := swapWhen{Context: context.Background(), once: new(sync.Once),
		ready: func() bool { _, err := os.Lstat(filepath.Join(out, "a.bin")); return err == nil },
		swap: func() {
			swapped = true
			if err := os.Rename(out, out+".moved"); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(outside, out); err != nil {
				t.Error(err)
			}
		}}
	_, _ = opened.WriteFiles(ctx, out, secrets.WriteOptions{})
	if !swapped {
		t.Fatal("the output directory was never swapped")
	}
	if got := listTree(t, outside); got != "" {
		t.Errorf("the write reached the folder the link leads to: %s", got)
	}
	if got := listTree(t, out+".moved"); got != "a.bin,b.bin" {
		t.Errorf("the output directory holds %s, want a.bin and b.bin", got)
	}
}
