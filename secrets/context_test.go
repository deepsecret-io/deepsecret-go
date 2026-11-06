// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// openSent sends a payload to bob and opens it with ctx.
func openSent(t *testing.T, ctx context.Context, size int) (*secrets.OpenedSecret, secrets.DecryptOptions) {
	t.Helper()
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "data.bin")
	writeFile(t, src, randomBytes(t, size), 0o600)
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	opt := secrets.DecryptOptions{TempDir: t.TempDir()}
	opened, err := f.client("bob@example.com").Secrets.Open(ctx, res.Secret.ID, opt)
	if err != nil {
		t.Fatal(err)
	}
	return opened, opt
}

// The context given to Open covers Open: the decrypt after it ends with its own.
func TestPayloadUsesItsOwnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	opened, _ := openSent(t, ctx, 1<<10)
	defer opened.Close()
	cancel()
	if _, err := opened.Payload(context.Background()); err != nil {
		t.Fatalf("Payload after Open's context ended: %v", err)
	}
}

// A decrypt that is cancelled stops, and Close still cleans up after it.
func TestCancelledPayloadLeavesNothingBehind(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	opened, opt := openSent(t, context.Background(), 12<<20)
	if !opened.OnDisk() {
		t.Fatal("the test needs a ciphertext on disk")
	}
	if _, err := opened.Payload(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Payload = %v, want context.Canceled", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadDir(opt.TempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestWriteFilesUsesItsOwnContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	opened, _ := openSent(t, context.Background(), 1<<10)
	defer opened.Close()
	out := filepath.Join(t.TempDir(), "out")
	if _, err := opened.WriteFiles(cancelled, out, secrets.WriteOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteFiles = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the cancelled write created its output: %v", err)
	}
	if _, err := opened.WriteFiles(context.Background(), out, secrets.WriteOptions{}); err != nil {
		t.Fatalf("WriteFiles after a cancelled one: %v", err)
	}
}
