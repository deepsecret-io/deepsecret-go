// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package secrets_test

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// A FIFO among the paths is refused, not opened: opening it would block the
// send until something wrote to it, with no way to cancel.
func TestSendRefusesAFIFO(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{fifo}, secrets.EncryptOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the send blocked on the FIFO")
	}
}
