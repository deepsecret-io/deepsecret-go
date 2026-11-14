// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// A folder sent while one of its logs is being written stops with
// ErrFileChanged naming the log, not the archive the folder goes out as.
// The link makes the folder go out as an archive, as /var/log does.
func TestSendNamesALogThatGrows(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := filepath.Join(t.TempDir(), "log")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "syslog")
	if err := os.WriteFile(logPath, bytes.Repeat([]byte("a log line\n"), 1<<16), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("syslog", filepath.Join(dir, "README")); err != nil {
		t.Fatal(err)
	}

	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		w, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer w.Close()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = w.WriteString("one more line\n")
			}
		}
	}()
	_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{dir},
		secrets.EncryptOptions{LocalFile: filepath.Join(t.TempDir(), "log"+secrets.LocalFileExt)})
	close(stop)
	<-stopped

	if !errors.Is(err, secrets.ErrFileChanged) {
		t.Fatalf("EncryptPaths: %v, want ErrFileChanged", err)
	}
	if msg := err.Error(); !strings.Contains(msg, filepath.Join("log", "syslog")) || strings.Contains(msg, "archive.tar") {
		t.Fatalf("the error does not name the log: %v", err)
	}
}

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
