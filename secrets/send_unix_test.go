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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// logLine is what each log starts with, and what grow appends.
var logLine = []byte("a log line\n")

// logFolder makes a folder of logs named names. With a link in it the
// folder goes out as an archive, as /var/log does; without, as files.
func logFolder(t *testing.T, link bool, names ...string) (string, []string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "log")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, bytes.Repeat(logLine, 1<<16), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if link {
		if err := os.Symlink(names[0], filepath.Join(dir, "README")); err != nil {
			t.Fatal(err)
		}
	}
	return dir, paths
}

// grow keeps appending lines to each of paths until the returned stop is
// called, as programs writing their logs do.
func grow(t *testing.T, paths ...string) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	for _, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Errorf("open %s to grow it: %v", path, err)
				return
			}
			defer w.Close()
			for {
				select {
				case <-done:
					return
				default:
					_, _ = w.Write(logLine)
				}
			}
		}()
	}
	return func() { close(done); wg.Wait() }
}

// bothWays runs a test for a folder sent as an archive and as files.
func bothWays(t *testing.T, test func(t *testing.T, link bool)) {
	for name, link := range map[string]bool{"archive": true, "files": false} {
		t.Run(name, func(t *testing.T) { test(t, link) })
	}
}

// A folder sent while its logs are being written stops with ErrFileChanged
// naming every log that changed, not only the first the send met, and
// never the archive the folder may go out as.
func TestSendNamesTheLogsThatGrow(t *testing.T) {
	bothWays(t, func(t *testing.T, link bool) {
		f := newFakeAPI(t, "alice@example.com", "bob@example.com")
		dir, logs := logFolder(t, link, "auth.log", "syslog")
		stop := grow(t, logs...)
		_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{dir},
			secrets.EncryptOptions{LocalFile: filepath.Join(t.TempDir(), "log"+secrets.LocalFileExt)})
		stop()

		if !errors.Is(err, secrets.ErrFileChanged) {
			t.Fatalf("EncryptPaths: %v, want ErrFileChanged", err)
		}
		msg := err.Error()
		for _, name := range []string{"auth.log", "syslog"} {
			if !strings.Contains(msg, filepath.Join("log", name)) {
				t.Errorf("the error does not name %s: %v", name, err)
			}
		}
		if !strings.Contains(msg, "1 more file changed during the send") || strings.Contains(msg, "archive.tar") {
			t.Errorf("the error does not list the other log: %v", err)
		}
	})
}

// A snapshot send of a folder whose logs are being written goes through,
// and each log the recipient decrypts is the start of the log as it is
// now, at least as long as it was before the send: the bytes it had when
// the send measured it, nothing else.
func TestSnapshotSendsLogsThatGrow(t *testing.T) {
	bothWays(t, func(t *testing.T, link bool) {
		f := newFakeAPI(t, "alice@example.com", "bob@example.com")
		dir, logs := logFolder(t, link, "auth.log", "syslog")
		local := filepath.Join(t.TempDir(), "log"+secrets.LocalFileExt)
		stop := grow(t, logs...)
		_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{dir},
			secrets.EncryptOptions{LocalFile: local, Snapshot: true})
		stop()
		if err != nil {
			t.Fatalf("EncryptPaths with Snapshot: %v", err)
		}

		o, err := f.client("bob@example.com").Secrets.OpenLocalFile(context.Background(), local, secrets.DecryptOptions{TempDir: t.TempDir()})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer o.Close()
		dst := t.TempDir()
		if _, err := o.WriteFiles(context.Background(), dst, secrets.WriteOptions{}); err != nil {
			t.Fatalf("write: %v", err)
		}
		for _, path := range logs {
			sent, err := os.ReadFile(filepath.Join(dst, "log", filepath.Base(path)))
			if err != nil {
				t.Fatal(err)
			}
			now, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(sent) < len(logLine)<<16 || !bytes.HasPrefix(now, sent) {
				t.Errorf("%s went out as %d bytes that are not the start of the log (%d bytes now)", filepath.Base(path), len(sent), len(now))
			}
		}
	})
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
