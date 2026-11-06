// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !nofido2 && (darwin || linux) && (amd64 || arm64)

package fido2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

func TestTrustedLibrary(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "libfido2.so.1.17.0")
	if err := os.WriteFile(good, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "libfido2.so.1")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := trustedLibrary(link)
	if err != nil {
		t.Fatalf("a private library was refused: %v", err)
	}
	if want, _ := filepath.EvalSymlinks(good); resolved != want {
		t.Errorf("resolved %s, want %s", resolved, want)
	}

	writable := filepath.Join(dir, "writable.so")
	if err := os.WriteFile(writable, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedLibrary(writable); err == nil {
		t.Error("a library others can write was accepted")
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	inOpen := filepath.Join(open, "libfido2.so.1")
	if err := os.WriteFile(inOpen, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedLibrary(inOpen); err == nil {
		t.Error("a library in a directory others can write was accepted")
	}
	if _, err := trustedLibrary(dir); err == nil {
		t.Error("a directory was accepted")
	}
	if _, err := trustedLibrary(filepath.Join(dir, "missing.so")); !os.IsNotExist(err) {
		t.Errorf("missing library: %v, want not exist", err)
	}
}

func TestLibraryPathsAreAbsolute(t *testing.T) {
	for _, p := range libraryPaths() {
		if !filepath.IsAbs(p) {
			t.Errorf("%s is not absolute", p)
		}
	}
}

// shortWait makes waits for a security key last wait, looking every poll,
// for one test.
func shortWait(t *testing.T, wait, poll time.Duration) {
	t.Helper()
	oldWait, oldPoll := insertWait, insertPoll
	insertWait, insertPoll = wait, poll
	t.Cleanup(func() { insertWait, insertPoll = oldWait, oldPoll })
}

// countPrompt answers no PIN and counts the requests to plug in a key.
type countPrompt struct{ inserts []string }

func (*countPrompt) PIN(context.Context, string, int, bool) ([]byte, error) {
	return nil, errors.New("no PIN in tests")
}
func (*countPrompt) Touch(string, string) {}
func (*countPrompt) TouchDone()           {}
func (p *countPrompt) Insert(want string) { p.inserts = append(p.inserts, want) }

func TestWaitForKey(t *testing.T) {
	shortWait(t, 200*time.Millisecond, time.Millisecond)
	ctx := context.Background()

	t.Run("there at once", func(t *testing.T) {
		p := &countPrompt{}
		if err := waitForKey(ctx, p, "it", func() (bool, error) { return true, nil }); err != nil {
			t.Fatal(err)
		}
		if len(p.inserts) != 0 {
			t.Errorf("asked %d times, want none", len(p.inserts))
		}
	})
	t.Run("plugged in later", func(t *testing.T) {
		p := &countPrompt{}
		tries := 0
		err := waitForKey(ctx, p, "the key", func() (bool, error) { tries++; return tries == 3, nil })
		if err != nil {
			t.Fatal(err)
		}
		if len(p.inserts) != 1 || p.inserts[0] != "the key" {
			t.Errorf("asked %q, want once for the key", p.inserts)
		}
	})
	t.Run("an error stops at once", func(t *testing.T) {
		p := &countPrompt{}
		boom := errors.New("boom")
		if err := waitForKey(ctx, p, "it", func() (bool, error) { return false, boom }); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
		if len(p.inserts) != 0 {
			t.Errorf("asked %d times, want none", len(p.inserts))
		}
	})
	t.Run("never plugged in", func(t *testing.T) {
		p := &countPrompt{}
		if err := waitForKey(ctx, p, "it", func() (bool, error) { return false, nil }); !errors.Is(err, errNotPlugged) {
			t.Fatalf("err = %v, want errNotPlugged", err)
		}
		if len(p.inserts) != 1 {
			t.Errorf("asked %d times, want once", len(p.inserts))
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		shortWait(t, time.Minute, 10*time.Millisecond)
		cctx, cancel := context.WithCancel(ctx)
		p := &countPrompt{}
		tries := 0
		err := waitForKey(cctx, p, "it", func() (bool, error) {
			if tries++; tries == 2 {
				cancel()
			}
			return false, nil
		})
		if !errors.Is(err, keystore.ErrCancelled) {
			t.Fatalf("err = %v, want ErrCancelled", err)
		}
	})
}

// TestDeriveWithoutAnEnrolledKey runs against the real libfido2 when it
// is installed: no connected device holds a random credential, so Derive
// asks to plug the key in, then fails with ErrNoSecurityKey, after silent
// checks only, with no touch or PIN.
func TestDeriveWithoutAnEnrolledKey(t *testing.T) {
	st, err := Check()
	if errors.Is(err, keystore.ErrNoSecurityKeySupport) {
		t.Skipf("no security key support here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("libfido2 %s, %d devices", st.Library, len(st.Devices))
	shortWait(t, 300*time.Millisecond, 100*time.Millisecond)
	p := &countPrompt{}
	_, err = New(p).Derive(context.Background(), keystore.DeriveRequest{
		RPID:        keystore.SecurityKeyRPID,
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Credentials: []keystore.DeriveCredential{{ID: make([]byte, 64), PRFInput: make([]byte, 32), Label: "Test key"}},
	})
	if !errors.Is(err, keystore.ErrNoSecurityKey) {
		t.Errorf("Derive = %v, want ErrNoSecurityKey", err)
	}
	if len(p.inserts) != 1 || p.inserts[0] != `the security key "Test key"` {
		t.Errorf("asked %q, want once for the test key", p.inserts)
	}
}
