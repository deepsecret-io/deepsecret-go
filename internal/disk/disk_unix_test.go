// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A folder that keeps ciphertext between runs must be private: other users
// could otherwise read its records or swap its files.
func TestCheckPrivateDir(t *testing.T) {
	base := t.TempDir()
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(private); err != nil {
		t.Fatalf("private folder refused: %v", err)
	}

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(open, 0o777)
	if err := CheckPrivateDir(open); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("world-writable folder: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(link); err == nil {
		t.Fatal("a symlink to a private folder was accepted")
	}
}

// A key file someone else may read is refused, as it is on Windows: the
// key in it is no longer private, and someone else may have put it there.
// The refusal names the command that fixes it.
func TestReadPrivateRefusesAnExposedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, []byte(`{"k":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPrivate(path); err != nil || string(got) != `{"k":1}` {
		t.Fatalf("a private file: %q, %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ReadPrivate(path)
		if err == nil || !strings.Contains(err.Error(), "is open to other users") || !strings.Contains(err.Error(), "chmod 600 "+path) {
			t.Errorf("mode %o: %v, want a refusal naming chmod 600", mode, err)
		}
	}
	if _, err := ReadPrivate(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Errorf("a missing file: %v, want not exist", err)
	}
}
