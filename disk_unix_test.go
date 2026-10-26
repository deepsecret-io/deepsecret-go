// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package sdk

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
	if err := checkPrivateDir(private); err != nil {
		t.Fatalf("private folder refused: %v", err)
	}

	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(open, 0o777)
	if err := checkPrivateDir(open); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("world-writable folder: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivateDir(link); err == nil {
		t.Fatal("a symlink to a private folder was accepted")
	}

	// The upload folder is checked before anything is read from or kept in
	// it.
	if _, err := ListPendingUploads(open); err == nil {
		t.Fatal("pending uploads were listed from an open folder")
	}
	if _, err := newSendSpool(EncryptOptions{ResumeDir: open}, "10000000-0000-4000-8000-000000000001", 0); err == nil {
		t.Fatal("a send kept its ciphertext in an open folder")
	}
}
