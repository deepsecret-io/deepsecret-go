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
