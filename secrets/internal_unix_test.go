// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

// A folder that keeps ciphertext between runs must be private: other users
// could otherwise read its records or swap its files.
func TestResumeFoldersMustBePrivate(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
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
