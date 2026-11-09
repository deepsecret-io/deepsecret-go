// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !windows

package disktest

import (
	"os"
	"testing"
)

// AssertPrivate fails t unless path is private to this user as the SDK
// makes what it keeps: a regular file with mode 0600, or a folder with
// mode 0700.
func AssertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if info.IsDir() {
		want = 0o700
	} else if !info.Mode().IsRegular() {
		t.Fatalf("%s is %v, want a regular file or a folder", path, info.Mode())
	}
	if info.Mode().Perm() != want {
		t.Errorf("%s has mode %v, want %v", path, info.Mode().Perm(), want)
	}
}

// MakePrivate makes the folder dir private to this user (0700), as a test
// that hands it to the SDK needs.
func MakePrivate(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a folder needs its execute bit; 0700 is the owner's alone.
		t.Fatal(err)
	}
}
