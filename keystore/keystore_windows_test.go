// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package keystore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// A key file someone else may open is refused: its private keys are no
// longer private, and someone may have put it there. Saving the key again
// makes it private.
func TestKeyFileOthersMayOpenIsRefused(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	dir := filepath.Join(t.TempDir(), "keys")
	if err := Save(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, dir)
	path := filepath.Join(dir, fp+".json")
	disktest.AssertPrivate(t, path)

	disktest.Expose(t, path)
	if _, err := Load(dir, fp, ""); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Errorf("Load of an exposed key file: %v", err)
	}
	if _, err := ReadInfo(dir, fp); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Errorf("ReadInfo of an exposed key file: %v", err)
	}
	if err := Save(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, path)
	if _, err := Load(dir, fp, ""); err != nil {
		t.Errorf("the key saved again: %v", err)
	}
}
