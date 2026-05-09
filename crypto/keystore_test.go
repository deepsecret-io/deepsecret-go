// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadKeyPair(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	tmpDir := t.TempDir()

	if err := SaveKeyPairTo(tmpDir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeyPairFrom(tmpDir, fp, "")
	if err != nil {
		t.Fatal(err)
	}
	loadedFP, _ := Fingerprint(loaded)
	if loadedFP != fp {
		t.Errorf("loaded fingerprint = %q, want %q", loadedFP, fp)
	}
	if loaded.StorageVersion != KeyStorageVersion {
		t.Errorf("storage version = %d, want %d", loaded.StorageVersion, KeyStorageVersion)
	}
}

func TestSaveLoadKeyPairWithPassword(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	tmpDir := t.TempDir()

	if err := SaveKeyPairTo(tmpDir, fp, kp, "mypassword"); err != nil {
		t.Fatal(err)
	}

	// Wrong password
	if _, err := LoadKeyPairFrom(tmpDir, fp, "wrongpassword"); err == nil {
		t.Error("wrong password should fail")
	}

	// Correct password
	loaded, err := LoadKeyPairFrom(tmpDir, fp, "mypassword")
	if err != nil {
		t.Fatal(err)
	}
	loadedFP, _ := Fingerprint(loaded)
	if loadedFP != fp {
		t.Errorf("loaded fingerprint = %q, want %q", loadedFP, fp)
	}

	// No password when encrypted
	if _, err := LoadKeyPairFrom(tmpDir, fp, ""); err == nil {
		t.Error("no password for encrypted key should fail")
	}
}

func TestLoadKeyPairRejectsUnknownVersion(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	tmpDir := t.TempDir()

	// Save with a future version
	kp.StorageVersion = 999
	data, _ := json.MarshalIndent(kp, "", "  ")
	os.WriteFile(filepath.Join(tmpDir, fp+".json"), data, 0600)

	_, err := LoadKeyPairFrom(tmpDir, fp, "")
	if err == nil {
		t.Error("should reject unknown storage version")
	}
}

func TestLoadKeyPairRejectsLegacyVersion(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	tmpDir := t.TempDir()

	// Save with version 0 (legacy — no version field)
	kp.StorageVersion = 0
	data, _ := json.MarshalIndent(kp, "", "  ")
	os.WriteFile(filepath.Join(tmpDir, fp+".json"), data, 0600)

	_, err := LoadKeyPairFrom(tmpDir, fp, "")
	if err == nil {
		t.Error("should reject legacy version 0")
	}
}

func TestListLocalKeysIn(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty dir
	keys, err := ListLocalKeysIn(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}

	// Save two keys
	kp1, _ := GenerateKeyPair()
	fp1, _ := Fingerprint(kp1)
	SaveKeyPairTo(tmpDir, fp1, kp1, "")

	kp2, _ := GenerateKeyPair()
	fp2, _ := Fingerprint(kp2)
	SaveKeyPairTo(tmpDir, fp2, kp2, "")

	keys, _ = ListLocalKeysIn(tmpDir)
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}

	// Non-existent dir
	keys, err = ListLocalKeysIn(filepath.Join(tmpDir, "nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	if keys != nil {
		t.Errorf("expected nil, got %v", keys)
	}
}

func TestDefaultKeysDir(t *testing.T) {
	dir := DefaultKeysDir()
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, ".deepsecret", "keys")
	if dir != expected {
		t.Errorf("got %q, want %q", dir, expected)
	}
}
