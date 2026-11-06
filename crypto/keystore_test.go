// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

	// Save with version 0 (legacy: no version field)
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

// A fingerprint names the key file read, and the primary one comes from
// the server: anything but hex, such as a path, is refused before any file
// is touched, and nothing is written outside the keys directory.
func TestKeyFileNameMustBeAFingerprint(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := SaveKeyPairTo(root, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	// A key planted outside the keys directory, under a name a hostile
	// server could point at.
	if err := os.Rename(filepath.Join(root, fp+".json"), filepath.Join(root, "planted.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../planted", "..", "", "abc", fp + "/../x", strings.Repeat("a", 65), "zzzzzzzzzzzzzzzz"} {
		if _, err := LoadKeyPairFrom(keys, name, ""); !errors.Is(err, errInvalidKeyName) {
			t.Errorf("load %q: %v, want refused", name, err)
		}
		if err := SaveKeyPairTo(keys, name, kp, ""); !errors.Is(err, errInvalidKeyName) {
			t.Errorf("save %q: %v, want refused", name, err)
		}
	}
	if _, err := os.Stat(keys); !os.IsNotExist(err) {
		t.Errorf("refused saves created %s: %v", keys, err)
	}

	// A fingerprint in upper case, or a prefix of 16, still finds its key.
	if err := SaveKeyPairTo(keys, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strings.ToUpper(fp), fp[:16]} {
		if _, err := LoadKeyPairFrom(keys, name, ""); err != nil {
			t.Errorf("load %q: %v", name, err)
		}
	}
}

// Saving a key makes its file private even when an older one was not, and
// replaces a link at its path instead of writing the private keys through
// it.
func TestSaveKeyPairFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and links differ on Windows")
	}
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	dir := t.TempDir()
	path := filepath.Join(dir, fp+".json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyPairTo(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v, %v; want mode 0600", info, err)
	}

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}
	if err := SaveKeyPairTo(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) != "untouched" {
		t.Errorf("the private keys were written through the link: %q, %v", data, err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v; want a private regular file", info, err)
	}
	if _, err := LoadKeyPairFrom(dir, fp, ""); err != nil {
		t.Errorf("load: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the keys directory holds %d entries, want the key alone", len(entries))
	}
}

// The public keys of a stored key pair are read without its password, by
// its full fingerprint only, and only when they hash to that fingerprint.
func TestLoadPublicKeysFrom(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	dir := t.TempDir()
	if err := SaveKeyPairTo(dir, fp, kp, "correct horse"); err != nil {
		t.Fatal(err)
	}

	pub, err := LoadPublicKeysFrom(dir, strings.ToUpper(fp))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint != fp || pub.ED25519 != kp.ED25519Public || pub.X25519 != kp.X25519Public ||
		pub.MLKEM768 != kp.MLKEM768PK || pub.MLDSA65 != kp.MLDSA65PK {
		t.Fatalf("public keys %+v do not match the stored key pair", pub)
	}

	// A prefix finds a key for LoadKeyPairFrom, but not here: the caller
	// asks whether this exact key is on the device.
	if _, err := LoadPublicKeysFrom(dir, fp[:16]); err == nil {
		t.Error("prefix accepted")
	}
	other, _ := GenerateKeyPair()
	otherFP, _ := Fingerprint(other)
	if _, err := LoadPublicKeysFrom(dir, otherFP); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing key: %v, want not exist", err)
	}

	// A file whose keys are not the ones its name says is refused.
	if err := SaveKeyPairTo(dir, otherFP, kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKeysFrom(dir, otherFP); err == nil || !strings.Contains(err.Error(), "holds the keys of") {
		t.Errorf("mislabelled key file: %v, want refused", err)
	}
}
