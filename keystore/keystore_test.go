// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keys"
)

func TestSaveLoadKeyPair(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	tmpDir := t.TempDir()

	if err := Save(tmpDir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(tmpDir, fp, "")
	if err != nil {
		t.Fatal(err)
	}
	loadedFP, _ := keys.Fingerprint(loaded)
	if loadedFP != fp {
		t.Errorf("loaded fingerprint = %q, want %q", loadedFP, fp)
	}
	if info, err := ReadInfo(tmpDir, fp); err != nil || info.Protection != ProtectionNone {
		t.Errorf("info = %+v, %v; want no protection", info, err)
	}
}

func TestSaveLoadKeyPairWithPassword(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	tmpDir := t.TempDir()

	if err := Save(tmpDir, fp, kp, "mypassword"); err != nil {
		t.Fatal(err)
	}

	// Wrong password
	if _, err := Load(tmpDir, fp, "wrongpassword"); err == nil {
		t.Error("wrong password should fail")
	}

	// Correct password
	loaded, err := Load(tmpDir, fp, "mypassword")
	if err != nil {
		t.Fatal(err)
	}
	loadedFP, _ := keys.Fingerprint(loaded)
	if loadedFP != fp {
		t.Errorf("loaded fingerprint = %q, want %q", loadedFP, fp)
	}

	// No password when encrypted
	if _, err := Load(tmpDir, fp, ""); err == nil {
		t.Error("no password for encrypted key should fail")
	}
}

func TestLoadKeyPairRejectsUnknownVersion(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	tmpDir := t.TempDir()

	// Save with a future version
	writeVersioned(t, filepath.Join(tmpDir, fp+".json"), kp, 999)

	_, err := Load(tmpDir, fp, "")
	if err == nil {
		t.Error("should reject unknown storage version")
	}
}

func TestLoadKeyPairRejectsLegacyVersion(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	tmpDir := t.TempDir()

	// Save with version 0 (legacy: no version field)
	writeVersioned(t, filepath.Join(tmpDir, fp+".json"), kp, 0)

	_, err := Load(tmpDir, fp, "")
	if err == nil {
		t.Error("should reject legacy version 0")
	}
}

func TestListLocalKeysIn(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty dir
	pubKeys, err := List(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pubKeys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(pubKeys))
	}

	// Save two keys
	kp1, _ := keys.Generate()
	fp1, _ := keys.Fingerprint(kp1)
	Save(tmpDir, fp1, kp1, "")

	kp2, _ := keys.Generate()
	fp2, _ := keys.Fingerprint(kp2)
	Save(tmpDir, fp2, kp2, "")

	pubKeys, _ = List(tmpDir)
	if len(pubKeys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(pubKeys))
	}

	// Non-existent dir
	pubKeys, err = List(filepath.Join(tmpDir, "nonexistent"))
	if err != nil {
		t.Fatal(err)
	}
	if pubKeys != nil {
		t.Errorf("expected nil, got %v", pubKeys)
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
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	root := t.TempDir()
	pubKeys := filepath.Join(root, "keys")
	if err := Save(root, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	// A key planted outside the keys directory, under a name a hostile
	// server could point at.
	if err := os.Rename(filepath.Join(root, fp+".json"), filepath.Join(root, "planted.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../planted", "..", "", "abc", fp + "/../x", strings.Repeat("a", 65), "zzzzzzzzzzzzzzzz"} {
		if _, err := Load(pubKeys, name, ""); !errors.Is(err, errInvalidKeyName) {
			t.Errorf("load %q: %v, want refused", name, err)
		}
		if err := Save(pubKeys, name, kp, ""); !errors.Is(err, errInvalidKeyName) {
			t.Errorf("save %q: %v, want refused", name, err)
		}
	}
	if _, err := os.Stat(pubKeys); !os.IsNotExist(err) {
		t.Errorf("refused saves created %s: %v", pubKeys, err)
	}

	// A fingerprint in upper case, or a prefix of 16, still finds its key.
	if err := Save(pubKeys, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{strings.ToUpper(fp), fp[:16]} {
		if _, err := Load(pubKeys, name, ""); err != nil {
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
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	dir := t.TempDir()
	path := filepath.Join(dir, fp+".json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(dir, fp, kp, ""); err != nil {
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
	if err := Save(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(elsewhere); err != nil || string(data) != "untouched" {
		t.Errorf("the private keys were written through the link: %q, %v", data, err)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v; want a private regular file", info, err)
	}
	if _, err := Load(dir, fp, ""); err != nil {
		t.Errorf("load: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the keys directory holds %d entries, want the key alone", len(entries))
	}
}

// The public keys of a stored key pair are read without its password, by
// its full fingerprint only, and only when they hash to that fingerprint.
func TestLoadPublicKeysFrom(t *testing.T) {
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	dir := t.TempDir()
	if err := Save(dir, fp, kp, "correct horse"); err != nil {
		t.Fatal(err)
	}

	pub, err := LoadPublic(dir, strings.ToUpper(fp))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Fingerprint != fp || pub.ED25519 != kp.ED25519Public || pub.X25519 != kp.X25519Public ||
		pub.MLKEM768 != kp.MLKEM768PK || pub.MLDSA65 != kp.MLDSA65PK {
		t.Fatalf("public keys %+v do not match the stored key pair", pub)
	}

	// A prefix finds a key for Load, but not here: the caller
	// asks whether this exact key is on the device.
	if _, err := LoadPublic(dir, fp[:16]); err == nil {
		t.Error("prefix accepted")
	}
	other, _ := keys.Generate()
	otherFP, _ := keys.Fingerprint(other)
	if _, err := LoadPublic(dir, otherFP); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing key: %v, want not exist", err)
	}

	// A file whose keys are not the ones its name says is refused.
	if err := Save(dir, otherFP, kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublic(dir, otherFP); err == nil || !strings.Contains(err.Error(), "holds the keys of") {
		t.Errorf("mislabelled key file: %v, want refused", err)
	}
}

// writeVersioned writes kp's public keys as a key file of the given storage
// version, with no version field when it is 0.
func writeVersioned(t *testing.T, path string, kp *keys.Pair, version int) {
	t.Helper()
	file := map[string]any{
		"ed25519_public": kp.ED25519Public,
		"x25519_public":  kp.X25519Public,
		"mlkem768_pk":    kp.MLKEM768PK,
		"mldsa65_pk":     kp.MLDSA65PK,
	}
	if version != 0 {
		file["storage_version"] = version
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
