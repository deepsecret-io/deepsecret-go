// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDevice is a security key: a secret per credential for assertions
// with user verification and another without, as CTAP 2.1 devices keep.
type fakeDevice struct {
	name  string
	creds map[string][2][]byte // credential id (hex) -> {with UV, without UV}
}

// fakeAuthenticator is a set of connected fake devices.
type fakeAuthenticator struct {
	connected []*fakeDevice
	withoutUV bool // answer with the secret for no user verification
	enrolls   int
	derives   int
}

func newFakeDevice(name string) *fakeDevice {
	return &fakeDevice{name: name, creds: map[string][2][]byte{}}
}

func prf(secret, input []byte) []byte {
	salt := PRFSalt(input)
	m := hmac.New(sha256.New, secret)
	m.Write(salt[:])
	return m.Sum(nil)
}

func (a *fakeAuthenticator) Enroll(_ context.Context, req EnrollRequest) (*EnrollResult, error) {
	a.enrolls++
	if len(a.connected) != 1 {
		return nil, ErrNoSecurityKey
	}
	d := a.connected[0]
	for _, ex := range req.Exclude {
		if _, ok := d.creds[hex.EncodeToString(ex)]; ok {
			return nil, ErrSecurityKeyEnrolled
		}
	}
	if req.RPID != SecurityKeyRPID || len(req.PRFInput) != prfInputSize || len(req.UserID) != userIDSize {
		return nil, errors.New("malformed enroll request")
	}
	id := mustRand(48)
	d.creds[hex.EncodeToString(id)] = [2][]byte{mustRand(32), mustRand(32)}
	out, err := a.derive(d, id, req.PRFInput)
	if err != nil {
		return nil, err
	}
	return &EnrollResult{CredentialID: id, AAGUID: bytes.Repeat([]byte{0xab}, 16), Device: d.name, Output: out}, nil
}

func (a *fakeAuthenticator) Derive(_ context.Context, req DeriveRequest) (*DeriveResult, error) {
	a.derives++
	for _, d := range a.connected {
		for _, c := range req.Credentials {
			if _, ok := d.creds[hex.EncodeToString(c.ID)]; ok {
				out, err := a.derive(d, c.ID, c.PRFInput)
				if err != nil {
					return nil, err
				}
				return &DeriveResult{CredentialID: c.ID, Output: out}, nil
			}
		}
	}
	return nil, ErrNoSecurityKey
}

func (a *fakeAuthenticator) derive(d *fakeDevice, id, input []byte) ([]byte, error) {
	secrets := d.creds[hex.EncodeToString(id)]
	if a.withoutUV {
		return prf(secrets[1], input), nil
	}
	return prf(secrets[0], input), nil
}

// v4Key stores a fresh key pair as a version 4 file under password.
func v4Key(t *testing.T, dir, password string) (*KeyPair, string) {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := Fingerprint(kp)
	if err := SaveKeyPairTo(dir, fp, kp, password); err != nil {
		t.Fatal(err)
	}
	return kp, fp
}

// protect turns the version 4 key fp into a security-key file with one
// key on dev and a recovery code, and returns the code.
func protect(t *testing.T, dir, fp, password string, a *fakeAuthenticator) string {
	t.Helper()
	e, err := EditKeyFile(context.Background(), dir, fp, Unlock{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.AddSecurityKey(context.Background(), a, ""); err != nil {
		t.Fatal(err)
	}
	code, err := e.SetRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	return code
}

func samePrivate(t *testing.T, got, want *KeyPair) {
	t.Helper()
	if got.ED25519Private != want.ED25519Private || got.X25519Private != want.X25519Private ||
		got.MLKEM768SK != want.MLKEM768SK || got.MLDSA65Seed != want.MLDSA65Seed {
		t.Fatal("unlocked private keys differ from the originals")
	}
}

func TestSecurityKeyProtectAndUnlock(t *testing.T) {
	ctx := context.Background()
	for _, password := range []string{"correct horse battery staple", ""} {
		dir := t.TempDir()
		kp, fp := v4Key(t, dir, password)
		dev := newFakeDevice("YubiKey 5C NFC")
		a := &fakeAuthenticator{connected: []*fakeDevice{dev}}
		code := protect(t, dir, fp, password, a)

		got, err := UnlockKeyPair(ctx, dir, fp, Unlock{SecurityKey: a})
		if err != nil {
			t.Fatal(err)
		}
		samePrivate(t, got, kp)
		if got.StorageVersion != SecurityKeyStorageVersion {
			t.Errorf("storage version = %d", got.StorageVersion)
		}

		// The recovery code opens it without any security key, typed in
		// lower case, with spaces and with Crockford's look-alikes.
		typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
		typed = strings.NewReplacer("0", "o", "1", "l").Replace(typed)
		got, err = UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: typed})
		if err != nil {
			t.Fatal(err)
		}
		samePrivate(t, got, kp)

		// A password no longer opens it, and old callers get a clear error.
		if _, err := LoadKeyPairFrom(dir, fp, password); !errors.Is(err, ErrSecurityKeyRequired) {
			t.Errorf("LoadKeyPairFrom = %v, want ErrSecurityKeyRequired", err)
		}
		if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{Password: password}); !errors.Is(err, ErrSecurityKeyRequired) {
			t.Errorf("UnlockKeyPair with a password = %v, want ErrSecurityKeyRequired", err)
		}

		// Public keys and the file description stay readable without it.
		pub, err := LoadPublicKeysFrom(dir, fp)
		if err != nil || pub.Fingerprint != fp {
			t.Fatalf("LoadPublicKeysFrom = %v, %v", pub, err)
		}
		info, err := ReadKeyFileInfo(dir, fp[:16])
		if err != nil {
			t.Fatal(err)
		}
		if info.Fingerprint != fp || info.Protection != ProtectionSecurityKey || len(info.Slots) != 2 {
			t.Fatalf("info = %+v", info)
		}
		if info.Slots[0].Type != SlotSecurityKey || info.Slots[0].Label != "YubiKey 5C NFC" || info.Slots[0].AAGUID != strings.Repeat("ab", 16) {
			t.Errorf("security key slot = %+v", info.Slots[0])
		}
		if info.Slots[1].Type != SlotRecoveryCode {
			t.Errorf("recovery slot = %+v", info.Slots[1])
		}
	}
}

func TestReadKeyFileInfoVersion4(t *testing.T) {
	dir := t.TempDir()
	_, fpPlain := v4Key(t, dir, "")
	_, fpPass := v4Key(t, dir, "pw")
	for fp, want := range map[string]Protection{fpPlain: ProtectionNone, fpPass: ProtectionPassword} {
		info, err := ReadKeyFileInfo(dir, fp)
		if err != nil {
			t.Fatal(err)
		}
		if info.Protection != want || len(info.Slots) != 0 || info.Public.Fingerprint != fp {
			t.Errorf("info = %+v, want protection %s", info, want)
		}
	}
}

func TestVersion4StaysAsItWas(t *testing.T) {
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "pw")
	before, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
	got, err := UnlockKeyPair(context.Background(), dir, fp, Unlock{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
	if _, err := LoadKeyPairFrom(dir, fp, ""); !errors.Is(err, ErrPasswordRequired) || err.Error() != "key pair is password-encrypted, provide a password" {
		t.Errorf("no password: %v", err)
	}
	if _, err := LoadKeyPairFrom(dir, fp, "nope"); !errors.Is(err, ErrWrongPassword) || err.Error() != "wrong password or corrupted key file" {
		t.Errorf("wrong password: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
	if !bytes.Equal(before, after) {
		t.Error("reading a version 4 file changed it")
	}
}

func TestNewSecurityKeyFile(t *testing.T) {
	dir := t.TempDir()
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("Key A")}}
	e, err := NewSecurityKeyFile(dir, kp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddSecurityKey(context.Background(), a, "Keyring"); err != nil {
		t.Fatal(err)
	}
	a.connected = []*fakeDevice{newFakeDevice("Key B")}
	if _, err := e.AddSecurityKey(context.Background(), a, "Safe"); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()
	got, err := UnlockKeyPair(context.Background(), dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
	if _, err := NewSecurityKeyFile(dir, kp); err == nil {
		t.Error("a second new file for the same key pair was allowed")
	}
}

func TestSlotRules(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "pw")
	devA := newFakeDevice("A")
	a := &fakeAuthenticator{connected: []*fakeDevice{devA}}

	e, err := EditKeyFile(ctx, dir, fp, Unlock{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); !errors.Is(err, ErrSlotRules) {
		t.Errorf("no security key: %v", err)
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(true); !errors.Is(err, ErrSlotRules) {
		t.Errorf("recovery code alone: %v", err)
	}
	if _, err := e.AddSecurityKey(ctx, a, ""); err != nil {
		t.Fatal(err)
	}
	// The same device cannot be enrolled twice as its own backup.
	if _, err := e.AddSecurityKey(ctx, a, ""); !errors.Is(err, ErrSecurityKeyEnrolled) {
		t.Errorf("same device twice: %v", err)
	}
	// Removing the recovery code leaves one way in: refused unless waived.
	for _, s := range e.Slots() {
		if s.Type == SlotRecoveryCode {
			if err := e.Remove(s.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.Commit(false); !errors.Is(err, ErrSlotRules) {
		t.Errorf("single way in without the waiver: %v", err)
	}
	if err := e.Commit(true); err != nil {
		t.Fatalf("single way in with the waiver: %v", err)
	}
	e.Close()

	// A waived single-key file still reads and unlocks.
	if _, err := ReadKeyFileInfo(dir, fp); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{SecurityKey: a}); err != nil {
		t.Fatal(err)
	}
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: "0000-0000-0000-0000-0000-0000-0000-0000"}); !errors.Is(err, ErrNoRecoveryCode) {
		t.Errorf("recovery code on a file without one: %v", err)
	}

	// At most four security keys.
	e, err = EditKeyFile(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 3; i++ {
		a.connected = []*fakeDevice{newFakeDevice("more")}
		if _, err := e.AddSecurityKey(ctx, a, ""); err != nil {
			t.Fatal(err)
		}
	}
	a.connected = []*fakeDevice{newFakeDevice("fifth")}
	if _, err := e.AddSecurityKey(ctx, a, ""); !errors.Is(err, ErrSlotRules) {
		t.Errorf("fifth security key: %v", err)
	}
	if _, err := e.AddSecurityKey(ctx, a, "bad\nlabel"); err == nil {
		t.Error("a label with a newline was accepted")
	}
}

func TestBackupKeyAndRemoval(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "")
	devA, devB := newFakeDevice("A"), newFakeDevice("B")
	a := &fakeAuthenticator{connected: []*fakeDevice{devA}}
	protect(t, dir, fp, "", a)

	e, err := EditKeyFile(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	a.connected = []*fakeDevice{devB}
	if _, err := e.AddSecurityKey(ctx, a, "Backup"); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// The backup alone opens it.
	got, err := UnlockKeyPair(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)

	// A is lost: remove it with B.
	e, err = EditKeyFile(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range e.Slots() {
		if s.Label == "A" {
			if err := e.Remove(s.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()
	a.connected = []*fakeDevice{devA}
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{SecurityKey: a}); !errors.Is(err, ErrNoSecurityKey) {
		t.Errorf("removed key: %v, want ErrNoSecurityKey", err)
	}
}

func TestUserVerificationMismatchDoesNotOpen(t *testing.T) {
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	protect(t, dir, fp, "", a)
	a.withoutUV = true
	if _, err := UnlockKeyPair(context.Background(), dir, fp, Unlock{SecurityKey: a}); !errors.Is(err, ErrSecurityKeyMismatch) {
		t.Errorf("unlock without user verification: %v, want ErrSecurityKeyMismatch", err)
	}
}

func TestWrongRecoveryCode(t *testing.T) {
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	code := protect(t, dir, fp, "", a)
	wrong := []byte(code)
	if wrong[0] == '0' {
		wrong[0] = '1'
	} else {
		wrong[0] = '0'
	}
	for _, typed := range []string{string(wrong), "too-short", code + "0", strings.Replace(code, code[:1], "U", 1)} {
		_, err := UnlockKeyPair(context.Background(), dir, fp, Unlock{RecoveryCode: typed})
		if !errors.Is(err, ErrWrongRecoveryCode) {
			t.Errorf("code %q: %v, want ErrWrongRecoveryCode", typed, err)
		}
		if err != nil && strings.Contains(err.Error(), NormalizeRecoveryCode(code)) {
			t.Error("an error repeats the recovery code")
		}
	}
}

func TestRecoveryCodeReplacement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	old := protect(t, dir, fp, "", a)
	e, err := EditKeyFile(ctx, dir, fp, Unlock{RecoveryCode: old})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := e.SetRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: old}); !errors.Is(err, ErrWrongRecoveryCode) {
		t.Errorf("old code: %v", err)
	}
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: fresh}); err != nil {
		t.Errorf("new code: %v", err)
	}
	info, _ := ReadKeyFileInfo(dir, fp)
	if len(info.Slots) != 2 {
		t.Errorf("slots after replacing the code = %d, want 2", len(info.Slots))
	}
}

func TestCommitPasswordBackToVersion4(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	protect(t, dir, fp, "", a)
	e, err := EditKeyFile(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CommitPassword("new password"); err != nil {
		t.Fatal(err)
	}
	e.Close()
	got, err := LoadKeyPairFrom(dir, fp, "new password")
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
	if got.StorageVersion != KeyStorageVersion {
		t.Errorf("storage version = %d, want %d", got.StorageVersion, KeyStorageVersion)
	}
}

func TestEditRefusesAChangedFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	e, err := EditKeyFile(ctx, dir, fp, Unlock{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.AddSecurityKey(ctx, a, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		t.Fatal(err)
	}
	// Another process rewrites the file in the meantime.
	kp, _ := LoadKeyPairFrom(dir, fp, "")
	if err := SaveKeyPairTo(dir, fp, kp, "other"); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); !errors.Is(err, ErrKeyFileChanged) {
		t.Errorf("commit over a changed file: %v, want ErrKeyFileChanged", err)
	}
	if _, err := LoadKeyPairFrom(dir, fp, "other"); err != nil {
		t.Errorf("the other process's file was overwritten: %v", err)
	}
}

// tamper protects a key, applies change to its JSON and returns the
// result of unlocking with the security key and with the code.
func tamper(t *testing.T, change func(f map[string]any)) (errKey, errCode error) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	code := protect(t, dir, fp, "", a)
	path := filepath.Join(dir, fp+".json")
	data, _ := os.ReadFile(path)
	var f map[string]any
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	change(f)
	data, _ = json.Marshal(f)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, errKey = UnlockKeyPair(ctx, dir, fp, Unlock{SecurityKey: a})
	_, errCode = UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: code})
	return errKey, errCode
}

func slot(f map[string]any, i int) map[string]any {
	return f["slots"].([]any)[i].(map[string]any)
}

func flipB64(s string) string {
	b, _ := b64.DecodeString(s)
	b[len(b)-1] ^= 1
	return b64.EncodeToString(b)
}

func TestTamperedKeyFileDoesNotOpen(t *testing.T) {
	cases := map[string]func(f map[string]any){
		"label":      func(f map[string]any) { slot(f, 0)["label"] = "Other" },
		"created_at": func(f map[string]any) { slot(f, 0)["created_at"] = "2020-01-01T00:00:00Z" },
		"prf_input": func(f map[string]any) {
			k := slot(f, 0)["fido2"].(map[string]any)
			k["prf_input"] = flipB64(k["prf_input"].(string))
		},
		"discoverable": func(f map[string]any) { slot(f, 0)["fido2"].(map[string]any)["discoverable"] = true },
		"uv off":       func(f map[string]any) { slot(f, 0)["fido2"].(map[string]any)["uv"] = false },
		"rp_id":        func(f map[string]any) { slot(f, 0)["fido2"].(map[string]any)["rp_id"] = "deepsecret.io" },
		"wrap nonce": func(f map[string]any) {
			w := slot(f, 0)["wrap"].(map[string]any)
			w["nonce"] = flipB64(w["nonce"].(string))
		},
		"wrapped key": func(f map[string]any) {
			w := slot(f, 1)["wrap"].(map[string]any)
			w["wrapped_key"] = flipB64(w["wrapped_key"].(string))
		},
		"recovery salt": func(f map[string]any) {
			r := slot(f, 1)["recovery_code"].(map[string]any)
			r["salt"] = flipB64(r["salt"].(string))
		},
		"private block": func(f map[string]any) {
			p := f["private"].(map[string]any)
			p["ciphertext"] = flipB64(p["ciphertext"].(string))
		},
		"slot dropped":     func(f map[string]any) { f["slots"] = f["slots"].([]any)[:1] },
		"slots reordered":  func(f map[string]any) { s := f["slots"].([]any); s[0], s[1] = s[1], s[0] },
		"unknown field":    func(f map[string]any) { f["note"] = "x" },
		"unknown slot key": func(f map[string]any) { slot(f, 0)["extra"] = 1 },
		"future version":   func(f map[string]any) { f["storage_version"] = 6 },
		"public key":       func(f map[string]any) { f["x25519_public"] = flipB64(f["x25519_public"].(string)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			errKey, errCode := tamper(t, change)
			if errKey == nil || errCode == nil {
				t.Errorf("tampered file opened: key %v, code %v", errKey, errCode)
			}
		})
	}
}

func TestSlotFromAnotherCopyDoesNotOpen(t *testing.T) {
	// Copy the file, replace the recovery code, then put the old copy's
	// recovery slot back: the private block's AAD no longer matches.
	ctx := context.Background()
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	oldCode := protect(t, dir, fp, "", a)
	path := filepath.Join(dir, fp+".json")
	oldData, _ := os.ReadFile(path)
	e, err := EditKeyFile(ctx, dir, fp, Unlock{SecurityKey: a})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()
	var oldFile, newFile map[string]any
	_ = json.Unmarshal(oldData, &oldFile)
	cur, _ := os.ReadFile(path)
	_ = json.Unmarshal(cur, &newFile)
	newFile["slots"].([]any)[1] = oldFile["slots"].([]any)[1]
	data, _ := json.Marshal(newFile)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := UnlockKeyPair(ctx, dir, fp, Unlock{RecoveryCode: oldCode}); err == nil {
		t.Error("an old recovery slot opened the new file")
	}
}

func TestDuplicateFieldRefused(t *testing.T) {
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	protect(t, dir, fp, "", a)
	path := filepath.Join(dir, fp+".json")
	data, _ := os.ReadFile(path)
	data = bytes.Replace(data, []byte(`"storage_version": 5,`), []byte(`"storage_version": 5, "storage_version": 5,`), 1)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := ReadKeyFileInfo(dir, fp); err == nil || !strings.Contains(err.Error(), "repeated field") {
		t.Errorf("duplicate field: %v", err)
	}
}

func TestFutureVersionMessage(t *testing.T) {
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "")
	kp.StorageVersion = 9
	data, _ := json.Marshal(kp)
	_ = os.WriteFile(filepath.Join(dir, fp+".json"), data, 0o600)
	_, err := LoadKeyPairFrom(dir, fp, "")
	if err == nil || !strings.Contains(err.Error(), "needs a newer version") {
		t.Errorf("future version: %v", err)
	}
}

func TestPrivateMustMatchPublic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	other, _ := GenerateKeyPair()
	if err := checkPrivateMatchesPublic(kp); err != nil {
		t.Fatal(err)
	}
	for name, swap := range map[string]func(k *KeyPair){
		"ed25519": func(k *KeyPair) { k.ED25519Private = other.ED25519Private },
		"x25519":  func(k *KeyPair) { k.X25519Private = other.X25519Private },
		"mlkem":   func(k *KeyPair) { k.MLKEM768SK = other.MLKEM768SK },
		"mldsa":   func(k *KeyPair) { k.MLDSA65Seed = other.MLDSA65Seed },
	} {
		k := *kp
		swap(&k)
		if err := checkPrivateMatchesPublic(&k); err == nil {
			t.Errorf("%s: a foreign private key passed", name)
		}
		if _, err := NewSecurityKeyFile(t.TempDir(), &k); err == nil {
			t.Errorf("%s: NewSecurityKeyFile accepted mismatched keys", name)
		}
	}
}

// TestDerivationVectors pins the PRF salt and the key-encryption key
// derivations: a change to either locks every user out of their files.
func TestDerivationVectors(t *testing.T) {
	input := bytes.Repeat([]byte{0x01}, 32)
	salt := PRFSalt(input)
	h := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), input...))
	if salt != h {
		t.Fatalf("PRFSalt = %x, want %x", salt, h)
	}
	fp := strings.Repeat("a", 64)
	kek, err := securityKeyKEK(bytes.Repeat([]byte{0x02}, 32), fp, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kek); got != securityKEKVector {
		t.Errorf("security key KEK = %s, want %s", got, securityKEKVector)
	}
	kek, err = recoveryKEK(bytes.Repeat([]byte{0x03}, 20), bytes.Repeat([]byte{0x04}, 16), fp, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kek); got != recoveryKEKVector {
		t.Errorf("recovery KEK = %s, want %s", got, recoveryKEKVector)
	}
}

// The vectors were checked against an independent HKDF-SHA256 (RFC 5869)
// implementation.
const (
	securityKEKVector = "d61ff396f56fd8493a2d4196a9a92e441e3a2bc612639f8f44e97b1416a587aa"
	recoveryKEKVector = "6df9158cc5ab8a709f8b8f93ba415eb46657dc9e4efe8b02318443f89ca2ea5d"
)

func TestRecoveryCodeFormat(t *testing.T) {
	code, text, err := newRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(text) != 39 || strings.Count(text, "-") != 7 {
		t.Errorf("code %q is not 8 groups of 4", text)
	}
	back, err := parseRecoveryCode(text)
	if err != nil || !bytes.Equal(back, code) {
		t.Errorf("parse(format(code)) = %x, %v", back, err)
	}
}

func FuzzParseSecurityKeyFile(f *testing.F) {
	dir := f.TempDir()
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	e, err := NewSecurityKeyFile(dir, kp)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := e.AddSecurityKey(context.Background(), a, ""); err != nil {
		f.Fatal(err)
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		f.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		f.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
	f.Add(data)
	f.Add([]byte(`{"storage_version":5}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if file, err := parseSecurityKeyFile(data, fp); err == nil {
			_, _, _ = file.unlock(context.Background(), fp, Unlock{RecoveryCode: "0000-0000-0000-0000-0000-0000-0000-0000"})
		}
	})
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// A second storage_version in another case must not send a version 5 file
// to the version 4 reader.
func TestVersionFieldInAnotherCase(t *testing.T) {
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	protect(t, dir, fp, "", a)
	path := filepath.Join(dir, fp+".json")
	data, _ := os.ReadFile(path)
	data = bytes.Replace(data, []byte(`"storage_version": 5,`), []byte(`"storage_version": 5, "Storage_Version": 4,`), 1)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := LoadKeyPairFrom(dir, fp, ""); err == nil || !strings.Contains(err.Error(), "repeated field") {
		t.Errorf("LoadKeyPairFrom: %v", err)
	}
	if _, err := EditKeyFile(context.Background(), dir, fp, Unlock{}); err == nil {
		t.Error("EditKeyFile accepted the file")
	}
}

// The editor refuses a version 4 file whose private keys do not give its
// public keys, so it never writes them back under new protection.
func TestEditRefusesMismatchedVersion4(t *testing.T) {
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "")
	other, _ := GenerateKeyPair()
	kp.MLDSA65Seed = other.MLDSA65Seed
	if err := SaveKeyPairTo(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := EditKeyFile(context.Background(), dir, fp, Unlock{}); err == nil || !strings.Contains(err.Error(), "ML-DSA-65") {
		t.Errorf("EditKeyFile on mismatched keys: %v", err)
	}
}
