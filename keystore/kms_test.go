// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

const (
	testARN     = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testARN2    = "arn:aws:kms:us-east-1:444455556666:key/mrk-0123456789abcdef0123456789abcdef"
	testAccount = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
	otherAcct   = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// fakeKMS behaves like AWS KMS for symmetric keys: a ciphertext names the
// key that made it and opens only with that key and the exact encryption
// context, which is its AAD.
type fakeKMS struct {
	keys    map[string][]byte // key ARN -> key material
	meta    map[string]KMSKey // what DescribeKey answers, by key id, alias or ARN
	fail    map[string]error  // Decrypt answers this error for a key ARN
	encrypt func(r *KMSResult)
	decrypt func(r *KMSResult)

	encrypts, decrypts int
	contexts           []map[string]string
	secrets            [][]byte // every plaintext Encrypt saw
	forbidden          *testing.T
}

func newFakeKMS(arns ...string) *fakeKMS {
	f := &fakeKMS{keys: map[string][]byte{}, meta: map[string]KMSKey{}, fail: map[string]error{}}
	for _, arn := range arns {
		f.keys[arn] = mustRand(32)
		f.meta[arn] = KMSKey{ARN: arn, Spec: KMSKeySpecSymmetric, Usage: KMSKeyUsageEncrypt, State: KMSKeyStateEnabled, Manager: KMSKeyManagerCustomer}
	}
	return f
}

// forbid makes any call fail the test: an unlock that must not reach KMS.
func forbid(t *testing.T) *fakeKMS { return &fakeKMS{forbidden: t} }

func contextAAD(c map[string]string) []byte {
	var b bytes.Buffer
	for _, k := range slices.Sorted(maps.Keys(c)) {
		b.WriteString(k + "\x00" + c[k] + "\x00")
	}
	return b.Bytes()
}

func (f *fakeKMS) DescribeKey(_ context.Context, keyID string) (*KMSKey, error) {
	if f.forbidden != nil {
		f.forbidden.Fatal("KMS was called")
	}
	m, ok := f.meta[keyID]
	if !ok {
		return nil, ErrKMSKeyUnavailable
	}
	return &m, nil
}

func (f *fakeKMS) Encrypt(_ context.Context, arn string, c map[string]string, plaintext []byte) (*KMSResult, error) {
	if f.forbidden != nil {
		f.forbidden.Fatal("KMS was called")
	}
	f.encrypts++
	f.contexts = append(f.contexts, maps.Clone(c))
	f.secrets = append(f.secrets, bytes.Clone(plaintext))
	key, ok := f.keys[arn]
	if !ok {
		return nil, ErrKMSKeyUnavailable
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := mustRand(gcm.NonceSize())
	ct := append([]byte{byte(len(arn))}, arn...)
	ct = append(ct, nonce...)
	ct = gcm.Seal(ct, nonce, plaintext, contextAAD(c))
	r := &KMSResult{KeyARN: arn, Data: ct}
	if f.encrypt != nil {
		f.encrypt(r)
	}
	return r, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, arn string, c map[string]string, ct []byte) (*KMSResult, error) {
	if f.forbidden != nil {
		f.forbidden.Fatal("KMS was called")
	}
	f.decrypts++
	f.contexts = append(f.contexts, maps.Clone(c))
	if err := f.fail[arn]; err != nil {
		return nil, err
	}
	if len(ct) < 1 || len(ct) < 1+int(ct[0])+12 || string(ct[1:1+int(ct[0])]) != arn {
		return nil, ErrKMSMismatch // IncorrectKeyException or InvalidCiphertextException
	}
	key, ok := f.keys[arn]
	if !ok {
		return nil, ErrKMSKeyUnavailable
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	rest := ct[1+int(ct[0]):]
	plain, err := gcm.Open(nil, rest[:12], rest[12:], contextAAD(c))
	if err != nil {
		return nil, ErrKMSMismatch
	}
	r := &KMSResult{KeyARN: arn, Data: plain}
	if f.decrypt != nil {
		f.decrypt(r)
	}
	return r, nil
}

// kmsKey stores a new key pair as a version 6 file under the KMS keys arns,
// with a recovery code when withCode is set, and returns the pair, its
// fingerprint and the code.
func kmsKey(t *testing.T, dir string, k KMS, withCode bool, arns ...string) (*keys.Pair, string, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewKMSKeyFile(dir, kp)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, arn := range arns {
		if _, err := e.AddKMS(context.Background(), k, arn, testAccount, ""); err != nil {
			t.Fatal(err)
		}
	}
	code := ""
	if withCode {
		if code, err = e.SetRecoveryCode(); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Commit(len(arns) == 1 && !withCode); err != nil {
		t.Fatal(err)
	}
	return kp, e.Fingerprint(), code
}

func TestKMSKeyFileRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k := newFakeKMS(testARN)
	kp, fp, _ := kmsKey(t, dir, k, false, testARN)

	got, err := Open(ctx, dir, fp, Unlock{KMS: k})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)

	info, err := ReadInfo(dir, fp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Protection != ProtectionKMS || len(info.Slots) != 1 {
		t.Fatalf("info: %+v", info)
	}
	s := info.Slots[0]
	if s.Type != SlotAWSKMS || s.KMSKeyARN != testARN || s.Account != testAccount || s.Label != "AWS KMS key 1234abcd (eu-west-1)" {
		t.Errorf("slot: %+v", s)
	}
	// Encrypt and Decrypt carry exactly the four context values.
	want := map[string]string{
		"deepsecret:purpose":     "keystore/v6/aws_kms",
		"deepsecret:fingerprint": fp,
		"deepsecret:account":     testAccount,
		"deepsecret:slot":        s.ID,
	}
	if len(k.contexts) != 2 || !maps.Equal(k.contexts[0], want) || !maps.Equal(k.contexts[1], want) {
		t.Errorf("contexts %v, want %v twice", k.contexts, want)
	}
	if _, err := LoadPublic(dir, fp); err != nil {
		t.Errorf("LoadPublic: %v", err)
	}
	if _, err := Load(dir, fp, ""); !errors.Is(err, ErrKMSRequired) {
		t.Errorf("Load: %v", err)
	}
	for name, u := range map[string]Unlock{
		"nothing":      {},
		"password":     {Password: "pw"},
		"security key": {SecurityKey: &fakeAuthenticator{}},
	} {
		if _, err := Open(ctx, dir, fp, u); !errors.Is(err, ErrKMSRequired) {
			t.Errorf("%s: %v", name, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
	if !bytes.Contains(data, []byte(`"storage_version": 6`)) || bytes.Contains(data, []byte("alias")) {
		t.Errorf("file: %s", data)
	}
	// The slot secret never reaches the file.
	for _, sec := range k.secrets {
		if bytes.Contains(data, []byte(b64.EncodeToString(sec))) || bytes.Contains(data, []byte(hex.EncodeToString(sec))) {
			t.Error("the slot secret is in the key file")
		}
	}
}

func TestKMSProtectRecoverAndUnprotect(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	kp, fp := v4Key(t, dir, "pw")
	k := newFakeKMS(testARN)
	e, err := Edit(ctx, dir, fp, Unlock{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddKMS(ctx, k, testARN, testAccount, "ci-deploy"); err != nil {
		t.Fatal(err)
	}
	code, err := e.SetRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()

	got, err := Open(ctx, dir, fp, Unlock{KMS: k})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
	// The recovery code opens it without KMS.
	got, err = Open(ctx, dir, fp, Unlock{RecoveryCode: code, KMS: forbid(t)})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
	if _, err := Open(ctx, dir, fp, Unlock{RecoveryCode: strings.Repeat("0", 32), KMS: forbid(t)}); !errors.Is(err, ErrWrongRecoveryCode) {
		t.Errorf("wrong code: %v", err)
	}

	// Back to version 4 under a new password.
	e, err = Edit(ctx, dir, fp, Unlock{RecoveryCode: code})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CommitPassword("new"); err != nil {
		t.Fatal(err)
	}
	e.Close()
	if got, err = Load(dir, fp, "new"); err != nil {
		t.Fatal(err)
	}
	samePrivate(t, got, kp)
}

func TestKMSSlotRules(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS(testARN, testARN2)

	t.Run("second way in", func(t *testing.T) {
		dir := t.TempDir()
		_, fp := v4Key(t, dir, "")
		e, _ := Edit(ctx, dir, fp, Unlock{})
		defer e.Close()
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(false); !errors.Is(err, ErrSlotRules) {
			t.Errorf("one KMS key without the waiver: %v", err)
		}
		if _, err := e.AddKMS(ctx, k, testARN2, testAccount, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(false); err != nil {
			t.Errorf("two KMS keys: %v", err)
		}
	})
	t.Run("never mixed", func(t *testing.T) {
		dir := t.TempDir()
		_, fp := v4Key(t, dir, "")
		a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
		e, _ := Edit(ctx, dir, fp, Unlock{})
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddSecurityKey(ctx, a, ""); !errors.Is(err, ErrSlotRules) || a.enrolls != 0 {
			t.Errorf("security key in a KMS file: %v (%d enrolls)", err, a.enrolls)
		}
		e.Close()
		e, _ = Edit(ctx, dir, fp, Unlock{})
		defer e.Close()
		if _, err := e.AddSecurityKey(ctx, a, ""); err != nil {
			t.Fatal(err)
		}
		before := k.encrypts
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); !errors.Is(err, ErrSlotRules) || k.encrypts != before {
			t.Errorf("KMS key in a security-key file: %v", err)
		}
	})
	t.Run("limits", func(t *testing.T) {
		dir := t.TempDir()
		arns := []string{testARN, testARN2,
			"arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000001",
			"arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000002",
			"arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-000000000003"}
		k := newFakeKMS(arns...)
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(dir, kp)
		defer e.Close()
		if _, err := e.SetRecoveryCode(); err != nil {
			t.Fatalf("recovery code on a new KMS file: %v", err)
		}
		for _, arn := range arns[:4] {
			if _, err := e.AddKMS(ctx, k, arn, testAccount, ""); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.AddKMS(ctx, k, arns[4], testAccount, ""); !errors.Is(err, ErrSlotRules) {
			t.Errorf("fifth KMS key: %v", err)
		}
		if err := e.Commit(false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("one key once, one account", func(t *testing.T) {
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(t.TempDir(), kp)
		defer e.Close()
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); !errors.Is(err, ErrSlotRules) {
			t.Errorf("same key twice: %v", err)
		}
		if _, err := e.AddKMS(ctx, k, testARN2, otherAcct, ""); !errors.Is(err, ErrSlotRules) {
			t.Errorf("another account: %v", err)
		}
		for _, bad := range []string{"", "6F1C2D3E-4B5A-4C7D-8E9F-0A1B2C3D4E5F", "00000000-0000-0000-0000-000000000000", "{" + testAccount + "}", "user@example.com"} {
			if _, err := e.AddKMS(ctx, k, testARN2, bad, ""); !errors.Is(err, ErrSlotRules) {
				t.Errorf("account %q: %v", bad, err)
			}
		}
	})
	t.Run("last KMS key", func(t *testing.T) {
		dir := t.TempDir()
		_, fp, _ := kmsKey(t, dir, k, true, testARN)
		e, err := Edit(ctx, dir, fp, Unlock{KMS: k})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		for _, s := range e.Slots() {
			if s.Type == SlotAWSKMS {
				_ = e.Remove(s.ID)
			}
		}
		if err := e.Commit(true); !errors.Is(err, ErrSlotRules) {
			t.Errorf("no KMS key left: %v", err)
		}
	})
}

func TestKMSKeyMustBeSymmetricCustomerAndEnabled(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS(testARN)
	cases := map[string]KMSKey{
		"rsa":         {Spec: "RSA_4096", Usage: KMSKeyUsageEncrypt, State: KMSKeyStateEnabled, Manager: KMSKeyManagerCustomer},
		"hmac":        {Spec: "HMAC_256", Usage: "GENERATE_VERIFY_MAC", State: KMSKeyStateEnabled, Manager: KMSKeyManagerCustomer},
		"disabled":    {Spec: KMSKeySpecSymmetric, Usage: KMSKeyUsageEncrypt, State: "Disabled", Manager: KMSKeyManagerCustomer},
		"pending":     {Spec: KMSKeySpecSymmetric, Usage: KMSKeyUsageEncrypt, State: "PendingDeletion", Manager: KMSKeyManagerCustomer},
		"aws managed": {Spec: KMSKeySpecSymmetric, Usage: KMSKeyUsageEncrypt, State: KMSKeyStateEnabled, Manager: "AWS"},
	}
	n := 0
	for name, key := range cases {
		n++
		arn := "arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-4000-8000-00000000000" + string(rune('0'+n))
		key.ARN = arn
		k.meta[arn] = key
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(t.TempDir(), kp)
		before := k.encrypts
		if _, err := e.AddKMS(ctx, k, arn, testAccount, ""); !errors.Is(err, ErrKMSKeyRejected) || k.encrypts != before {
			t.Errorf("%s: %v (encrypts %d)", name, err, k.encrypts-before)
		}
		e.Close()
	}
	// Only a full key ARN is taken, before KMS is asked anything: an alias
	// can be re-pointed by anyone with kms:UpdateAlias.
	for _, bad := range []string{"", "alias/ci", "arn:aws:kms:eu-west-1:111122223333:alias/ci", "1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws-iso:kms:us-iso-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab", testARN + "/x", strings.ToUpper(testARN)} {
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(t.TempDir(), kp)
		if _, err := e.AddKMS(ctx, forbid(t), bad, testAccount, ""); !errors.Is(err, ErrKMSNotKeyARN) || !errors.Is(err, ErrKMSKeyRejected) {
			t.Errorf("%q: %v", bad, err)
		}
		e.Close()
	}
	// KMS describing another key than the one asked for is refused.
	k.meta[testARN2] = KMSKey{ARN: testARN, Spec: KMSKeySpecSymmetric, Usage: KMSKeyUsageEncrypt, State: KMSKeyStateEnabled, Manager: KMSKeyManagerCustomer}
	kp, _ := keys.Generate()
	e, _ := NewKMSKeyFile(t.TempDir(), kp)
	defer e.Close()
	if _, err := e.AddKMS(ctx, k, testARN2, testAccount, ""); !errors.Is(err, ErrKMSMismatch) {
		t.Errorf("described another key: %v", err)
	}
}

func TestKMSAnswersAreChecked(t *testing.T) {
	ctx := context.Background()
	t.Run("encrypt for another key", func(t *testing.T) {
		k := newFakeKMS(testARN)
		k.encrypt = func(r *KMSResult) { r.KeyARN = testARN2 }
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(t.TempDir(), kp)
		defer e.Close()
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); !errors.Is(err, ErrKMSMismatch) {
			t.Errorf("%v", err)
		}
	})
	for name, change := range map[string]func(r *KMSResult){
		"empty ciphertext":     func(r *KMSResult) { r.Data = nil },
		"oversized ciphertext": func(r *KMSResult) { r.Data = make([]byte, maxKMSCiphertextLen+1) },
	} {
		k := newFakeKMS(testARN)
		k.encrypt = change
		kp, _ := keys.Generate()
		e, _ := NewKMSKeyFile(t.TempDir(), kp)
		if _, err := e.AddKMS(ctx, k, testARN, testAccount, ""); !errors.Is(err, ErrKMSMismatch) {
			t.Errorf("%s: %v", name, err)
		}
		e.Close()
	}
	for name, change := range map[string]func(r *KMSResult){
		"another key":  func(r *KMSResult) { r.KeyARN = testARN2 },
		"31 bytes":     func(r *KMSResult) { r.Data = r.Data[:31] },
		"33 bytes":     func(r *KMSResult) { r.Data = append(r.Data, 0) },
		"another one":  func(r *KMSResult) { r.Data = mustRand(32) },
		"empty answer": func(r *KMSResult) { r.Data = nil },
	} {
		dir := t.TempDir()
		k := newFakeKMS(testARN)
		_, fp, _ := kmsKey(t, dir, k, false, testARN)
		k.decrypt = change
		_, err := Open(ctx, dir, fp, Unlock{KMS: k})
		if !errors.Is(err, ErrKMSMismatch) {
			t.Errorf("decrypt, %s: %v", name, err)
		}
		for _, sec := range k.secrets {
			if strings.Contains(err.Error(), b64.EncodeToString(sec)) || strings.Contains(err.Error(), hex.EncodeToString(sec)) ||
				strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(sec)) {
				t.Errorf("%s: the error holds the slot secret", name)
			}
		}
	}
}

// Only an outage or an unusable key moves the unlock to the next KMS slot;
// a refusal is shown at once.
func TestKMSNextSlot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k := newFakeKMS(testARN, testARN2)
	kp, fp, _ := kmsKey(t, dir, k, false, testARN, testARN2)

	for _, err := range []error{ErrKMSUnreachable, ErrKMSKeyUnavailable} {
		k.fail[testARN] = err
		got, oerr := Open(ctx, dir, fp, Unlock{KMS: k})
		if oerr != nil {
			t.Fatalf("%v on the first key: %v", err, oerr)
		}
		samePrivate(t, got, kp)
	}
	k.fail[testARN2] = ErrKMSUnreachable
	if _, err := Open(ctx, dir, fp, Unlock{KMS: k}); !errors.Is(err, ErrKMSUnreachable) {
		t.Errorf("both down: %v", err)
	}
	k.fail = map[string]error{testARN: ErrKMSAccessDenied}
	k.decrypts = 0
	if _, err := Open(ctx, dir, fp, Unlock{KMS: k}); !errors.Is(err, ErrKMSAccessDenied) || k.decrypts != 1 {
		t.Errorf("access denied: %v after %d decrypts", err, k.decrypts)
	}
	k.fail = map[string]error{testARN: context.Canceled}
	k.decrypts = 0
	if _, err := Open(ctx, dir, fp, Unlock{KMS: k}); !errors.Is(err, context.Canceled) || k.decrypts != 1 {
		t.Errorf("cancelled: %v after %d decrypts", err, k.decrypts)
	}
}

// tamperKMS writes a KMS file with two KMS slots and a recovery code,
// applies change to its JSON, and returns the results of unlocking through
// KMS and with the code.
func tamperKMS(t *testing.T, change func(f map[string]any)) (errKMS, errCode error) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	k := newFakeKMS(testARN, testARN2)
	_, fp, code := kmsKey(t, dir, k, true, testARN, testARN2)
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
	_, errKMS = Open(ctx, dir, fp, Unlock{KMS: k})
	_, errCode = Open(ctx, dir, fp, Unlock{RecoveryCode: code})
	return errKMS, errCode
}

func kmsField(f map[string]any, i int) map[string]any {
	return slot(f, i)["aws_kms"].(map[string]any)
}

func TestTamperedKMSFileDoesNotOpen(t *testing.T) {
	cases := map[string]func(f map[string]any){
		"key arn":    func(f map[string]any) { kmsField(f, 0)["key_arn"] = testARN2; kmsField(f, 1)["key_arn"] = testARN },
		"account":    func(f map[string]any) { kmsField(f, 0)["account"] = otherAcct; kmsField(f, 1)["account"] = otherAcct },
		"ciphertext": func(f map[string]any) { kmsField(f, 0)["ciphertext"] = flipB64(kmsField(f, 0)["ciphertext"].(string)) },
		"swapped secrets": func(f map[string]any) {
			a, b := kmsField(f, 0), kmsField(f, 1)
			a["ciphertext"], b["ciphertext"] = b["ciphertext"], a["ciphertext"]
		},
		"label":      func(f map[string]any) { slot(f, 0)["label"] = "renamed" },
		"created_at": func(f map[string]any) { slot(f, 0)["created_at"] = "2020-01-01T00:00:00Z" },
		"slot id":    func(f map[string]any) { slot(f, 0)["id"] = "0000000000000000" },
		"wrap": func(f map[string]any) {
			w := slot(f, 0)["wrap"].(map[string]any)
			w["wrapped_key"] = flipB64(w["wrapped_key"].(string))
		},
		"private block": func(f map[string]any) {
			p := f["private"].(map[string]any)
			p["ciphertext"] = flipB64(p["ciphertext"].(string))
		},
		"slot dropped": func(f map[string]any) { f["slots"] = f["slots"].([]any)[1:] },
	}
	for name, change := range cases {
		errKMS, errCode := tamperKMS(t, change)
		if errKMS == nil || errCode == nil {
			t.Errorf("%s: opened (KMS: %v, code: %v)", name, errKMS, errCode)
		}
	}
}

// A slot from another copy of the same key file, sealing the same file key
// under the same KMS key, does not open the private block.
func TestKMSSlotFromAnotherCopyDoesNotOpen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k := newFakeKMS(testARN, testARN2)
	_, fp, _ := kmsKey(t, dir, k, false, testARN, testARN2)
	path := filepath.Join(dir, fp+".json")
	orig, _ := os.ReadFile(path)
	// A second copy: the same file with a third slot added.
	e, err := Edit(ctx, dir, fp, Unlock{KMS: k})
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
	copyB, _ := os.ReadFile(path)
	var a, b map[string]any
	_ = json.Unmarshal(orig, &a)
	_ = json.Unmarshal(copyB, &b)
	a["slots"] = append(a["slots"].([]any), b["slots"].([]any)[2])
	data, _ := json.Marshal(a)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := Open(ctx, dir, fp, Unlock{KMS: k}); err == nil {
		t.Error("a slot from another copy opened the file")
	}
}

func TestVersion6ReaderIsStrict(t *testing.T) {
	cases := map[string]struct {
		change func(f map[string]any)
		want   string
	}{
		"unknown field":      {func(f map[string]any) { kmsField(f, 0)["region"] = "eu-west-1" }, "unknown field"},
		"alias":              {func(f map[string]any) { kmsField(f, 0)["key_arn"] = "arn:aws:kms:eu-west-1:111122223333:alias/ci" }, "not a KMS key ARN"},
		"upper-case account": {func(f map[string]any) { kmsField(f, 0)["account"] = strings.ToUpper(testAccount) }, "lower-case UUID"},
		"empty ciphertext":   {func(f map[string]any) { kmsField(f, 0)["ciphertext"] = "" }, "ciphertext"},
		"6145-byte blob":     {func(f map[string]any) { kmsField(f, 0)["ciphertext"] = b64.EncodeToString(make([]byte, 6145)) }, "ciphertext"},
		"two accounts":       {func(f map[string]any) { kmsField(f, 1)["account"] = otherAcct }, "different accounts"},
		"repeated key":       {func(f map[string]any) { kmsField(f, 1)["key_arn"] = testARN }, "repeated KMS key"},
		"fido2 slot":         {func(f map[string]any) { slot(f, 0)["type"] = "fido2" }, "holds no security key"},
		"future slot type":   {func(f map[string]any) { slot(f, 0)["type"] = "gcp_kms" }, "needs a newer version"},
		"kms data on a code": {func(f map[string]any) { slot(f, 2)["aws_kms"] = kmsField(f, 0) }, "recovery data only"},
		"no KMS key":         {func(f map[string]any) { f["slots"] = f["slots"].([]any)[2:] }, "0 KMS keys"},
		"version 5":          {func(f map[string]any) { f["storage_version"] = 5 }, ""},
	}
	for name, c := range cases {
		dir := t.TempDir()
		k := newFakeKMS(testARN, testARN2)
		_, fp, _ := kmsKey(t, dir, k, true, testARN, testARN2)
		path := filepath.Join(dir, fp+".json")
		data, _ := os.ReadFile(path)
		var f map[string]any
		_ = json.Unmarshal(data, &f)
		c.change(f)
		data, _ = json.Marshal(f)
		_ = os.WriteFile(path, data, 0o600)
		_, err := ReadInfo(dir, fp)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// A 6144-byte blob is within bounds.
	if err := (&kmsSlotV6{KeyARN: testARN, Account: testAccount, Ciphertext: b64.EncodeToString(make([]byte, 6144))}).check(); err != nil {
		t.Errorf("6144 bytes: %v", err)
	}
	// A version 5 file never holds a KMS slot.
	dir := t.TempDir()
	_, fp := v4Key(t, dir, "")
	a := &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}}
	protect(t, dir, fp, "", a)
	path := filepath.Join(dir, fp+".json")
	data, _ := os.ReadFile(path)
	var f map[string]any
	_ = json.Unmarshal(data, &f)
	slot(f, 0)["aws_kms"] = map[string]any{"key_arn": testARN, "account": testAccount, "ciphertext": "AA"}
	data, _ = json.Marshal(f)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := ReadInfo(dir, fp); err == nil || !strings.Contains(err.Error(), "fido2 data only") {
		t.Errorf("KMS data in a version 5 slot: %v", err)
	}
	slot(f, 0)["type"] = "aws_kms"
	delete(slot(f, 0), "fido2")
	data, _ = json.Marshal(f)
	_ = os.WriteFile(path, data, 0o600)
	if _, err := ReadInfo(dir, fp); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("KMS slot in a version 5 file: %v", err)
	}
}

// Every exported function that reads key files handles every version: no
// panic, and the error each version calls for.
func TestEveryEntryPointEveryVersion(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, none := v4Key(t, dir, "")
	_, pw := v4Key(t, dir, "pw")
	_, sk := v4Key(t, dir, "")
	protect(t, dir, sk, "", &fakeAuthenticator{connected: []*fakeDevice{newFakeDevice("A")}})
	k := newFakeKMS(testARN)
	_, km, _ := kmsKey(t, dir, k, false, testARN)
	future, _ := keys.Generate()
	fut, _ := keys.Fingerprint(future)
	writeVersioned(t, filepath.Join(dir, fut+".json"), future, 7)

	names, err := List(dir)
	if err != nil || len(names) != 5 {
		t.Fatalf("List: %v, %v", names, err)
	}
	want := map[string]Protection{none: ProtectionNone, pw: ProtectionPassword, sk: ProtectionSecurityKey, km: ProtectionKMS}
	for fp, p := range want {
		info, err := ReadInfo(dir, fp)
		if err != nil || info.Protection != p {
			t.Errorf("ReadInfo %s: %v, %v", p, info, err)
		}
		if _, err := LoadPublic(dir, fp); err != nil {
			t.Errorf("LoadPublic %s: %v", p, err)
		}
	}
	loadWant := map[string]error{pw: ErrPasswordRequired, sk: ErrSecurityKeyRequired, km: ErrKMSRequired}
	for fp, wantErr := range loadWant {
		if _, err := Load(dir, fp, ""); !errors.Is(err, wantErr) {
			t.Errorf("Load %s: %v", fp[:8], err)
		}
		if _, err := Open(ctx, dir, fp, Unlock{}); !errors.Is(err, wantErr) {
			t.Errorf("Open %s: %v", fp[:8], err)
		}
		if _, err := Edit(ctx, dir, fp, Unlock{}); !errors.Is(err, wantErr) {
			t.Errorf("Edit %s: %v", fp[:8], err)
		}
	}
	for name, call := range map[string]func() error{
		"ReadInfo":   func() error { _, err := ReadInfo(dir, fut); return err },
		"Load":       func() error { _, err := Load(dir, fut, ""); return err },
		"LoadPublic": func() error { _, err := LoadPublic(dir, fut); return err },
		"Open":       func() error { _, err := Open(ctx, dir, fut, Unlock{}); return err },
		"Edit":       func() error { _, err := Edit(ctx, dir, fut, Unlock{}); return err },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "needs a newer version") {
			t.Errorf("%s on version 7: %v", name, err)
		}
	}
	other := t.TempDir()
	for fp, ok := range map[string]bool{none: false, pw: false, sk: true, km: true, fut: false} {
		data, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
		got, err := Import(other, data, false)
		if ok != (err == nil) || (ok && got != fp) {
			t.Errorf("Import %s: %q, %v", fp[:8], got, err)
		}
	}
}

func TestImport(t *testing.T) {
	ctx := context.Background()
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "keys")
	k := newFakeKMS(testARN, testARN2)
	kp, fp, _ := kmsKey(t, src, k, false, testARN)
	data, _ := os.ReadFile(filepath.Join(src, fp+".json"))

	got, err := Import(dst, data, false)
	if err != nil || got != fp {
		t.Fatalf("Import: %q, %v", got, err)
	}
	disktest.AssertPrivate(t, filepath.Join(dst, fp+".json"))
	opened, err := Open(ctx, dst, fp, Unlock{KMS: k})
	if err != nil {
		t.Fatal(err)
	}
	samePrivate(t, opened, kp)
	if _, err := Import(dst, data, false); err != nil {
		t.Errorf("same bytes again: %v", err)
	}

	// A newer file for the same key pair needs replace.
	e, _ := Edit(ctx, src, fp, Unlock{KMS: k})
	if _, err := e.AddKMS(ctx, k, testARN2, testAccount, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		t.Fatal(err)
	}
	e.Close()
	newer, _ := os.ReadFile(filepath.Join(src, fp+".json"))
	if _, err := Import(dst, newer, false); !errors.Is(err, ErrKeyFileExists) {
		t.Errorf("different bytes: %v", err)
	}
	if _, err := Import(dst, newer, true); err != nil {
		t.Errorf("replace: %v", err)
	}
	if info, _ := ReadInfo(dst, fp); info == nil || len(info.Slots) != 2 {
		t.Errorf("after replace: %+v", info)
	}

	var f map[string]any
	_ = json.Unmarshal(data, &f)
	slot(f, 0)["label"] = "\u202ehidden"
	bad, _ := json.Marshal(f)
	for name, d := range map[string][]byte{
		"empty":          nil,
		"garbage":        []byte("not json"),
		"oversized":      bytes.Repeat([]byte(" "), maxKeyFileSize+1),
		"control label":  bad,
		"repeated field": bytes.Replace(data, []byte(`"storage_version": 6,`), []byte(`"storage_version": 6, "Storage_Version": 6,`), 1),
		"trailing data":  append(bytes.Clone(data), []byte(`{}`)...),
	} {
		if _, err := Import(t.TempDir(), d, true); err == nil {
			t.Errorf("%s: imported", name)
		}
	}
}

// TestKMSVectors pins the version 6 derivations and AADs, and the version 5
// AADs as the code wrote them before version 6 existed: a change to any
// locks users out of their files.
func TestKMSVectors(t *testing.T) {
	fp := strings.Repeat("a", 64)
	kek, err := kmsKEK(bytes.Repeat([]byte{0x05}, 32), fp, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kek); got != kmsKEKVector {
		t.Errorf("KMS KEK = %s, want %s", got, kmsKEKVector)
	}
	kek, err = recoveryKEK(kmsStorageVersion, bytes.Repeat([]byte{0x03}, 20), bytes.Repeat([]byte{0x04}, 16), fp, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kek); got != recoveryV6KEKVector {
		t.Errorf("version 6 recovery KEK = %s, want %s", got, recoveryV6KEKVector)
	}
	if _, err := recoveryKEK(4, nil, nil, fp, "0123456789abcdef"); err == nil {
		t.Error("recovery KEK for version 4")
	}

	key := fileSlot{ID: "0123456789abcdef", Type: SlotSecurityKey, Label: "YubiKey 5C", CreatedAt: "2026-11-02T10:00:00Z",
		FIDO2: &fido2SlotV5{RPID: SecurityKeyRPID, CredentialID: "Y3JlZA", AAGUID: strings.Repeat("ab", 16), PRFInput: "cHJm", UV: true},
		Wrap:  wrapV5{Nonce: "bm9uY2U", WrappedKey: "d3JhcA"}}
	code := fileSlot{ID: "fedcba9876543210", Type: SlotRecoveryCode, Label: "Recovery code", CreatedAt: "2026-11-02T10:01:00Z",
		RecoveryCode: &recoverySlotV5{Salt: "c2FsdA"}, Wrap: wrapV5{Nonce: "bjI", WrappedKey: "dzI"}}
	kms := fileSlot{ID: "0123456789abcdef", Type: SlotAWSKMS, Label: "ci-deploy", CreatedAt: "2026-11-11T10:00:00Z",
		AWSKMS: &kmsSlotV6{KeyARN: testARN, Account: testAccount, Ciphertext: "Y2lwaGVy"},
		Wrap:   wrapV5{Nonce: "bm9uY2U", WrappedKey: "d3JhcA"}}
	sum := func(b []byte, err error) string {
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:])
	}
	for name, c := range map[string]struct{ got, want string }{
		"v5 key slot":  {sum(slotAAD(5, fp, &key)), "e8c4a7548b70339dc696de38130db7108b5505461577b45b3b0b9574e7afbf93"},
		"v5 code slot": {sum(slotAAD(5, fp, &code)), "cb6fd11e348ec36acb587d07ad4fdda1ae32b1b0adb40eb2212f6331ef3eb5ba"},
		"v5 private":   {sum(privateAAD(5, fp, []fileSlot{key, code})), "cbe0399635f97959bae2671d6dc79aac6c7efb93cb2ba3e84ec869e79be73ce8"},
		"v6 KMS slot":  {sum(slotAAD(6, fp, &kms)), kmsSlotAADVector},
		"v6 code slot": {sum(slotAAD(6, fp, &code)), codeSlotV6AADVector},
		"v6 private":   {sum(privateAAD(6, fp, []fileSlot{kms, code})), privateV6AADVector},
	} {
		if c.got != c.want {
			t.Errorf("%s AAD hash = %s, want %s", name, c.got, c.want)
		}
	}
	if _, err := slotAAD(4, fp, &kms); err == nil {
		t.Error("slot AAD for version 4")
	}
}

// The KEK vectors were checked against an independent HKDF-SHA256 (RFC 5869)
// implementation. The version 5 AAD hashes were taken from the code before
// version 6 was added.
const (
	kmsKEKVector        = "7dbe471477faea2785b7e11ad3cc133e33ab9f2ff4c429d78ede736146921763"
	recoveryV6KEKVector = "bb749c2ec3651e3373de39b95db8a938edf3b87469f710021f6add1fa0112ab9"
	kmsSlotAADVector    = "10bd0542ad6ce8b11cd03c4d0eb2479ec290466ec056f6297485b60490c572df"
	codeSlotV6AADVector = "7a263c92eea2cd5bad67d7181f5a60649fb03cced614ac095a687d86bf75a5b2"
	privateV6AADVector  = "03a827dc85b11d1018c816edac0706bada0ea024d1d1ee55cf2f3a4b9d5ff5b2"
)

func FuzzParseKMSKeyFile(f *testing.F) {
	dir := f.TempDir()
	k := newFakeKMS(testARN, testARN2)
	kp, _ := keys.Generate()
	fp, _ := keys.Fingerprint(kp)
	e, err := NewKMSKeyFile(dir, kp)
	if err != nil {
		f.Fatal(err)
	}
	for _, arn := range []string{testARN, testARN2} {
		if _, err := e.AddKMS(context.Background(), k, arn, testAccount, ""); err != nil {
			f.Fatal(err)
		}
	}
	if _, err := e.SetRecoveryCode(); err != nil {
		f.Fatal(err)
	}
	if err := e.Commit(false); err != nil {
		f.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, fp+".json"))
	f.Add(data)
	f.Add([]byte(`{"storage_version":6}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		if file, err := parseSlotFile(data, fp); err == nil {
			_, _, _ = file.unlock(context.Background(), fp, Unlock{KMS: k})
			_, _, _ = file.unlock(context.Background(), fp, Unlock{RecoveryCode: "0000-0000-0000-0000-0000-0000-0000-0000"})
		}
		_, _ = Import(dir+"/import", data, true)
	})
}
