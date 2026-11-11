// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/secrets"
)

const testKMSARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// testKMS is one fake symmetric KMS key: AES-GCM with the encryption
// context as AAD, and a count of the decrypts it answered.
type testKMS struct {
	key      []byte
	decrypts int
}

func newTestKMS() *testKMS {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &testKMS{key: k}
}

func (k *testKMS) aad(c map[string]string) []byte {
	return []byte(c[keystore.KMSContextKeyPurpose] + "|" + c[keystore.KMSContextKeyFingerprint] + "|" + c[keystore.KMSContextKeyAccount] + "|" + c[keystore.KMSContextKeySlot])
}

func (k *testKMS) DescribeKey(context.Context, string) (*keystore.KMSKey, error) {
	return &keystore.KMSKey{ARN: testKMSARN, Spec: keystore.KMSKeySpecSymmetric, Usage: keystore.KMSKeyUsageEncrypt,
		State: keystore.KMSKeyStateEnabled, Manager: keystore.KMSKeyManagerCustomer}, nil
}

func (k *testKMS) Encrypt(_ context.Context, _ string, c map[string]string, p []byte) (*keystore.KMSResult, error) {
	block, _ := aes.NewCipher(k.key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return &keystore.KMSResult{KeyARN: testKMSARN, Data: gcm.Seal(nonce, nonce, p, k.aad(c))}, nil
}

func (k *testKMS) Decrypt(_ context.Context, _ string, c map[string]string, ct []byte) (*keystore.KMSResult, error) {
	k.decrypts++
	block, _ := aes.NewCipher(k.key)
	gcm, _ := cipher.NewGCM(block)
	if len(ct) < gcm.NonceSize() {
		return nil, keystore.ErrKMSMismatch
	}
	p, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], k.aad(c))
	if err != nil {
		return nil, keystore.ErrKMSMismatch
	}
	return &keystore.KMSResult{KeyARN: testKMSARN, Data: p}, nil
}

// TestKMSProtectedKeys sends and opens secrets with key pairs that only a
// KMS key (or the recovery code) unlocks, once per operation.
func TestKMSProtectedKeys(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	k := newTestKMS()
	const account = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
	codes := map[string]string{}
	for _, a := range []*fakeActor{alice, bob} {
		e, err := keystore.Edit(context.Background(), a.keys, a.fp, keystore.Unlock{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddKMS(context.Background(), k, testKMSARN, account, ""); err != nil {
			t.Fatal(err)
		}
		if codes[a.email], err = e.SetRecoveryCode(); err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(false); err != nil {
			t.Fatal(err)
		}
		e.Close()
	}
	c := f.client(alice.email)

	if _, err := c.Secrets.EncryptText(context.Background(), []string{bob.email}, "hi", secrets.EncryptOptions{Name: "no-kms"}); !errors.Is(err, keystore.ErrKMSRequired) {
		t.Fatalf("send without KMS: %v", err)
	}
	res, err := c.Secrets.EncryptText(context.Background(), []string{bob.email}, "hello bob", secrets.EncryptOptions{Name: "greeting", Unlock: keystore.Unlock{KMS: k}})
	if err != nil {
		t.Fatal(err)
	}
	if k.decrypts != 1 {
		t.Errorf("one send unlocked %d times, want 1", k.decrypts)
	}
	if _, err := f.client(bob.email).Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{}); !errors.Is(err, keystore.ErrKMSRequired) {
		t.Fatalf("bob decrypt without KMS: %v", err)
	}
	out, err := f.client(bob.email).Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{Unlock: keystore.Unlock{KMS: k}})
	if err != nil || out.Decrypted.Message != "hello bob" {
		t.Fatalf("bob decrypt: %+v, %v", out, err)
	}
	out, err = f.client(bob.email).Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{Unlock: keystore.Unlock{RecoveryCode: codes[bob.email]}})
	if err != nil || out.Decrypted.Message != "hello bob" {
		t.Fatalf("bob decrypt with the recovery code: %+v, %v", out, err)
	}
}
