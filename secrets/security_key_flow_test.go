// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// testSecurityKey is one fake FIDO2 key: a secret per credential, and a
// count of the unlocks it answered.
type testSecurityKey struct {
	secrets map[string][]byte
	derives int
}

func (k *testSecurityKey) output(id, input []byte) []byte {
	salt := keystore.PRFSalt(input)
	m := hmac.New(sha256.New, k.secrets[hex.EncodeToString(id)])
	m.Write(salt[:])
	return m.Sum(nil)
}

func (k *testSecurityKey) Enroll(_ context.Context, req keystore.EnrollRequest) (*keystore.EnrollResult, error) {
	id, secret := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(id)
	_, _ = rand.Read(secret)
	k.secrets[hex.EncodeToString(id)] = secret
	return &keystore.EnrollResult{CredentialID: id, Device: "Test key", Output: k.output(id, req.PRFInput)}, nil
}

func (k *testSecurityKey) Derive(_ context.Context, req keystore.DeriveRequest) (*keystore.DeriveResult, error) {
	k.derives++
	for _, c := range req.Credentials {
		if _, ok := k.secrets[hex.EncodeToString(c.ID)]; ok {
			return &keystore.DeriveResult{CredentialID: c.ID, Output: k.output(c.ID, c.PRFInput)}, nil
		}
	}
	return nil, keystore.ErrNoSecurityKey
}

// TestSecurityKeyProtectedSender sends and opens secrets with a sender key
// that only a security key or its recovery code unlocks, once per
// operation.
func TestSecurityKeyProtectedSender(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	key := &testSecurityKey{secrets: map[string][]byte{}}
	e, err := keystore.Edit(context.Background(), alice.keys, alice.fp, keystore.Unlock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddSecurityKey(context.Background(), key, ""); err != nil {
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
	c := f.client(alice.email)

	// Without the security key, the send stops before anything is sealed.
	if _, err := c.Secrets.EncryptText(context.Background(), []string{bob.email}, "hi", secrets.EncryptOptions{Name: "no-key"}); !errors.Is(err, keystore.ErrSecurityKeyRequired) {
		t.Fatalf("send without the security key: %v", err)
	}

	res, err := c.Secrets.EncryptText(context.Background(), []string{bob.email}, "hello bob", secrets.EncryptOptions{Name: "greeting", Unlock: keystore.Unlock{SecurityKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	if key.derives != 1 {
		t.Errorf("one send unlocked the key %d times, want 1", key.derives)
	}
	out, err := f.client(bob.email).Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{})
	if err != nil || out.Decrypted.Message != "hello bob" {
		t.Fatalf("bob decrypt: %+v, %v", out, err)
	}

	// A send to herself checks her own key on this device without
	// unlocking it, then she opens it with the security key.
	key.derives = 0
	res, err = c.Secrets.EncryptText(context.Background(), []string{alice.email}, "note to self", secrets.EncryptOptions{Name: "self", Unlock: keystore.Unlock{SecurityKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := c.Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{Unlock: keystore.Unlock{SecurityKey: key}})
	if err != nil || mine.Decrypted.Message != "note to self" {
		t.Fatalf("self decrypt: %+v, %v", mine, err)
	}
	if key.derives != 2 {
		t.Errorf("a send and a decrypt unlocked the key %d times, want 2", key.derives)
	}

	// The recovery code works in place of the security key.
	if _, err := c.Secrets.EncryptText(context.Background(), []string{bob.email}, "via code", secrets.EncryptOptions{Name: "code", Unlock: keystore.Unlock{RecoveryCode: code}}); err != nil {
		t.Fatalf("send with the recovery code: %v", err)
	}
	if _, _, err := c.Identity.LoadPrimary(context.Background(), keystore.Unlock{SecurityKey: key}); err != nil {
		t.Fatalf("LoadPrimaryIdentityWith: %v", err)
	}
	if _, _, err := c.Identity.LoadPrimary(context.Background(), keystore.Unlock{}); !errors.Is(err, keystore.ErrSecurityKeyRequired) {
		t.Fatalf("LoadPrimaryIdentity without the key: %v", err)
	}
}
