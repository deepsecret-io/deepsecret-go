// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/deepsecret-io/sdk/crypto"
)

// testSecurityKey is one fake FIDO2 key: a secret per credential, and a
// count of the unlocks it answered.
type testSecurityKey struct {
	secrets map[string][]byte
	derives int
}

func (k *testSecurityKey) output(id, input []byte) []byte {
	salt := crypto.PRFSalt(input)
	m := hmac.New(sha256.New, k.secrets[hex.EncodeToString(id)])
	m.Write(salt[:])
	return m.Sum(nil)
}

func (k *testSecurityKey) Enroll(_ context.Context, req crypto.EnrollRequest) (*crypto.EnrollResult, error) {
	id, secret := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(id)
	_, _ = rand.Read(secret)
	k.secrets[hex.EncodeToString(id)] = secret
	return &crypto.EnrollResult{CredentialID: id, Device: "Test key", Output: k.output(id, req.PRFInput)}, nil
}

func (k *testSecurityKey) Derive(_ context.Context, req crypto.DeriveRequest) (*crypto.DeriveResult, error) {
	k.derives++
	for _, c := range req.Credentials {
		if _, ok := k.secrets[hex.EncodeToString(c.ID)]; ok {
			return &crypto.DeriveResult{CredentialID: c.ID, Output: k.output(c.ID, c.PRFInput)}, nil
		}
	}
	return nil, crypto.ErrNoSecurityKey
}

// TestSecurityKeyProtectedSender sends and opens secrets with a sender key
// that only a security key or its recovery code unlocks, once per
// operation.
func TestSecurityKeyProtectedSender(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	key := &testSecurityKey{secrets: map[string][]byte{}}
	e, err := crypto.EditKeyFile(context.Background(), alice.keys, alice.fp, crypto.Unlock{})
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
	if _, err := c.EncryptText(context.Background(), []string{bob.email}, "hi", EncryptOptions{Name: "no-key"}); !errors.Is(err, crypto.ErrSecurityKeyRequired) {
		t.Fatalf("send without the security key: %v", err)
	}

	res, err := c.EncryptText(context.Background(), []string{bob.email}, "hello bob", EncryptOptions{Name: "greeting", SecurityKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if key.derives != 1 {
		t.Errorf("one send unlocked the key %d times, want 1", key.derives)
	}
	out, err := f.client(bob.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{})
	if err != nil || out.Decrypted.Message != "hello bob" {
		t.Fatalf("bob decrypt: %+v, %v", out, err)
	}

	// A send to herself checks her own key on this device without
	// unlocking it, then she opens it with the security key.
	key.derives = 0
	res, err = c.EncryptText(context.Background(), []string{alice.email}, "note to self", EncryptOptions{Name: "self", SecurityKey: key})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := c.DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{SecurityKey: key})
	if err != nil || mine.Decrypted.Message != "note to self" {
		t.Fatalf("self decrypt: %+v, %v", mine, err)
	}
	if key.derives != 2 {
		t.Errorf("a send and a decrypt unlocked the key %d times, want 2", key.derives)
	}

	// The recovery code works in place of the security key.
	if _, err := c.EncryptText(context.Background(), []string{bob.email}, "via code", EncryptOptions{Name: "code", RecoveryCode: code}); err != nil {
		t.Fatalf("send with the recovery code: %v", err)
	}
	if _, _, err := c.LoadPrimaryIdentityWith(context.Background(), crypto.Unlock{SecurityKey: key}); err != nil {
		t.Fatalf("LoadPrimaryIdentityWith: %v", err)
	}
	if _, _, err := c.LoadPrimaryIdentity(context.Background(), ""); !errors.Is(err, crypto.ErrSecurityKeyRequired) {
		t.Fatalf("LoadPrimaryIdentity without the key: %v", err)
	}
}
