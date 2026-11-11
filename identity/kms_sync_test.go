// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

const kmsARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

type sealKMS struct{ key []byte }

func (k sealKMS) DescribeKey(context.Context, string) (*keystore.KMSKey, error) {
	return &keystore.KMSKey{ARN: kmsARN, Spec: keystore.KMSKeySpecSymmetric, Usage: keystore.KMSKeyUsageEncrypt,
		State: keystore.KMSKeyStateEnabled, Manager: keystore.KMSKeyManagerCustomer}, nil
}

func (k sealKMS) Encrypt(_ context.Context, _ string, _ map[string]string, p []byte) (*keystore.KMSResult, error) {
	block, _ := aes.NewCipher(k.key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return &keystore.KMSResult{KeyARN: kmsARN, Data: gcm.Seal(nonce, nonce, p, nil)}, nil
}

func (k sealKMS) Decrypt(context.Context, string, map[string]string, []byte) (*keystore.KMSResult, error) {
	return nil, errors.New("not used")
}

// A key pair whose KMS slots are bound to one account is not registered
// under another: the key policies written for its encryption context would
// not match the account that uses it.
func TestSyncRefusesAKMSKeyOfAnotherAccount(t *testing.T) {
	const bound = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
	for _, tc := range []struct {
		signedIn string
		refused  bool
	}{
		{bound, false},
		{"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", true},
	} {
		dir := t.TempDir()
		kp, _ := newKeyPair(t)
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		e, err := keystore.NewKMSKeyFile(dir, kp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.AddKMS(context.Background(), sealKMS{key}, kmsARN, bound, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.Commit(true); err != nil {
			t.Fatal(err)
		}
		e.Close()
		var uploads atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			var data any = map[string]any{}
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/identities":
				uploads.Add(1)
			case r.URL.Path == "/api/v1/actors/me":
				data = actorAnswer(tc.signedIn, OrgKindPersonal)
			case r.URL.Path == "/api/v1/orgs":
				data = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
		}))
		api, err := transport.NewClient(srv.URL, "test-key")
		if err != nil {
			t.Fatal(err)
		}
		store := knownkeys.New(filepath.Join(t.TempDir(), "known_keys.json"), srv.URL, dir)
		err = New(api, store, dir).Sync(context.Background(), kp, false)
		srv.Close()
		if tc.refused != errors.Is(err, ErrKMSAccountMismatch) {
			t.Errorf("signed in as %s: %v", tc.signedIn, err)
		}
		if want := map[bool]int64{true: 0, false: 1}[tc.refused]; uploads.Load() != want {
			t.Errorf("signed in as %s: %d uploads", tc.signedIn, uploads.Load())
		}
	}
}

// A key file that exists but does not read is not taken for a missing one:
// Sync refuses rather than register a key pair whose binding it cannot see.
func TestSyncRefusesAnUnreadableKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not make a key file unreadable on Windows")
	}
	dir := t.TempDir()
	kp, fp := newKeyPair(t)
	if err := keystore.Save(dir, fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, fp+".json"), 0o640); err != nil {
		t.Fatal(err)
	}
	var uploads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var data any = map[string]any{}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/identities":
			uploads.Add(1)
		case r.URL.Path == "/api/v1/actors/me":
			data = actorAnswer("6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f", OrgKindPersonal)
		case r.URL.Path == "/api/v1/orgs":
			data = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	defer srv.Close()
	api, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	store := knownkeys.New(filepath.Join(t.TempDir(), "known_keys.json"), srv.URL, dir)
	if err := New(api, store, dir).Sync(context.Background(), kp, false); err == nil || uploads.Load() != 0 {
		t.Errorf("Sync with an unreadable key file: %v, %d uploads", err, uploads.Load())
	}
}
