// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// Nothing is uploaded for an account this device knows as someone else: the
// server is claiming the caller is them.
func TestSyncRefusesAnEmailKnownAsSomeoneElse(t *testing.T) {
	kp, _ := newKeyPair(t)
	var uploads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var data any = map[string]any{}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/identities":
			uploads.Add(1)
		case r.URL.Path == "/api/v1/actors/me":
			data = actorAnswer("actor-1", OrgKindPersonal)
		case r.URL.Path == "/api/v1/orgs":
			data = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(srv.Close)
	api, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	store := knownkeys.New(filepath.Join(t.TempDir(), "known_keys.json"), srv.URL, t.TempDir())
	someoneElse := strings.Repeat("a", 64)
	if err := store.RecordFirstUse([]knownkeys.Person{{Email: "ana@example.com", Fingerprint: someoneElse}}, false); err != nil {
		t.Fatal(err)
	}
	err = New(api, store, t.TempDir()).Sync(context.Background(), kp, false)
	if err == nil || !strings.Contains(err.Error(), "someone else") {
		t.Fatalf("Sync = %v", err)
	}
	if n := uploads.Load(); n != 0 {
		t.Errorf("%d uploads", n)
	}
}

func TestLoadPrimaryUnlocksWithAPassword(t *testing.T) {
	kp, fp := newKeyPair(t)
	dir := t.TempDir()
	if err := keystore.Save(dir, fp, kp, "pw"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{
			"keys": []map[string]any{{"id": "k1", "fingerprint": fp, "is_primary": true}},
		}})
	}))
	t.Cleanup(srv.Close)
	api, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	store := knownkeys.New(filepath.Join(t.TempDir(), "known_keys.json"), srv.URL, dir)
	c := New(api, store, dir)
	got, gotFP, err := c.LoadPrimary(context.Background(), keystore.Unlock{Password: "pw"})
	if err != nil || gotFP != fp || got.ED25519Private != kp.ED25519Private {
		t.Fatalf("LoadPrimary = %v, %v", gotFP, err)
	}
	if _, _, err := c.LoadPrimary(context.Background(), keystore.Unlock{Password: "wrong"}); !errors.Is(err, keystore.ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
}
