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
	"slices"
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

// RecordOwnAccount records the account as the user's own with a key pair on
// this device that the server lists for it, uploading nothing. It refuses
// what Sync refuses, a key that is not on this device and one the account
// does not list, and records nothing then.
func TestRecordOwnAccount(t *testing.T) {
	const ana, bo = "ana@example.com", "bo@example.com" // ana is the account actorAnswer names
	kp, fp := newKeyPair(t)
	_, elsewhere := newKeyPair(t)
	someoneElse := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name       string
		registered string                       // the key the server lists for ana
		record     string                       // the fingerprint passed
		before     func(*knownkeys.Store) error // what this device knew already
		refused    string                       // what the refusal says, or "" when it records
	}{
		{name: "registered elsewhere", registered: fp, record: fp},
		{name: "known by that key on first use", registered: fp, record: fp, before: func(s *knownkeys.Store) error {
			return s.RecordFirstUse([]knownkeys.Person{{Email: ana, Fingerprint: fp}}, false)
		}},
		{name: "upper case", registered: fp, record: strings.ToUpper(fp)},
		{name: "not a full fingerprint", registered: fp, record: fp[:16], refused: "64 hex characters"},
		{name: "not on this device", registered: elsewhere, record: elsewhere, refused: "on this device"},
		{name: "not registered", registered: elsewhere, record: fp, refused: "not registered"},
		{name: "known as someone else", registered: fp, record: fp, before: func(s *knownkeys.Store) error {
			return s.RecordFirstUse([]knownkeys.Person{{Email: ana, Fingerprint: someoneElse}}, false)
		}, refused: "someone else"},
		{name: "another account's key", registered: fp, record: fp, before: func(s *knownkeys.Store) error {
			_, err := s.RecordOwnAccount(bo, fp, true)
			return err
		}, refused: "your account " + bo + "'s key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var uploads atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				var data any = map[string]any{}
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/api/v1/identities":
					uploads.Add(1)
				case r.URL.Path == "/api/v1/identities":
					data = map[string]any{"keys": []map[string]any{{"id": "k1", "fingerprint": tc.registered, "is_primary": true}}}
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
			dir := t.TempDir()
			if err := keystore.Save(dir, fp, kp, ""); err != nil {
				t.Fatal(err)
			}
			store := knownkeys.New(filepath.Join(t.TempDir(), "known_keys.json"), srv.URL, dir)
			if tc.before != nil {
				if err := tc.before(store); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.List(ana)
			if err != nil {
				t.Fatal(err)
			}

			err = New(api, store, dir).RecordOwnAccount(context.Background(), tc.record)
			known, lerr := store.List(ana)
			if lerr != nil {
				t.Fatal(lerr)
			}
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("RecordOwnAccount = %v", err)
				}
				if len(known) != 1 || known[0].Fingerprint != fp || known[0].State != knownkeys.Own {
					t.Fatalf("ana's known keys %+v, want her key as the user's own", known)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("RecordOwnAccount = %v, want it refused saying %q", err, tc.refused)
				}
				if len(known) != len(before) || slices.ContainsFunc(known, func(k knownkeys.KnownKey) bool { return k.State == knownkeys.Own }) {
					t.Fatalf("ana's known keys %+v after the refusal, want %+v", known, before)
				}
			}
			if n := uploads.Load(); n != 0 {
				t.Errorf("%d uploads", n)
			}
		})
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
