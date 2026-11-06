// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

func newKeyPair(t *testing.T) (*keys.Pair, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return kp, fp
}

// meServer answers /actors/me with me and /orgs with orgs (or a 500 when
// orgs is nil), and counts the requests each path gets.
func meServer(t *testing.T, me map[string]any, orgs []map[string]any) (*transport.Client, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		var data any
		switch {
		case r.URL.Path == "/api/v1/actors/me":
			data = me
		case r.URL.Path == "/api/v1/orgs" && orgs != nil:
			data = orgs
		default:
			http.Error(w, `{"success":false,"message":"no"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(srv.Close)
	c, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	return c, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[path]
	}
}

func actorAnswer(id, kind string) map[string]any {
	return map[string]any{
		"actor":           map[string]any{"id": id, "email": "ana@example.com", "name": "Ana"},
		"membership":      map[string]any{"org_id": "org-1", "role": "owner", "org_kind": kind},
		"effective_state": "ACTIVE_OWNER",
		"subscription":    map[string]any{"status": "active"},
	}
}

// whoAmI reads the membership's kind, which tells a personal workspace
// from an organization, and the tier name from /orgs.
func TestWhoAmIReadsTheOrgKind(t *testing.T) {
	for _, kind := range []string{OrgKindPersonal, OrgKindOrganization} {
		c, _ := meServer(t, actorAnswer("actor-1", kind), []map[string]any{{"id": "org-1", "tier_name": "Personal"}})
		info, err := whoAmI(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if info.Membership == nil || info.Membership.OrgKind != kind || info.Membership.Role != "owner" {
			t.Errorf("membership %+v, want kind %s", info.Membership, kind)
		}
		if info.ID != "actor-1" || info.Email != "ana@example.com" || info.OrgID != "org-1" || info.TierName != "Personal" {
			t.Errorf("flat fields %+v", info)
		}
	}

	// /orgs failing only leaves the tier name out.
	c, _ := meServer(t, actorAnswer("actor-1", OrgKindPersonal), nil)
	info, err := whoAmI(context.Background(), c)
	if err != nil || info.TierName != "" || info.Membership.OrgKind != OrgKindPersonal {
		t.Fatalf("without /orgs: %+v, %v", info, err)
	}
}

// resolveActorID, which every secrets list calls first, makes one request:
// /actors/me, never the tier lookup. An answer without an ID fails.
func TestResolveActorIDIsOneRequest(t *testing.T) {
	c, hits := meServer(t, actorAnswer("actor-1", OrgKindOrganization), []map[string]any{{"id": "org-1", "tier_name": "Team"}})
	id, err := resolveActorID(context.Background(), c)
	if err != nil || id != "actor-1" {
		t.Fatalf("resolveActorID = %q, %v", id, err)
	}
	if hits("/api/v1/actors/me") != 1 || hits("/api/v1/orgs") != 0 {
		t.Errorf("requests: actors/me %d, orgs %d; want 1 and 0", hits("/api/v1/actors/me"), hits("/api/v1/orgs"))
	}

	c, _ = meServer(t, actorAnswer("", OrgKindOrganization), nil)
	if id, err := resolveActorID(context.Background(), c); err == nil {
		t.Fatalf("an answer without an ID gave %q", id)
	}
}

// The security key label goes out when a key pair is registered and when
// it is changed, and comes back in the caller's own key list.
func TestSecurityKeyLabel(t *testing.T) {
	kp, fp := newKeyPair(t)
	var mu sync.Mutex
	got := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got[r.Method+" "+r.URL.Path] = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		data := map[string]any{"message": "ok"}
		if r.Method == http.MethodGet {
			data = map[string]any{"keys": []map[string]any{{"id": "k1", "fingerprint": fp, "security_key": true}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(srv.Close)
	c, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	if err := syncIdentity(context.Background(), c, kp, true); err != nil {
		t.Fatal(err)
	}
	if err := setKeySecurityKey(context.Background(), c, "k1", false); err != nil {
		t.Fatal(err)
	}
	listed, err := listRemoteKeys(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if v := got["POST /api/v1/identities"]["security_key"]; v != true {
		t.Errorf("register: security_key = %v, want true", v)
	}
	if v, ok := got["PUT /api/v1/identities/k1/security-key"]["security_key"]; !ok || v != false {
		t.Errorf("update: security_key = %v (sent %v), want false", v, ok)
	}
	if len(listed) != 1 || !listed[0].SecurityKey {
		t.Errorf("listed keys: %+v, want the label set", listed)
	}
}
