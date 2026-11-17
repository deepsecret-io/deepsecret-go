// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
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

// meServer answers /members/me with me and /orgs with orgs (or a 500 when
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
		case r.URL.Path == "/api/v1/members/me":
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

func memberAnswer(id, kind string) map[string]any {
	return map[string]any{
		"member":          map[string]any{"id": id, "email": "ana@example.com", "name": "Ana"},
		"membership":      map[string]any{"org_id": "org-1", "role": "owner", "org_kind": kind},
		"effective_state": "ACTIVE_OWNER",
		"subscription":    map[string]any{"status": "active"},
	}
}

// whoAmI reads the membership's kind, which tells a personal workspace
// from an organization, and the tier name from /orgs.
func TestWhoAmIReadsTheOrgKind(t *testing.T) {
	for _, kind := range []string{OrgKindPersonal, OrgKindOrganization} {
		c, _ := meServer(t, memberAnswer("member-1", kind), []map[string]any{{"id": "org-1", "tier_name": "Personal"}})
		info, err := whoAmI(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if info.Membership == nil || info.Membership.OrgKind != kind || info.Membership.Role != "owner" {
			t.Errorf("membership %+v, want kind %s", info.Membership, kind)
		}
		if info.ID != "member-1" || info.Email != "ana@example.com" || info.OrgID != "org-1" || info.TierName != "Personal" {
			t.Errorf("flat fields %+v", info)
		}
	}

	// /orgs failing only leaves the tier name out.
	c, _ := meServer(t, memberAnswer("member-1", OrgKindPersonal), nil)
	info, err := whoAmI(context.Background(), c)
	if err != nil || info.TierName != "" || info.Membership.OrgKind != OrgKindPersonal {
		t.Fatalf("without /orgs: %+v, %v", info, err)
	}
}

// resolveMemberID, which every secrets list calls first, makes one request:
// /members/me, never the tier lookup. An answer without an ID fails.
func TestResolveMemberIDIsOneRequest(t *testing.T) {
	c, hits := meServer(t, memberAnswer("member-1", OrgKindOrganization), []map[string]any{{"id": "org-1", "tier_name": "Team"}})
	id, err := resolveMemberID(context.Background(), c)
	if err != nil || id != "member-1" {
		t.Fatalf("resolveMemberID = %q, %v", id, err)
	}
	if hits("/api/v1/members/me") != 1 || hits("/api/v1/orgs") != 0 {
		t.Errorf("requests: members/me %d, orgs %d; want 1 and 0", hits("/api/v1/members/me"), hits("/api/v1/orgs"))
	}

	c, _ = meServer(t, memberAnswer("", OrgKindOrganization), nil)
	if id, err := resolveMemberID(context.Background(), c); err == nil {
		t.Fatalf("an answer without an ID gave %q", id)
	}
}

// The protection label goes out when a key pair is registered and when it
// is changed, and comes back in the caller's own key list. A protection the
// server does not take is left out of a registration, which still goes
// ahead, and refused before any request when set on its own.
func TestProtectionLabel(t *testing.T) {
	kp, fp := newKeyPair(t)
	var mu sync.Mutex
	got := map[string]map[string]any{}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got[r.Method+" "+r.URL.Path] = body
		requests++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		data := map[string]any{"message": "ok"}
		if r.Method == http.MethodGet {
			data = map[string]any{"keys": []map[string]any{
				{"id": "k1", "fingerprint": fp, "protection": "aws_kms"},
				{"id": "k2", "fingerprint": strings.Repeat("ab", 32), "protection": ""},
			}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(srv.Close)
	c, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}

	if err := syncIdentity(context.Background(), c, kp, keystore.ProtectionSecurityKey); err != nil {
		t.Fatal(err)
	}
	if v := got["POST /api/v1/identities"]["protection"]; v != "security_key" {
		t.Errorf("register: protection = %v, want security_key", v)
	}
	if _, ok := got["POST /api/v1/identities"]["security_key"]; ok {
		t.Error("register still sends security_key")
	}
	for _, p := range []keystore.Protection{"", "bogus"} {
		if err := syncIdentity(context.Background(), c, kp, p); err != nil {
			t.Fatalf("register with %q: %v", p, err)
		}
		if v, ok := got["POST /api/v1/identities"]["protection"]; ok {
			t.Errorf("register with %q: sent protection %v", p, v)
		}
	}

	for _, p := range []keystore.Protection{keystore.ProtectionNone, keystore.ProtectionPassword, keystore.ProtectionSecurityKey, keystore.ProtectionKMS} {
		if err := setKeyProtection(context.Background(), c, "k1", p); err != nil {
			t.Fatal(err)
		}
		if v, ok := got["PUT /api/v1/identities/k1/protection"]["protection"]; !ok || v != string(p) {
			t.Errorf("update: protection = %v (sent %v), want %s", v, ok, p)
		}
	}
	before := requests
	for _, p := range []keystore.Protection{"", "bogus"} {
		if err := setKeyProtection(context.Background(), c, "k1", p); !errors.Is(err, ErrUnknownProtection) {
			t.Errorf("update with %q: err = %v, want ErrUnknownProtection", p, err)
		}
	}
	if requests != before {
		t.Errorf("a refused update made %d requests", requests-before)
	}

	listed, err := listRemoteKeys(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].Protection != keystore.ProtectionKMS || listed[1].Protection != "" {
		t.Errorf("listed keys: %+v, want aws_kms and not reported", listed)
	}
}
