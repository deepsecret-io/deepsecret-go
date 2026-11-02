// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
)

func newKeyPair(t *testing.T) (*crypto.KeyPair, string) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := crypto.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return kp, fp
}

// bundle is kp's published key bundle, as the identities endpoint lists it.
func bundle(t *testing.T, kp *crypto.KeyPair) map[string]any {
	t.Helper()
	fp, _ := crypto.Fingerprint(kp)
	edSig, mldsaSig, err := crypto.SignKeyBundle(kp)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"ed25519": kp.ED25519Public, "x25519": kp.X25519Public, "mlkem768": kp.MLKEM768PK,
		"mldsa65": kp.MLDSA65PK, "fingerprint": fp, "signature": edSig, "signature_mldsa65": mldsaSig,
		"is_primary": true,
	}
}

// keysServer serves bundles as every actor's key list.
func keysServer(t *testing.T, bundles ...map[string]any) *api.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/identities/actor/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"keys": bundles}})
	}))
	t.Cleanup(srv.Close)
	c, err := api.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetRecipientKeys(t *testing.T) {
	kp, fp := newKeyPair(t)
	other, _ := newKeyPair(t)
	otherBundle := bundle(t, other)

	cases := []struct {
		name string
		edit func(b map[string]any)
		want string // "" when the keys are accepted
	}{
		{"whole bundle", func(map[string]any) {}, ""},
		{"no fingerprint", func(b map[string]any) { delete(b, "fingerprint") }, "has no fingerprint"},
		{"empty fingerprint", func(b map[string]any) { b["fingerprint"] = "" }, "has no fingerprint"},
		{"another key's fingerprint", func(b map[string]any) { b["fingerprint"] = otherBundle["fingerprint"] }, "fingerprint mismatch"},
		{"upper-case fingerprint", func(b map[string]any) { b["fingerprint"] = strings.ToUpper(fp) }, "fingerprint mismatch"},
		{"no Ed25519 signature", func(b map[string]any) { delete(b, "signature") }, "no Ed25519 self-signature"},
		{"no ML-DSA-65 signature", func(b map[string]any) { delete(b, "signature_mldsa65") }, "no ML-DSA-65 self-signature"},
		{"no signatures", func(b map[string]any) { b["signature"], b["signature_mldsa65"] = "", "" }, "no Ed25519 self-signature"},
		{"another key's Ed25519 signature", func(b map[string]any) { b["signature"] = otherBundle["signature"] }, "Ed25519 key bundle signature verification failed"},
		{"another key's ML-DSA-65 signature", func(b map[string]any) { b["signature_mldsa65"] = otherBundle["signature_mldsa65"] }, "ML-DSA-65 key bundle signature verification failed"},
		{"swapped encryption key", func(b map[string]any) {
			// The fingerprint follows the swap, so only the signatures catch it.
			b["x25519"] = other.X25519Public
			b["fingerprint"], _ = crypto.FingerprintFromPubs(kp.ED25519Public, other.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
		}, "Ed25519 key bundle signature verification failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle(t, kp)
			tc.edit(b)
			keys, err := GetRecipientKeys(keysServer(t, b), "bob@example.com")
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if keys.Fingerprint != fp || keys.X25519 != kp.X25519Public || keys.MLKEM768 != kp.MLKEM768PK {
					t.Fatalf("keys %+v are not the bundle's", keys)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// The primary bundle is the one checked and returned: a broken non-primary
// bundle beside it does not matter, and a broken primary one is not passed
// over for a whole one.
func TestGetRecipientKeysChecksThePrimary(t *testing.T) {
	kp, fp := newKeyPair(t)
	other, _ := newKeyPair(t)
	primary, secondary := bundle(t, kp), bundle(t, other)
	secondary["is_primary"] = false
	delete(secondary, "signature")

	keys, err := GetRecipientKeys(keysServer(t, secondary, primary), "bob@example.com")
	if err != nil || keys.Fingerprint != fp {
		t.Fatalf("keys %+v, %v: want the primary", keys, err)
	}

	secondary, primary = bundle(t, other), bundle(t, kp)
	secondary["is_primary"] = false
	delete(primary, "signature_mldsa65")
	if _, err := GetRecipientKeys(keysServer(t, secondary, primary), "bob@example.com"); err == nil {
		t.Fatal("broken primary bundle accepted")
	}
}

// A sender's own keys, as the server lists them, are accepted only when
// they are the sending identity or another key pair on this device.
func TestCheckOwnKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sender, senderFP := newKeyPair(t)
	stored, storedFP := newKeyPair(t)
	// A password-protected key is checked without its password.
	if err := crypto.SaveKeyPair(storedFP, stored, "correct horse"); err != nil {
		t.Fatal(err)
	}
	attacker, _ := newKeyPair(t)

	pubs := func(kp *crypto.KeyPair) *crypto.PublicKeys {
		fp, _ := crypto.Fingerprint(kp)
		return &crypto.PublicKeys{ED25519: kp.ED25519Public, X25519: kp.X25519Public,
			MLKEM768: kp.MLKEM768PK, MLDSA65: kp.MLDSA65PK, Fingerprint: fp}
	}

	if err := CheckOwnKeys(pubs(sender), senderFP); err != nil {
		t.Errorf("sending identity: %v", err)
	}
	if err := CheckOwnKeys(pubs(stored), senderFP); err != nil {
		t.Errorf("another key on this device: %v", err)
	}
	if err := CheckOwnKeys(pubs(attacker), senderFP); err == nil || !strings.Contains(err.Error(), "not a key on this device") {
		t.Errorf("substituted key: %v, want refused", err)
	}

	// The fingerprint is computed from the keys, never taken from the
	// Fingerprint field.
	forged := pubs(attacker)
	forged.Fingerprint = senderFP
	if err := CheckOwnKeys(forged, senderFP); err == nil {
		t.Error("substituted key labelled with the sender's fingerprint accepted")
	}
}

// meServer answers /actors/me with me and /orgs with orgs (or a 500 when
// orgs is nil), and counts the requests each path gets.
func meServer(t *testing.T, me map[string]any, orgs []map[string]any) (*api.Client, func(path string) int) {
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
	c, err := api.NewClient(srv.URL, "test-key")
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

// WhoAmI reads the membership's kind, which tells a personal workspace
// from an organization, and the tier name from /orgs.
func TestWhoAmIReadsTheOrgKind(t *testing.T) {
	for _, kind := range []string{OrgKindPersonal, OrgKindOrganization} {
		c, _ := meServer(t, actorAnswer("actor-1", kind), []map[string]any{{"id": "org-1", "tier_name": "Personal"}})
		info, err := WhoAmI(c)
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
	info, err := WhoAmI(c)
	if err != nil || info.TierName != "" || info.Membership.OrgKind != OrgKindPersonal {
		t.Fatalf("without /orgs: %+v, %v", info, err)
	}
}

// ResolveActorID, which every secrets list calls first, makes one request:
// /actors/me, never the tier lookup. An answer without an ID fails.
func TestResolveActorIDIsOneRequest(t *testing.T) {
	c, hits := meServer(t, actorAnswer("actor-1", OrgKindOrganization), []map[string]any{{"id": "org-1", "tier_name": "Team"}})
	id, err := ResolveActorID(c)
	if err != nil || id != "actor-1" {
		t.Fatalf("ResolveActorID = %q, %v", id, err)
	}
	if hits("/api/v1/actors/me") != 1 || hits("/api/v1/orgs") != 0 {
		t.Errorf("requests: actors/me %d, orgs %d; want 1 and 0", hits("/api/v1/actors/me"), hits("/api/v1/orgs"))
	}

	c, _ = meServer(t, actorAnswer("", OrgKindOrganization), nil)
	if id, err := ResolveActorID(c); err == nil {
		t.Fatalf("an answer without an ID gave %q", id)
	}
}
