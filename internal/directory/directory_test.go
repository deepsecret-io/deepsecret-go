// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// bundle is kp's published key bundle, as the identities endpoint lists it.
func bundle(t *testing.T, kp *keys.Pair) map[string]any {
	t.Helper()
	fp, _ := keys.Fingerprint(kp)
	edSig, mldsaSig, err := SignKeyBundle(kp)
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
func keysServer(t *testing.T, bundles ...map[string]any) *transport.Client {
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
	c, err := transport.NewClient(srv.URL, "test-key")
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
			b["fingerprint"], _ = keys.FingerprintFromPubs(kp.ED25519Public, other.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
		}, "Ed25519 key bundle signature verification failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := bundle(t, kp)
			tc.edit(b)
			pubKeys, err := GetRecipientKeys(context.Background(), keysServer(t, b), "bob@example.com")
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if pubKeys.Fingerprint != fp || pubKeys.X25519 != kp.X25519Public || pubKeys.MLKEM768 != kp.MLKEM768PK {
					t.Fatalf("keys %+v are not the bundle's", pubKeys)
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

	pubKeys, err := GetRecipientKeys(context.Background(), keysServer(t, secondary, primary), "bob@example.com")
	if err != nil || pubKeys.Fingerprint != fp {
		t.Fatalf("keys %+v, %v: want the primary", pubKeys, err)
	}

	secondary, primary = bundle(t, other), bundle(t, kp)
	secondary["is_primary"] = false
	delete(primary, "signature_mldsa65")
	if _, err := GetRecipientKeys(context.Background(), keysServer(t, secondary, primary), "bob@example.com"); err == nil {
		t.Fatal("broken primary bundle accepted")
	}
}
