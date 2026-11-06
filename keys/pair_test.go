// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keys

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if kp.ED25519Public == "" || kp.ED25519Private == "" {
		t.Error("ed25519 keys should not be empty")
	}
	if kp.X25519Public == "" || kp.X25519Private == "" {
		t.Error("x25519 keys should not be empty")
	}
	if kp.MLKEM768PK == "" || kp.MLKEM768SK == "" {
		t.Error("mlkem768 keys should not be empty")
	}
	if kp.MLDSA65PK == "" || kp.MLDSA65Seed == "" {
		t.Error("mldsa65 keys should not be empty")
	}
}

func TestFingerprint(t *testing.T) {
	kp, _ := Generate()

	fp1, err := Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp1) != FingerprintLen {
		t.Errorf("fingerprint length = %d, want %d", len(fp1), FingerprintLen)
	}

	// Same keys produce same fingerprint
	fp2, _ := FingerprintFromPubs(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
	if fp1 != fp2 {
		t.Errorf("fingerprints should match: %s != %s", fp1, fp2)
	}

	// Different keys produce different fingerprint
	kp2, _ := Generate()
	fp3, _ := Fingerprint(kp2)
	if fp1 == fp3 {
		t.Error("different key pairs should have different fingerprints")
	}
}

func TestShortFingerprint(t *testing.T) {
	fp := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	short := ShortFingerprint(fp)
	if short != "abcdef0123456789" {
		t.Errorf("short = %q, want %q", short, "abcdef0123456789")
	}
	if ShortFingerprint("abc") != "abc" {
		t.Error("short input should pass through")
	}
}

// A Pair holds key material and nothing about how a file stores it: a field
// added here would reach every caller and every accidental log.
func TestPairFieldsAreKeyMaterialOnly(t *testing.T) {
	want := []string{"ED25519Public", "X25519Public", "MLKEM768PK", "MLDSA65PK",
		"ED25519Private", "X25519Private", "MLKEM768SK", "MLDSA65Seed"}
	typ := reflect.TypeFor[Pair]()
	var got []string
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	if !slices.Equal(got, want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
}

// A Pair that reaches a log or an error wrapper shows its public keys only.
func TestPairJSONIsPublicOnly(t *testing.T) {
	p, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(maps.Keys(fields)); !slices.Equal(got,
		[]string{"ed25519_public", "mldsa65_pk", "mlkem768_pk", "x25519_public"}) {
		t.Errorf("JSON fields = %v", got)
	}
}
