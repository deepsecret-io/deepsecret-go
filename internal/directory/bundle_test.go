// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/sign"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

func TestSignAndVerifyKeyBundle(t *testing.T) {
	kp, _ := keys.Generate()

	edSig, mldsaSig, err := SignKeyBundle(kp)
	if err != nil {
		t.Fatal(err)
	}
	if edSig == "" || mldsaSig == "" {
		t.Error("signatures should not be empty")
	}

	// Valid dual signatures
	if err := VerifyKeyBundleSignature(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK, edSig, mldsaSig); err != nil {
		t.Errorf("valid signatures should verify: %v", err)
	}

	// Wrong Ed25519 key should fail
	kp2, _ := keys.Generate()
	if err := VerifyKeyBundleSignature(kp2.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK, edSig, mldsaSig); err == nil {
		t.Error("mismatched ed25519 key should fail verification")
	}

	// Wrong ML-DSA-65 key should fail
	if err := VerifyKeyBundleSignature(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp2.MLDSA65PK, edSig, mldsaSig); err == nil {
		t.Error("mismatched mldsa65 key should fail verification")
	}
}

// A self-signature covers the bundle digest itself, nothing before or
// after it. Every registered key on the server is signed so, and the API
// checks the same bytes: changing them is a protocol change.
func TestKeyBundleSignatureCoversTheDigest(t *testing.T) {
	kp, _ := keys.Generate()
	digest, err := keyBundleDigest(kp)
	if err != nil {
		t.Fatal(err)
	}
	edPriv, _ := base64.RawStdEncoding.DecodeString(kp.ED25519Private)
	seed, _ := base64.RawStdEncoding.DecodeString(kp.MLDSA65Seed)
	mldsaSig, err := sign.SignMLDSA65(seed, digest)
	if err != nil {
		t.Fatal(err)
	}
	edSig := ed25519.Sign(ed25519.PrivateKey(edPriv), digest)
	if err := VerifyKeyBundleSignature(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK,
		base64.RawStdEncoding.EncodeToString(edSig), base64.RawStdEncoding.EncodeToString(mldsaSig)); err != nil {
		t.Errorf("a signature over the digest: %v", err)
	}
}

// resize returns the base64 value in with its last byte cut off (by -1) or
// a zero byte added (by +1).
func resize(t *testing.T, in string, by int) string {
	t.Helper()
	b, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	if by < 0 {
		b = b[:len(b)+by]
	} else {
		b = append(b, make([]byte, by)...)
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// shiftedKeys moves the last byte of kp's Ed25519 key to the front of its
// X25519 key: a 31-byte key and a 33-byte key that hash, end to end, exactly
// like the whole bundle. Its fingerprint, its digest and so both of its
// self-signatures are those of kp's bundle.
func shiftedKeys(t *testing.T, kp *keys.Pair) (ed25519Pub, x25519Pub string) {
	t.Helper()
	ed, err := base64.RawStdEncoding.DecodeString(kp.ED25519Public)
	if err != nil {
		t.Fatal(err)
	}
	x, err := base64.RawStdEncoding.DecodeString(kp.X25519Public)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(ed[:31]),
		base64.RawStdEncoding.EncodeToString(append([]byte{ed[31]}, x...))
}

// noPanic runs f and reports a panic as a failure of the test, instead of
// letting it end the test binary.
func noPanic(t *testing.T, f func() error) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	return f()
}

// A bundle comes from the server, so every key and signature in it is held
// to its exact size before anything is verified. ed25519.Verify panics on a
// key of another size, and the hash over the keys cannot tell where one key
// ends and the next begins.
func TestVerifyKeyBundleSignatureRefusesWrongSizes(t *testing.T) {
	kp, _ := keys.Generate()
	edSig, mldsaSig, err := SignKeyBundle(kp)
	if err != nil {
		t.Fatal(err)
	}
	shiftedED, shiftedX := shiftedKeys(t, kp)
	whole := [6]string{kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK, edSig, mldsaSig}
	fields := []string{"ed25519 public key", "x25519 public key", "mlkem768 public key", "mldsa65 public key", "ed25519 signature", "mldsa65 signature"}

	type testCase struct {
		name string
		in   [6]string
		want string
	}
	shifted := whole
	shifted[0], shifted[1] = shiftedED, shiftedX
	cases := []testCase{{"a byte moved from the Ed25519 key to the X25519 key", shifted, "ed25519 public key must be 32 bytes, got 31"}}
	for i, field := range fields {
		short, long, empty := whole, whole, whole
		short[i], long[i], empty[i] = resize(t, whole[i], -1), resize(t, whole[i], 1), ""
		cases = append(cases,
			testCase{field + " one byte short", short, field + " must be"},
			testCase{field + " one byte long", long, field + " must be"},
			testCase{field + " empty", empty, field + " must be"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := noPanic(t, func() error {
				return VerifyKeyBundleSignature(c.in[0], c.in[1], c.in[2], c.in[3], c.in[4], c.in[5])
			})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}

	if err := VerifyKeyBundleSignature(whole[0], whole[1], whole[2], whole[3], whole[4], whole[5]); err != nil {
		t.Errorf("a whole bundle: %v", err)
	}
}
