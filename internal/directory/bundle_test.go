// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package directory

import (
	"crypto/ed25519"
	"encoding/base64"
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
