// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
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
	if kp.StorageVersion != KeyStorageVersion {
		t.Errorf("storage version = %d, want %d", kp.StorageVersion, KeyStorageVersion)
	}
}

func TestFingerprint(t *testing.T) {
	kp, _ := GenerateKeyPair()

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
	kp2, _ := GenerateKeyPair()
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

func TestSignAndVerifyKeyBundle(t *testing.T) {
	kp, _ := GenerateKeyPair()

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
	kp2, _ := GenerateKeyPair()
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
	kp, _ := GenerateKeyPair()
	digest, err := keyBundleDigest(kp)
	if err != nil {
		t.Fatal(err)
	}
	edPriv, _ := base64.RawStdEncoding.DecodeString(kp.ED25519Private)
	seed, _ := base64.RawStdEncoding.DecodeString(kp.MLDSA65Seed)
	mldsaSig, err := SignMLDSA65(seed, digest)
	if err != nil {
		t.Fatal(err)
	}
	edSig := ed25519.Sign(ed25519.PrivateKey(edPriv), digest)
	if err := VerifyKeyBundleSignature(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK,
		base64.RawStdEncoding.EncodeToString(edSig), base64.RawStdEncoding.EncodeToString(mldsaSig)); err != nil {
		t.Errorf("a signature over the digest: %v", err)
	}
}
