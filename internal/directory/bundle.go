// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package directory

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/sign"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// ── Key Bundle Signing ───────────────────────────────────────────────────────

// keyBundleDigest computes SHA-256(ed25519_pub || x25519_pub || mlkem768_pub || mldsa65_pub).
func keyBundleDigest(kp *keys.Pair) ([]byte, error) {
	ed, err := base64.RawStdEncoding.DecodeString(kp.ED25519Public)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 public: %w", err)
	}
	x, err := base64.RawStdEncoding.DecodeString(kp.X25519Public)
	if err != nil {
		return nil, fmt.Errorf("decode x25519 public: %w", err)
	}
	m, err := base64.RawStdEncoding.DecodeString(kp.MLKEM768PK)
	if err != nil {
		return nil, fmt.Errorf("decode mlkem768 pk: %w", err)
	}
	d, err := base64.RawStdEncoding.DecodeString(kp.MLDSA65PK)
	if err != nil {
		return nil, fmt.Errorf("decode mldsa65 pk: %w", err)
	}

	h := sha256.New()
	h.Write(ed)
	h.Write(x)
	h.Write(m)
	h.Write(d)
	return h.Sum(nil), nil
}

// SignKeyBundle signs the key bundle digest with both Ed25519 and ML-DSA-65.
// Returns two base64-encoded signatures: (ed25519Sig, mldsa65Sig).
func SignKeyBundle(kp *keys.Pair) (string, string, error) {
	digest, err := keyBundleDigest(kp)
	if err != nil {
		return "", "", err
	}

	edPriv, err := base64.RawStdEncoding.DecodeString(kp.ED25519Private)
	if err != nil {
		return "", "", fmt.Errorf("decode ed25519 private: %w", err)
	}
	edSig := ed25519.Sign(ed25519.PrivateKey(edPriv), digest)

	mldsaSeed, err := base64.RawStdEncoding.DecodeString(kp.MLDSA65Seed)
	if err != nil {
		return "", "", fmt.Errorf("decode mldsa65 seed: %w", err)
	}
	mldsaSig, err := sign.SignMLDSA65(mldsaSeed, digest)
	if err != nil {
		return "", "", err
	}

	return base64.RawStdEncoding.EncodeToString(edSig),
		base64.RawStdEncoding.EncodeToString(mldsaSig), nil
}

// VerifyKeyBundleSignature verifies that a key bundle was self-signed by both
// the Ed25519 and ML-DSA-65 private keys. Both signatures must be valid.
func VerifyKeyBundleSignature(ed25519Pub, x25519Pub, mlkem768PK, mldsa65PK, edSignature, mldsaSignature string) error {
	edPub, err := base64.RawStdEncoding.DecodeString(ed25519Pub)
	if err != nil {
		return fmt.Errorf("decode ed25519 pub: %w", err)
	}
	x, err := base64.RawStdEncoding.DecodeString(x25519Pub)
	if err != nil {
		return fmt.Errorf("decode x25519 pub: %w", err)
	}
	m, err := base64.RawStdEncoding.DecodeString(mlkem768PK)
	if err != nil {
		return fmt.Errorf("decode mlkem768 pk: %w", err)
	}
	d, err := base64.RawStdEncoding.DecodeString(mldsa65PK)
	if err != nil {
		return fmt.Errorf("decode mldsa65 pk: %w", err)
	}
	edSig, err := base64.RawStdEncoding.DecodeString(edSignature)
	if err != nil {
		return fmt.Errorf("decode ed25519 signature: %w", err)
	}
	mldsaSig, err := base64.RawStdEncoding.DecodeString(mldsaSignature)
	if err != nil {
		return fmt.Errorf("decode mldsa65 signature: %w", err)
	}

	h := sha256.New()
	h.Write(edPub)
	h.Write(x)
	h.Write(m)
	h.Write(d)
	digest := h.Sum(nil)

	if !ed25519.Verify(ed25519.PublicKey(edPub), digest, edSig) {
		return fmt.Errorf("Ed25519 key bundle signature verification failed")
	}
	if !sign.VerifyMLDSA65(d, digest, mldsaSig) {
		return fmt.Errorf("ML-DSA-65 key bundle signature verification failed")
	}
	return nil
}
