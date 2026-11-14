// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package directory

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/sign"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// ── Key Bundle Signing ───────────────────────────────────────────────────────

// x25519PubKeySize is the size of an X25519 public key in bytes.
const x25519PubKeySize = 32

// bundleKeys is a bundle's four public keys as raw bytes, each of exactly
// its algorithm's size.
type bundleKeys struct {
	ed25519, x25519, mlkem768, mldsa65 []byte
}

// decodeBundleKeys decodes a bundle's four public keys and holds each to its
// exact size, before anything is hashed or verified. The digest and the
// fingerprint hash the keys end to end, so a short key beside a long one
// hashes like a whole bundle, and ed25519.Verify panics on a key of any
// other size.
func decodeBundleKeys(ed25519Pub, x25519Pub, mlkem768PK, mldsa65PK string) (*bundleKeys, error) {
	var k bundleKeys
	var err error
	if k.ed25519, err = decodeSized("ed25519 public key", ed25519Pub, ed25519.PublicKeySize); err != nil {
		return nil, err
	}
	if k.x25519, err = decodeSized("x25519 public key", x25519Pub, x25519PubKeySize); err != nil {
		return nil, err
	}
	if k.mlkem768, err = decodeSized("mlkem768 public key", mlkem768PK, mlkem.EncapsulationKeySize768); err != nil {
		return nil, err
	}
	if k.mldsa65, err = decodeSized("mldsa65 public key", mldsa65PK, sign.MLDSA65PubKeySize); err != nil {
		return nil, err
	}
	return &k, nil
}

// decodeSized decodes one base64 field of a bundle and refuses it unless it
// is exactly size bytes.
func decodeSized(name, in string, size int) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, size, len(b))
	}
	return b, nil
}

// digest computes SHA-256(ed25519_pub || x25519_pub || mlkem768_pub || mldsa65_pub).
func (k *bundleKeys) digest() []byte {
	h := sha256.New()
	h.Write(k.ed25519)
	h.Write(k.x25519)
	h.Write(k.mlkem768)
	h.Write(k.mldsa65)
	return h.Sum(nil)
}

// keyBundleDigest computes the digest of kp's public keys, which its
// self-signatures cover.
func keyBundleDigest(kp *keys.Pair) ([]byte, error) {
	k, err := decodeBundleKeys(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
	if err != nil {
		return nil, err
	}
	return k.digest(), nil
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
// A bundle comes from the server, so every key and signature is held to its
// exact size first: a malformed one is an error here, never a panic.
func VerifyKeyBundleSignature(ed25519Pub, x25519Pub, mlkem768PK, mldsa65PK, edSignature, mldsaSignature string) error {
	k, err := decodeBundleKeys(ed25519Pub, x25519Pub, mlkem768PK, mldsa65PK)
	if err != nil {
		return err
	}
	edSig, err := decodeSized("ed25519 signature", edSignature, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	mldsaSig, err := decodeSized("mldsa65 signature", mldsaSignature, sign.MLDSA65SignatureSize)
	if err != nil {
		return err
	}

	digest := k.digest()
	if !ed25519.Verify(k.ed25519, digest, edSig) {
		return fmt.Errorf("Ed25519 key bundle signature verification failed")
	}
	if !sign.VerifyMLDSA65(k.mldsa65, digest, mldsaSig) {
		return fmt.Errorf("ML-DSA-65 key bundle signature verification failed")
	}
	return nil
}
