// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/canon"
	"github.com/deepsecret-io/deepsecret-go/internal/sign"
)

// ── Types ────────────────────────────────────────────────────────────────────

// Pair holds a hybrid cryptographic identity (Ed25519 + X25519 + ML-KEM-768
// + ML-DSA-65). Private fields are stored locally and never uploaded to the
// server. They are tagged json:"-" so an accidental json.Marshal cannot leak
// them; package keystore has its own on-disk struct for persistence, and
// explicitly opts in to writing private material.
type Pair struct {
	// Public key material (base64 raw-standard encoded).
	ED25519Public string `json:"ed25519_public"`
	X25519Public  string `json:"x25519_public"`
	MLKEM768PK    string `json:"mlkem768_pk"`
	MLDSA65PK     string `json:"mldsa65_pk"`

	// Private key material. json:"-" prevents accidental marshaling.
	ED25519Private string `json:"-"`
	X25519Private  string `json:"-"`
	MLKEM768SK     string `json:"-"`
	MLDSA65Seed    string `json:"-"`
}

// MarshalJSON returns the public-only view of a Pair so debug logs, error
// wrappers, or telemetry that accidentally serialize the struct cannot leak
// private key material. Code that genuinely needs to persist a key uses
// keystore.go's on-disk struct directly.
func (k *Pair) MarshalJSON() ([]byte, error) {
	type publicKeyPair struct {
		ED25519Public string `json:"ed25519_public"`
		X25519Public  string `json:"x25519_public"`
		MLKEM768PK    string `json:"mlkem768_pk"`
		MLDSA65PK     string `json:"mldsa65_pk"`
	}
	return json.Marshal(publicKeyPair{
		ED25519Public: k.ED25519Public,
		X25519Public:  k.X25519Public,
		MLKEM768PK:    k.MLKEM768PK,
		MLDSA65PK:     k.MLDSA65PK,
	})
}

// PublicKeys holds a recipient's public key bundle for encryption.
// The Fingerprint field is validated against the public keys when sealing:
// if non-empty and it does not match the computed fingerprint, Seal returns
// an error.
type PublicKeys struct {
	ED25519     string // base64-encoded Ed25519 public key
	X25519      string // base64-encoded X25519 public key
	MLKEM768    string // base64-encoded ML-KEM-768 encapsulation key
	MLDSA65     string // base64-encoded ML-DSA-65 public key
	Fingerprint string // full SHA-256 hex fingerprint (64 chars), or empty
}

// FingerprintLen is the length of a full hex-encoded SHA-256 fingerprint.
const FingerprintLen = canon.FingerprintLen

// ── Key Generation ───────────────────────────────────────────────────────────

// Generate creates a new hybrid key pair: Ed25519 + X25519 + ML-KEM-768 + ML-DSA-65.
// All keys are generated from crypto/rand and returned as base64-encoded strings.
func Generate() (*Pair, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}

	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}

	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("mlkem768 keygen: %w", err)
	}

	mldsaPub, mldsaSeed, err := sign.GenerateMLDSA65Key()
	if err != nil {
		return nil, fmt.Errorf("mldsa65 keygen: %w", err)
	}

	return &Pair{
		ED25519Private: base64.RawStdEncoding.EncodeToString(edPriv),
		ED25519Public:  base64.RawStdEncoding.EncodeToString(edPub),
		X25519Private:  base64.RawStdEncoding.EncodeToString(x25519Key.Bytes()),
		X25519Public:   base64.RawStdEncoding.EncodeToString(x25519Key.PublicKey().Bytes()),
		MLKEM768SK:     base64.RawStdEncoding.EncodeToString(mlkemDK.Bytes()),
		MLKEM768PK:     base64.RawStdEncoding.EncodeToString(mlkemDK.EncapsulationKey().Bytes()),
		MLDSA65Seed:    base64.RawStdEncoding.EncodeToString(mldsaSeed),
		MLDSA65PK:      base64.RawStdEncoding.EncodeToString(mldsaPub),
	}, nil
}

// ── Fingerprinting ───────────────────────────────────────────────────────────

// Fingerprint computes the full SHA-256 hex fingerprint from a key pair.
//
//	fingerprint = hex(SHA-256(ed25519_pub || x25519_pub || mlkem768_pub || mldsa65_pub))
//
// The result is 64 hex characters (256 bits). Use ShortFingerprint for UI display.
func Fingerprint(kp *Pair) (string, error) {
	return FingerprintFromPubs(kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK)
}

// FingerprintFromPubs computes a full SHA-256 hex fingerprint from base64-encoded
// public keys. Inputs are raw bytes (base64-decoded), concatenated in order:
// ed25519_pub || x25519_pub || mlkem768_pub || mldsa65_pub.
func FingerprintFromPubs(ed25519Pub, x25519Pub, mlkemPK, mldsa65PK string) (string, error) {
	ed, err := base64.RawStdEncoding.DecodeString(ed25519Pub)
	if err != nil {
		return "", fmt.Errorf("decode ed25519 pub: %w", err)
	}
	x, err := base64.RawStdEncoding.DecodeString(x25519Pub)
	if err != nil {
		return "", fmt.Errorf("decode x25519 pub: %w", err)
	}
	m, err := base64.RawStdEncoding.DecodeString(mlkemPK)
	if err != nil {
		return "", fmt.Errorf("decode mlkem pk: %w", err)
	}
	d, err := base64.RawStdEncoding.DecodeString(mldsa65PK)
	if err != nil {
		return "", fmt.Errorf("decode mldsa65 pk: %w", err)
	}

	h := sha256.New()
	h.Write(ed)
	h.Write(x)
	h.Write(m)
	h.Write(d)
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ShortFingerprint returns the first 16 hex characters of a fingerprint for
// display purposes. This is NOT the canonical fingerprint: it is a UI
// convenience only. The full 64-char fingerprint is used in all protocol
// operations.
func ShortFingerprint(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}
