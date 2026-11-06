// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package sign holds the ML-DSA-65 primitives the SDK signs and verifies with.
package sign

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ML-DSA-65 constants (FIPS 204, Level 3).
const (
	MLDSA65PubKeySize    = mldsa65.PublicKeySize // 1952
	MLDSA65SeedSize      = mldsa65.SeedSize      // 32
	MLDSA65SignatureSize = mldsa65.SignatureSize // 3309
)

// GenerateMLDSA65Key generates a new ML-DSA-65 key pair.
// Returns the public key (1952 bytes) and seed (32 bytes).
func GenerateMLDSA65Key() (pub []byte, seed []byte, err error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa65 keygen: %w", err)
	}
	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa65 marshal public key: %w", err)
	}
	seedBytes := sk.Seed()
	return pubBytes, seedBytes, nil
}

// SignMLDSA65 signs a message using ML-DSA-65 from a 32-byte seed.
// Returns a 3309-byte signature.
func SignMLDSA65(seed []byte, message []byte) ([]byte, error) {
	if len(seed) != MLDSA65SeedSize {
		return nil, fmt.Errorf("mldsa65 sign: seed must be %d bytes, got %d", MLDSA65SeedSize, len(seed))
	}
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)
	_, sk := mldsa65.NewKeyFromSeed(&seedArr)

	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, message, nil, false, sig); err != nil {
		return nil, fmt.Errorf("mldsa65 sign: %w", err)
	}
	return sig, nil
}

// VerifyMLDSA65 verifies an ML-DSA-65 signature.
func VerifyMLDSA65(pub []byte, message []byte, sig []byte) bool {
	if len(pub) != MLDSA65PubKeySize || len(sig) != MLDSA65SignatureSize {
		return false
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, message, nil, sig)
}
