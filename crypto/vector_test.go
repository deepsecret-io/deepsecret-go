// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"testing"
)

// TestCanonicalEncodingVector produces a deterministic test vector that other
// language SDKs MUST reproduce to confirm compatible canonical encoding.
//
// This test does NOT test HPKE (which involves randomness). It tests the
// canonical encoding used for SignableBytes and AAD, which must be identical
// across all implementations.
func TestCanonicalEncodingVector(t *testing.T) {
	// Fixed inputs (all implementations must use these exact values)
	env := &Envelope{
		Version:              "3",
		CipherSuite:          "HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_ED25519_MLDSA65",
		SenderFingerprint:    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		SenderED25519:        bytes.Repeat([]byte{0x01}, ED25519PubKeySize),
		SenderX25519:         bytes.Repeat([]byte{0x02}, X25519PubKeySize),
		SenderMLKEM768:       bytes.Repeat([]byte{0x03}, MLKEM768PubKeySize),
		SenderMLDSA65:        bytes.Repeat([]byte{0x04}, MLDSA65PubKeySize),
		RecipientFingerprint: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
		PayloadType:          "message",
		Timestamp:            1700000000,
		Enc:                  bytes.Repeat([]byte{0x05}, 100),
		Ciphertext:           bytes.Repeat([]byte{0x06}, 200),
		Compressed:           false,
		Compression:          "",
	}

	// Compute SignableBytes
	signable := env.SignableBytes()
	signableHex := hex.EncodeToString(signable)

	// Compute AAD
	aad := env.AAD()
	aadHex := hex.EncodeToString(aad)

	t.Logf("SignableBytes = %s", signableHex)
	t.Logf("AAD          = %s", aadHex)

	// Verify by manually computing the expected hash
	h := sha256.New()
	// Field 1: Version
	writeLenPrefixed(h, []byte("3"))
	// Field 2: CipherSuite
	writeLenPrefixed(h, []byte("HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_ED25519_MLDSA65"))
	// Field 3: SenderFingerprint
	writeLenPrefixed(h, []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"))
	// Field 4: SenderED25519
	writeLenPrefixed(h, bytes.Repeat([]byte{0x01}, 32))
	// Field 5: SenderX25519
	writeLenPrefixed(h, bytes.Repeat([]byte{0x02}, 32))
	// Field 6: SenderMLKEM768
	writeLenPrefixed(h, bytes.Repeat([]byte{0x03}, 1184))
	// Field 7: SenderMLDSA65
	writeLenPrefixed(h, bytes.Repeat([]byte{0x04}, 1952))
	// Field 8: RecipientFingerprint
	writeLenPrefixed(h, []byte("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"))
	// Field 9: PayloadType
	writeLenPrefixed(h, []byte("message"))
	// Field 10: Timestamp (1700000000 as 8-byte big-endian)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], 1700000000)
	writeLenPrefixed(h, ts[:])
	// Field 11: Enc
	writeLenPrefixed(h, bytes.Repeat([]byte{0x05}, 100))
	// Field 12: Ciphertext
	writeLenPrefixed(h, bytes.Repeat([]byte{0x06}, 200))
	// Field 13: Compressed (false = 0x00)
	writeLenPrefixed(h, []byte{0x00})
	// Field 14: Compression (empty string)
	writeLenPrefixed(h, []byte{})
	expectedSignable := hex.EncodeToString(h.Sum(nil))

	if signableHex != expectedSignable {
		t.Errorf("SignableBytes mismatch:\n  got:  %s\n  want: %s", signableHex, expectedSignable)
	}

	// AAD is fields 1-10, 13-14 (skip 11 and 12: Enc and Ciphertext)
	h2 := sha256.New()
	writeLenPrefixed(h2, []byte("3"))
	writeLenPrefixed(h2, []byte("HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_ED25519_MLDSA65"))
	writeLenPrefixed(h2, []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"))
	writeLenPrefixed(h2, bytes.Repeat([]byte{0x01}, 32))
	writeLenPrefixed(h2, bytes.Repeat([]byte{0x02}, 32))
	writeLenPrefixed(h2, bytes.Repeat([]byte{0x03}, 1184))
	writeLenPrefixed(h2, bytes.Repeat([]byte{0x04}, 1952))
	writeLenPrefixed(h2, []byte("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"))
	writeLenPrefixed(h2, []byte("message"))
	writeLenPrefixed(h2, ts[:])
	// skip Enc and Ciphertext
	writeLenPrefixed(h2, []byte{0x00})
	writeLenPrefixed(h2, []byte{})
	expectedAAD := hex.EncodeToString(h2.Sum(nil))

	if aadHex != expectedAAD {
		t.Errorf("AAD mismatch:\n  got:  %s\n  want: %s", aadHex, expectedAAD)
	}

	// Log the canonical vectors for use by other SDKs
	t.Logf("=== Canonical Test Vectors ===")
	t.Logf("SignableBytes hex: %s", signableHex)
	t.Logf("AAD hex:           %s", aadHex)
}

// writeLenPrefixed is a test helper matching the production writeField logic.
func writeLenPrefixed(h hash.Hash, data []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	h.Write(length[:])
	h.Write(data)
}
