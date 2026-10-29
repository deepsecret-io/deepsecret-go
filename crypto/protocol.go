// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// ── Protocol Constants ───────────────────────────────────────────────────────

const (
	// ProtocolVersion is the protocol version every manifest carries.
	ProtocolVersion = "4"

	// CipherSuite identifies protocol v4: HPKE with the X25519-ML-KEM-768
	// KEM, HKDF-SHA256 and AES-256-GCM for the wraps, AES-256-GCM in 1 MiB
	// chunks for the payload, and Ed25519 plus ML-DSA-65 signatures.
	CipherSuite = "DS4_HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_STREAM1M_ED25519_MLDSA65"

	// KDF identifies the key derivation function used within HPKE and for
	// the payload key.
	KDF = "hkdf-sha256"
)

// ── Key Size Constants ───────────────────────────────────────────────────────
//
// Named constants for all key sizes used in validation. These match the
// standard sizes for each algorithm and are checked when keys are decoded
// and when a manifest is validated.

const (
	// ED25519PubKeySize is the size of an Ed25519 public key in bytes.
	ED25519PubKeySize = ed25519.PublicKeySize // 32

	// ED25519SignatureSize is the size of an Ed25519 signature in bytes.
	ED25519SignatureSize = ed25519.SignatureSize // 64

	// X25519PubKeySize is the size of an X25519 public key in bytes.
	X25519PubKeySize = 32

	// MLKEM768PubKeySize is the size of an ML-KEM-768 encapsulation key in bytes.
	MLKEM768PubKeySize = 1184

	// MLKEM768SeedSize is the size of an ML-KEM-768 decapsulation key seed in bytes.
	MLKEM768SeedSize = 64

	// ED25519PrivKeySize is the size of an Ed25519 private key (seed+pub) in bytes.
	ED25519PrivKeySize = ed25519.PrivateKeySize // 64

	// X25519PrivKeySize is the size of an X25519 private key in bytes.
	X25519PrivKeySize = 32
)

// ── Payload parameters ───────────────────────────────────────────────────────

// validPayloadTypes is the set of allowed payload types.
var validPayloadTypes = map[string]bool{
	"message": true,
	"data":    true,
	"files":   true,
}

// validCompressions is the set of allowed compression values.
var validCompressions = map[string]bool{
	"":     true,
	"zstd": true,
}

// validatePayloadParams checks the payload type and that the compression
// flag and algorithm agree.
func validatePayloadParams(payloadType string, compressed bool, compression string) error {
	if !validPayloadTypes[payloadType] {
		return fmt.Errorf("invalid payload type %q: must be \"message\", \"data\", or \"files\"", payloadType)
	}
	if !validCompressions[compression] {
		return fmt.Errorf("invalid compression %q: must be \"zstd\" or empty", compression)
	}
	if !compressed && compression != "" {
		return fmt.Errorf("inconsistent params: Compressed=false but Compression=%q (set Compressed=true or clear Compression)", compression)
	}
	if compressed && compression == "" {
		return fmt.Errorf("inconsistent params: Compressed=true but Compression is empty (specify \"zstd\")")
	}
	return nil
}

// ── Canonical Encoding ───────────────────────────────────────────────────────
//
// Every hashed structure (the manifest's SignableBytes, the chunk associated
// data, the wrap HPKE info and the wrap digest) uses the same length-prefixed
// encoding, which is trivially reproducible in any language. Each field is:
//
//	[4 bytes: big-endian uint32 length] [N bytes: field data]
//
// Strings are UTF-8 bytes (length = byte count), byte slices are raw, int64
// values are 8 bytes big-endian and booleans one byte (0x01 or 0x00). Field
// order is fixed and MUST be reproduced exactly; adding a field requires a
// protocol version bump.

// writeField writes a length-prefixed field: [4-byte big-endian uint32 len][data].
//
// The receiver is hash.Hash (not io.Writer) because this function is exclusively
// used for hashing. hash.Hash.Write never returns an error per the hash.Hash
// contract: "It never returns an error."
func writeField(h hash.Hash, data []byte) {
	var length [4]byte
	// #nosec G115 -- every hashed field is a key, ID or digest, a wrap of fixed size (Wrap.validate) or a field of a manifest capped at 1 MiB, far below 4 GiB.
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	h.Write(length[:])
	h.Write(data)
}

// ── Serialization ────────────────────────────────────────────────────────────

// cborEnc is a canonical CBOR encoder for deterministic serialization.
var cborEnc cbor.EncMode
var cborEncErr error
var cborEncOnce sync.Once

func canonicalEncoder() (cbor.EncMode, error) {
	cborEncOnce.Do(func() {
		cborEnc, cborEncErr = cbor.CanonicalEncOptions().EncMode()
	})
	return cborEnc, cborEncErr
}

// cborMarshal encodes v to canonical CBOR bytes.
func cborMarshal(v any) ([]byte, error) {
	enc, err := canonicalEncoder()
	if err != nil {
		return nil, fmt.Errorf("cbor encoder init: %w", err)
	}
	return enc.Marshal(v)
}
