// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// ── Protocol Constants ───────────────────────────────────────────────────────

const (
	// ProtocolVersion is the current envelope format version.
	ProtocolVersion = "3"

	// CipherSuite identifies the HPKE cipher suite with hybrid PQ signatures:
	// KEM=MLKEM768-X25519, KDF=HKDF-SHA256, AEAD=AES-256-GCM, SIG=Ed25519+ML-DSA-65.
	CipherSuite = "HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_ED25519_MLDSA65"

	// KDF identifies the key derivation function used within HPKE.
	KDF = "hkdf-sha256"
)

// ── Key Size Constants ───────────────────────────────────────────────────────
//
// Named constants for all key sizes used in validation. These match the
// standard sizes for each algorithm and are checked during envelope validation
// and input checks.

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

// ── Valid values for EncryptParams ───────────────────────────────────────────

// validPayloadTypes is the set of allowed PayloadType values.
var validPayloadTypes = map[string]bool{
	"message": true,
	"data":    true,
	"files":   true,
}

// validCompressions is the set of allowed Compression values.
var validCompressions = map[string]bool{
	"":     true,
	"zstd": true,
}

// ── Envelope ─────────────────────────────────────────────────────────────────

// Envelope is the encrypted wire format stored in object storage.
// Serialized with MessagePack. Protocol v2 uses RFC 9180 HPKE with the
// MLKEM768-X25519 hybrid KEM, HKDF-SHA256, and AES-256-GCM. The suite
// identifier used in the protocol is [CipherSuite].
//
// # Sender Public Bundle
//
// The envelope carries the sender's full public key bundle (Ed25519, X25519,
// ML-KEM-768) so that decryptors can:
//  1. Verify the Ed25519 signature without an out-of-band key lookup
//  2. Recompute the sender fingerprint from the embedded keys and verify it
//     matches SenderFingerprint — this cryptographically binds the signing key
//     to the claimed sender identity
//
// This makes the envelope fully self-verifiable. External key lookup is not
// required for cryptographic verification, only for trust decisions.
//
// # Why the sender bundle is included in both AAD and the signature
//
// Including the sender's public keys in the canonical encoding (and thus in
// both SignableBytes and AAD) is intentional:
//
//   - It prevents an attacker from swapping the sender keys in the envelope
//     after encryption, since any change would invalidate both the AEAD tag
//     (via AAD mismatch) and the Ed25519 signature (via SignableBytes mismatch).
//
//   - The overhead is ~1,248 bytes (32 + 32 + 1184) per envelope. This is
//     acceptable for typical encrypted payloads (files, messages, key-value
//     data), though it may be significant for very small secrets.
//
//   - This design enables fully self-contained offline verification without
//     any network calls, which is essential for multi-language SDK portability
//     and air-gapped environments.
type Envelope struct {
	Version              string `cbor:"version"`        // "3"
	CipherSuite          string `cbor:"cipher_suite"`   // HPKE cipher suite identifier
	SenderFingerprint    string `cbor:"sender_fp"`      // full SHA-256 hex fingerprint (64 chars)
	SenderED25519        []byte `cbor:"sender_ed25519"` // sender's Ed25519 public key (ED25519PubKeySize bytes)
	SenderX25519         []byte `cbor:"sender_x25519"`  // sender's X25519 public key (X25519PubKeySize bytes)
	SenderMLKEM768       []byte `cbor:"sender_mlkem"`   // sender's ML-KEM-768 public key (MLKEM768PubKeySize bytes)
	SenderMLDSA65        []byte `cbor:"sender_mldsa65"` // sender's ML-DSA-65 public key (MLDSA65PubKeySize bytes)
	RecipientFingerprint string `cbor:"recipient_fp"`   // full SHA-256 hex fingerprint (64 chars)
	PayloadType          string `cbor:"payload_type"`   // "files", "data", "message"
	Timestamp            int64  `cbor:"timestamp"`      // Unix seconds (informational/audit)

	// HPKE fields
	Enc        []byte `cbor:"enc"`        // HPKE encapsulated key (KEM output)
	Ciphertext []byte `cbor:"ciphertext"` // HPKE AEAD ciphertext (includes GCM tag)

	Compressed  bool   `cbor:"compressed"`  // whether plaintext was pre-compressed
	Compression string `cbor:"compression"` // "zstd" or ""

	Signature        []byte `cbor:"sig"`         // Ed25519 signature over SignableBytes()
	SignatureMLDSA65 []byte `cbor:"sig_mldsa65"` // ML-DSA-65 signature over SignableBytes()
}

// VerifySenderIdentity recomputes the fingerprint from the embedded sender
// public keys and checks it matches SenderFingerprint. Returns nil if valid.
//
// This method validates the presence and size of all three sender key fields
// before computing the fingerprint, so it is safe to call independently
// (outside HybridDecrypt).
func (e *Envelope) VerifySenderIdentity() error {
	if len(e.SenderED25519) != ED25519PubKeySize {
		return fmt.Errorf("sender identity check: ed25519 key must be %d bytes, got %d",
			ED25519PubKeySize, len(e.SenderED25519))
	}
	if len(e.SenderX25519) != X25519PubKeySize {
		return fmt.Errorf("sender identity check: x25519 key must be %d bytes, got %d",
			X25519PubKeySize, len(e.SenderX25519))
	}
	if len(e.SenderMLKEM768) != MLKEM768PubKeySize {
		return fmt.Errorf("sender identity check: mlkem768 key must be %d bytes, got %d",
			MLKEM768PubKeySize, len(e.SenderMLKEM768))
	}
	if len(e.SenderMLDSA65) != MLDSA65PubKeySize {
		return fmt.Errorf("sender identity check: mldsa65 key must be %d bytes, got %d",
			MLDSA65PubKeySize, len(e.SenderMLDSA65))
	}
	if e.SenderFingerprint == "" {
		return fmt.Errorf("sender identity check: missing sender fingerprint")
	}

	h := sha256.New()
	h.Write(e.SenderED25519)
	h.Write(e.SenderX25519)
	h.Write(e.SenderMLKEM768)
	h.Write(e.SenderMLDSA65)
	computed := fmt.Sprintf("%x", h.Sum(nil))

	if computed != e.SenderFingerprint {
		return fmt.Errorf("sender identity mismatch: embedded keys compute fingerprint %s but envelope claims %s",
			ShortFingerprint(computed), ShortFingerprint(e.SenderFingerprint))
	}
	return nil
}

// ── Canonical Encoding ───────────────────────────────────────────────────────
//
// SignableBytes and AAD use an identical length-prefixed canonical encoding that
// is trivially reproducible in any language.
//
// # Encoding Rules
//
// Each field is encoded as:
//
//	[4 bytes: big-endian uint32 length] [N bytes: field data]
//
// Specific field types:
//   - Strings:     UTF-8 bytes, length = byte count (not rune count)
//   - Byte slices: raw bytes, length = len(slice)
//   - int64:       8 bytes big-endian (fixed, length prefix is always 0x00000008)
//   - bool:        1 byte: 0x01 for true, 0x00 for false (length prefix is 0x00000001)
//
// Field order is fixed and MUST be reproduced exactly. Adding fields requires
// a protocol version bump.
//
// # Signed Fields vs AAD Fields
//
// SignableBytes covers ALL envelope fields except Signature (fields 1–13).
// AAD covers metadata-only fields (fields 1–9, 12–13) — excluding Enc and
// Ciphertext (fields 10–11) since those are HPKE outputs already integrity-
// protected by the AEAD.

// SignableBytes computes SHA-256 over all envelope fields (except signatures)
// using the canonical length-prefixed encoding.
//
// Field order (all implementations MUST use this exact order):
//
//  1. Version              (string)
//  2. CipherSuite          (string)
//  3. SenderFingerprint    (string, 64 hex chars)
//  4. SenderED25519        (bytes, ED25519PubKeySize)
//  5. SenderX25519         (bytes, X25519PubKeySize)
//  6. SenderMLKEM768       (bytes, MLKEM768PubKeySize)
//  7. SenderMLDSA65        (bytes, MLDSA65PubKeySize)
//  8. RecipientFingerprint (string, 64 hex chars)
//  9. PayloadType          (string)
//  10. Timestamp            (int64, 8 bytes big-endian)
//  11. Enc                  (bytes, variable)
//  12. Ciphertext           (bytes, variable)
//  13. Compressed           (bool, 1 byte)
//  14. Compression          (string)
func (e *Envelope) SignableBytes() []byte {
	h := sha256.New()
	encodeMetadata(h, e)
	writeField(h, e.Enc)        // field 11
	writeField(h, e.Ciphertext) // field 12
	encodeTail(h, e)
	return h.Sum(nil)
}

// AAD returns the authenticated associated data for HPKE Seal/Open.
// It binds the AEAD ciphertext to envelope metadata so the ciphertext cannot
// be transplanted to a different context.
//
// AAD encodes fields 1–10 and 13–14 (same as SignableBytes minus Enc and
// Ciphertext at fields 11–12, since those are HPKE outputs already covered
// by the AEAD).
func (e *Envelope) AAD() []byte {
	h := sha256.New()
	encodeMetadata(h, e)
	encodeTail(h, e)
	return h.Sum(nil)
}

// encodeMetadata writes fields 1–10 (shared prefix between SignableBytes and AAD).
func encodeMetadata(h hash.Hash, e *Envelope) {
	writeField(h, []byte(e.Version))              // 1
	writeField(h, []byte(e.CipherSuite))          // 2
	writeField(h, []byte(e.SenderFingerprint))    // 3
	writeField(h, e.SenderED25519)                // 4
	writeField(h, e.SenderX25519)                 // 5
	writeField(h, e.SenderMLKEM768)               // 6
	writeField(h, e.SenderMLDSA65)                // 7
	writeField(h, []byte(e.RecipientFingerprint)) // 8
	writeField(h, []byte(e.PayloadType))          // 9
	var ts [8]byte                                // 10
	binary.BigEndian.PutUint64(ts[:], uint64(e.Timestamp))
	writeField(h, ts[:])
}

// encodeTail writes fields 12–13 (shared suffix between SignableBytes and AAD).
func encodeTail(h hash.Hash, e *Envelope) {
	if e.Compressed { // 12
		writeField(h, []byte{1})
	} else {
		writeField(h, []byte{0})
	}
	writeField(h, []byte(e.Compression)) // 13
}

// writeField writes a length-prefixed field: [4-byte big-endian uint32 len][data].
//
// The receiver is hash.Hash (not io.Writer) because this function is exclusively
// used for hashing. hash.Hash.Write never returns an error per the hash.Hash
// contract: "It never returns an error."
func writeField(h hash.Hash, data []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	h.Write(length[:])
	h.Write(data)
}

// ── Serialization ────────────────────────────────────────────────────────────

// cborEnc is a canonical CBOR encoder for deterministic envelope serialization.
var cborEnc cbor.EncMode
var cborEncErr error
var cborEncOnce sync.Once

func envelopeEncoder() (cbor.EncMode, error) {
	cborEncOnce.Do(func() {
		cborEnc, cborEncErr = cbor.CanonicalEncOptions().EncMode()
	})
	return cborEnc, cborEncErr
}

// cborMarshal encodes v to canonical CBOR bytes.
func cborMarshal(v any) ([]byte, error) {
	enc, err := envelopeEncoder()
	if err != nil {
		return nil, fmt.Errorf("cbor encoder init: %w", err)
	}
	return enc.Marshal(v)
}

// Marshal serializes the envelope to canonical CBOR binary format.
func (e *Envelope) Marshal() ([]byte, error) {
	return cborMarshal(e)
}

// UnmarshalEnvelope deserializes CBOR bytes into an Envelope.
func UnmarshalEnvelope(data []byte) (*Envelope, error) {
	var env Envelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	return &env, nil
}

// ── Encrypt/Decrypt Types ────────────────────────────────────────────────────

// EncryptParams configures the low-level HPKE encryption operation.
type EncryptParams struct {
	PayloadType string // "message", "data", or "files"
	Compressed  bool   // whether plaintext was pre-compressed
	Compression string // compression algorithm identifier ("zstd" or "")
}

// validate checks that EncryptParams contains valid and consistent values.
func (p EncryptParams) validate() error {
	if !validPayloadTypes[p.PayloadType] {
		return fmt.Errorf("invalid payload type %q: must be \"message\", \"data\", or \"files\"", p.PayloadType)
	}
	if !validCompressions[p.Compression] {
		return fmt.Errorf("invalid compression %q: must be \"zstd\" or empty", p.Compression)
	}
	// Enforce consistency between Compressed flag and Compression algorithm.
	if !p.Compressed && p.Compression != "" {
		return fmt.Errorf("inconsistent params: Compressed=false but Compression=%q (set Compressed=true or clear Compression)", p.Compression)
	}
	if p.Compressed && p.Compression == "" {
		return fmt.Errorf("inconsistent params: Compressed=true but Compression is empty (specify \"zstd\")")
	}
	return nil
}

// DecryptResult holds the output of a successful decryption.
type DecryptResult struct {
	Plaintext   []byte    // decrypted payload (may still be compressed)
	Compressed  bool      // whether plaintext needs decompression
	Compression string    // compression algorithm used
	Envelope    *Envelope // the parsed envelope (for inspection/logging)
}

