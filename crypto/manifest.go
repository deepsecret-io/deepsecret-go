// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ── Signed manifest (protocol v4 §5) ────────────────────────────────────────

const (
	// MaxRecipients bounds the recipient list of one revision.
	MaxRecipients = 1000

	// maxManifestSize bounds a serialized manifest before parsing. A
	// manifest with MaxRecipients entries is about 120 KB.
	maxManifestSize = 1 << 20

	// maxRevisionIDLen bounds the revision id (a UUID is 36 characters).
	maxRevisionIDLen = 64
)

// ManifestRecipient lists one wrap in the manifest.
type ManifestRecipient struct {
	Fingerprint string `cbor:"recipient_fp"` // full SHA-256 hex fingerprint (64 chars)
	WrapDigest  []byte `cbor:"wrap_digest"`  // Wrap.Digest() of that recipient's wrap
}

// Manifest describes one revision's payload and every recipient of it, and
// is signed by the sender with Ed25519 and ML-DSA-65. Every recipient holds
// the content key and could encrypt other content under it, so only this
// signature over the payload digest shows who wrote the payload. Covering
// the recipient list stops a recipient being added, removed or swapped.
//
// The sender's full public key bundle is embedded and bound by fingerprint,
// so a manifest verifies without an external key lookup. Trust in the
// sender (primary key, fingerprint status) is decided by the caller.
type Manifest struct {
	Version           string              `cbor:"version"`
	CipherSuite       string              `cbor:"cipher_suite"`
	RevisionID        string              `cbor:"revision_id"`
	SenderFingerprint string              `cbor:"sender_fp"`
	SenderED25519     []byte              `cbor:"sender_ed25519"`
	SenderX25519      []byte              `cbor:"sender_x25519"`
	SenderMLKEM768    []byte              `cbor:"sender_mlkem"`
	SenderMLDSA65     []byte              `cbor:"sender_mldsa65"`
	PayloadType       string              `cbor:"payload_type"`
	Compressed        bool                `cbor:"compressed"`
	Compression       string              `cbor:"compression"`
	ChunkSize         int64               `cbor:"chunk_size"`
	PlaintextSize     int64               `cbor:"plaintext_size"`
	CiphertextSize    int64               `cbor:"ciphertext_size"`
	PayloadDigest     []byte              `cbor:"payload_digest"` // SHA-256 of the stored payload object
	Timestamp         int64               `cbor:"timestamp"`      // Unix seconds
	Recipients        []ManifestRecipient `cbor:"recipients"`     // sorted by fingerprint, no duplicates

	Signature        []byte `cbor:"sig"`         // Ed25519 over SignableBytes
	SignatureMLDSA65 []byte `cbor:"sig_mldsa65"` // ML-DSA-65 over SignableBytes
}

// SignableBytes is SHA-256 over every field except the two signatures, in
// declaration order, each written with writeField. Strings are UTF-8,
// booleans one byte, integers 8 bytes big-endian. The recipient list is a
// 4-byte big-endian count followed by each fingerprint and wrap digest.
func (m *Manifest) SignableBytes() []byte {
	h := sha256.New()
	writeField(h, []byte(m.Version))
	writeField(h, []byte(m.CipherSuite))
	writeField(h, []byte(m.RevisionID))
	writeField(h, []byte(m.SenderFingerprint))
	writeField(h, m.SenderED25519)
	writeField(h, m.SenderX25519)
	writeField(h, m.SenderMLKEM768)
	writeField(h, m.SenderMLDSA65)
	writeField(h, []byte(m.PayloadType))
	writeField(h, boolField(m.Compressed))
	writeField(h, []byte(m.Compression))
	writeField(h, int64Field(m.ChunkSize))
	writeField(h, int64Field(m.PlaintextSize))
	writeField(h, int64Field(m.CiphertextSize))
	writeField(h, m.PayloadDigest)
	writeField(h, int64Field(m.Timestamp))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(m.Recipients)))
	writeField(h, count[:])
	for _, r := range m.Recipients {
		writeField(h, []byte(r.Fingerprint))
		writeField(h, r.WrapDigest)
	}
	return h.Sum(nil)
}

func boolField(b bool) []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}

func int64Field(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}

// Marshal serializes the manifest to canonical CBOR.
func (m *Manifest) Marshal() ([]byte, error) {
	return cborMarshal(m)
}

// UnmarshalManifest parses a serialized manifest and checks its structure.
// It does not verify the signatures; Open does.
func UnmarshalManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 || len(data) > maxManifestSize {
		return nil, fmt.Errorf("manifest must be 1 to %d bytes, got %d", maxManifestSize, len(data))
	}
	var m Manifest
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Recipient returns the manifest entry for fingerprint fp, if any.
func (m *Manifest) Recipient(fp string) (ManifestRecipient, bool) {
	for _, r := range m.Recipients {
		if r.Fingerprint == fp {
			return r, true
		}
	}
	return ManifestRecipient{}, false
}

// validate checks everything about the manifest that does not need a key.
func (m *Manifest) validate() error {
	if m.Version != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version %q (expected %q)", m.Version, ProtocolVersion)
	}
	if m.CipherSuite != CipherSuite {
		return fmt.Errorf("unsupported cipher suite %q", m.CipherSuite)
	}
	if m.RevisionID == "" || len(m.RevisionID) > maxRevisionIDLen {
		return fmt.Errorf("malformed manifest: revision id must be 1 to %d bytes", maxRevisionIDLen)
	}
	if err := validatePayloadParams(m.PayloadType, m.Compressed, m.Compression); err != nil {
		return fmt.Errorf("malformed manifest: %w", err)
	}
	if m.ChunkSize != ChunkSize {
		return fmt.Errorf("unsupported chunk size %d (expected %d)", m.ChunkSize, ChunkSize)
	}
	if m.PlaintextSize < 0 || m.CiphertextSize != ciphertextSizeFor(m.PlaintextSize) {
		return fmt.Errorf("malformed manifest: ciphertext size %d does not fit plaintext size %d", m.CiphertextSize, m.PlaintextSize)
	}
	if len(m.PayloadDigest) != sha256.Size {
		return fmt.Errorf("malformed manifest: payload digest must be %d bytes", sha256.Size)
	}
	if len(m.Signature) != ED25519SignatureSize {
		return fmt.Errorf("malformed manifest: sig must be %d bytes, got %d", ED25519SignatureSize, len(m.Signature))
	}
	if len(m.SignatureMLDSA65) != MLDSA65SignatureSize {
		return fmt.Errorf("malformed manifest: sig_mldsa65 must be %d bytes, got %d", MLDSA65SignatureSize, len(m.SignatureMLDSA65))
	}
	if err := verifySenderBundle(m.SenderFingerprint, m.SenderED25519, m.SenderX25519, m.SenderMLKEM768, m.SenderMLDSA65); err != nil {
		return err
	}
	if len(m.Recipients) == 0 || len(m.Recipients) > MaxRecipients {
		return fmt.Errorf("malformed manifest: must list 1 to %d recipients, got %d", MaxRecipients, len(m.Recipients))
	}
	for i, r := range m.Recipients {
		if !isFingerprint(r.Fingerprint) {
			return fmt.Errorf("malformed manifest: recipient %d has an invalid fingerprint", i)
		}
		if len(r.WrapDigest) != sha256.Size {
			return fmt.Errorf("malformed manifest: recipient %d wrap digest must be %d bytes", i, sha256.Size)
		}
		if i > 0 && m.Recipients[i-1].Fingerprint >= r.Fingerprint {
			return fmt.Errorf("malformed manifest: recipients must be sorted by fingerprint with no duplicates")
		}
	}
	return nil
}

// verifySignatures checks both signatures with the embedded sender keys.
func (m *Manifest) verifySignatures() error {
	signable := m.SignableBytes()
	if !ed25519.Verify(ed25519.PublicKey(m.SenderED25519), signable, m.Signature) {
		return fmt.Errorf("Ed25519 signature verification failed: manifest may be tampered with")
	}
	if !VerifyMLDSA65(m.SenderMLDSA65, signable, m.SignatureMLDSA65) {
		return fmt.Errorf("ML-DSA-65 signature verification failed: manifest may be tampered with")
	}
	return nil
}

// verifySenderBundle checks the embedded key sizes and that they compute
// the claimed fingerprint, which binds the signing keys to the sender.
func verifySenderBundle(fp string, ed, x, mlkem, mldsa []byte) error {
	if len(ed) != ED25519PubKeySize || len(x) != X25519PubKeySize ||
		len(mlkem) != MLKEM768PubKeySize || len(mldsa) != MLDSA65PubKeySize {
		return fmt.Errorf("sender identity check: embedded public keys have the wrong sizes")
	}
	h := sha256.New()
	h.Write(ed)
	h.Write(x)
	h.Write(mlkem)
	h.Write(mldsa)
	if computed := hex.EncodeToString(h.Sum(nil)); computed != fp {
		return fmt.Errorf("sender identity mismatch: embedded keys compute fingerprint %s but manifest claims %s",
			ShortFingerprint(computed), ShortFingerprint(fp))
	}
	return nil
}

// isFingerprint reports whether s is a full lower-case hex fingerprint.
func isFingerprint(s string) bool {
	if len(s) != FingerprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
