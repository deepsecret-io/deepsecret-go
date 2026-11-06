// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package protocol

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/mlkem"
	"crypto/sha256"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/canon"
)

// ── Per-recipient wraps (protocol v4 §4) ────────────────────────────────────

// Wrap is a revision's content key sealed with HPKE for one recipient. A
// wrap only opens to the key it was made for, and its HPKE info binds it to
// one sender, one recipient, one revision and one payload. It travels as
// JSON {enc, ct}; the fingerprint is the key it was made for.
type Wrap struct {
	RecipientFingerprint string // full SHA-256 hex fingerprint (64 chars)
	Enc                  []byte // HPKE encapsulated key, fresh for every wrap (WrapEncSize bytes)
	Ciphertext           []byte // the sealed content key (WrapCiphertextSize bytes)
}

const (
	// WrapEncSize is the HPKE encapsulated key of the X25519-ML-KEM-768
	// KEM: an ML-KEM-768 ciphertext (1088 bytes) and an X25519 share (32).
	WrapEncSize = 1120

	// WrapCiphertextSize is the size of a sealed content key: the key plus
	// the AES-256-GCM tag.
	WrapCiphertextSize = ContentKeySize + 16
)

// wrapInfo is the HPKE info of a wrap:
//
//	SHA-256(fields("deepsecret/v4/wrap", version, revision_id, sender_fp, recipient_fp, payload_digest))
func wrapInfo(revisionID, senderFP, recipientFP string, payloadDigest []byte) []byte {
	h := sha256.New()
	writeField(h, []byte("deepsecret/v4/wrap"))
	writeField(h, []byte(ProtocolVersion))
	writeField(h, []byte(revisionID))
	writeField(h, []byte(senderFP))
	writeField(h, []byte(recipientFP))
	writeField(h, payloadDigest)
	return h.Sum(nil)
}

// Digest is SHA-256(fields(recipient_fp, enc, ct)), the value the signed
// manifest lists for this recipient.
func (w *Wrap) Digest() []byte {
	h := sha256.New()
	writeField(h, []byte(w.RecipientFingerprint))
	writeField(h, w.Enc)
	writeField(h, w.Ciphertext)
	return h.Sum(nil)
}

// validate checks the wrap's sizes before any key is used on it.
func (w *Wrap) validate() error {
	if w == nil || !canon.IsFingerprint(w.RecipientFingerprint) || len(w.Enc) != WrapEncSize || len(w.Ciphertext) != WrapCiphertextSize {
		return fmt.Errorf("malformed wrap")
	}
	return nil
}

// sealContentKey wraps the content key for one recipient with a fresh HPKE
// context.
func sealContentKey(contentKey []byte, recipient hpke.PublicKey, recipientFP string, info []byte) (*Wrap, error) {
	enc, sender, err := hpke.NewSender(recipient, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke sender setup: %w", err)
	}
	ct, err := sender.Seal(nil, contentKey)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}
	return &Wrap{RecipientFingerprint: recipientFP, Enc: enc, Ciphertext: ct}, nil
}

// openContentKey opens a wrap with the recipient's private key.
func openContentKey(w *Wrap, priv hpke.PrivateKey, info []byte) ([]byte, error) {
	recipient, err := hpke.NewRecipient(w.Enc, priv, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke recipient setup: %w", err)
	}
	key, err := recipient.Open(nil, w.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wrap does not open with this key")
	}
	if len(key) != ContentKeySize {
		clear(key)
		return nil, fmt.Errorf("wrap holds a %d-byte key, want %d", len(key), ContentKeySize)
	}
	return key, nil
}

// buildHPKEPublicKey constructs an HPKE hybrid public key from separate
// ML-KEM-768 and X25519 public key bytes.
func buildHPKEPublicKey(mlkemPKBytes, x25519PubBytes []byte) (hpke.PublicKey, error) {
	mlkemEK, err := mlkem.NewEncapsulationKey768(mlkemPKBytes)
	if err != nil {
		return nil, fmt.Errorf("parse mlkem768 pk: %w", err)
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(x25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 pub: %w", err)
	}
	return hpke.NewHybridPublicKey(mlkemEK, x25519Pub)
}

// buildHPKEPrivateKey constructs an HPKE hybrid private key from separate
// ML-KEM-768 seed and X25519 private key bytes.
func buildHPKEPrivateKey(mlkemSeedBytes, x25519PrivBytes []byte) (hpke.PrivateKey, error) {
	mlkemDK, err := mlkem.NewDecapsulationKey768(mlkemSeedBytes)
	if err != nil {
		return nil, fmt.Errorf("parse mlkem768 sk: %w", err)
	}
	x25519Priv, err := ecdh.X25519().NewPrivateKey(x25519PrivBytes)
	if err != nil {
		return nil, fmt.Errorf("parse x25519 priv: %w", err)
	}
	return hpke.NewHybridPrivateKey(mlkemDK, x25519Priv)
}
