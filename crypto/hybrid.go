// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// hpkeInfo builds the HPKE info parameter that binds key derivation to this
// specific sender/recipient/payload context.
func hpkeInfo(senderFP, recipientFP, payloadType string) []byte {
	return []byte(fmt.Sprintf("deepsecret/v3|suite=%s|sender=%s|recipient=%s|type=%s",
		CipherSuite, senderFP, recipientFP, payloadType))
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

// HybridEncrypt encrypts plaintext for a recipient using HPKE (RFC 9180) with
// the MLKEM768-X25519 hybrid KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD.
//
// The sender's full public key bundle is embedded in the envelope so that
// decryptors can verify sender identity without external key lookups (see
// [Envelope] docs for the trust model).
//
// If recipient.Fingerprint is non-empty, it is validated against the computed
// fingerprint and an error is returned on mismatch.
//
// Returns the MessagePack-serialized Envelope bytes.
func HybridEncrypt(plaintext []byte, senderKP *KeyPair, recipient *PublicKeys, params EncryptParams) ([]byte, error) {
	// ── Input validation ──
	if senderKP == nil {
		return nil, fmt.Errorf("sender key pair must not be nil")
	}
	if recipient == nil {
		return nil, fmt.Errorf("recipient public keys must not be nil")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	if recipient.ED25519 == "" || recipient.X25519 == "" || recipient.MLKEM768 == "" || recipient.MLDSA65 == "" {
		return nil, fmt.Errorf("recipient public keys must include ED25519, X25519, MLKEM768, and MLDSA65")
	}
	if senderKP.ED25519Private == "" || senderKP.ED25519Public == "" ||
		senderKP.X25519Public == "" || senderKP.MLKEM768PK == "" ||
		senderKP.MLDSA65Seed == "" || senderKP.MLDSA65PK == "" {
		return nil, fmt.Errorf("sender key pair is missing required fields")
	}

	// ── Decode recipient public keys ──
	recipientEdPub, err := base64.RawStdEncoding.DecodeString(recipient.ED25519)
	if err != nil {
		return nil, fmt.Errorf("decode recipient ed25519: %w", err)
	}
	x25519PubBytes, err := base64.RawStdEncoding.DecodeString(recipient.X25519)
	if err != nil {
		return nil, fmt.Errorf("decode recipient x25519: %w", err)
	}
	mlkemPKBytes, err := base64.RawStdEncoding.DecodeString(recipient.MLKEM768)
	if err != nil {
		return nil, fmt.Errorf("decode recipient mlkem768: %w", err)
	}

	// ── Decode sender keys ──
	edPrivBytes, err := base64.RawStdEncoding.DecodeString(senderKP.ED25519Private)
	if err != nil {
		return nil, fmt.Errorf("decode sender ed25519 private: %w", err)
	}
	senderEdPub, err := base64.RawStdEncoding.DecodeString(senderKP.ED25519Public)
	if err != nil {
		return nil, fmt.Errorf("decode sender ed25519 public: %w", err)
	}
	senderX25519Pub, err := base64.RawStdEncoding.DecodeString(senderKP.X25519Public)
	if err != nil {
		return nil, fmt.Errorf("decode sender x25519 public: %w", err)
	}
	senderMLKEMPub, err := base64.RawStdEncoding.DecodeString(senderKP.MLKEM768PK)
	if err != nil {
		return nil, fmt.Errorf("decode sender mlkem768 public: %w", err)
	}
	senderMLDSAPub, err := base64.RawStdEncoding.DecodeString(senderKP.MLDSA65PK)
	if err != nil {
		return nil, fmt.Errorf("decode sender mldsa65 public: %w", err)
	}
	mldsaSeedBytes, err := base64.RawStdEncoding.DecodeString(senderKP.MLDSA65Seed)
	if err != nil {
		return nil, fmt.Errorf("decode sender mldsa65 seed: %w", err)
	}

	// Validate decoded key sizes
	if len(edPrivBytes) != ED25519PrivKeySize {
		return nil, fmt.Errorf("sender ed25519 private key: expected %d bytes, got %d", ED25519PrivKeySize, len(edPrivBytes))
	}
	if len(senderEdPub) != ED25519PubKeySize {
		return nil, fmt.Errorf("sender ed25519 public key: expected %d bytes, got %d", ED25519PubKeySize, len(senderEdPub))
	}
	if len(senderX25519Pub) != X25519PubKeySize {
		return nil, fmt.Errorf("sender x25519 public key: expected %d bytes, got %d", X25519PubKeySize, len(senderX25519Pub))
	}
	if len(senderMLKEMPub) != MLKEM768PubKeySize {
		return nil, fmt.Errorf("sender mlkem768 public key: expected %d bytes, got %d", MLKEM768PubKeySize, len(senderMLKEMPub))
	}
	if len(senderMLDSAPub) != MLDSA65PubKeySize {
		return nil, fmt.Errorf("sender mldsa65 public key: expected %d bytes, got %d", MLDSA65PubKeySize, len(senderMLDSAPub))
	}
	if len(mldsaSeedBytes) != MLDSA65SeedSize {
		return nil, fmt.Errorf("sender mldsa65 seed: expected %d bytes, got %d", MLDSA65SeedSize, len(mldsaSeedBytes))
	}
	if len(recipientEdPub) != ED25519PubKeySize {
		return nil, fmt.Errorf("recipient ed25519 public key: expected %d bytes, got %d", ED25519PubKeySize, len(recipientEdPub))
	}
	if len(x25519PubBytes) != X25519PubKeySize {
		return nil, fmt.Errorf("recipient x25519 public key: expected %d bytes, got %d", X25519PubKeySize, len(x25519PubBytes))
	}
	if len(mlkemPKBytes) != MLKEM768PubKeySize {
		return nil, fmt.Errorf("recipient mlkem768 public key: expected %d bytes, got %d", MLKEM768PubKeySize, len(mlkemPKBytes))
	}

	// ── Compute fingerprints ──
	senderFP, err := Fingerprint(senderKP)
	if err != nil {
		return nil, fmt.Errorf("compute sender fingerprint: %w", err)
	}
	recipientFP, err := FingerprintFromPubs(recipient.ED25519, recipient.X25519, recipient.MLKEM768, recipient.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("compute recipient fingerprint: %w", err)
	}

	// Validate provided fingerprint matches computed one (prevents key substitution)
	if recipient.Fingerprint != "" && recipient.Fingerprint != recipientFP {
		return nil, fmt.Errorf("recipient fingerprint mismatch: provided %s but keys compute to %s",
			ShortFingerprint(recipient.Fingerprint), ShortFingerprint(recipientFP))
	}

	// ── Build HPKE public key from components ──
	recipientPub, err := buildHPKEPublicKey(mlkemPKBytes, x25519PubBytes)
	if err != nil {
		return nil, fmt.Errorf("build hpke public key: %w", err)
	}

	// ── HPKE setup ──
	info := hpkeInfo(senderFP, recipientFP, params.PayloadType)
	enc, sender, err := hpke.NewSender(recipientPub, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke sender setup: %w", err)
	}

	// ── Build envelope with full sender public bundle ──
	env := &Envelope{
		Version:              ProtocolVersion,
		CipherSuite:          CipherSuite,
		SenderFingerprint:    senderFP,
		SenderED25519:        senderEdPub,
		SenderX25519:         senderX25519Pub,
		SenderMLKEM768:       senderMLKEMPub,
		SenderMLDSA65:        senderMLDSAPub,
		RecipientFingerprint: recipientFP,
		PayloadType:          params.PayloadType,
		Timestamp:            time.Now().Unix(),
		Enc:                  enc,
		Compressed:           params.Compressed,
		Compression:          params.Compression,
	}

	// ── HPKE Seal with AAD binding ciphertext to metadata ──
	ciphertext, err := sender.Seal(env.AAD(), plaintext)
	if err != nil {
		return nil, fmt.Errorf("hpke seal: %w", err)
	}
	env.Ciphertext = ciphertext

	// ── Dual signatures (Ed25519 + ML-DSA-65) over same SignableBytes ──
	signable := env.SignableBytes()
	env.Signature = ed25519.Sign(ed25519.PrivateKey(edPrivBytes), signable)
	env.SignatureMLDSA65, err = SignMLDSA65(mldsaSeedBytes, signable)
	if err != nil {
		return nil, fmt.Errorf("mldsa65 sign: %w", err)
	}

	return cborMarshal(env)
}

// HybridDecrypt verifies the Ed25519 signature and decrypts the HPKE envelope.
//
// The envelope carries the sender's full public key bundle. HybridDecrypt:
//  1. Validates envelope field sizes
//  2. Verifies recipient fingerprint matches the local key pair
//  3. Recomputes the sender fingerprint from the embedded public keys and
//     verifies it matches SenderFingerprint (sender identity binding)
//  4. If senderED25519Pub is non-empty (base64), verifies the envelope's
//     embedded Ed25519 key matches it (defense-in-depth via external trust)
//  5. Verifies the Ed25519 signature over SignableBytes
//  6. Decrypts via HPKE Open
//
// Pass senderED25519Pub="" for self-contained verification (steps 1–3, 5–6).
func HybridDecrypt(envelopeData []byte, kp *KeyPair, senderED25519Pub string) (*DecryptResult, error) {
	// ── Input validation ──
	if kp == nil {
		return nil, fmt.Errorf("recipient key pair must not be nil")
	}
	if len(envelopeData) == 0 {
		return nil, fmt.Errorf("envelope data must not be empty")
	}
	// Reject oversized envelopes before parsing to prevent memory exhaustion.
	// 1 GiB is well above any realistic encrypted secret (sender pubkeys plus
	// ciphertext) but small enough that a single malicious envelope cannot
	// OOM the SDK. The constant is typed int64 so it does not overflow the
	// 32-bit `int` on 32-bit targets (linux/386, linux/arm, etc.).
	// 100 GiB is well above the Organization tier's 50 GiB upload cap and
	// gives headroom for compressed envelopes that expand modestly above
	// the raw payload (sender pubkeys + AEAD overhead). Sized as int64 so
	// 32-bit targets don't overflow.
	const maxEnvelopeSize int64 = 100 << 30
	if int64(len(envelopeData)) > maxEnvelopeSize {
		return nil, fmt.Errorf("envelope too large: %d bytes (max %d)", len(envelopeData), maxEnvelopeSize)
	}

	var env Envelope
	if err := cbor.Unmarshal(envelopeData, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	if env.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %q (expected %q)", env.Version, ProtocolVersion)
	}

	// ── Validate required fields using named constants ──
	if len(env.Enc) == 0 {
		return nil, fmt.Errorf("malformed envelope: missing enc field")
	}
	if len(env.Ciphertext) == 0 {
		return nil, fmt.Errorf("malformed envelope: missing ciphertext")
	}
	if len(env.Signature) != ED25519SignatureSize {
		return nil, fmt.Errorf("malformed envelope: signature must be %d bytes, got %d",
			ED25519SignatureSize, len(env.Signature))
	}
	if len(env.SenderED25519) != ED25519PubKeySize {
		return nil, fmt.Errorf("malformed envelope: sender_ed25519 must be %d bytes, got %d",
			ED25519PubKeySize, len(env.SenderED25519))
	}
	if len(env.SenderX25519) != X25519PubKeySize {
		return nil, fmt.Errorf("malformed envelope: sender_x25519 must be %d bytes, got %d",
			X25519PubKeySize, len(env.SenderX25519))
	}
	if len(env.SenderMLKEM768) != MLKEM768PubKeySize {
		return nil, fmt.Errorf("malformed envelope: sender_mlkem must be %d bytes, got %d",
			MLKEM768PubKeySize, len(env.SenderMLKEM768))
	}
	if len(env.SenderMLDSA65) != MLDSA65PubKeySize {
		return nil, fmt.Errorf("malformed envelope: sender_mldsa65 must be %d bytes, got %d",
			MLDSA65PubKeySize, len(env.SenderMLDSA65))
	}
	if len(env.SignatureMLDSA65) != MLDSA65SignatureSize {
		return nil, fmt.Errorf("malformed envelope: sig_mldsa65 must be %d bytes, got %d",
			MLDSA65SignatureSize, len(env.SignatureMLDSA65))
	}

	// ── Verify recipient fingerprint (early fail before expensive crypto) ──
	if env.RecipientFingerprint != "" {
		recipientFP, err := Fingerprint(kp)
		if err != nil {
			return nil, fmt.Errorf("compute recipient fingerprint: %w", err)
		}
		if env.RecipientFingerprint != recipientFP {
			return nil, fmt.Errorf("envelope recipient fingerprint %s does not match local key %s",
				ShortFingerprint(env.RecipientFingerprint), ShortFingerprint(recipientFP))
		}
	}

	// ── Verify sender identity binding ──
	// Recompute fingerprint from embedded public keys and check it matches
	// the claimed SenderFingerprint. VerifySenderIdentity also validates
	// field sizes defensively.
	if err := env.VerifySenderIdentity(); err != nil {
		return nil, err
	}

	// ── Optional defense-in-depth: external sender key cross-check ──
	if senderED25519Pub != "" {
		externalKey, err := base64.RawStdEncoding.DecodeString(senderED25519Pub)
		if err != nil {
			return nil, fmt.Errorf("decode sender ed25519 pub: %w", err)
		}
		if len(externalKey) != ED25519PubKeySize {
			return nil, fmt.Errorf("external sender ed25519 key: expected %d bytes, got %d", ED25519PubKeySize, len(externalKey))
		}
		if !bytes.Equal(env.SenderED25519, externalKey) {
			return nil, fmt.Errorf("sender ed25519 key in envelope does not match externally-provided key")
		}
	}

	// ── Verify dual signatures (both must pass) ──
	signable := env.SignableBytes()
	if !ed25519.Verify(ed25519.PublicKey(env.SenderED25519), signable, env.Signature) {
		return nil, fmt.Errorf("Ed25519 signature verification failed: envelope may be tampered with")
	}
	if !VerifyMLDSA65(env.SenderMLDSA65, signable, env.SignatureMLDSA65) {
		return nil, fmt.Errorf("ML-DSA-65 signature verification failed: envelope may be tampered with")
	}

	// ── Decode and validate recipient private keys ──
	x25519PrivBytes, err := base64.RawStdEncoding.DecodeString(kp.X25519Private)
	if err != nil {
		return nil, fmt.Errorf("decode x25519 private: %w", err)
	}
	if len(x25519PrivBytes) != X25519PrivKeySize {
		return nil, fmt.Errorf("recipient x25519 private key: expected %d bytes, got %d", X25519PrivKeySize, len(x25519PrivBytes))
	}
	mlkemSeedBytes, err := base64.RawStdEncoding.DecodeString(kp.MLKEM768SK)
	if err != nil {
		return nil, fmt.Errorf("decode mlkem768 sk: %w", err)
	}
	if len(mlkemSeedBytes) != MLKEM768SeedSize {
		return nil, fmt.Errorf("recipient mlkem768 seed: expected %d bytes, got %d", MLKEM768SeedSize, len(mlkemSeedBytes))
	}

	// ── Build HPKE private key from components ──
	recipientPriv, err := buildHPKEPrivateKey(mlkemSeedBytes, x25519PrivBytes)
	if err != nil {
		return nil, fmt.Errorf("build hpke private key: %w", err)
	}

	// ── HPKE Open ──
	info := hpkeInfo(env.SenderFingerprint, env.RecipientFingerprint, env.PayloadType)
	recipient, err := hpke.NewRecipient(env.Enc, recipientPriv, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("hpke recipient setup: %w", err)
	}

	decrypted, err := recipient.Open(env.AAD(), env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("hpke open failed (wrong key or corrupted): %w", err)
	}

	return &DecryptResult{
		Plaintext:   decrypted,
		Compressed:  env.Compressed,
		Compression: env.Compression,
		Envelope:    &env,
	}, nil
}
