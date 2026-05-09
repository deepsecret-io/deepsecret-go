// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestCanonicalEncoding(t *testing.T) {
	h := sha256.New()
	writeField(h, []byte("hello"))
	sum1 := h.Sum(nil)

	h2 := sha256.New()
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 5)
	h2.Write(length[:])
	h2.Write([]byte("hello"))
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("writeField output does not match manual construction")
	}
}

func TestCanonicalEncodingNoAmbiguity(t *testing.T) {
	h1 := sha256.New()
	writeField(h1, []byte("ab"))
	writeField(h1, []byte("cd"))
	sum1 := h1.Sum(nil)

	h2 := sha256.New()
	writeField(h2, []byte("abc"))
	writeField(h2, []byte("d"))
	sum2 := h2.Sum(nil)

	if bytes.Equal(sum1, sum2) {
		t.Error("length-prefixed encoding should prevent concatenation ambiguity")
	}
}

func TestSignableBytesAndAADConsistency(t *testing.T) {
	env := &Envelope{
		Version:              "2",
		CipherSuite:          CipherSuite,
		SenderFingerprint:    "aaaa",
		SenderED25519:        make([]byte, ED25519PubKeySize),
		SenderX25519:         make([]byte, X25519PubKeySize),
		SenderMLKEM768:       make([]byte, MLKEM768PubKeySize),
		RecipientFingerprint: "bbbb",
		PayloadType:          "message",
		Timestamp:            1234567890,
		Enc:                  []byte{1, 2, 3},
		Ciphertext:           []byte{4, 5, 6},
		Compressed:           false,
		Compression:          "",
	}

	sig := env.SignableBytes()
	aad := env.AAD()

	// They must differ (SignableBytes includes Enc+Ciphertext, AAD does not)
	if bytes.Equal(sig, aad) {
		t.Error("SignableBytes and AAD should differ")
	}

	// Deterministic
	if !bytes.Equal(env.SignableBytes(), sig) {
		t.Error("SignableBytes should be deterministic")
	}
	if !bytes.Equal(env.AAD(), aad) {
		t.Error("AAD should be deterministic")
	}

	// Changing a metadata field changes both
	env2 := *env
	env2.Timestamp = 999
	if bytes.Equal(env2.SignableBytes(), sig) {
		t.Error("changing timestamp should change SignableBytes")
	}
	if bytes.Equal(env2.AAD(), aad) {
		t.Error("changing timestamp should change AAD")
	}

	// Changing a sender bundle field changes both
	env3 := *env
	env3.SenderED25519 = make([]byte, ED25519PubKeySize)
	env3.SenderED25519[0] = 0xFF
	if bytes.Equal(env3.SignableBytes(), sig) {
		t.Error("changing sender ed25519 should change SignableBytes")
	}
	if bytes.Equal(env3.AAD(), aad) {
		t.Error("changing sender ed25519 should change AAD")
	}
}

func TestUnmarshalEnvelope(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("hello"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	env, err := UnmarshalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if env.Version != ProtocolVersion {
		t.Errorf("version = %q, want %q", env.Version, ProtocolVersion)
	}
	if env.CipherSuite != CipherSuite {
		t.Errorf("suite = %q, want %q", env.CipherSuite, CipherSuite)
	}
	if env.PayloadType != "message" {
		t.Errorf("type = %q, want %q", env.PayloadType, "message")
	}
	if env.RecipientFingerprint != recipientFP {
		t.Errorf("recipient fp = %q, want %q", env.RecipientFingerprint, recipientFP)
	}
	if len(env.SenderFingerprint) != FingerprintLen {
		t.Errorf("sender fp length = %d, want %d", len(env.SenderFingerprint), FingerprintLen)
	}
	if len(env.SenderED25519) != ED25519PubKeySize {
		t.Errorf("sender ed25519 = %d bytes, want %d", len(env.SenderED25519), ED25519PubKeySize)
	}
	if len(env.SenderX25519) != X25519PubKeySize {
		t.Errorf("sender x25519 = %d bytes, want %d", len(env.SenderX25519), X25519PubKeySize)
	}
	if len(env.SenderMLKEM768) != MLKEM768PubKeySize {
		t.Errorf("sender mlkem = %d bytes, want %d", len(env.SenderMLKEM768), MLKEM768PubKeySize)
	}
	if err := env.VerifySenderIdentity(); err != nil {
		t.Errorf("VerifySenderIdentity failed: %v", err)
	}
}

func TestVerifySenderIdentityRejectsTamperedKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelopeBytes, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelopeBytes)

	env.SenderED25519[0] ^= 0xFF
	if err := env.VerifySenderIdentity(); err == nil {
		t.Error("should reject tampered sender key")
	}
}

func TestVerifySenderIdentityRejectsMissingSizes(t *testing.T) {
	env := &Envelope{
		SenderFingerprint: "aaaa",
		SenderED25519:     []byte{1, 2, 3}, // wrong size
		SenderX25519:      make([]byte, X25519PubKeySize),
		SenderMLKEM768:    make([]byte, MLKEM768PubKeySize),
	}
	if err := env.VerifySenderIdentity(); err == nil {
		t.Error("should reject wrong-size ed25519 key")
	}

	env2 := &Envelope{
		SenderFingerprint: "aaaa",
		SenderED25519:     make([]byte, ED25519PubKeySize),
		SenderX25519:      nil, // missing
		SenderMLKEM768:    make([]byte, MLKEM768PubKeySize),
	}
	if err := env2.VerifySenderIdentity(); err == nil {
		t.Error("should reject missing x25519 key")
	}

	env3 := &Envelope{
		SenderFingerprint: "", // missing
		SenderED25519:     make([]byte, ED25519PubKeySize),
		SenderX25519:      make([]byte, X25519PubKeySize),
		SenderMLKEM768:    make([]byte, MLKEM768PubKeySize),
	}
	if err := env3.VerifySenderIdentity(); err == nil {
		t.Error("should reject missing fingerprint")
	}
}

func TestVerifySenderIdentityRejectsTamperedX25519(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelopeBytes, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelopeBytes)

	env.SenderX25519[0] ^= 0xFF
	if err := env.VerifySenderIdentity(); err == nil {
		t.Error("should reject tampered sender x25519 key")
	}
}

func TestVerifySenderIdentityRejectsTamperedMLKEM(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelopeBytes, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelopeBytes)

	env.SenderMLKEM768[0] ^= 0xFF
	if err := env.VerifySenderIdentity(); err == nil {
		t.Error("should reject tampered sender mlkem768 key")
	}
}

func TestEncryptParamsValidation(t *testing.T) {
	p := EncryptParams{PayloadType: "invalid"}
	if err := p.validate(); err == nil {
		t.Error("should reject invalid payload type")
	}

	p2 := EncryptParams{PayloadType: "message", Compression: "lz4"}
	if err := p2.validate(); err == nil {
		t.Error("should reject invalid compression")
	}

	// Compressed=false with non-empty Compression is inconsistent
	p3 := EncryptParams{PayloadType: "message", Compressed: false, Compression: "zstd"}
	if err := p3.validate(); err == nil {
		t.Error("should reject Compressed=false with Compression='zstd'")
	}

	// Valid combinations
	p4 := EncryptParams{PayloadType: "files", Compressed: true, Compression: "zstd"}
	if err := p4.validate(); err != nil {
		t.Errorf("valid params should pass: %v", err)
	}

	p5 := EncryptParams{PayloadType: "message"}
	if err := p5.validate(); err != nil {
		t.Errorf("minimal valid params should pass: %v", err)
	}
}
