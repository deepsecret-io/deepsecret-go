// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestHybridEncryptDecryptRoundtrip(t *testing.T) {
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

	tests := []struct {
		name      string
		plaintext string
		params    EncryptParams
	}{
		{"message", "Hello, World!", EncryptParams{PayloadType: "message"}},
		{"compressed", "compressed payload", EncryptParams{PayloadType: "message", Compressed: true, Compression: "zstd"}},
		{"files", "file content bytes", EncryptParams{PayloadType: "files"}},
		{"data", `{"key":"value"}`, EncryptParams{PayloadType: "data"}},
		{"empty", "", EncryptParams{PayloadType: "message"}},
		{"large", string(make([]byte, 100_000)), EncryptParams{PayloadType: "files"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope, err := HybridEncrypt([]byte(tt.plaintext), sender, recipientPub, tt.params)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			// Self-contained decrypt (no external key)
			result, err := HybridDecrypt(envelope, recipient, "")
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if string(result.Plaintext) != tt.plaintext {
				t.Errorf("plaintext mismatch: got %d bytes, want %d bytes",
					len(result.Plaintext), len(tt.plaintext))
			}
			if result.Compressed != tt.params.Compressed {
				t.Errorf("compressed = %v, want %v", result.Compressed, tt.params.Compressed)
			}
			if result.Compression != tt.params.Compression {
				t.Errorf("compression = %q, want %q", result.Compression, tt.params.Compression)
			}
		})
	}
}

func TestHybridDecryptWrongKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	wrongRecipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("secret"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	_, err := HybridDecrypt(envelope, wrongRecipient, "")
	if err == nil {
		t.Error("decryption with wrong key should fail")
	}
}

func TestHybridDecryptWrongSenderKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	fakeSender, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("secret"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	// External key that doesn't match the envelope's embedded key
	_, err := HybridDecrypt(envelope, recipient, fakeSender.ED25519Public)
	if err == nil {
		t.Error("decryption with wrong external sender key should fail")
	}
}

func TestSelfEncryptDecrypt(t *testing.T) {
	kp, _ := GenerateKeyPair()
	fp, _ := Fingerprint(kp)

	pub := &PublicKeys{
		ED25519:     kp.ED25519Public,
		X25519:      kp.X25519Public,
		MLKEM768:    kp.MLKEM768PK,
		MLDSA65:     kp.MLDSA65PK,
		Fingerprint: fp,
	}

	msg := "self-encrypted message"
	envelope, err := HybridEncrypt([]byte(msg), kp, pub, EncryptParams{PayloadType: "message"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := HybridDecrypt(envelope, kp, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Plaintext) != msg {
		t.Errorf("got %q, want %q", string(result.Plaintext), msg)
	}
}

func TestFingerprintMismatchRejectsEncrypt(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	_, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	if err == nil {
		t.Error("should reject mismatched fingerprint")
	}
}

func TestEmptyFingerprintAllowed(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()

	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	envelope, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	if err != nil {
		t.Fatalf("empty fingerprint should be allowed: %v", err)
	}

	result, err := HybridDecrypt(envelope, recipient, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Plaintext) != "test" {
		t.Error("roundtrip failed")
	}
}

func TestDecryptWithoutExternalKey(t *testing.T) {
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

	envelope, _ := HybridEncrypt([]byte("self-contained"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	result, err := HybridDecrypt(envelope, recipient, "")
	if err != nil {
		t.Fatalf("should decrypt with embedded key: %v", err)
	}
	if string(result.Plaintext) != "self-contained" {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptWithExternalKeyMatch(t *testing.T) {
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

	envelope, _ := HybridEncrypt([]byte("external-check"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	// External key matches — should succeed
	result, err := HybridDecrypt(envelope, recipient, sender.ED25519Public)
	if err != nil {
		t.Fatalf("should decrypt with matching external key: %v", err)
	}
	if string(result.Plaintext) != "external-check" {
		t.Error("plaintext mismatch")
	}
}

func TestDecryptRejectsSwappedSenderKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	otherSender, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	_, err := HybridDecrypt(envelope, recipient, otherSender.ED25519Public)
	if err == nil {
		t.Error("should reject when external key doesn't match envelope's embedded key")
	}
}

func TestSenderBundleInEnvelope(t *testing.T) {
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

	senderEdPub, _ := base64.RawStdEncoding.DecodeString(sender.ED25519Public)
	senderX25519Pub, _ := base64.RawStdEncoding.DecodeString(sender.X25519Public)
	senderMLKEMPub, _ := base64.RawStdEncoding.DecodeString(sender.MLKEM768PK)

	if !bytes.Equal(env.SenderED25519, senderEdPub) {
		t.Error("envelope should contain sender's Ed25519 public key")
	}
	if !bytes.Equal(env.SenderX25519, senderX25519Pub) {
		t.Error("envelope should contain sender's X25519 public key")
	}
	if !bytes.Equal(env.SenderMLKEM768, senderMLKEMPub) {
		t.Error("envelope should contain sender's ML-KEM-768 public key")
	}
	if len(env.SenderFingerprint) != FingerprintLen {
		t.Errorf("sender fingerprint length = %d, want %d", len(env.SenderFingerprint), FingerprintLen)
	}
}

func TestRecipientFingerprintCheckOnDecrypt(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	other, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)

	recipientPub := &PublicKeys{
		ED25519:     recipient.ED25519Public,
		X25519:      recipient.X25519Public,
		MLKEM768:    recipient.MLKEM768PK,
		MLDSA65:     recipient.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("secret"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	_, err := HybridDecrypt(envelope, other, "")
	if err == nil {
		t.Error("should fail when recipient fingerprint does not match local key")
	}
}

// ── Input validation tests ──────────────────────────────────────────────────

func TestEncryptRejectsNilSender(t *testing.T) {
	recipient, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	_, err := HybridEncrypt([]byte("test"), nil, recipientPub, EncryptParams{PayloadType: "message"})
	if err == nil {
		t.Error("should reject nil sender")
	}
}

func TestEncryptRejectsNilRecipient(t *testing.T) {
	sender, _ := GenerateKeyPair()

	_, err := HybridEncrypt([]byte("test"), sender, nil, EncryptParams{PayloadType: "message"})
	if err == nil {
		t.Error("should reject nil recipient")
	}
}

func TestEncryptRejectsInvalidPayloadType(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	_, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "invalid"})
	if err == nil {
		t.Error("should reject invalid payload type")
	}
}

func TestEncryptRejectsInvalidCompression(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	_, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message", Compression: "lz4"})
	if err == nil {
		t.Error("should reject unsupported compression")
	}
}

func TestEncryptRejectsEmptyRecipientKeys(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{ED25519: "abc"} // missing X25519 and MLKEM768

	_, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	if err == nil {
		t.Error("should reject incomplete recipient keys")
	}
}

func TestDecryptRejectsNilKeyPair(t *testing.T) {
	_, err := HybridDecrypt([]byte{1}, nil, "")
	if err == nil {
		t.Error("should reject nil key pair")
	}
}

func TestDecryptRejectsEmptyData(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := HybridDecrypt(nil, kp, "")
	if err == nil {
		t.Error("should reject nil envelope data")
	}
	_, err = HybridDecrypt([]byte{}, kp, "")
	if err == nil {
		t.Error("should reject empty envelope data")
	}
}

func TestEncryptRejectsMalformedSenderPrivateKey(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	// Corrupt the sender's Ed25519 private key to wrong size
	badSender := *sender
	badSender.ED25519Private = base64.RawStdEncoding.EncodeToString([]byte("too-short"))
	_, err := HybridEncrypt([]byte("test"), &badSender, recipientPub, EncryptParams{PayloadType: "message"})
	if err == nil {
		t.Error("should reject malformed sender ed25519 private key")
	}
}

func TestDecryptRejectsMalformedRecipientPrivateKeys(t *testing.T) {
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

	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	// Corrupt recipient's X25519 private key
	badRecipient := *recipient
	badRecipient.X25519Private = base64.RawStdEncoding.EncodeToString([]byte("short"))
	_, err := HybridDecrypt(envelope, &badRecipient, "")
	if err == nil {
		t.Error("should reject malformed recipient x25519 private key")
	}

	// Corrupt recipient's MLKEM seed
	badRecipient2 := *recipient
	badRecipient2.MLKEM768SK = base64.RawStdEncoding.EncodeToString([]byte("short"))
	_, err = HybridDecrypt(envelope, &badRecipient2, "")
	if err == nil {
		t.Error("should reject malformed recipient mlkem768 seed")
	}
}

// ── Malformed base64 tests ──────────────────────────────────────────────────

func TestEncryptRejectsMalformedRecipientBase64(t *testing.T) {
	sender, _ := GenerateKeyPair()
	valid, _ := GenerateKeyPair()

	tests := []struct {
		name string
		pub  PublicKeys
	}{
		{
			"bad ed25519",
			PublicKeys{ED25519: "!!!invalid-base64!!!", X25519: valid.X25519Public, MLKEM768: valid.MLKEM768PK},
		},
		{
			"bad x25519",
			PublicKeys{ED25519: valid.ED25519Public, X25519: "!!!invalid-base64!!!", MLKEM768: valid.MLKEM768PK},
		},
		{
			"bad mlkem768",
			PublicKeys{ED25519: valid.ED25519Public, X25519: valid.X25519Public, MLKEM768: "!!!invalid-base64!!!"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HybridEncrypt([]byte("test"), sender, &tt.pub, EncryptParams{PayloadType: "message"})
			if err == nil {
				t.Errorf("should reject malformed base64 in recipient %s", tt.name)
			}
		})
	}
}

func TestEncryptRejectsMalformedSenderBase64(t *testing.T) {
	recipient, _ := GenerateKeyPair()
	recipientPub := &PublicKeys{
		ED25519:  recipient.ED25519Public,
		X25519:   recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK,
	}

	tests := []struct {
		name  string
		field string // which field to corrupt
	}{
		{"bad ed25519 private", "ed25519_private"},
		{"bad ed25519 public", "ed25519_public"},
		{"bad x25519 public", "x25519_public"},
		{"bad mlkem768 public", "mlkem768_pk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender, _ := GenerateKeyPair()
			switch tt.field {
			case "ed25519_private":
				sender.ED25519Private = "!!!bad!!!"
			case "ed25519_public":
				sender.ED25519Public = "!!!bad!!!"
			case "x25519_public":
				sender.X25519Public = "!!!bad!!!"
			case "mlkem768_pk":
				sender.MLKEM768PK = "!!!bad!!!"
			}
			_, err := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
			if err == nil {
				t.Errorf("should reject malformed base64 in sender %s", tt.field)
			}
		})
	}
}

// ── Corrupted envelope tests ────────────────────────────────────────────────

func TestDecryptRejectsCorruptedMsgpack(t *testing.T) {
	kp, _ := GenerateKeyPair()

	_, err := HybridDecrypt([]byte("this is not msgpack"), kp, "")
	if err == nil {
		t.Error("should reject corrupted msgpack")
	}

	// Truncated valid msgpack
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)
	recipientPub := &PublicKeys{
		ED25519: recipient.ED25519Public, X25519: recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK, Fingerprint: recipientFP,
	}
	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})

	// Truncate at various points
	for _, cutAt := range []int{10, 50, len(envelope) / 2, len(envelope) - 1} {
		_, err := HybridDecrypt(envelope[:cutAt], recipient, "")
		if err == nil {
			t.Errorf("should reject truncated envelope at byte %d", cutAt)
		}
	}
}

func TestDecryptRejectsTamperedMetadata(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)
	recipientPub := &PublicKeys{
		ED25519: recipient.ED25519Public, X25519: recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK, Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("secret payload"), sender, recipientPub, EncryptParams{PayloadType: "files"})
	env, _ := UnmarshalEnvelope(envelope)

	// Each tampering should cause either signature or AAD failure
	tests := []struct {
		name   string
		tamper func(e *Envelope)
	}{
		{"CipherSuite", func(e *Envelope) { e.CipherSuite = "FAKE-SUITE" }},
		{"PayloadType", func(e *Envelope) { e.PayloadType = "message" }},
		{"Compressed", func(e *Envelope) { e.Compressed = true }},
		{"Compression", func(e *Envelope) { e.Compression = "zstd" }},
		{"Timestamp", func(e *Envelope) { e.Timestamp = 999 }},
		{"SenderFingerprint", func(e *Envelope) {
			e.SenderFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"RecipientFingerprint", func(e *Envelope) {
			e.RecipientFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *env
			tt.tamper(&tampered)
			data, err := tampered.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			_, err = HybridDecrypt(data, recipient, "")
			if err == nil {
				t.Errorf("should reject envelope with tampered %s", tt.name)
			}
		})
	}
}

// ── Compression flag consistency tests ──────────────────────────────────────

func TestEncryptParamsCompressedTrueEmptyCompression(t *testing.T) {
	// Compressed=true with empty Compression is inconsistent: the decrypt side
	// needs a named algorithm to decompress. Reject at encrypt time.
	p := EncryptParams{PayloadType: "message", Compressed: true, Compression: ""}
	if err := p.validate(); err == nil {
		t.Error("should reject Compressed=true with empty Compression")
	}
}

// ── Version mismatch / future compatibility tests ───────────────────────────

func TestDecryptRejectsUnknownVersion(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)
	recipientPub := &PublicKeys{
		ED25519: recipient.ED25519Public, X25519: recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK, Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelope)

	// Set a future version
	env.Version = "99"
	data, _ := env.Marshal()
	_, err := HybridDecrypt(data, recipient, "")
	if err == nil {
		t.Error("should reject unknown protocol version")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unsupported protocol version")) {
		t.Errorf("error should mention version mismatch, got: %v", err)
	}
}

func TestDecryptRejectsVersion1(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)
	recipientPub := &PublicKeys{
		ED25519: recipient.ED25519Public, X25519: recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK, Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelope)

	// Downgrade to v1
	env.Version = "1"
	data, _ := env.Marshal()
	_, err := HybridDecrypt(data, recipient, "")
	if err == nil {
		t.Error("should reject v1 envelopes")
	}
}

func TestDecryptRejectsEmptyVersion(t *testing.T) {
	sender, _ := GenerateKeyPair()
	recipient, _ := GenerateKeyPair()
	recipientFP, _ := Fingerprint(recipient)
	recipientPub := &PublicKeys{
		ED25519: recipient.ED25519Public, X25519: recipient.X25519Public,
		MLKEM768: recipient.MLKEM768PK, MLDSA65: recipient.MLDSA65PK, Fingerprint: recipientFP,
	}

	envelope, _ := HybridEncrypt([]byte("test"), sender, recipientPub, EncryptParams{PayloadType: "message"})
	env, _ := UnmarshalEnvelope(envelope)

	env.Version = ""
	data, _ := env.Marshal()
	_, err := HybridDecrypt(data, recipient, "")
	if err == nil {
		t.Error("should reject empty version")
	}
}
