// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package protocol

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/deepsecret-io/sdk/crypto"
)

// Protocol v4 test vectors. Other SDKs MUST reproduce every value here.
// They cover the deterministic parts of v4: payload key derivation, chunk
// associated data and nonces, one sealed chunk, the payload digest, the
// wrap HPKE info, the wrap digest and the manifest's SignableBytes. HPKE
// and signatures are randomized and are covered by the round-trip tests.
var (
	vecContentKey  = seq(0x00, 32)
	vecRevisionID  = "00000000-0000-4000-8000-000000000000"
	vecSecretName  = "prod database · token"
	vecPayloadType = "message"
	vecPlaintext   = []byte("hello, protocol v4")
	vecSenderFP    = strings.Repeat("a1", 32)
	vecRecipientFP = strings.Repeat("b2", 32)
)

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func vecManifest(digest []byte, ctSize int64) *Manifest {
	return &Manifest{
		Version:           ProtocolVersion,
		CipherSuite:       CipherSuite,
		RevisionID:        vecRevisionID,
		SecretName:        vecSecretName,
		SenderFingerprint: vecSenderFP,
		SenderED25519:     bytes.Repeat([]byte{0x01}, ED25519PubKeySize),
		SenderX25519:      bytes.Repeat([]byte{0x02}, X25519PubKeySize),
		SenderMLKEM768:    bytes.Repeat([]byte{0x03}, MLKEM768PubKeySize),
		SenderMLDSA65:     bytes.Repeat([]byte{0x04}, crypto.MLDSA65PubKeySize),
		PayloadType:       vecPayloadType,
		Compressed:        false,
		Compression:       "",
		ChunkSize:         ChunkSize,
		PlaintextSize:     int64(len(vecPlaintext)),
		CiphertextSize:    ctSize,
		PayloadDigest:     digest,
		Timestamp:         1700000000,
		Recipients:        []ManifestRecipient{{Fingerprint: vecRecipientFP, WrapDigest: bytes.Repeat([]byte{0x05}, 32)}},
	}
}

func TestProtocolV4Vectors(t *testing.T) {
	pk, err := derivePayloadKey(vecContentKey)
	if err != nil {
		t.Fatal(err)
	}
	aad := chunkAAD(vecRevisionID, vecPayloadType)
	var ct bytes.Buffer
	stream, err := encryptStream(&ct, bytes.NewReader(vecPlaintext), pk, aad)
	if err != nil {
		t.Fatal(err)
	}
	wrap := &Wrap{RecipientFingerprint: vecRecipientFP, Enc: bytes.Repeat([]byte{0x06}, 1120), Ciphertext: bytes.Repeat([]byte{0x07}, WrapCiphertextSize)}

	got := map[string]string{
		"payload_key":       hex.EncodeToString(pk),
		"chunk_aad":         hex.EncodeToString(aad),
		"nonce_0_last":      hex.EncodeToString(chunkNonce(0, true)),
		"nonce_258_mid":     hex.EncodeToString(chunkNonce(258, false)),
		"payload":           hex.EncodeToString(ct.Bytes()),
		"payload_digest":    hex.EncodeToString(stream.Digest),
		"wrap_info":         hex.EncodeToString(wrapInfo(vecRevisionID, vecSenderFP, vecRecipientFP, stream.Digest)),
		"wrap_digest":       hex.EncodeToString(wrap.Digest()),
		"manifest_signable": hex.EncodeToString(vecManifest(stream.Digest, stream.CiphertextSize).SignableBytes()),
	}
	// Independently reproduced with Python's hashlib and cryptography
	// (HKDF, AES-GCM) from the PROTOCOL_V4.md text.
	want := map[string]string{
		"payload_key":       "ec6cf7c3ffa966463c409062719555e7686139fd657c6f5bdf80482d6338e665",
		"chunk_aad":         "ed32b8ce1f21e27e6fd8197df06367924fdcde3e79e8fcb0b571712b990c0514",
		"nonce_0_last":      "000000000000000000000001",
		"nonce_258_mid":     "000000000000000000010200",
		"payload":           "56e439be9172a7cb03836cb31b9956231a86ab9767fbeb4b3255417d7e992ee3056c",
		"payload_digest":    "3041ecd979c95f894064abbd6ae21b75774e4e8395e028fb9c865aadcd8c9a9e",
		"wrap_info":         "ac64b46219d05d2ece03bd615ba5fcb1aa560d6e873a235800f1093f08b1b288",
		"wrap_digest":       "c7590017027e790b898533ccbead4bbbca69cefae3a511afa16a77c743c52d30",
		"manifest_signable": "78046c933d4c1d7204637cdc123371653439e7342490cef668b800eecfb739cc",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s:\n got  %s\n want %s", k, got[k], v)
		}
	}
}
