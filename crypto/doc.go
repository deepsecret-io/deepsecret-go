// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package crypto provides low-level cryptographic primitives for the DeepSecret
// protocol v2.
//
// # Protocol
//
// Protocol v2 uses RFC 9180 HPKE (Hybrid Public Key Encryption) with:
//   - KEM:  MLKEM768-X25519 (hybrid post-quantum + classical)
//   - KDF:  HKDF-SHA256
//   - AEAD: AES-256-GCM
//
// Ed25519 signatures provide sender authentication (HPKE alone only provides
// confidentiality, not sender identity).
//
// # Trust Model
//
// Each envelope carries the sender's full public key bundle (Ed25519, X25519,
// ML-KEM-768). On decrypt, the SDK:
//  1. Recomputes the sender fingerprint from the embedded keys
//  2. Verifies it matches the claimed SenderFingerprint
//  3. Verifies the Ed25519 signature using the now-bound embedded key
//
// This makes each envelope self-verifiable without external key lookups. An
// optional external Ed25519 key can be supplied for defense-in-depth (e.g.,
// cross-checking against a trusted identity service).
//
// # Identity Keys
//
// Each identity consists of three key pairs:
//   - Ed25519     — digital signatures and sender authentication
//   - X25519      — classical ECDH (used by HPKE hybrid KEM)
//   - ML-KEM-768  — post-quantum KEM (FIPS 203, used by HPKE hybrid KEM)
//
// # Package Layout
//
//   - identity.go  — key generation, fingerprints, bundle signing, verification
//   - keystore.go  — password-protected key storage (Argon2id + AES-256-GCM)
//   - envelope.go  — envelope types, canonical encoding, serialization, constants
//   - hybrid.go    — HPKE encrypt/decrypt with Ed25519 signing
//
// # Usage
//
//	// Generate and save a key pair
//	kp, _ := crypto.GenerateKeyPair()
//	fp, _ := crypto.Fingerprint(kp)
//	crypto.SaveKeyPair(fp, kp, "optional-password")
//
//	// Encrypt
//	sealed, _ := crypto.HybridEncrypt(plaintext, senderKP, recipientPub, crypto.EncryptParams{
//	    PayloadType: "message",
//	})
//
//	// Decrypt (self-contained: envelope carries sender bundle)
//	result, _ := crypto.HybridDecrypt(sealed, recipientKP, "")
//
//	// Decrypt (defense-in-depth: cross-check against known sender key)
//	result, _ = crypto.HybridDecrypt(sealed, recipientKP, trustedSenderED25519Pub)
package crypto
