// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package crypto provides the cryptographic primitives of DeepSecret
// protocol v4 (sdk/PROTOCOL_V4.md): one payload per revision, encrypted
// once, with a wrap of its content key for every recipient.
//
// # Protocol
//
// Each revision has a fresh random content key K. The payload is encrypted
// once with AES-256-GCM in 1 MiB chunks under a key derived from K with
// HKDF-SHA256, and the stored object is hashed into a payload digest. K is
// then wrapped for every recipient with RFC 9180 HPKE in base mode:
//   - KEM:  X25519-ML-KEM-768 (hybrid post-quantum + classical)
//   - KDF:  HKDF-SHA256
//   - AEAD: AES-256-GCM
//
// Every wrap uses a fresh HPKE context, and its HPKE info binds it to one
// sender, one recipient, one revision and one payload digest.
//
// # Trust Model
//
// The sender signs a manifest with Ed25519 and ML-DSA-65 (both required).
// It covers the revision, the payload digest and sizes, and every
// recipient's fingerprint and wrap digest, and it embeds the sender's full
// public key bundle. Every recipient holds K and could encrypt other content
// under it, so only this signature shows who wrote the payload.
//
// Opening a revision:
//  1. Recomputes the sender fingerprint from the embedded keys
//  2. Verifies both signatures with the now-bound embedded keys
//  3. Checks the revision, that the caller is listed, and the wrap digest
//  4. Opens the wrap and derives the payload key
//  5. Verifies the payload's size and digest against the manifest before
//     releasing any plaintext, then decrypts the chunks in order
//
// A manifest verifies without external key lookups. An optional external
// Ed25519 key can be supplied for defense-in-depth (e.g., cross-checking
// against a trusted identity service).
//
// # Identity Keys
//
// Each identity consists of four key pairs:
//   - Ed25519     : classical signatures and sender authentication
//   - ML-DSA-65   : post-quantum signatures (FIPS 204)
//   - X25519      : classical ECDH (used by the HPKE hybrid KEM)
//   - ML-KEM-768  : post-quantum KEM (FIPS 203, used by the HPKE hybrid KEM)
//
// # Package Layout
//
//   - identity.go  : key generation, fingerprints, bundle signing, verification
//   - keystore.go  : password-protected key storage (Argon2id + AES-256-GCM)
//   - protocol.go  : protocol constants, canonical encoding, serialization
//   - stream.go    : the chunked payload stream
//   - wrap.go      : per-recipient HPKE wraps of the content key
//   - manifest.go  : the signed manifest
//   - seal.go      : Seal and Open, the entry points
//
// # Usage
//
//	// Generate and save a key pair
//	kp, _ := crypto.GenerateKeyPair()
//	fp, _ := crypto.Fingerprint(kp)
//	crypto.SaveKeyPair(fp, kp, "optional-password")
//
//	// Seal once for every recipient
//	payload, sealed, _ := crypto.SealBytes(plaintext, senderKP, []*crypto.PublicKeys{alicePub, bobPub}, crypto.SealParams{
//	    RevisionID:  revisionID,
//	    SecretName:  "db-password",
//	    PayloadType: "message",
//	})
//
//	// Open as one recipient, then decrypt the payload
//	wrap, _ := sealed.Wrap(aliceFP)
//	opened, _ := crypto.Open(sealed.ManifestData, wrap, aliceKP, crypto.OpenParams{RevisionID: revisionID, SecretName: "db-password"})
//	defer opened.Close()
//	plaintext, _ = opened.Decrypt(payload)
package crypto
