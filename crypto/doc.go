// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package crypto handles a user's keys: generating them, fingerprints and
// safety numbers, and the key files on a device, protected by a password or by
// security keys with a recovery code.
//
// Encrypting and decrypting secrets is the sdk package's job, which also
// checks keys against the ones this device knows.
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
//   - identity.go      : key generation, fingerprints, bundle signing, verification
//   - safety_number.go : safety numbers, a fingerprint as digits to compare aloud
//   - keystore.go      : password-protected key storage (Argon2id + AES-256-GCM)
//   - security_key.go  : security-key protected key storage (version 5, docs/yubikey-design.md)
//   - recovery_code.go : the printed recovery code of a security-key protected key
//
// # Usage
//
//	// Generate and save a key pair
//	kp, _ := crypto.GenerateKeyPair()
//	fp, _ := crypto.Fingerprint(kp)
//	crypto.SaveKeyPairTo(dir, fp, kp, "optional-password")
package crypto
