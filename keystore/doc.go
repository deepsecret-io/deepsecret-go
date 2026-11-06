// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package keystore keeps key pairs in files on a device, protected by a
// password or by security keys with a recovery code. Encrypting and decrypting
// secrets is package secrets' job, which also checks keys against the ones
// this device knows.
//
//   - keystore.go      : password-protected key storage (Argon2id + AES-256-GCM)
//   - security_key.go  : security-key protected key storage (version 5, docs/yubikey-design.md)
//   - recovery_code.go : the printed recovery code of a security-key protected key
//
// Usage:
//
//	kp, _ := keys.Generate()
//	fp, _ := keys.Fingerprint(kp)
//	keystore.Save(dir, fp, kp, "optional-password")
package keystore
