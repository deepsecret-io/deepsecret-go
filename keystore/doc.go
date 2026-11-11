// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package keystore keeps key pairs in files on a device, protected by a
// password, by security keys, or by AWS KMS keys, the last two with an
// optional recovery code. Encrypting and decrypting secrets is package
// secrets' job, which also checks keys against the ones this device knows.
//
//   - keystore.go      : password-protected key storage (Argon2id + AES-256-GCM)
//   - security_key.go  : slot files (versions 5 and 6: security keys and AWS KMS keys), docs/yubikey-design.md
//   - kms.go           : AWS KMS protected key storage (version 6, docs/kms-design.md), Import
//   - recovery_code.go : the printed recovery code of a slot file
//
// Usage:
//
//	kp, _ := keys.Generate()
//	fp, _ := keys.Fingerprint(kp)
//	keystore.Save(dir, fp, kp, "optional-password")
package keystore
