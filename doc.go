// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package sdk provides a high-level Go SDK for the DeepSecret API.
//
// DeepSecret uses protocol v4 (PROTOCOL_V4.md): each revision's payload is
// encrypted once with AES-256-GCM in 1 MiB chunks under a fresh content
// key, that key is wrapped for every recipient with hybrid post-quantum
// HPKE (X25519-ML-KEM-768, HKDF-SHA256, AES-256-GCM), and the sender signs
// a manifest covering the payload and every wrap with Ed25519 and
// ML-DSA-65. All cryptographic operations happen client-side: private keys
// never leave the device.
//
// # Package Structure
//
//	sdk/           : high-level orchestration (encrypt, decrypt, revoke)
//	sdk/api/       : HTTP client, presigned URL upload/download
//	sdk/identity/  : actor info, key management, resolution
//	sdk/secrets/   : secret CRUD, creation request types
//	sdk/payload/   : CBOR payload types (wire format)
//	sdk/crypto/    : payload stream, HPKE wraps, signed manifest, keystore
//	sdk/compress/  : streaming zstd compression/decompression
//	sdk/archive/   : tar creation/extraction, path validation
//
// The crypto, compress, and archive packages are standalone with no API
// dependency. They can be used independently or ported to other languages.
//
// # Recipients
//
// One send seals the payload once for any number of recipients and uploads
// it once. The sender is a recipient only when listed. Sending again under
// an existing name adds a revision, and must list everyone who has access
// now unless EncryptOptions.RevokeMissing is set. RevokeRecipient removes
// one recipient.
//
// # Memory Model
//
// Files stream, so memory stays flat at any size, up to 100 GiB a secret:
//
//   - Each file is read once, encoded into the CBOR payload, compressed and
//     sealed chunk by chunk into a private temporary file that holds only
//     ciphertext
//   - The object is uploaded from that file, in parts above the server's
//     multipart threshold
//
// On decrypt the object is downloaded into a temporary file, so its digest
// can be checked against the signed manifest before any plaintext is
// released. WriteFiles (and DecryptToDir) then decrypt it once to check
// every file and again to write them. Both sides need free disk space for
// the encrypted payload, in EncryptOptions.TempDir or DecryptOptions.TempDir,
// else $DEEPSECRET_TMPDIR, else the system temp directory.
//
// Messages and key-value data are small and are handled in memory, as is
// DecryptSecretFull for payloads up to DefaultMaxInMemorySize.
//
// # Quick Start
//
//	client, err := sdk.NewClient("https://api.deepsecret.io", "your-api-key")
//	if err != nil { log.Fatal(err) }
//
//	// Encrypt a message for two recipients in one send
//	res, _ := client.EncryptText([]string{"alice@example.com", "bob@example.com"}, "sensitive data", sdk.EncryptOptions{})
//
//	// Decrypt a secret (as one of its recipients)
//	result, _ := client.DecryptSecret(res.Secret.ID)
//	fmt.Println(result.Message)
//
//	// Write a files secret of any size to disk
//	_, written, _ := client.DecryptToDir(secretID, "./out", sdk.DecryptOptions{}, sdk.WriteOptions{})
//	fmt.Println(len(written.Files), "files")
//
// # Secret Management
//
//	secrets, total, _ := client.ListSecrets("received", sdk.ListOptions{Limit: 50})
//	info, _ := client.DescribeSecret(secretID)
//	client.RevokeRecipient(secretID, "bob@example.com")
//	client.DeleteSecret(secretID)
package sdk
