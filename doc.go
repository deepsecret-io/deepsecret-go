// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package sdk provides a high-level Go SDK for the DeepSecret API.
//
// DeepSecret uses hybrid post-quantum encryption (HPKE with MLKEM768-X25519,
// HKDF-SHA256, AES-256-GCM) with Ed25519 signatures. All cryptographic
// operations happen client-side — private keys never leave the device.
//
// # Package Structure
//
//	sdk/           — high-level orchestration (encrypt, decrypt)
//	sdk/api/       — HTTP client, presigned URL upload/download
//	sdk/identity/  — actor info, key management, resolution
//	sdk/secrets/   — secret CRUD, creation request types
//	sdk/payload/   — CBOR payload types (wire format)
//	sdk/crypto/    — HPKE encrypt/decrypt, Ed25519 signing, keystore
//	sdk/compress/  — streaming zstd compression/decompression
//	sdk/archive/   — tar creation/extraction, path validation
//
// The crypto, compress, and archive packages are standalone with no API
// dependency. They can be used independently or ported to other languages.
//
// # Memory Model
//
// The current protocol uses single-shot HPKE encryption, which requires the
// full plaintext payload in memory. For large files, this means:
//
//   - File data is loaded into the CBOR payload (in memory)
//   - The payload is optionally compressed (in memory)
//   - The compressed payload is encrypted as a single HPKE operation
//   - The encrypted envelope is uploaded to storage
//
// The archive and compress packages support streaming internally, but the
// HPKE single-shot constraint means the full encrypted envelope must be
// buffered. Future protocol versions may add chunked encryption to enable
// true end-to-end streaming for very large payloads.
//
// # Quick Start
//
//	client, err := sdk.NewClient("https://api.deepsecret.io", "your-api-key")
//	if err != nil { log.Fatal(err) }
//
//	// Encrypt a message
//	secret, _ := client.EncryptText("recipient@example.com", "sensitive data")
//
//	// Decrypt a secret
//	result, _ := client.DecryptSecret(secret.ID)
//	fmt.Println(result.Message)
//
// # Secret Management
//
//	secrets, total, _ := client.ListSecrets("received", sdk.ListOptions{Limit: 50})
//	info, _ := client.DescribeSecret(secretID)
//	client.DeleteSecret(secretID)
package sdk
