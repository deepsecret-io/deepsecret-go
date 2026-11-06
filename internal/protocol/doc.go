// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package protocol implements DeepSecret protocol v4 (PROTOCOL_V4.md): one
// payload per revision, encrypted once, with a wrap of its content key for
// every recipient. It is internal so a caller cannot skip what the sdk package
// adds around it: checking keys against the ones this device knows, and
// refusing a rollback.
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
// # Package Layout
//
//   - protocol.go : protocol constants and field hashing
//   - stream.go   : the chunked payload stream
//   - wrap.go     : per-recipient HPKE wraps of the content key
//   - manifest.go : the signed manifest
//   - seal.go     : Seal and Open, the entry points
package protocol
