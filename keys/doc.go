// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package keys holds a user's key material: generating key pairs, fingerprints
// and safety numbers. It reads and writes no files: package keystore keeps key
// pairs on a device.
//
// Each identity consists of four key pairs:
//   - Ed25519     : classical signatures and sender authentication
//   - ML-DSA-65   : post-quantum signatures (FIPS 204)
//   - X25519      : classical ECDH (used by the HPKE hybrid KEM)
//   - ML-KEM-768  : post-quantum KEM (FIPS 203, used by the HPKE hybrid KEM)
package keys
