// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package compress provides streaming compression and decompression for the
// DeepSecret SDK.
//
// This is a standalone reusable package with no dependency on the archive,
// crypto, or API client packages. It is used by both the archive package
// (for tar compression) and the crypto package (for payload compression
// before encryption).
//
// # Streaming Architecture
//
// The primary APIs are streaming:
//
//	[NewCompressWriter] wraps an io.Writer with compression
//	[NewDecompressReader] wraps an io.Reader with decompression
//
// The []byte convenience APIs ([Compress], [Decompress]) are thin wrappers
// suitable only for small payloads.
//
// # Algorithms
//
// Only Zstandard ([Zstd]) is supported. The [None] algorithm passes data
// through unchanged.
//
// # Limits
//
// Decompression operations accept an optional [Limits] struct to bound
// output size, preventing decompression bombs.
package compress
