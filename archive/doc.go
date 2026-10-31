// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package archive provides file expansion, archiving, and compression for the
// DeepSecret SDK.
//
// This package is standalone (no dependency on the API client or crypto package)
// and is designed for cross-language portability. Its behavior is specified
// precisely enough that Go, JavaScript, Python, and Rust implementations can
// produce identical archives and validate identical paths.
//
// # Streaming Architecture
//
// The package is streaming-first. The primary APIs operate on io.Writer /
// io.Reader pipelines to avoid buffering large archives in memory:
//
// Creation pipelines:
//
//	file → tar.Writer → compressor → io.Writer      (via WriteTar)
//	io.Reader → tar.Writer → compressor → io.Writer  (via WriteTarStream)
//
// Extraction pipeline:
//
//	io.Reader → decompressor → tar.Reader → disk     (via ExtractTarReader)
//
// Primary streaming APIs:
//   - [WriteTar] — stream disk files into a tar archive
//   - [WriteTarFromBytes] — stream in-memory entries (sorted, deterministic)
//   - [WriteTarStream] — stream reader-backed entries (caller-ordered, no buffering)
//   - [ExtractTarReader] — stream a tar archive to disk
//   - [NewCompressWriter] / [NewDecompressReader] — composable compression
//
// The []byte convenience APIs ([CreateTar], [ExtractTar], etc.) are thin
// wrappers over the streaming APIs, suitable only for small payloads.
//
// # Archive Path Model
//
// Archive entry names (as stored in tar headers) use a strict portable format:
//   - Forward-slash separated (never backslash)
//   - No leading or trailing slashes
//   - No empty segments (no "a//b")
//   - No "." or ".." segments
//   - No backslash characters (prevents Windows path ambiguity)
//   - No null bytes
//   - Must not be empty
//
// Invalid paths are rejected with an error, never silently rewritten. This
// design prevents tar-slip, zip-slip, and cross-platform path ambiguity.
//
// # Security
//
// Extraction is hardened against:
//   - Path traversal (../ in entry names)
//   - Symlink traversal: no entry, hard link source or recorded path may
//     pass through a symlink or other non-directory below the output
//     directory, and AllowOverwrite never replaces a directory, so cleanup
//     and directory times only touch what extraction created (not race-free
//     against concurrent local filesystem attackers)
//   - Archive bombs (configurable size and entry count limits, pre-checked
//     before writing)
//   - Dangerous entry types (devices, FIFOs and sockets are rejected;
//     symlinks and hard links are created only at the leaf)
//   - Duplicate entry names (rejected on both creation and extraction)
//
// # Determinism
//
// [CreateTarFromBytes] / [WriteTarFromBytes] are fully byte-deterministic:
// identical inputs always produce identical archive bytes. Entries are sorted,
// and all metadata (timestamps, uid/gid) is normalized to canonical values.
//
// [CreateTar] / [WriteTar] are path-order deterministic (sorted by archive
// path) but preserve source file metadata (ModTime, permissions) from the host
// filesystem. Two runs on the same files at different times will produce
// different archives because ModTime differs. Use the FromBytes variants when
// exact byte reproducibility is required.
//
// Both creation paths:
//   - Sort entries lexicographically by archive path
//   - Reject duplicate archive paths
//   - Use forward slashes on all platforms
//   - Use PAX tar format
//   - Normalize uid/gid to 0, uname/gname to empty
//   - Normalize mode to permission bits only (no setuid/setgid/sticky)
//
// # Limits
//
// All extraction and decompression operations accept an optional [Limits]
// struct that controls:
//   - MaxEntries:       maximum number of archive entries
//   - MaxEntrySize:     maximum size of a single entry in bytes
//   - MaxTotalSize:     maximum total uncompressed size in bytes
//
// Total size is pre-checked against the declared entry size BEFORE writing,
// so an entry that would exceed the budget is rejected without I/O.
//
// Default limits are applied when nil is passed. Use [DefaultLimits] to see
// the defaults, or provide custom limits for specific use cases.
package archive
