// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package compress

import (
	"bytes"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Algorithm identifies a compression algorithm.
type Algorithm string

const (
	// None means no compression (pass-through).
	None Algorithm = ""

	// Zstd is Zstandard compression (recommended: fast with high ratio).
	Zstd Algorithm = "zstd"
)

// ── Streaming APIs (primary) ─────────────────────────────────────────────────

// NewCompressWriter returns a WriteCloser that compresses data written to it,
// writing compressed output to w. The caller MUST call Close to flush and
// finalize the stream.
//
// For [None], the returned writer passes through to w directly.
func NewCompressWriter(w io.Writer, algo Algorithm) (io.WriteCloser, error) {
	switch algo {
	case None:
		return nopWriteCloser{w}, nil
	case Zstd:
		return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algo)
	}
}

// BestCompressionMaxSize is the largest input [NewCompressWriterFor]
// compresses at zstd's best level. Above it, the default level keeps pace
// with a network upload: the best level runs at tens of MB/s.
const BestCompressionMaxSize = 1 << 30

// NewCompressWriterFor is [NewCompressWriter] for an input of about
// inputSize bytes: inputs up to [BestCompressionMaxSize] use the best
// compression level, larger ones the default level.
func NewCompressWriterFor(w io.Writer, algo Algorithm, inputSize int64) (io.WriteCloser, error) {
	if algo == Zstd && inputSize > BestCompressionMaxSize {
		return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
	}
	return NewCompressWriter(w, algo)
}

// CompressedSize returns how many bytes data compresses to with algo, at
// zstd's default level on one goroutine: a cheap estimate of whether
// compressing is worth it, for a sample of a larger input.
func CompressedSize(data []byte, algo Algorithm) (int64, error) {
	if algo == None {
		return int64(len(data)), nil
	}
	if algo != Zstd {
		return 0, fmt.Errorf("unsupported compression algorithm: %s", algo)
	}
	var n countingDiscard
	w, err := zstd.NewWriter(&n, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return 0, err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close() // the write error is returned; the partial output is discarded.
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}
	return int64(n), nil
}

// countingDiscard counts and discards what is written to it.
type countingDiscard int64

func (c *countingDiscard) Write(p []byte) (int, error) {
	*c += countingDiscard(len(p))
	return len(p), nil
}

// NewDecompressReader returns a ReadCloser that decompresses data from r.
// The caller MUST call Close when done reading.
//
// For [None], the returned reader passes through from r directly.
func NewDecompressReader(r io.Reader, algo Algorithm) (io.ReadCloser, error) {
	switch algo {
	case None:
		return io.NopCloser(r), nil
	case Zstd:
		// Cap the decoder's working memory and pin concurrency to one goroutine
		// so a hostile payload cannot steer the decompressor into large
		// in-memory dictionary/window allocations on a streaming read. The
		// output-size limit is enforced at a higher layer by readBounded.
		zr, err := zstd.NewReader(r,
			zstd.WithDecoderMaxMemory(256<<20),
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
		)
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algo)
	}
}

// ── Convenience APIs ([]byte, for small payloads) ────────────────────────────

// Compress compresses data using the specified algorithm.
// Returns the original data unchanged if algo is [None].
//
// This buffers the full compressed output in memory. For large data, use
// [NewCompressWriter] directly.
func Compress(data []byte, algo Algorithm) ([]byte, error) {
	if algo == None {
		return data, nil
	}
	var buf bytes.Buffer
	w, err := NewCompressWriter(&buf, algo)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close() // the write error is returned; the partial output is discarded.
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress decompresses data with bounded output size.
// Returns the original data unchanged if algo is [None].
//
// Pass nil for [DefaultLimits]. The MaxOutputSize limit prevents
// decompression bombs.
//
// This buffers the full decompressed output in memory. For large data, use
// [NewDecompressReader] directly.
func Decompress(data []byte, algo Algorithm, limits *Limits) ([]byte, error) {
	if algo == None {
		return data, nil
	}
	lim := limits.resolve()
	r, err := NewDecompressReader(bytes.NewReader(data), algo)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return readBounded(r, lim.MaxOutputSize)
}

// EncodeZstd compresses data with Zstandard.
// Convenience wrapper for Compress(data, Zstd).
func EncodeZstd(data []byte) ([]byte, error) {
	return Compress(data, Zstd)
}

// DecodeZstd decompresses Zstandard data with default size limits.
// Use [Decompress] directly if you need custom limits.
func DecodeZstd(data []byte) ([]byte, error) {
	return Decompress(data, Zstd, nil)
}

// DecodeZstdBounded decompresses Zstandard data with size limits.
// Convenience wrapper for Decompress(data, Zstd, limits).
func DecodeZstdBounded(data []byte, limits *Limits) ([]byte, error) {
	return Decompress(data, Zstd, limits)
}

// readBounded reads up to maxBytes from r.
func readBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("decompressed data exceeds size limit (%d bytes)", maxBytes)
	}
	return data, nil
}

// nopWriteCloser wraps an io.Writer with a no-op Close.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
