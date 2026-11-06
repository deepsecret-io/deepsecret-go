// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package compress

import (
	"bytes"
	"io"
	"testing"
)

func TestCompressDecompressRoundtrip(t *testing.T) {
	original := []byte("hello world hello world hello world repeated data")
	for _, algo := range []Algorithm{None, Zstd} {
		t.Run(string(algo), func(t *testing.T) {
			compressed, err := Compress(original, algo)
			if err != nil {
				t.Fatal(err)
			}
			decompressed, err := Decompress(compressed, algo, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decompressed, original) {
				t.Error("roundtrip mismatch")
			}
		})
	}
}

func TestCompressUnsupported(t *testing.T) {
	_, err := Compress([]byte("data"), "lz4")
	if err == nil {
		t.Error("unsupported algorithm should return error")
	}
}

func TestDecompressMalformed(t *testing.T) {
	_, err := Decompress([]byte("not valid compressed data"), Zstd, nil)
	if err == nil {
		t.Error("malformed compressed data should return error")
	}
}

func TestDecompressSizeLimit(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 100_000)
	compressed, _ := EncodeZstd(big)

	limits := &Limits{MaxOutputSize: 1000}
	_, err := Decompress(compressed, Zstd, limits)
	if err == nil {
		t.Error("should reject decompressed data exceeding size limit")
	}
}

func TestStreamingRoundtrip(t *testing.T) {
	original := bytes.Repeat([]byte("streaming test "), 1000)

	var compressed bytes.Buffer
	w, err := NewCompressWriter(&compressed, Zstd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := NewDecompressReader(&compressed, Zstd)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decompressed, original) {
		t.Error("streaming roundtrip mismatch")
	}
}

func TestLargeCompression(t *testing.T) {
	data := make([]byte, 100_000)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	compressed, err := Compress(data, Zstd)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(data) {
		t.Errorf("expected compression: compressed=%d >= original=%d", len(compressed), len(data))
	}
	decompressed, err := Decompress(compressed, Zstd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(decompressed) != len(data) {
		t.Errorf("decompressed size = %d, want %d", len(decompressed), len(data))
	}
}
