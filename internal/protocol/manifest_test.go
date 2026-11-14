// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package protocol

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// sealedManifest is the serialized manifest of a small sealed message.
func sealedManifest(t *testing.T) []byte {
	t.Helper()
	sender, alice := newParty(t), newParty(t)
	_, sealed := seal(t, []byte("payload"), sender, msgParams, alice)
	return sealed.ManifestData
}

// withSizes is the manifest in data with its two sizes replaced. The
// signatures no longer cover it, which UnmarshalManifest does not check.
func withSizes(t *testing.T, data []byte, plaintextSize, ciphertextSize int64) []byte {
	t.Helper()
	m, err := UnmarshalManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	m.PlaintextSize, m.CiphertextSize = plaintextSize, ciphertextSize
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A manifest's sizes must be ones a payload can have: every chunk of up to
// 1 MiB adds a 16-byte tag, and an empty payload is one empty chunk.
func TestManifestAcceptsRealSizes(t *testing.T) {
	data := sealedManifest(t)
	cases := map[string]struct{ plaintext, ciphertext int64 }{
		"empty payload":             {0, 16},
		"one byte":                  {1, 17},
		"exactly one chunk":         {ChunkSize, ChunkSize + 16},
		"one byte over a chunk":     {ChunkSize + 1, ChunkSize + 1 + 2*16},
		"a multiple of the chunk":   {3 * ChunkSize, 3*ChunkSize + 3*16},
		"one byte over a multiple":  {3*ChunkSize + 1, 3*ChunkSize + 1 + 4*16},
		"500 GiB":                   {500 << 30, 500<<30 + 512000*16},
		"near the end of the range": {math.MaxInt64 - 1<<47, math.MaxInt64 - 1<<31},
	}
	for name, c := range cases {
		m, err := UnmarshalManifest(withSizes(t, data, c.plaintext, c.ciphertext))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if m.PlaintextSize != c.plaintext || m.CiphertextSize != c.ciphertext {
			t.Errorf("%s: sizes %d and %d", name, m.PlaintextSize, m.CiphertextSize)
		}
	}
}

// Sizes no payload can have are refused, and that includes a plaintext size
// so large that adding the tags wraps around an int64: the negative
// ciphertext size it wraps to would otherwise pass as the matching one and
// reach the caller that allocates by it.
func TestManifestRefusesImpossibleSizes(t *testing.T) {
	data := sealedManifest(t)
	cases := map[string]struct{ plaintext, ciphertext int64 }{
		"largest int64, wrapped ciphertext size":  {math.MaxInt64, math.MinInt64 + 1<<47 - 1},
		"overflowing size, wrapped ciphertext":    {math.MaxInt64 - 1<<46, math.MinInt64 + 1<<46 - 1<<30 - 1},
		"largest int64, largest ciphertext size":  {math.MaxInt64, math.MaxInt64},
		"negative plaintext size":                 {-1, 15},
		"most negative plaintext size":            {math.MinInt64, 16},
		"empty payload with no tag":               {0, 0},
		"ciphertext smaller than one tag":         {0, 15},
		"negative ciphertext size":                {0, -16},
		"one chunk with no tag":                   {ChunkSize, ChunkSize},
		"one tag short":                           {ChunkSize + 1, ChunkSize + 1 + 16},
		"one tag too many":                        {ChunkSize, ChunkSize + 2*16},
		"ciphertext smaller than the plaintext":   {ChunkSize, 16},
		"sizes of another payload, one byte less": {1, 16},
	}
	for name, c := range cases {
		_, err := UnmarshalManifest(withSizes(t, data, c.plaintext, c.ciphertext))
		if err == nil || !strings.Contains(err.Error(), "does not fit plaintext size") {
			t.Errorf("%s: plaintext %d, ciphertext %d: got %v, want a size error", name, c.plaintext, c.ciphertext, err)
		}
	}
}

// withPair is the manifest in data with one more key and value after its
// own: a map canonical CBOR never writes. The key must be shorter than 24
// bytes and value is CBOR.
func withPair(t *testing.T, data []byte, key string, value []byte) []byte {
	t.Helper()
	// A manifest is a map of 20 pairs, a count that fits in the first byte.
	if data[0] != 0xa0|20 {
		t.Fatalf("the manifest starts with %#x, not a map of 20 pairs", data[0])
	}
	out := append([]byte{0xa0 | 21}, data[1:]...)
	out = append(out, 0x60|byte(len(key)))
	out = append(out, key...)
	return append(out, value...)
}

func errorAs[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// A manifest is read strictly: the signatures cover the decoded fields, not
// the bytes, so bytes that say the same thing another way, or that another
// parser could read differently, are refused.
func TestUnmarshalManifestRefusesLooseCBOR(t *testing.T) {
	data := sealedManifest(t)
	if _, err := UnmarshalManifest(data); err != nil {
		t.Fatalf("the manifest as sealed: %v", err)
	}
	if bytes.Count(data, []byte("\x67version")) != 1 {
		t.Fatal("the manifest does not hold the version key once")
	}

	cases := map[string]struct {
		data    []byte
		refused func(error) bool
	}{
		"secret name twice":         {withPair(t, data, "secret_name", []byte("\x69api-token")), errorAs[*cbor.DupMapKeyError]},
		"version twice, same value": {withPair(t, data, "version", []byte("\x614")), errorAs[*cbor.DupMapKeyError]},
		"unknown field":             {withPair(t, data, "extra", []byte{0x01}), errorAs[*cbor.UnknownFieldError]},
		"key in another case":       {bytes.Replace(data, []byte("\x67version"), []byte("\x67Version"), 1), errorAs[*cbor.UnknownFieldError]},
		"map of indefinite length":  {append(append([]byte{0xbf}, data[1:]...), 0xff), errorAs[*cbor.IndefiniteLengthError]},
		"data after the manifest":   {append(bytes.Clone(data), 0x00), errorAs[*cbor.ExtraneousDataError]},
		"more keys than a manifest": {append([]byte{0xb8, 33}, data[1:]...), errorAs[*cbor.MaxMapPairsError]},
		"more recipients than 1000": {withPair(t, data, "more", []byte{0x99, 0x03, 0xe9}), errorAs[*cbor.MaxArrayElementsError]},
		"nested past a recipient":   {withPair(t, data, "deep", []byte{0x81, 0x81, 0x81, 0x81, 0x01}), errorAs[*cbor.MaxNestedLevelError]},
	}
	for name, c := range cases {
		if _, err := UnmarshalManifest(c.data); err == nil || !c.refused(err) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
