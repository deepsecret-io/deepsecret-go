// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestCanonicalEncoding(t *testing.T) {
	h := sha256.New()
	writeField(h, []byte("hello"))
	sum1 := h.Sum(nil)

	h2 := sha256.New()
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], 5)
	h2.Write(length[:])
	h2.Write([]byte("hello"))
	sum2 := h2.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Error("writeField output does not match manual construction")
	}
}

func TestCanonicalEncodingNoAmbiguity(t *testing.T) {
	h1 := sha256.New()
	writeField(h1, []byte("ab"))
	writeField(h1, []byte("cd"))
	sum1 := h1.Sum(nil)

	h2 := sha256.New()
	writeField(h2, []byte("abc"))
	writeField(h2, []byte("d"))
	sum2 := h2.Sum(nil)

	if bytes.Equal(sum1, sum2) {
		t.Error("length-prefixed encoding should prevent concatenation ambiguity")
	}
}

func TestPayloadParamsValidation(t *testing.T) {
	cases := []struct {
		name        string
		payloadType string
		compressed  bool
		compression string
		ok          bool
	}{
		{"invalid payload type", "invalid", false, "", false},
		{"invalid compression", "message", true, "lz4", false},
		{"compression without flag", "message", false, "zstd", false},
		{"flag without compression", "message", true, "", false},
		{"compressed files", "files", true, "zstd", true},
		{"minimal", "message", false, "", true},
	}
	for _, c := range cases {
		err := validatePayloadParams(c.payloadType, c.compressed, c.compression)
		if c.ok && err != nil {
			t.Errorf("%s: should pass: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: should be rejected", c.name)
		}
	}
}
