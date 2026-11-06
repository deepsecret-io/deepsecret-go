// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package payload defines the plaintext payload types for encrypted secrets.
//
// These types are serialized with CBOR (RFC 8949) inside the encrypted payload.
// Canonical CBOR encoding is used for deterministic output.
package payload

import (
	"fmt"
	"os"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// cborEnc is a canonical CBOR encoder for deterministic serialization.
// Initialized lazily on first use via encoder().
var cborEnc cbor.EncMode
var cborEncErr error
var cborEncOnce sync.Once

func encoder() (cbor.EncMode, error) {
	cborEncOnce.Do(func() {
		cborEnc, cborEncErr = cbor.CanonicalEncOptions().EncMode()
	})
	return cborEnc, cborEncErr
}

// Marshal encodes v to canonical CBOR bytes.
func Marshal(v any) ([]byte, error) {
	enc, err := encoder()
	if err != nil {
		return nil, fmt.Errorf("cbor encoder init: %w", err)
	}
	return enc.Marshal(v)
}

// Unmarshal decodes CBOR bytes into v.
func Unmarshal(data []byte, v any) error {
	return cbor.Unmarshal(data, v)
}

// Payload is the CBOR-encoded plaintext structure inside an encrypted secret.
type Payload struct {
	Type    string         `cbor:"type"`
	Files   []FileEntry    `cbor:"files,omitempty"`
	Entries []KeyValuePair `cbor:"entries,omitempty"`
	Message string         `cbor:"message,omitempty"`

	// Archive indicates this payload contains a single tar archive file
	// that should be auto-extracted on decrypt. The ArchiveCompression
	// field indicates how the tar is compressed ("zstd" or "").
	Archive            bool   `cbor:"archive,omitempty"`
	ArchiveCompression string `cbor:"archive_compression,omitempty"`
}

// FileEntry is a file within an encrypted payload.
type FileEntry struct {
	Name   string      `cbor:"name"`
	Data   []byte      `cbor:"data"`
	Size   int64       `cbor:"size"`
	SHA256 string      `cbor:"sha256"`
	Mode   os.FileMode `cbor:"mode"`
}

// KeyValuePair is a key-value entry within an encrypted payload.
type KeyValuePair struct {
	Key   string `cbor:"key"`
	Value string `cbor:"value"`
}
