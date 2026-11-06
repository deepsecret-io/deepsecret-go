// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package canon holds the byte-level rules key files and the protocol share:
// canonical CBOR, and what counts as a fingerprint or a layout control
// character.
package canon

import (
	"fmt"
	"sync"
	"unicode"

	"github.com/fxamacker/cbor/v2"
)

// FingerprintLen is the length of a full fingerprint, as lower-case hex.
const FingerprintLen = 64

var (
	encOnce sync.Once
	enc     cbor.EncMode
	errEnc  error
)

// Marshal encodes v to canonical CBOR bytes.
func Marshal(v any) ([]byte, error) {
	encOnce.Do(func() {
		enc, errEnc = cbor.CanonicalEncOptions().EncMode()
	})
	if errEnc != nil {
		return nil, fmt.Errorf("cbor encoder init: %w", errEnc)
	}
	return enc.Marshal(v)
}

// IsLayoutControl reports whether r is a control character, a line or
// paragraph separator, or a bidi formatting character: one that can change
// how the text around it reads.
func IsLayoutControl(r rune) bool {
	switch {
	case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
		return true
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// IsFingerprint reports whether s is a full fingerprint: FingerprintLen
// lower-case hex characters.
func IsFingerprint(s string) bool {
	if len(s) != FingerprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
