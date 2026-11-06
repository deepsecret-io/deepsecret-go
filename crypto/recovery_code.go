// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"strings"
)

// A recovery code is 20 random bytes (160 bits), shown once as 32
// Crockford base32 characters in 8 groups of 4: "7K2M-9QXA-...". It opens
// a security-key protected key file without the security key.
const (
	recoveryCodeBytes  = 20
	recoveryCodeChars  = 32
	recoveryGroupChars = 4
)

// recoveryEncoding is Crockford's base32 alphabet: no I, L, O or U, so a
// handwritten code reads back without guessing.
var recoveryEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// newRecoveryCode returns a fresh recovery code and its display form.
func newRecoveryCode() ([]byte, string, error) {
	code := make([]byte, recoveryCodeBytes)
	if _, err := io.ReadFull(rand.Reader, code); err != nil {
		return nil, "", err
	}
	return code, formatRecoveryCode(code), nil
}

// formatRecoveryCode renders code in groups of 4 characters joined by "-".
func formatRecoveryCode(code []byte) string {
	text := recoveryEncoding.EncodeToString(code)
	groups := make([]string, 0, len(text)/recoveryGroupChars)
	for i := 0; i < len(text); i += recoveryGroupChars {
		groups = append(groups, text[i:i+recoveryGroupChars])
	}
	return strings.Join(groups, "-")
}

// NormalizeRecoveryCode returns s as recovery code characters only: upper
// case, without spaces or hyphens, with Crockford's look-alikes read as
// the digits they stand for (I and L as 1, O as 0). It does not check
// the length; it lets a caller compare what the user typed back with a
// group of a code it showed.
func NormalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '\t', '-':
			continue
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// parseRecoveryCode reads a recovery code as the user typed it.
func parseRecoveryCode(s string) ([]byte, error) {
	text := NormalizeRecoveryCode(s)
	if len(text) != recoveryCodeChars {
		return nil, ErrWrongRecoveryCode
	}
	code, err := recoveryEncoding.DecodeString(text)
	if err != nil || len(code) != recoveryCodeBytes {
		return nil, ErrWrongRecoveryCode
	}
	return code, nil
}
