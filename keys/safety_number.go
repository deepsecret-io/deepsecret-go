// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keys

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/internal/canon"
)

// ── Safety numbers ──────────────────────────────────────────────────────────
//
// A safety number is a key fingerprint as decimal digits, for two people to
// read to each other and compare (PROTOCOL_V4.md §11). A key's number
// is 30 digits; the number of two keys is both of theirs, the smaller one
// first, so each of the two people sees the same 60 digits.

// safetyNumberDomain separates safety number hashes from every other use
// of SHA-512.
const safetyNumberDomain = "DeepSecret safety number v1"

// safetyNumberIterations is how many SHA-512 hashes make a key's number,
// as Signal does, so finding a key whose number matches another's costs
// that many hashes per try.
const safetyNumberIterations = 5200

// SafetyNumberLen is the length of one key's safety number in digits.
const SafetyNumberLen = 30

// ErrSafetyNumberInput refuses a fingerprint a safety number cannot be
// made from: anything but 64 lower-case hex characters.
var ErrSafetyNumberInput = errors.New("a safety number needs a full key fingerprint: 64 lower-case hex characters")

// SafetyNumber is the 30-digit safety number of one key, from its full
// fingerprint (Fingerprint). Upper-case hex is refused: fingerprints are
// lower case everywhere, so a caller that has another form lowers it
// first.
//
//	h = SHA-512("DeepSecret safety number v1" || 0x00 || fp32)
//	5199 times: h = SHA-512(h || fp32)
//	six 5-byte big-endian integers from h[0:30], each mod 100000, as 5 digits
func SafetyNumber(fingerprint string) (string, error) {
	if !canon.IsFingerprint(fingerprint) {
		return "", ErrSafetyNumberInput
	}
	fp, err := hex.DecodeString(fingerprint)
	if err != nil {
		return "", ErrSafetyNumberInput
	}

	h := sha512.New()
	h.Write([]byte(safetyNumberDomain))
	h.Write([]byte{0})
	h.Write(fp)
	sum := h.Sum(nil)
	for i := 1; i < safetyNumberIterations; i++ {
		h.Reset()
		h.Write(sum)
		h.Write(fp)
		sum = h.Sum(sum[:0])
	}

	var b strings.Builder
	b.Grow(SafetyNumberLen)
	var chunk [8]byte
	for i := 0; i < SafetyNumberLen/5; i++ {
		copy(chunk[3:], sum[i*5:i*5+5])
		fmt.Fprintf(&b, "%05d", binary.BigEndian.Uint64(chunk[:])%100000)
	}
	return b.String(), nil
}

// PairSafetyNumber is the 60-digit safety number of two keys, from their
// full fingerprints: both keys' numbers, the smaller one first. Both people
// get the same number, whichever key is theirs. The two keys may be the
// same.
func PairSafetyNumber(a, b string) (string, error) {
	na, err := SafetyNumber(a)
	if err != nil {
		return "", err
	}
	nb, err := SafetyNumber(b)
	if err != nil {
		return "", err
	}
	if nb < na {
		na, nb = nb, na
	}
	return na + nb, nil
}

// GroupDigits splits a safety number into groups of five digits joined by
// spaces, as it is shown and read aloud.
func GroupDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 5 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+5, len(s))])
	}
	return b.String()
}
