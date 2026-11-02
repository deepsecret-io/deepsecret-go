// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"errors"
	"strings"
	"testing"
)

// The safety number vectors (sdk/PROTOCOL_V4.md §11), reproduced
// independently in Python with hashlib. Every client computes the same
// digits from the same fingerprint.
var safetyNumberVectors = []struct{ fingerprint, number string }{
	{strings.Repeat("0", 64), "224986806177197315331983184070"},
	{strings.Repeat("f", 64), "164093753234229265496299669170"},
	// SHA-256("DeepSecret safety number test vector")
	{"f282d3c8021155ac8b7f96fa35d1b84959855c84aa64690049664a206c8837fa", "131325027556127308613184997296"},
}

func TestSafetyNumberVectors(t *testing.T) {
	for _, v := range safetyNumberVectors {
		got, err := SafetyNumber(v.fingerprint)
		if err != nil {
			t.Fatalf("%s: %v", v.fingerprint, err)
		}
		if got != v.number {
			t.Errorf("SafetyNumber(%s) = %s, want %s", v.fingerprint, got, v.number)
		}
	}
}

// Both people see the same 60 digits: the smaller key number first,
// whichever key is theirs.
func TestPairSafetyNumber(t *testing.T) {
	zero, ff := strings.Repeat("0", 64), strings.Repeat("f", 64)
	want := "164093753234229265496299669170" + "224986806177197315331983184070"
	ab, err := PairSafetyNumber(zero, ff)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := PairSafetyNumber(ff, zero)
	if err != nil {
		t.Fatal(err)
	}
	if ab != want || ba != want {
		t.Errorf("pair = %s and %s, want %s both ways", ab, ba, want)
	}

	// The same key twice is allowed: its number twice.
	same, err := PairSafetyNumber(zero, zero)
	if err != nil || same != strings.Repeat("224986806177197315331983184070", 2) {
		t.Errorf("same key twice = %q, %v", same, err)
	}
}

// Numbers are digits only, 30 for a key and 60 for a pair, for any key.
func TestSafetyNumberShape(t *testing.T) {
	for i := 0; i < 3; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		fp, err := Fingerprint(kp)
		if err != nil {
			t.Fatal(err)
		}
		one, err := SafetyNumber(fp)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := PairSafetyNumber(fp, safetyNumberVectors[2].fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if len(one) != SafetyNumberLen || len(pair) != 2*SafetyNumberLen {
			t.Errorf("lengths %d and %d", len(one), len(pair))
		}
		if strings.Trim(one+pair, "0123456789") != "" {
			t.Errorf("not digits only: %s, %s", one, pair)
		}
		if !strings.Contains(pair, one) {
			t.Errorf("the pair %s does not hold the key's number %s", pair, one)
		}
	}
}

// Only a full lower-case fingerprint makes a number. Upper case is
// refused, not lowered: a fingerprint is lower case everywhere.
func TestSafetyNumberRefusesInput(t *testing.T) {
	valid := safetyNumberVectors[2].fingerprint
	for name, in := range map[string]string{
		"empty":      "",
		"short":      valid[:63],
		"prefix":     valid[:16],
		"long":       valid + "0",
		"upper case": strings.ToUpper(valid),
		"non-hex":    "g" + valid[1:],
		"spaces":     " " + valid[1:],
		"grouped":    GroupDigits(valid),
	} {
		if n, err := SafetyNumber(in); !errors.Is(err, ErrSafetyNumberInput) || n != "" {
			t.Errorf("%s: got %q, %v", name, n, err)
		}
		if n, err := PairSafetyNumber(valid, in); !errors.Is(err, ErrSafetyNumberInput) || n != "" {
			t.Errorf("%s as the second key: got %q, %v", name, n, err)
		}
		if n, err := PairSafetyNumber(in, valid); !errors.Is(err, ErrSafetyNumberInput) || n != "" {
			t.Errorf("%s as the first key: got %q, %v", name, n, err)
		}
	}
}

func TestGroupDigits(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"12345":                          "12345",
		"1234567":                        "12345 67",
		"224986806177197315331983184070": "22498 68061 77197 31533 19831 84070",
	}
	for in, want := range cases {
		if got := GroupDigits(in); got != want {
			t.Errorf("GroupDigits(%q) = %q, want %q", in, got, want)
		}
	}
}
