// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package knownkeys

import (
	"strings"
	"testing"
)

// Emails from a file are looked up and printed, so they may not hold path
// characters, controls (C0 or C1, such as an ANSI escape), formatting marks
// such as a right-to-left override, or letters from other scripts that
// pass for another address.
func TestPlausibleEmail(t *testing.T) {
	for _, s := range []string{"alice@example.com", "o'brien+x@example.co.uk"} {
		if !PlausibleEmail(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{
		"", "alice", "@example.com", "alice@", "a b@example.com", "a/b@example.com", "../x@y",
		"a\x1b[31m@example.com", "a\u009b31m@example.com", "a\u202e@example.com", "a\x00@example.com",
		"bad\xff@example.com", strings.Repeat("a", 250) + "@example.com",
		"ünï@exämple.com", "\u0430lice@example.com", "a\u00a0b@example.com",
	} {
		if PlausibleEmail(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
