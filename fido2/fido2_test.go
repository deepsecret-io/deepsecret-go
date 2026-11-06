// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package fido2

import "testing"

func TestDeviceName(t *testing.T) {
	cases := map[string]string{
		"YubiKey OTP+FIDO+CCID":       "YubiKey OTP+FIDO+CCID",
		"  Key\x1b[31m red \u202e x ": "Key[31m red  x",
		"":                            "security key",
		"\x00\x07":                    "security key",
	}
	for in, want := range cases {
		if got := deviceName(in); got != want {
			t.Errorf("deviceName(%q) = %q, want %q", in, got, want)
		}
	}
	long := deviceName("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij")
	if len([]rune(long)) != 64 {
		t.Errorf("long name kept %d characters, want 64", len([]rune(long)))
	}
}
