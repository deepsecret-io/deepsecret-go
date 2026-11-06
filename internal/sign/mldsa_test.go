// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sign

import "testing"

func TestMLDSA65SignAndVerify(t *testing.T) {
	pub, seed, err := GenerateMLDSA65Key()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1952 || len(seed) != 32 {
		t.Fatalf("sizes: pub %d, seed %d", len(pub), len(seed))
	}
	msg := []byte("message")
	sig, err := SignMLDSA65(seed, msg)
	if err != nil || len(sig) != 3309 {
		t.Fatalf("sign: %d bytes, %v", len(sig), err)
	}
	if !VerifyMLDSA65(pub, msg, sig) {
		t.Error("a good signature failed")
	}
	if VerifyMLDSA65(pub, []byte("other"), sig) {
		t.Error("a signature passed for another message")
	}
}
