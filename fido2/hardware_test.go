// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build fido2hw

package fido2

// A test on a real security key. It needs one FIDO2 key with a PIN
// connected, and five touches (two to enroll, one for each of three
// unlocks); it creates a non-discoverable credential, which uses no storage
// on the key. A wrong PIN stops the test after one try.
//
//	DEEPSECRET_TEST_PIN=123456 go test -tags fido2hw -run TestHardware -v ./fido2/

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

type envPrompt struct {
	t *testing.T
}

// PIN gives the PIN from the environment, and refuses to give it again
// once the security key said it is wrong, so a wrong DEEPSECRET_TEST_PIN
// costs one retry, not three.
func (p *envPrompt) PIN(_ context.Context, _ string, retries int, wrong bool) ([]byte, error) {
	if wrong {
		return nil, fmt.Errorf("wrong DEEPSECRET_TEST_PIN, %d retries left", retries)
	}
	return []byte(os.Getenv("DEEPSECRET_TEST_PIN")), nil
}
func (p *envPrompt) Touch(device, reason string) { p.t.Logf("touch %s %s", device, reason) }
func (p *envPrompt) TouchDone()                  {}
func (p *envPrompt) Insert(want string)          { p.t.Logf("plug in %s", want) }

func TestHardwareEnrollAndDerive(t *testing.T) {
	if os.Getenv("DEEPSECRET_TEST_PIN") == "" {
		t.Skip("set DEEPSECRET_TEST_PIN to the security key's PIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	a := New(&envPrompt{t: t})
	input := make([]byte, 32)
	userID := make([]byte, 16)
	_, _ = rand.Read(input)
	_, _ = rand.Read(userID)
	enrolled, err := a.Enroll(ctx, keystore.EnrollRequest{
		RPID: keystore.SecurityKeyRPID, UserID: userID, UserName: "deepsecret-test", DisplayName: "DeepSecret test", PRFInput: input,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("enrolled on %s, credential %d bytes, aaguid %x", enrolled.Device, len(enrolled.CredentialID), enrolled.AAGUID)
	req := keystore.DeriveRequest{
		RPID:        keystore.SecurityKeyRPID,
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Credentials: []keystore.DeriveCredential{{ID: enrolled.CredentialID, PRFInput: input, Label: "test"}},
	}
	for i := 0; i < 2; i++ {
		got, err := a.Derive(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Output, enrolled.Output) {
			t.Fatalf("derive %d gave a different output from enrollment", i+1)
		}
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	req.Credentials[0].PRFInput = other
	got, err := a.Derive(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.Output, enrolled.Output) {
		t.Fatal("a different PRF input gave the same output")
	}
}
