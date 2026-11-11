// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build kmsaws

package awskms

// The real-AWS test, run by hand for each release against a real KMS key
// (its full key ARN) with AWS credentials allowed kms:DescribeKey,
// kms:Encrypt and kms:Decrypt on it:
//
//	DEEPSECRET_TEST_KMS_KEY=arn:aws:kms:<region>:<account>:key/<id> go test -tags kmsaws -run TestRealKMS -v ./awskms/
//
// It writes nothing outside a temporary directory, and every call it makes
// shows in the account's CloudTrail.

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

func TestRealKMS(t *testing.T) {
	keyID := os.Getenv("DEEPSECRET_TEST_KMS_KEY")
	if keyID == "" {
		t.Skip("DEEPSECRET_TEST_KMS_KEY is not set")
	}
	ctx := context.Background()
	c, err := New(ctx, Options{AppID: "deepsecret-go-test"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := keystore.DescribeKMSKey(ctx, c, keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("KMS key %s (%s, %s, %s)", key.ARN, key.Spec, key.State, key.Manager)
	if caller, err := c.CallerARN(ctx, keystore.KMSKeyRegion(key.ARN)); err == nil {
		t.Logf("AWS identity %s", caller)
	}

	dir := t.TempDir()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	account := uuid.NewString()
	e, err := keystore.NewKMSKeyFile(dir, kp)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := e.AddKMS(ctx, c, keyID, account, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(true); err != nil {
		t.Fatal(err)
	}
	fp := e.Fingerprint()
	e.Close()
	t.Logf("key pair %s, slot %s, account %s: look for this context in CloudTrail", fp, slot.ID, account)

	got, err := keystore.Open(ctx, dir, fp, keystore.Unlock{KMS: c})
	if err != nil {
		t.Fatal(err)
	}
	if got.ED25519Private != kp.ED25519Private || got.MLKEM768SK != kp.MLKEM768SK {
		t.Fatal("the unlocked private keys differ")
	}

	// KMS itself refuses any other encryption context.
	res, err := c.Encrypt(ctx, key.ARN, keystore.KMSContext(fp, slot.ID, account), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Decrypt(ctx, key.ARN, keystore.KMSContext(fp, slot.ID, uuid.NewString()), res.Data)
	if !errors.Is(err, keystore.ErrKMSMismatch) {
		t.Errorf("Decrypt with another account in the context: %v", err)
	}

	// Record the TLS key exchange the endpoint agrees to with this
	// client's TLS configuration.
	host := strings.TrimPrefix(endpoint(keystore.KMSKeyRegion(key.ARN), false), "https://")
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host+":443", c.transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatalf("TLS to %s: %v", host, err)
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	t.Logf("TLS to %s: version %s, key exchange %s", host, tls.VersionName(st.Version), st.CurveID)
	if st.CurveID != tls.X25519MLKEM768 {
		t.Logf("NOTE: %s did not agree to the hybrid post-quantum key exchange", host)
	}
}
