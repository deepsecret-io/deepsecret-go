// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package awskms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

const arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// recorder answers every request itself, so no request leaves the test,
// and keeps what was asked.
type recorder struct {
	reqs   []*http.Request
	bodies [][]byte
	answer func(r *http.Request, body []byte) (*http.Response, error)
}

func (rec *recorder) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	rec.reqs = append(rec.reqs, r)
	rec.bodies = append(rec.bodies, body)
	return rec.answer(r, body)
}

func jsonAnswer(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

// isolate gives the test an AWS environment of its own: static
// credentials, and every endpoint and CA override the client must ignore.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writeCA(t, caFile)
	cfgFile := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgFile, []byte("[default]\nregion = eu-west-1\nendpoint_url = https://attacker.example\nca_bundle = "+caFile+"\n\n[profile other]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"AWS_CONFIG_FILE":                        cfgFile,
		"AWS_SHARED_CREDENTIALS_FILE":            filepath.Join(dir, "credentials"),
		"AWS_ACCESS_KEY_ID":                      "AKIDEXAMPLE",
		"AWS_SECRET_ACCESS_KEY":                  "test-secret-key",
		"AWS_SESSION_TOKEN":                      "",
		"AWS_PROFILE":                            "",
		"AWS_REGION":                             "",
		"AWS_DEFAULT_REGION":                     "",
		"AWS_ROLE_ARN":                           "",
		"AWS_WEB_IDENTITY_TOKEN_FILE":            "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI":     "",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "",
		"AWS_EC2_METADATA_DISABLED":              "true",
		"AWS_ENDPOINT_URL":                       "https://attacker.example",
		"AWS_ENDPOINT_URL_KMS":                   "https://attacker.example",
		"AWS_ENDPOINT_URL_STS":                   "https://attacker.example",
		"AWS_CA_BUNDLE":                          caFile,
		"AWS_USE_FIPS_ENDPOINT":                  "",
		"AWS_USE_DUALSTACK_ENDPOINT":             "",
	} {
		t.Setenv(k, v)
	}
}

func writeCA(t *testing.T, path string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "attacker CA"}, IsCA: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newRecorded builds a client with New and wraps the transport New built.
func newRecorded(t *testing.T, o Options, answer func(r *http.Request, body []byte) (*http.Response, error)) (*Client, *recorder) {
	t.Helper()
	c, err := New(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	// The client the KMS and STS clients send through carries the transport
	// whose TLS configuration the tests check; requests reaching the
	// recorder prove they send through this client.
	if c.http.Transport != http.RoundTripper(c.transport) {
		t.Fatal("the HTTP client does not use the transport New configured")
	}
	rec := &recorder{answer: answer}
	c.http.Transport = rec
	return c, rec
}

func decryptOK(plain []byte) func(*http.Request, []byte) (*http.Response, error) {
	return func(_ *http.Request, _ []byte) (*http.Response, error) {
		return jsonAnswer(200, map[string]any{"KeyId": arn, "Plaintext": base64.StdEncoding.EncodeToString(plain), "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}), nil
	}
}

func TestOverridesAreIgnored(t *testing.T) {
	isolate(t)
	c, rec := newRecorded(t, Options{AppID: "deepsecret-cli/1.2.3"}, decryptOK(bytes.Repeat([]byte{7}, 32)))
	// The transport New built trusts the system's roots, not AWS_CA_BUNDLE
	// or the profile's ca_bundle.
	if tc := c.transport.TLSClientConfig; tc == nil || tc.RootCAs != nil || tc.InsecureSkipVerify || tc.MinVersion < 0x0303 {
		t.Fatalf("TLS config: %+v", tc)
	}
	encCtx := keystore.KMSContext(strings.Repeat("a", 64), "0123456789abcdef", "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f")
	res, err := c.Decrypt(context.Background(), arn, encCtx, []byte("blob"))
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyARN != arn || len(res.Data) != 32 {
		t.Errorf("result: %+v", res)
	}
	r := rec.reqs[0]
	if r.URL.Scheme != "https" || r.URL.Host != "kms.eu-west-1.amazonaws.com" {
		t.Errorf("request went to %s", r.URL)
	}
	if got := r.Header.Get("X-Amz-Target"); got != "TrentService.Decrypt" {
		t.Errorf("target %q", got)
	}
	// The SDK writes the app id's "/" as "-".
	if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, "app/deepsecret-cli-1.2.3") {
		t.Errorf("user agent %q", ua)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.bodies[0], &body)
	if body["KeyId"] != arn || body["EncryptionAlgorithm"] != "SYMMETRIC_DEFAULT" {
		t.Errorf("body: %v", body)
	}
	gotCtx, _ := body["EncryptionContext"].(map[string]any)
	if len(gotCtx) != 4 || gotCtx["deepsecret:purpose"] != "keystore/v6/aws_kms" {
		t.Errorf("context: %v", gotCtx)
	}
	k, _ := c.client("eu-west-1")
	if o := k.Options(); o.ClientLogMode != 0 {
		t.Errorf("log mode %v", o.ClientLogMode)
	}

	// STS for the caller's identity is pinned the same way.
	rec.answer = func(_ *http.Request, _ []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(
			`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/ci/run` + "\u202e\t" + `</Arn><UserId>X</UserId><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))}, nil
	}
	caller, err := c.CallerARN(context.Background(), "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if caller != "arn:aws:sts::111122223333:assumed-role/ci/run" {
		t.Errorf("caller %q: control characters must go", caller)
	}
	if h := rec.reqs[len(rec.reqs)-1].URL.Host; h != "sts.eu-west-1.amazonaws.com" {
		t.Errorf("STS went to %s", h)
	}
}

func TestFIPSEndpointAndPartitions(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	c, rec := newRecorded(t, Options{}, decryptOK(make([]byte, 32)))
	if _, err := c.Decrypt(context.Background(), arn, nil, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if h := rec.reqs[0].URL.Host; h != "kms-fips.eu-west-1.amazonaws.com" {
		t.Errorf("FIPS host %s", h)
	}
	for region, want := range map[string]string{
		"cn-north-1":    "https://kms.cn-north-1.amazonaws.com.cn",
		"us-gov-west-1": "https://kms.us-gov-west-1.amazonaws.com",
		"eu-central-2":  "https://kms.eu-central-2.amazonaws.com",
	} {
		if got := endpoint(region, false); got != want {
			t.Errorf("%s: %s", region, got)
		}
	}
	for _, bad := range []string{"", "eu-west", "x", "eu-west-1.evil.com", "EU-west-1", "eu-west-1/", "eu--1"} {
		if validRegion(bad) {
			t.Errorf("region %q accepted", bad)
		}
	}
}

func TestOnlyKeyARNsAreCalled(t *testing.T) {
	isolate(t)
	c, rec := newRecorded(t, Options{}, decryptOK(make([]byte, 32)))
	for _, bad := range []string{"alias/ci", "arn:aws:kms:eu-west-1:111122223333:alias/ci", "1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:attacker.example/x:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"} {
		if _, err := c.Decrypt(context.Background(), bad, nil, []byte("x")); !errors.Is(err, keystore.ErrKMSKeyRejected) {
			t.Errorf("%q: %v", bad, err)
		}
		if _, err := c.Encrypt(context.Background(), bad, nil, []byte("x")); !errors.Is(err, keystore.ErrKMSKeyRejected) {
			t.Errorf("%q: %v", bad, err)
		}
		if _, err := c.DescribeKey(context.Background(), bad); !errors.Is(err, keystore.ErrKMSNotKeyARN) {
			t.Errorf("DescribeKey %q: %v", bad, err)
		}
	}
	if len(rec.reqs) != 0 {
		t.Errorf("%d requests sent", len(rec.reqs))
	}
}

func TestDescribeKeyGoesToTheKeysRegion(t *testing.T) {
	isolate(t)
	usARN := "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	c, rec := newRecorded(t, Options{}, func(_ *http.Request, _ []byte) (*http.Response, error) {
		return jsonAnswer(200, map[string]any{"KeyMetadata": map[string]any{
			"Arn": usARN, "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
			"KeyState": "Enabled", "KeyManager": "CUSTOMER", "Description": "ci\x1b]0;title\x07 key",
		}}), nil
	})
	key, err := c.DescribeKey(context.Background(), usARN)
	if err != nil {
		t.Fatal(err)
	}
	if key.ARN != usARN || key.Spec != "SYMMETRIC_DEFAULT" || key.Manager != "CUSTOMER" || key.Description != "ci]0;title key" {
		t.Errorf("key: %+v", key)
	}
	if h := rec.reqs[0].URL.Host; h != "kms.us-east-1.amazonaws.com" {
		t.Errorf("DescribeKey went to %s", h)
	}
}

func TestErrorsMap(t *testing.T) {
	isolate(t)
	cases := map[string]error{
		"AccessDeniedException":       keystore.ErrKMSAccessDenied,
		"UnrecognizedClientException": keystore.ErrKMSCredentialsRejected,
		"ExpiredTokenException":       keystore.ErrKMSCredentialsRejected,
		"InvalidSignatureException":   keystore.ErrKMSCredentialsRejected,
		"DisabledException":           keystore.ErrKMSKeyUnavailable,
		"KMSInvalidStateException":    keystore.ErrKMSKeyUnavailable,
		"NotFoundException":           keystore.ErrKMSKeyUnavailable,
		"KeyUnavailableException":     keystore.ErrKMSKeyUnavailable,
		"InvalidCiphertextException":  keystore.ErrKMSMismatch,
		"IncorrectKeyException":       keystore.ErrKMSMismatch,
		"InvalidKeyUsageException":    keystore.ErrKMSKeyRejected,
		"LimitExceededException":      keystore.ErrKMSUnreachable,
	}
	for code, want := range cases {
		c, _ := newRecorded(t, Options{}, func(_ *http.Request, _ []byte) (*http.Response, error) {
			return jsonAnswer(400, map[string]any{"__type": code, "message": "User: arn:aws:sts::1:assumed-role/x/y is not authorized\x1b[2J"}), nil
		})
		_, err := c.Decrypt(context.Background(), arn, nil, []byte("x"))
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", code, err, want)
		}
		// Rejected credentials are not a refused permission, and the other
		// way round: each gets its own hint.
		if want == keystore.ErrKMSCredentialsRejected && errors.Is(err, keystore.ErrKMSAccessDenied) ||
			want == keystore.ErrKMSAccessDenied && errors.Is(err, keystore.ErrKMSCredentialsRejected) {
			t.Errorf("%s: %v matches both", code, err)
		}
		if err != nil && strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("%s: the message keeps a control character", code)
		}
	}
	// A transport failure is an outage.
	c, _ := newRecorded(t, Options{}, func(_ *http.Request, _ []byte) (*http.Response, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.Decrypt(ctx, arn, nil, []byte("x")); !errors.Is(err, keystore.ErrKMSUnreachable) {
		t.Errorf("transport failure: %v", err)
	}
	// A cancelled unlock is a cancellation, not an outage, so no other key
	// is tried.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := c.Decrypt(ctx, arn, nil, []byte("x")); !errors.Is(err, context.Canceled) || errors.Is(err, keystore.ErrKMSUnreachable) {
		t.Errorf("cancelled: %v", err)
	}
	// A wrong algorithm in the answer is refused.
	c, _ = newRecorded(t, Options{}, func(_ *http.Request, _ []byte) (*http.Response, error) {
		return jsonAnswer(200, map[string]any{"KeyId": arn, "Plaintext": "AAAA", "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"}), nil
	})
	if _, err := c.Decrypt(context.Background(), arn, nil, []byte("x")); !errors.Is(err, keystore.ErrKMSMismatch) {
		t.Errorf("algorithm: %v", err)
	}
}

func TestNoCredentials(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	c, rec := newRecorded(t, Options{}, decryptOK(nil))
	if _, err := c.Decrypt(context.Background(), arn, nil, []byte("x")); !errors.Is(err, keystore.ErrKMSNoCredentials) {
		t.Errorf("%v", err)
	}
	if len(rec.reqs) != 0 {
		t.Errorf("%d KMS requests without credentials", len(rec.reqs))
	}
	if _, err := New(context.Background(), Options{Profile: "missing"}); !errors.Is(err, keystore.ErrKMSNoCredentials) {
		t.Errorf("missing profile: %v", err)
	}
	if _, err := New(context.Background(), Options{AppID: "bad id\n"}); err == nil {
		t.Error("app id with a newline accepted")
	}
}

// The real KMS behaviour lives in the kmsaws test; this pins only that
// aws.Config was loaded with the profile asked for.
func TestProfile(t *testing.T) {
	isolate(t)
	c, err := New(context.Background(), Options{Profile: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if c.region != "us-east-1" {
		t.Errorf("region %q", c.region)
	}
	_ = aws.String
}
