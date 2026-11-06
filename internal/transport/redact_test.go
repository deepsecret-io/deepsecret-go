// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A presigned URL's signature never reaches an error: a transport failure
// names the storage host only.
func TestPresignedURLsStayOutOfErrors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	signed := srv.URL + "/bucket/rev-1?X-Amz-Credential=AKIAEXAMPLE%2F20261026&X-Amz-Signature=deadbeefcafe"
	srv.Close() // every request now fails in transport

	c, err := NewClient("http://127.0.0.1:1", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", signed, nil)
	_, err = c.doPresigned(req)
	if err == nil {
		t.Fatal("request to a closed server succeeded")
	}
	for _, leak := range []string{"X-Amz-Signature", "deadbeefcafe", "AKIAEXAMPLE", "/bucket/rev-1"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaks %q", err, leak)
		}
	}
	if !strings.Contains(err.Error(), strings.TrimPrefix(srv.URL, "http://")) {
		t.Errorf("error %q does not name the host", err)
	}

	for raw, want := range map[string]string{
		"https://acct.r2.cloudflarestorage.com/b/k?X-Amz-Signature=s": "https://acct.r2.cloudflarestorage.com",
		"https://user:pass@host.example/b?sig=1#frag":                 "https://host.example",
		"not a url %%":         "(storage URL)",
		"/relative/path?sig=1": "(storage URL)",
	} {
		if got := redactURL(raw); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A storage error body can echo the access key and the signature; only
// its error code is kept.
func TestStorageErrorBodiesAreReducedToTheirCode(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><Error><Code>SignatureDoesNotMatch</Code><Message>The request signature we calculated does not match</Message><AWSAccessKeyId>AKIAEXAMPLEKEY</AWSAccessKeyId><SignatureProvided>deadbeefcafe</SignatureProvided><StringToSign>AWS4-HMAC-SHA256...</StringToSign></Error>`)
	got := storageFailure("upload failed", 403, body)
	if got != "upload failed (status 403, SignatureDoesNotMatch)" {
		t.Errorf("storageFailure = %q", got)
	}
	se := &storageError{status: 400, code: storageErrorCode(body)}
	for _, leak := range []string{"AKIAEXAMPLEKEY", "deadbeefcafe", "StringToSign"} {
		if strings.Contains(got, leak) || strings.Contains(se.Error(), leak) {
			t.Errorf("error leaks %q", leak)
		}
	}
	for _, b := range []string{"", "plain text", "<Code>\x1b[31mevil</Code>", "<Code>" + strings.Repeat("A", 80) + "</Code>"} {
		if code := storageErrorCode([]byte(b)); code != "" {
			t.Errorf("storageErrorCode(%q) = %q, want none", b, code)
		}
	}
	if got := printableExcerpt([]byte("bad\x1b]0;title\x07gateway"), 10); got != "bad?]0;tit" {
		t.Errorf("printableExcerpt = %q", got)
	}
}
