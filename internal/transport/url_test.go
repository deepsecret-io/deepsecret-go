// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The API URL is parsed once and held to one rule, whatever its letter
// case: https, or plaintext HTTP for a loopback host or one on the
// allowlist. "HTTP://host" used to pass a prefix test for "http://" and
// send the credential in clear.
func TestBaseURLRules(t *testing.T) {
	t.Setenv("DEEPSECRET_INSECURE_HOSTS", "")
	for _, tc := range []struct {
		url, base string
		plain     bool
	}{
		{"https://api.example.com", "https://api.example.com", false},
		{"https://api.example.com/", "https://api.example.com", false},
		{"HTTPS://api.example.com/base//", "https://api.example.com/base", false},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"HTTP://LOCALHOST:8080/", "http://LOCALHOST:8080", true},
		{"http://[::1]:8080", "http://[::1]:8080", true},
	} {
		base, plain, err := parseBaseURL(tc.url)
		if err != nil || base != tc.base || plain != tc.plain {
			t.Errorf("parseBaseURL(%q) = %q, %v, %v; want %q, %v", tc.url, base, plain, err, tc.base, tc.plain)
		}
	}
	for _, refused := range []string{
		"http://api.example.com",
		"HTTP://api.example.com",
		"Http://api.example.com:8080/",
		"hTTp://localhost.example.com",
		"https://user:hunter2@api.example.com",
		"https://user@api.example.com",
		"https://api.example.com?token=hunter2",
		"https://api.example.com/?",
		"https://api.example.com/#hunter2",
		"https://api.example.com/#",
		"ftp://api.example.com",
		"ws://127.0.0.1",
		"api.example.com",
		"https://",
		"https://:443",
		"http:127.0.0.1",
		"",
	} {
		if err := ValidateTransportSecurity(refused); err == nil {
			t.Errorf("ValidateTransportSecurity(%q) passed", refused)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error for %q quotes what the URL held: %v", refused, err)
		}
		if c, err := NewClient(refused, "test-key"); err == nil {
			t.Errorf("NewClient(%q) = a client on %q, want it refused", refused, c.BaseURL())
		}
	}

	// The allowlist names exact hosts, compared without case.
	t.Setenv("DEEPSECRET_INSECURE_HOSTS", "vpn.internal, 10.0.0.5")
	if base, plain, err := parseBaseURL("HTTP://VPN.internal:8080/"); err != nil || base != "http://VPN.internal:8080" || !plain {
		t.Errorf("a host on the allowlist: %q, %v, %v", base, plain, err)
	}
	if err := ValidateTransportSecurity("HTTP://other.internal"); err == nil {
		t.Error("a host off the allowlist passed in upper case")
	}
}

// A presigned URL comes from the server, which is not trusted with content:
// against an https API it must be https and hold no user info, and the
// refusal never quotes it.
func TestPresignedURLRules(t *testing.T) {
	secure, err := NewClient("https://api.example.com", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewClient("http://127.0.0.1:1", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	const signature = "?X-Amz-Credential=AKIAEXAMPLE&X-Amz-Signature=deadbeefcafe"
	for _, tc := range []struct {
		url           string
		secure, local bool // whether each client takes it
	}{
		{"https://acct.r2.cloudflarestorage.com/b/k" + signature, true, true},
		{"HTTPS://storage.internal:9000/b/k" + signature, true, true},
		{"https://10.0.0.5/b/k" + signature, true, true}, // storage on a private network
		{"http://storage.example.com/b/k" + signature, false, true},
		{"HTTP://127.0.0.1:9000/b/k" + signature, false, true},
		{"https://user:pass@storage.example.com/b/k" + signature, false, false},
		{"http://user@127.0.0.1:9000/b/k" + signature, false, false},
		{"ftp://storage.example.com/b/k" + signature, false, false},
		{"file:///etc/passwd", false, false},
		{"//storage.example.com/b/k" + signature, false, false},
		{"/b/k" + signature, false, false},
		{"https:///b/k" + signature, false, false},
		{"not a url %%" + signature, false, false},
		{"https://storage.example.com/b/\x7fk" + signature, false, false},
		{"", false, false},
	} {
		for name, c := range map[string]*Client{"an https API": secure, "a loopback API": local} {
			want := tc.secure
			if c == local {
				want = tc.local
			}
			req, err := c.presignedRequest(context.Background(), "GET", tc.url, nil)
			switch {
			case want && (err != nil || !strings.EqualFold(req.URL.String(), tc.url)):
				t.Errorf("%s, %q: %v, want it used as it is", name, tc.url, err)
			case !want && !errors.Is(err, errPresignedURL):
				t.Errorf("%s, %q: %v, want errPresignedURL", name, tc.url, err)
			}
			if err != nil {
				for _, leak := range []string{"deadbeefcafe", "AKIAEXAMPLE", "/b/k", "pass", "storage.example.com"} {
					if strings.Contains(err.Error(), leak) {
						t.Errorf("%s, %q: the error leaks %q: %v", name, tc.url, leak, err)
					}
				}
			}
		}
	}
}

// What net/http refuses about a presigned URL is redacted like a failed
// request: an error that quotes a URL keeps its scheme and host only.
func TestURLErrorsAreRedacted(t *testing.T) {
	_, err := http.NewRequest("GET", "https://storage.example.com/b/\x7fk?X-Amz-Signature=deadbeefcafe", nil)
	if err == nil {
		t.Fatal("net/http took a URL with a control character")
	}
	got := redactURLError(err)
	if got == nil || strings.Contains(got.Error(), "deadbeefcafe") || strings.Contains(got.Error(), "/b/") {
		t.Fatalf("redactURLError = %v, want the URL cut down", got)
	}
	if redactURLError(nil) != nil {
		t.Fatal("redactURLError(nil) is not nil")
	}
	if plain := errors.New("no URL here"); redactURLError(plain) != plain {
		t.Fatal("an error without a URL was changed")
	}
}

// badStorageAPI is an https API whose every presigned URL is plaintext
// HTTP, pointing at storage that counts what reaches it.
type badStorageAPI struct {
	api, storage *httptest.Server
	reached      atomic.Int32
	asked        atomic.Int32 // presign calls
}

func newBadStorageAPI(t *testing.T) (*badStorageAPI, *Client) {
	t.Helper()
	b := &badStorageAPI{}
	b.storage = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.reached.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"etag"`)
	}))
	t.Cleanup(b.storage.Close)
	bad := b.storage.URL + "/bucket/rev-1?X-Amz-Signature=deadbeefcafe"
	b.api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		switch {
		case strings.HasSuffix(r.URL.Path, "/storage/presign"):
			b.asked.Add(1)
			data = map[string]any{"url": bad}
		case strings.HasSuffix(r.URL.Path, "/presign"):
			b.asked.Add(1)
			data = map[string]any{"url": bad, "size": 4096, "part_size": S3MinPartSize}
		case strings.HasSuffix(r.URL.Path, "/multipart/init"):
			data = map[string]any{"upload_id": "up-1", "part_size": S3MinPartSize, "max_part_number": 1, "expires_at": time.Now().Add(time.Hour)}
		case strings.HasSuffix(r.URL.Path, "/multipart/status"):
			data = map[string]any{"upload_id": "up-1", "state": "in_progress", "part_size": S3MinPartSize, "max_part_number": 1, "parts": []any{}}
		case strings.HasSuffix(r.URL.Path, "/multipart/part-urls"):
			b.asked.Add(1)
			data = map[string]any{"expires_in": 600, "parts": []any{map[string]any{"part_number": 1, "url": bad}}}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	t.Cleanup(b.api.Close)
	c, err := NewClient(b.api.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Transport.(*http.Transport).TLSClientConfig = b.api.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return b, c
}

// writerAt discards what a download writes.
type writerAt struct{}

func (writerAt) WriteAt(p []byte, _ int64) (int, error) { return len(p), nil }

// Every way a presigned URL is used checks it first: an https API that
// hands out plaintext URLs gets no request sent to them, for an upload, a
// download, or a part, and the failure is not retried or quoted.
func TestPlaintextPresignedURLsAreNeverUsed(t *testing.T) {
	unit := backoffUnit
	backoffUnit = time.Millisecond
	t.Cleanup(func() { backoffUnit = unit })
	ctx := context.Background()
	payload := bytes.Repeat([]byte("c"), 4096)

	for name, use := range map[string]func(c *Client) error{
		"single PUT": func(c *Client) error {
			return c.PresignUploadFrom(ctx, "org-1", "rev-1", bytes.NewReader(payload), int64(len(payload)), nil, 0, nil)
		},
		"download reader": func(c *Client) error {
			body, _, err := c.PresignDownloadReader(ctx, "rev-1", 0)
			if err == nil {
				_ = body.Close()
			}
			return err
		},
		"multipart upload": func(c *Client) error {
			return c.MultipartUploadOpts(ctx, "rev-1", bytes.NewReader(payload), int64(len(payload)), MultipartUploadOptions{Threads: 1})
		},
		"range download": func(c *Client) error {
			return c.DownloadToFile(ctx, "rev-1", writerAt{}, 4096, MultipartDownloadOptions{Threads: 1})
		},
	} {
		b, c := newBadStorageAPI(t)
		err := use(c)
		if !errors.Is(err, errPresignedURL) {
			t.Errorf("%s: %v, want errPresignedURL", name, err)
			continue
		}
		for _, leak := range []string{"deadbeefcafe", "/bucket/rev-1", strings.TrimPrefix(b.storage.URL, "http://")} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error leaks %q: %v", name, leak, err)
			}
		}
		if n := b.reached.Load(); n != 0 {
			t.Errorf("%s: %d requests reached the plaintext storage URL", name, n)
		}
		if n := b.asked.Load(); n != 1 {
			t.Errorf("%s: the client asked for a URL %d times, want once: a refused URL is not retried", name, n)
		}
	}
}

// Confirming a single-PUT upload is retried through a transient failure,
// as the multipart calls are: the server answers a confirm of a confirmed
// revision with success, and the payload is already in storage.
func TestConfirmUploadRetriesTransientFailures(t *testing.T) {
	unit := backoffUnit
	backoffUnit = time.Millisecond
	t.Cleanup(func() { backoffUnit = unit })

	var calls atomic.Int32
	status := http.StatusBadGateway
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) < 3 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"success":false,"error":"try again"}`)
			return
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"status":"uploaded"}}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ConfirmUpload(context.Background(), "rev-1"); err != nil {
		t.Fatalf("confirm through two 502s: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("%d confirm calls, want 3", n)
	}

	// A refusal is final: it is not sent again.
	calls.Store(0)
	status = http.StatusGone
	if err := c.ConfirmUpload(context.Background(), "rev-1"); err == nil {
		t.Fatal("a refused confirm passed")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d confirm calls after a 410, want 1", n)
	}
}
