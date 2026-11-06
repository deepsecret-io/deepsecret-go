// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package transport is the SDK's HTTP client: API requests, login session
// renewal, and presigned uploads and downloads. The sdk package makes a view of
// it for each call, with the call's context (WithContext).
package transport

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- MD5 only as S3 requires it: Content-MD5 and part ETags, transfer checksums, never a security control.
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/deepsecret-io/sdk/api"
)

// Bounds on the response bodies the client holds in memory, so a hostile or
// broken server cannot exhaust it. A body over its bound fails with
// api.ErrResponseTooLarge; it is never cut short and used.
const (
	// maxAPIResponseSize bounds an API response. The largest the API sends
	// is a secret's revision list: up to 100 revisions (the top tier's
	// MaxRevisionsPerSecret), each listing the files of a send whose
	// request the API caps at 2 MiB, with names JSON does not escape. That
	// is about 210 MiB at the very most.
	maxAPIResponseSize = 256 << 20

	// maxHealthResponseSize bounds the /health probe, a few bytes of JSON.
	maxHealthResponseSize = 64 << 10

	// maxErrorExcerpt is how much of a failed storage request's body is
	// read to quote in its error. Only the start explains the failure, so
	// the rest is not read.
	maxErrorExcerpt = 4096
)

// readBody reads resp's body, refusing one that declares or turns out to
// be longer than limit bytes.
func readBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", api.ErrResponseTooLarge, resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: over %d bytes", api.ErrResponseTooLarge, limit)
	}
	return b, nil
}

// Response is the backend's JSON response envelope.
type Response struct {
	Success     bool            `json:"success"`
	Data        json.RawMessage `json:"data,omitempty"`
	Error       string          `json:"error,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Maintenance bool            `json:"maintenance,omitempty"`
}

// Client manages authentication and HTTP communication with the DeepSecret API.
type Client struct {
	*core

	// ctx ends this view's requests, including object-storage uploads and
	// downloads, so a cancelled call unblocks instead of waiting for the
	// per-call timeout. See WithContext.
	ctx context.Context
}

// core is what every view of a client shares: its connections and its login
// session.
type core struct {
	baseURL    string
	httpClient *http.Client

	// apiKey is the credential: an API key, or "bearer:" and a session
	// token, which the client renews while in use (session.go). Guarded
	// by authMu; refreshMu makes concurrent refreshes one and guards
	// refreshedAt, when the client last asked for a refresh.
	apiKey      string
	session     *api.SessionStore
	authMu      sync.Mutex
	refreshMu   sync.Mutex
	refreshedAt time.Time

	// presignClient is a separate client used for object-storage presign
	// uploads/downloads. It carries no auth headers (the presigned URL is the
	// authentication) and rejects every redirect: S3 PUT/GET should never
	// redirect, and a 30x from a compromised presign endpoint should not be
	// allowed to redirect attacker-controlled bodies anywhere.
	presignClient *http.Client

	// maxResponse bounds an API response body: maxAPIResponseSize, which
	// tests lower.
	maxResponse int64
}

// WithContext is c for one call: its requests end with ctx. It shares c's
// connections and login session, so it is cheap to make.
func (c *Client) WithContext(ctx context.Context) *Client {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Client{core: c.core, ctx: ctx}
}

// Context is the context that ends this client's requests.
func (c *Client) Context() context.Context { return c.ctx }

// isLocalhostURL returns true if the URL targets loopback (127.0.0.1, ::1,
// localhost). These are the only hosts where HTTP is acceptable (dev/testing).
func isLocalhostURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// ValidateTransportSecurity rejects plaintext HTTP API URLs unless the host
// is loopback (127.0.0.1, ::1, localhost). For self-hosted deployments on
// closed networks, set DEEPSECRET_INSECURE_HOSTS to a comma-separated host
// allowlist (e.g. "vpn.internal,10.0.0.5"); only those exact hostnames are
// permitted to use plaintext HTTP, and a loud warning is still printed.
// The legacy global DEEPSECRET_ALLOW_INSECURE_HTTP env var is no longer
// honored; set the per-host allowlist instead.
func ValidateTransportSecurity(apiURL string) error {
	if !strings.HasPrefix(apiURL, "http://") || isLocalhostURL(apiURL) {
		return nil
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("invalid API URL %q: %w", apiURL, err)
	}
	host := strings.ToLower(u.Hostname())

	allow := os.Getenv("DEEPSECRET_INSECURE_HOSTS")
	if allow == "" {
		return fmt.Errorf("API URL uses plaintext HTTP (%s). Credentials would be sent unencrypted.\n  Use HTTPS, or set DEEPSECRET_INSECURE_HOSTS=<host>[,<host>...] to allow this exact host (not recommended)", apiURL)
	}
	for _, h := range strings.Split(allow, ",") {
		if strings.ToLower(strings.TrimSpace(h)) == host {
			fmt.Fprintf(os.Stderr, "\n  WARNING: DEEPSECRET_INSECURE_HOSTS allows plaintext HTTP for %q.\n     Credentials will be sent unencrypted. This is dangerous outside of a controlled network.\n\n", host)
			return nil
		}
	}
	return fmt.Errorf("API URL uses plaintext HTTP (%s) but host %q is not in DEEPSECRET_INSECURE_HOSTS", apiURL, host)
}

// validateAPIKey rejects API keys that contain CRLF, control characters, or
// other bytes that could be used to splice extra HTTP headers into a request.
// `bearer:` prefix is allowed (the token after it must still pass the check).
func validateAPIKey(apiKey string) error {
	v := strings.TrimPrefix(apiKey, "bearer:")
	if v == "" {
		return fmt.Errorf("API key is empty")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("API key contains control character at offset %d", i)
		}
	}
	return nil
}

// NewClient creates a new API client. Returns an error if the URL uses
// plaintext HTTP on a non-localhost host (override with
// DEEPSECRET_ALLOW_INSECURE_HTTP=1) or if the API key contains characters
// that are invalid in an HTTP header value.
func NewClient(apiURL, apiKey string) (*Client, error) {
	if err := ValidateTransportSecurity(apiURL); err != nil {
		return nil, err
	}
	if err := validateAPIKey(apiKey); err != nil {
		return nil, err
	}
	base := strings.TrimRight(apiURL, "/")

	apiTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	apiClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: apiTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			orig := via[0].URL
			if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
				// Cross-host redirect: refuse outright. Returning an error
				// prevents the request from being re-issued, so the auth
				// header never reaches the new host.
				return fmt.Errorf("refusing redirect from %s://%s to %s://%s (credential leak prevention)", orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
			}
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			// Same-host redirect: keep auth headers so the followup request
			// can authenticate. Stripping them here breaks legitimate API
			// behaviour like trailing-slash normalization or path rewrites.
			return nil
		},
	}

	// Storage transfers run many requests to one host at once. Each runs
	// on its own HTTP/1.1 connection, so parallel parts are parallel TCP
	// streams (HTTP/2 would carry them all on one connection, under one
	// congestion window). A finished part's connection is kept for the
	// next part rather than closed: Go keeps 2 idle per host by default,
	// so about every other part would pay a new TLS handshake and TCP slow
	// start.
	presignTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		MaxIdleConns:          2 * api.MaxDownloadConcurrency,
		MaxIdleConnsPerHost:   api.MaxDownloadConcurrency,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	presignClient := &http.Client{
		Transport: presignTransport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("refusing redirect on presign URL (request would be re-issued to %s://%s)", req.URL.Scheme, req.URL.Host)
		},
	}

	return &Client{ctx: context.Background(), core: &core{
		baseURL:       base,
		apiKey:        apiKey,
		httpClient:    apiClient,
		presignClient: presignClient,
		maxResponse:   maxAPIResponseSize,
	}}, nil
}

// NewClientFromEnv creates a client from DS_API_URL and DS_API_KEY env vars.
func NewClientFromEnv() (*Client, error) {
	u := os.Getenv("DS_API_URL")
	if u == "" {
		return nil, fmt.Errorf("DS_API_URL environment variable not set")
	}
	key := os.Getenv("DS_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("DS_API_KEY environment variable not set")
	}
	return NewClient(u, key)
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// CheckMaintenance probes the API with an unauthenticated /health request.
// Returns (true, message) if the API is in maintenance mode, (false, "") if
// it's serving normally, and a non-nil error if the probe itself failed.
func (c *Client) CheckMaintenance() (bool, string, error) {
	req, err := http.NewRequestWithContext(c.ctx, "GET", c.baseURL+"/api/v1/health", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("health probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readBody(resp, maxHealthResponseSize)
	if err != nil {
		return false, "", fmt.Errorf("health probe: %w", err)
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		var r Response
		if jsonErr := json.Unmarshal(body, &r); jsonErr == nil && r.Maintenance {
			return true, r.Error, nil
		}
	}
	return false, "", nil
}

// ── HTTP methods ─────────────────────────────────────────────────────────────

// Get performs an authenticated GET request.
func (c *Client) Get(path string) (*Response, error) { return c.do("GET", path, nil) }

// Post performs an authenticated POST request with a JSON body.
func (c *Client) Post(path string, body any) (*Response, error) {
	return c.do("POST", path, body)
}

// Put performs an authenticated PUT request with a JSON body.
func (c *Client) Put(path string, body any) (*Response, error) {
	return c.do("PUT", path, body)
}

// Delete performs an authenticated DELETE request with an optional JSON body.
func (c *Client) Delete(path string, body any) (*Response, error) {
	return c.do("DELETE", path, body)
}

// do sends an API request. A session token close to expiry is refreshed
// first, and a request refused with 401 is sent once more if the session
// could be renewed: a 401 comes from authentication, before the handler
// runs, so the retry cannot repeat an action.
func (c *Client) do(method, path string, body any) (*Response, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
	}
	key := c.freshCredential()
	resp, err := c.send(method, path, data, key)
	if isBearer(key) && errors.Is(err, api.ErrUnauthorized) && c.renewSession(key) == nil {
		if renewed := c.credential(); renewed != key {
			return c.send(method, path, data, renewed)
		}
	}
	return resp, err
}

// send makes one API request authenticated with key.
func (c *Client) send(method, path string, data []byte, key string) (*Response, error) {
	var bodyReader io.Reader
	if data != nil {
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(c.ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if token, ok := strings.CutPrefix(key, "bearer:"); ok {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("DS-API-KEY", key)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := readBody(resp, c.maxResponse)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var apiResp Response
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("decode response (status %d): %s", resp.StatusCode, printableExcerpt(respBody, 200))
	}

	if resp.StatusCode == http.StatusServiceUnavailable && apiResp.Maintenance {
		return &apiResp, &api.MaintenanceError{Message: apiResp.Error}
	}

	if !apiResp.Success {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return &apiResp, &api.Error{
			StatusCode: resp.StatusCode,
			Code:       apiResp.ErrorCode,
			Message:    apiResp.Error,
			RetryAfter: retryAfter,
		}
	}

	return &apiResp, nil
}

// parseRetryAfter parses the Retry-After header per RFC 7231: either a
// decimal number of seconds or an HTTP-date. Returns 0 when the header is
// missing or malformed.
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconvParseInt(h); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// strconvParseInt is a tiny inline replacement for strconv.ParseInt to avoid
// pulling another import into the file. Accepts non-negative decimal only.
func strconvParseInt(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("non-digit")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// ── Presigned URL operations ─────────────────────────────────────────────────

// DefaultPresignExpiryMinutes is the lifetime the SDK requests for every
// presigned URL. Mirrors the server's MaxPresignExpiryMinutes (30 min) so
// the SDK always asks for the maximum it's allowed, long enough to finish
// multi-GiB multipart uploads / parallel-Range downloads on slow links,
// while still bounded enough that a leaked URL has a finite abuse window.
const DefaultPresignExpiryMinutes = 30

// resolveExpiryMinutes returns the requested presign expiry in minutes,
// falling back to DefaultPresignExpiryMinutes when the caller passes 0
// (or a negative value). The server independently clamps to its own
// MaxPresignExpiryMinutes, so this is purely a client-side default.
func resolveExpiryMinutes(v int) int {
	if v <= 0 {
		return DefaultPresignExpiryMinutes
	}
	return v
}

// PathSegment is id escaped as one segment of a request path. An ID comes from
// the caller or the server, so it must not add segments, a query or a fragment.
// An empty ID, "." and ".." cannot be made into a segment: checkPath refuses
// the path they produce.
func PathSegment(id string) string {
	return url.PathEscape(id)
}

// checkPath refuses a request path with an empty, "." or ".." segment. Only an
// ID can put one there, and it would reach another endpoint with the caller's
// credential: an empty segment is the collection above it, and the others step
// up the path. Escaping them does not help, since %2E means "." (RFC 3986,
// section 6.2.2.2), so servers and proxies decode it and remove the segment
// before routing.
func checkPath(path string) error {
	segments, _, _ := strings.Cut(path, "?")
	for segment := range strings.SplitSeq(strings.TrimPrefix(segments, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return api.ErrInvalidID
		}
	}
	return nil
}

// presignUploadURL requests a presigned upload URL via the org-scoped endpoint.
func (c *Client) presignUploadURL(orgID, objectKey string, expiryMinutes int) (string, error) {
	resp, err := c.Post("/api/v1/orgs/"+PathSegment(orgID)+"/storage/presign", map[string]any{
		"key":            objectKey,
		"operation":      "put",
		"expiry_minutes": expiryMinutes,
	})
	if err != nil {
		return "", fmt.Errorf("get presigned upload URL: %w", err)
	}
	var presign struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(resp.Data, &presign); err != nil {
		return "", fmt.Errorf("parse presign response: %w", err)
	}
	return presign.URL, nil
}

// presignDownloadURL requests a presigned download URL via the revision-scoped endpoint.
func (c *Client) presignDownloadURL(revisionID string, expiryMinutes int) (string, error) {
	plan, err := c.presignDownloadPlan(revisionID, expiryMinutes)
	if err != nil {
		return "", err
	}
	return plan.URL, nil
}

// PresignDownloadPlan is the response shape for a download presign request,
// including size and recommended part_size. The SDK uses these to decide
// between a single-stream Range-resume download and a fan-out parallel
// multipart download.
type PresignDownloadPlan struct {
	URL      string
	Size     int64 // 0 if the server didn't populate it (older API)
	PartSize int64 // server-recommended chunk size for parallel Range reads
}

// presignDownloadPlan requests a presigned download URL plus size hints so
// the caller can pick a transport strategy. Only ONE call is made: the
// response is reused for every Range GET in a parallel download.
func (c *Client) presignDownloadPlan(revisionID string, expiryMinutes int) (*PresignDownloadPlan, error) {
	resp, err := c.Post("/api/v1/secrets/revisions/"+PathSegment(revisionID)+"/presign", map[string]any{
		"expiry_minutes": expiryMinutes,
	})
	if err != nil {
		return nil, fmt.Errorf("get presigned download URL: %w", err)
	}
	var presign struct {
		URL      string `json:"url"`
		Size     int64  `json:"size,omitempty"`
		PartSize int64  `json:"part_size,omitempty"`
	}
	if err := json.Unmarshal(resp.Data, &presign); err != nil {
		return nil, fmt.Errorf("parse presign response: %w", err)
	}
	return &PresignDownloadPlan{URL: presign.URL, Size: presign.Size, PartSize: presign.PartSize}, nil
}

// ConfirmUpload asks the backend to HEAD the uploaded object and mark the
// revision as uploaded. Downloads are blocked until this succeeds.
func (c *Client) ConfirmUpload(revisionID string) error {
	_, err := c.Post("/api/v1/secrets/revisions/"+PathSegment(revisionID)+"/confirm", map[string]any{})
	if err != nil {
		return fmt.Errorf("confirm upload: %w", err)
	}
	return nil
}

// PresignUploadReader gets a presigned PUT URL and streams data from a reader.
// The caller must provide the exact size and base64-encoded MD5 hash (required
// by S3 presigned PUT). For convenience, use [PresignUpload] with []byte data.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignUploadReader(orgID, objectKey string, r io.ReadSeeker, size int64, contentMD5 string, expiryMinutes int) error {
	url, err := c.presignUploadURL(orgID, objectKey, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return err
	}
	return c.uploadReaderToPresignedURL(url, r, size, contentMD5)
}

// PresignDownloadReader gets a presigned GET URL and returns a reader for the
// response body. The caller MUST close the returned ReadCloser.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignDownloadReader(revisionID string, expiryMinutes int) (io.ReadCloser, int64, error) {
	presignedURL, err := c.presignDownloadURL(revisionID, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return nil, 0, err
	}
	getReq, gerr := http.NewRequestWithContext(c.ctx, "GET", presignedURL, nil)
	if gerr != nil {
		return nil, 0, gerr
	}
	httpResp, err := c.doPresigned(getReq)
	if err != nil {
		return nil, 0, fmt.Errorf("download: %w", err)
	}
	if httpResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, maxErrorExcerpt))
		_ = httpResp.Body.Close() // the body was read or is discarded; closing only releases the connection.
		return nil, 0, errors.New(storageFailure("download failed", httpResp.StatusCode, body))
	}
	return httpResp.Body, httpResp.ContentLength, nil
}

// PresignUpload gets a presigned PUT URL and uploads data from a byte slice.
// Convenience wrapper: computes MD5 and size automatically.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignUpload(orgID, objectKey string, data []byte, expiryMinutes int) error {
	url, err := c.presignUploadURL(orgID, objectKey, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return err
	}
	return c.uploadToPresignedURL(url, data)
}

// PresignUploadFrom uploads the size bytes of src to a presigned PUT URL
// for objectKey, reading src once for the Content-MD5 and again for each
// attempt, so it can be a file. onProgress and status are optional; status
// follows the upload as one part on one connection.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignUploadFrom(orgID, objectKey string, src io.ReaderAt, size int64, onProgress func(int64, int64), expiryMinutes int, status *TransferStatus) error {
	h := md5.New() // #nosec G401 -- S3 Content-MD5, a transfer checksum: the signed manifest covers the payload's SHA-256.
	if _, err := io.Copy(h, io.NewSectionReader(src, 0, size)); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	contentMD5 := base64.StdEncoding.EncodeToString(h.Sum(nil))
	url, err := c.presignUploadURL(orgID, objectKey, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return err
	}
	status.start(size, 1, 0, 0, nil)
	conn := status.begin(1, size)
	err = c.putToPresignedURL(url, func() (io.Reader, error) {
		return io.NewSectionReader(src, 0, size), nil
	}, size, contentMD5, func(transferred, total int64) {
		conn.set(transferred)
		if onProgress != nil {
			onProgress(transferred, total)
		}
	})
	status.end(conn, err == nil)
	return err
}

const maxRetries = 3

// secureJitter returns a uniform random float in [-1, 1] using crypto/rand.
// Predictable jitter (e.g. unseeded math/rand on Go ≤1.19) defeats the
// purpose of jittered backoff under coordinated retry storms.
func secureJitter() float64 {
	var b [8]byte
	if _, err := io.ReadFull(cryptorand.Reader, b[:]); err != nil {
		return 0
	}
	v := binary.LittleEndian.Uint64(b[:]) >> 11 // 53 bits
	return float64(v)/float64(1<<53)*2 - 1
}

// maxBackoff caps the wait before any retry.
const maxBackoff = time.Minute

// backoffUnit scales retry waits; tests shorten it.
var backoffUnit = time.Second

// retryBackoff sleeps for exponential backoff with jitter before a retry.
// base = 2^attempt seconds up to maxBackoff, jitter = ±25% sourced from
// crypto/rand.
// Returns ctx.Err() if the context is cancelled during the sleep so Ctrl+C
// unblocks an in-progress upload/download retry within a few ms instead of
// waiting for the timer to elapse.
func retryBackoff(ctx context.Context, attempt int) error {
	base := math.Min(math.Pow(2, float64(attempt)), maxBackoff.Seconds())
	jitter := base * 0.25 * secureJitter()
	d := min(time.Duration((base+jitter)*float64(backoffUnit)), maxBackoff)
	if d < backoffUnit/10 {
		d = backoffUnit / 10
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// presignTimeout returns a request timeout proportional to payload size.
func presignTimeout(size int64) time.Duration {
	return 5*time.Minute + time.Duration(size/(10*1024*1024))*time.Minute
}

// putToPresignedURL is the shared body-shipping core for every presign upload.
// It runs the retry loop, applies exponential backoff, and forwards the
// progress callback if one is supplied.
func (c *Client) putToPresignedURL(presignedURL string, makeBody func() (io.Reader, error), size int64, contentMD5 string, onProgress func(int64, int64)) error {
	timeout := presignTimeout(size)

	ctx := c.ctx
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Bail before scheduling more work if the caller already hit Ctrl+C.
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			if err := retryBackoff(ctx, attempt); err != nil {
				return err
			}
		}

		body, err := makeBody()
		if err != nil {
			return err
		}
		if onProgress != nil {
			body = &progressCallbackReader{r: body, onProgress: onProgress, total: size}
		}

		// A per-attempt deadline rather than the shared client's Timeout,
		// which concurrent transfers would race on.
		retry, err := func() (bool, error) {
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			req, err := http.NewRequestWithContext(attemptCtx, "PUT", presignedURL, body)
			if err != nil {
				return false, err
			}
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Content-MD5", contentMD5)
			// Matches the IfNoneMatch signed into the presigned URL by the
			// backend. Must be sent verbatim or S3 returns SignatureDoesNotMatch.
			req.Header.Set("If-None-Match", "*")
			req.ContentLength = size

			resp, err := c.doPresigned(req)
			if err != nil {
				return true, fmt.Errorf("upload: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode >= 300 {
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorExcerpt))
				return resp.StatusCode >= 500, errors.New(storageFailure("upload failed", resp.StatusCode, respBody))
			}
			return false, nil
		}()
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("upload failed after %d retries: %w", maxRetries, lastErr)
}

func (c *Client) uploadReaderToPresignedURL(presignedURL string, r io.ReadSeeker, size int64, contentMD5 string) error {
	first := true
	makeBody := func() (io.Reader, error) {
		if first {
			first = false
			return r, nil
		}
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek for retry: %w", err)
		}
		return r, nil
	}
	return c.putToPresignedURL(presignedURL, makeBody, size, contentMD5, nil)
}

func (c *Client) uploadToPresignedURL(presignedURL string, data []byte) error {
	md5Sum := md5.Sum(data) // #nosec G401 -- S3 Content-MD5, a transfer checksum: the signed manifest covers the payload's SHA-256.
	contentMD5 := base64.StdEncoding.EncodeToString(md5Sum[:])
	return c.putToPresignedURL(presignedURL, func() (io.Reader, error) {
		return bytes.NewReader(data), nil
	}, int64(len(data)), contentMD5, nil)
}

// ── Progress-aware presigned operations ───────────────────────────────────────

// progressCallbackReader wraps a reader with a progress callback.
type progressCallbackReader struct {
	r           io.Reader
	onProgress  func(transferred, total int64)
	transferred int64
	total       int64
}

func (pr *progressCallbackReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.transferred += int64(n)
	if pr.onProgress != nil {
		pr.onProgress(pr.transferred, pr.total)
	}
	return n, err
}

// PresignUploadWithProgress uploads data with a progress callback.
// onProgress is called with (bytesTransferred, totalBytes) during upload.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignUploadWithProgress(orgID, objectKey string, data []byte, onProgress func(int64, int64), expiryMinutes int) error {
	url, err := c.presignUploadURL(orgID, objectKey, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return err
	}
	md5Sum := md5.Sum(data) // #nosec G401 -- S3 Content-MD5, a transfer checksum: the signed manifest covers the payload's SHA-256.
	contentMD5 := base64.StdEncoding.EncodeToString(md5Sum[:])
	return c.putToPresignedURL(url, func() (io.Reader, error) {
		return bytes.NewReader(data), nil
	}, int64(len(data)), contentMD5, onProgress)
}
