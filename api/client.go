// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package api provides the shared HTTP client for the DeepSecret SDK.
//
// Sub-packages (secrets, identity) accept [Client] to make API calls.
// The root sdk package creates a [Client] and passes it to sub-packages
// during orchestration.
package api

import (
	"bytes"
	"context"
	"crypto/md5"
	cryptorand "crypto/rand"
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
)

// Response is the backend's JSON response envelope.
type Response struct {
	Success     bool            `json:"success"`
	Data        json.RawMessage `json:"data,omitempty"`
	Error       string          `json:"error,omitempty"`
	ErrorCode   string          `json:"error_code,omitempty"`
	Maintenance bool            `json:"maintenance,omitempty"`
}

// MaintenanceError is returned when the API is in maintenance mode (HTTP 503 +
// `maintenance: true` flag). Callers can branch on it via [IsMaintenanceError].
type MaintenanceError struct {
	Message string
}

func (e *MaintenanceError) Error() string {
	if e.Message == "" {
		return "API is under maintenance"
	}
	return e.Message
}

// APIError is returned for any non-success API response. StatusCode is the
// HTTP status; Code is the server-provided error code (when present); Message
// is the server's human-readable error string. Callers branch with errors.Is
// against the package sentinels (ErrNotFound, ErrUnauthorized, etc.) which
// match the matching HTTP statuses.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	// RetryAfter is parsed from the Retry-After response header when present.
	// Zero means "not provided"; callers should fall back to their own
	// backoff schedule.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error (status %d, %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// Sentinel errors callers can use with errors.Is. Each maps to one or more
// HTTP status codes returned by the backend.
var (
	ErrUnauthorized = errors.New("unauthorized") // 401
	ErrForbidden    = errors.New("forbidden")    // 403
	ErrNotFound     = errors.New("not found")    // 404
	ErrConflict     = errors.New("conflict")     // 409
	ErrTierLimit    = errors.New("tier limit")   // 402, 429 with code=tier_limit
	ErrRateLimited  = errors.New("rate limited") // 429
	ErrServerError  = errors.New("server error") // 5xx (not maintenance)
	ErrBadRequest   = errors.New("bad request")  // 400, 422
)

// Is implements errors.Is so callers can write
//
//	if errors.Is(err, api.ErrNotFound) { ... }
//
// against the high-level sentinels regardless of which concrete APIError was
// returned.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	case ErrTierLimit:
		return e.StatusCode == http.StatusPaymentRequired ||
			(e.StatusCode == http.StatusTooManyRequests && e.Code == "tier_limit")
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests && e.Code != "tier_limit"
	case ErrServerError:
		return e.StatusCode >= 500 && e.StatusCode < 600
	case ErrBadRequest:
		return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity
	}
	return false
}

// Client manages authentication and HTTP communication with the DeepSecret API.
type Client struct {
	baseURL    string
	httpClient *http.Client

	// apiKey is the credential: an API key, or "bearer:" and a session
	// token, which the client refreshes before it expires (session.go).
	// Guarded by authMu; refreshMu makes concurrent refreshes one.
	apiKey    string
	session   *SessionStore
	authMu    sync.Mutex
	refreshMu sync.Mutex

	// presignClient is a separate client used for object-storage presign
	// uploads/downloads. It carries no auth headers (the presigned URL is the
	// authentication) and rejects every redirect: S3 PUT/GET should never
	// redirect, and a 30x from a compromised presign endpoint should not be
	// allowed to redirect attacker-controlled bodies anywhere.
	presignClient *http.Client

	// rootCtx is the cancellation context propagated to every outgoing HTTP
	// request. Defaults to context.Background(); callers (typically the CLI)
	// override it via SetRootContext so SIGINT/SIGTERM unblock in-flight
	// uploads/downloads instead of leaving the process stuck on a Read until
	// the per-call timeout fires. Reads/writes are fenced behind ctxMu.
	rootCtx context.Context
	ctxMu   sync.RWMutex
}

// SetRootContext installs a base context that every subsequent HTTP request
// from this Client derives from. Cancelling that context unblocks in-flight
// API calls AND object-storage PUT/GET requests. Pass context.Background()
// to clear. Safe to call concurrently with in-flight requests; only future
// requests pick up the new ctx.
func (c *Client) SetRootContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	c.ctxMu.Lock()
	c.rootCtx = ctx
	c.ctxMu.Unlock()
}

// Context returns the root context set with SetRootContext, or background.
// Long local work, such as sealing or decrypting a large payload, checks it
// so a cancel stops it too.
func (c *Client) Context() context.Context { return c.reqCtx() }

// reqCtx returns the current root context, defaulting to background if none
// was set. Cheap read-locked access on the hot path.
func (c *Client) reqCtx() context.Context {
	c.ctxMu.RLock()
	defer c.ctxMu.RUnlock()
	if c.rootCtx == nil {
		return context.Background()
	}
	return c.rootCtx
}

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

	presignTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	presignClient := &http.Client{
		Transport: presignTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing redirect on presign URL (request would be re-issued to %s://%s)", req.URL.Scheme, req.URL.Host)
		},
	}

	return &Client{
		baseURL:       base,
		apiKey:        apiKey,
		httpClient:    apiClient,
		presignClient: presignClient,
	}, nil
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

// IsMaintenanceError reports whether err (or any error wrapped inside err)
// is a MaintenanceError.
func IsMaintenanceError(err error) bool {
	if err == nil {
		return false
	}
	var m *MaintenanceError
	return errors.As(err, &m)
}

// MaintenanceMessage extracts the server-provided maintenance message from err,
// or returns an empty string if err is not a MaintenanceError.
func MaintenanceMessage(err error) string {
	if err == nil {
		return ""
	}
	var m *MaintenanceError
	if errors.As(err, &m) && m != nil {
		return m.Message
	}
	return ""
}

// CheckMaintenance probes the API with an unauthenticated /health request.
// Returns (true, message) if the API is in maintenance mode, (false, "") if
// it's serving normally, and a non-nil error if the probe itself failed.
func (c *Client) CheckMaintenance() (bool, string, error) {
	req, err := http.NewRequestWithContext(c.reqCtx(), "GET", c.baseURL+"/api/v1/health", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("health probe failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
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
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
	}
	key := c.freshCredential()
	resp, err := c.send(method, path, data, key)
	if isBearer(key) && errors.Is(err, ErrUnauthorized) && c.renewSession(key) == nil {
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

	req, err := http.NewRequestWithContext(c.reqCtx(), method, c.baseURL+path, bodyReader)
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
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var apiResp Response
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("decode response (status %d): %s", resp.StatusCode, string(respBody))
	}

	if resp.StatusCode == http.StatusServiceUnavailable && apiResp.Maintenance {
		return &apiResp, &MaintenanceError{Message: apiResp.Error}
	}

	if !apiResp.Success {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return &apiResp, &APIError{
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

// presignUploadURL requests a presigned upload URL via the org-scoped endpoint.
func (c *Client) presignUploadURL(orgID, objectKey string, expiryMinutes int) (string, error) {
	resp, err := c.Post("/api/v1/orgs/"+orgID+"/storage/presign", map[string]any{
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
	resp, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/presign", map[string]any{
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
	_, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/confirm", map[string]any{})
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
	getReq, gerr := http.NewRequestWithContext(c.reqCtx(), "GET", presignedURL, nil)
	if gerr != nil {
		return nil, 0, gerr
	}
	httpResp, err := c.presignClient.Do(getReq)
	if err != nil {
		return nil, 0, fmt.Errorf("download: %w", err)
	}
	if httpResp.StatusCode >= 300 {
		body, _ := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		return nil, 0, fmt.Errorf("download failed (status %d): %s", httpResp.StatusCode, string(body))
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
// attempt, so it can be a file. onProgress is optional.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignUploadFrom(orgID, objectKey string, src io.ReaderAt, size int64, onProgress func(int64, int64), expiryMinutes int) error {
	h := md5.New()
	if _, err := io.Copy(h, io.NewSectionReader(src, 0, size)); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	contentMD5 := base64.StdEncoding.EncodeToString(h.Sum(nil))
	url, err := c.presignUploadURL(orgID, objectKey, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return err
	}
	return c.putToPresignedURL(url, func() (io.Reader, error) {
		return io.NewSectionReader(src, 0, size), nil
	}, size, contentMD5, onProgress)
}

// PresignDownload gets a presigned GET URL and downloads data into memory.
// For large downloads, use [PresignDownloadReader] to stream.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignDownload(revisionID string, expiryMinutes int) ([]byte, error) {
	url, err := c.presignDownloadURL(revisionID, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return nil, err
	}
	return c.downloadFromPresignedURL(url)
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

	ctx := c.reqCtx()
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

			resp, err := c.presignClient.Do(req)
			if err != nil {
				return true, fmt.Errorf("upload: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				return resp.StatusCode >= 500, fmt.Errorf("upload failed (status %d): %s", resp.StatusCode, string(respBody))
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
	md5Sum := md5.Sum(data)
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
	md5Sum := md5.Sum(data)
	contentMD5 := base64.StdEncoding.EncodeToString(md5Sum[:])
	return c.putToPresignedURL(url, func() (io.Reader, error) {
		return bytes.NewReader(data), nil
	}, int64(len(data)), contentMD5, onProgress)
}

// PresignDownloadWithProgress downloads data with a progress callback.
// onProgress is called with (bytesTransferred, totalBytes) during download.
//
// expiryMinutes sets the presigned URL lifetime; 0 = DefaultPresignExpiryMinutes.
func (c *Client) PresignDownloadWithProgress(revisionID string, onProgress func(int64, int64), expiryMinutes int) ([]byte, error) {
	presignedURL, err := c.presignDownloadURL(revisionID, resolveExpiryMinutes(expiryMinutes))
	if err != nil {
		return nil, err
	}
	return c.getFromPresignedURL(presignedURL, onProgress)
}

func (c *Client) downloadFromPresignedURL(presignedURL string) ([]byte, error) {
	return c.getFromPresignedURL(presignedURL, nil)
}

// getFromPresignedURL downloads the full body, retrying on transient errors.
//
// Range-resume semantics: if a download is partially received and the
// connection drops mid-body, the next retry uses HTTP `Range: bytes=N-` to
// resume from where it stopped instead of restarting at byte zero. S3
// supports Range natively on every GET, so this works without any
// server-side change. The buffer is preserved across retries; the payload
// digest and chunk AEAD checks happen at the client when the assembled bytes
// are decrypted, so a Range-resumed body is no less secure than a single-shot
// one.
func (c *Client) getFromPresignedURL(presignedURL string, onProgress func(int64, int64)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(c.reqCtx(), 10*time.Minute)
	defer cancel()
	var buf bytes.Buffer
	var totalSize int64 = -1 // unknown until first response

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 0 {
			if err := retryBackoff(ctx, attempt); err != nil {
				return nil, err
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", presignedURL, nil)
		if err != nil {
			return nil, err
		}
		// On retry after a partial body, ask for the remainder via Range.
		// S3 returns 206 Partial Content; we append to the buffer in place.
		var rangeStart int64
		if buf.Len() > 0 {
			rangeStart = int64(buf.Len())
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", rangeStart))
		}

		resp, err := c.presignClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("download: %w", err)
			continue
		}
		if resp.StatusCode >= 500 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("download failed (status %d): %s", resp.StatusCode, string(body))
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode != http.StatusPartialContent {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("download failed (status %d): %s", resp.StatusCode, string(body))
		}

		// Pin total size from the first non-Range response. ContentLength on
		// a 206 reflects only the requested range, not the whole object.
		if totalSize < 0 {
			if resp.StatusCode == http.StatusPartialContent {
				// The server unexpectedly returned Range on the first call;
				// treat as full reset.
				buf.Reset()
				rangeStart = 0
			}
			totalSize = resp.ContentLength
		}
		// Defense: if we asked for Range and got 200 (server ignored Range),
		// reset the buffer so we don't double-count bytes.
		if rangeStart > 0 && resp.StatusCode == http.StatusOK {
			buf.Reset()
		}

		// Pin the buffer length BEFORE this attempt's read starts. The
		// inner reader's onProgress already passes a cumulative count; if
		// we recompute buf.Len() each call (instead of capturing once) it
		// double-counts as io.Copy interleaves reads and buffer writes,
		// producing the >100% progress observed on Range-resume retries.
		startLen := int64(buf.Len())
		var reader io.Reader = resp.Body
		if onProgress != nil {
			reader = &progressCallbackReader{r: reader, onProgress: func(n, _ int64) {
				onProgress(startLen+n, totalSize)
			}, total: totalSize}
		}

		// Stream into the buffer so a mid-body failure preserves what we
		// already have for the next Range-resume attempt.
		_, copyErr := io.Copy(&buf, reader)
		resp.Body.Close()
		if copyErr != nil {
			lastErr = fmt.Errorf("download read: %w", copyErr)
			continue
		}
		// Some S3-compatible backends may close the connection without
		// reporting an error; if Content-Length tells us we're short, retry.
		if totalSize > 0 && int64(buf.Len()) < totalSize+rangeStart {
			lastErr = fmt.Errorf("short read: got %d of %d bytes", buf.Len(), totalSize+rangeStart)
			continue
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("download failed after %d retries: %w", maxRetries, lastErr)
}
