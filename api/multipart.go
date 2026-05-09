// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ── Server-side hard limits ─────────────────────────────────────────────────
// These mirror the constants in the API server (lib/config/config.go) so the
// SDK rejects out-of-range values before contacting the server.

const (
	// S3MinPartSize is the smallest part size S3 accepts (final part may be smaller).
	S3MinPartSize = int64(5 * 1024 * 1024)
	// S3MaxPartSize is the largest part size S3 accepts.
	S3MaxPartSize = int64(5 * 1024 * 1024 * 1024)
	// S3MaxParts is the maximum number of parts in a single multipart upload.
	S3MaxParts = 10000

	// multipartUploadConcurrency caps in-flight part uploads. S3 throughput
	// is dominated by parallelism; 4 is a conservative default that avoids
	// saturating residential uplinks.
	multipartUploadConcurrency = 4

	// multipartPartMaxRetries is how many times a single failed part PUT is
	// retried before the upload as a whole fails. Each retry uses fresh
	// presigned URLs (the previous one may be stale or sign-mismatched).
	multipartPartMaxRetries = 4
)

// ── Wire types ──────────────────────────────────────────────────────────────

// MultipartInitResponse is returned by POST /multipart/init.
type MultipartInitResponse struct {
	UploadID      string    `json:"upload_id"`
	PartSize      int64     `json:"part_size"`
	MaxPartNumber int       `json:"max_part_number"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// MultipartPartURLResponse is returned by POST /multipart/part-url.
type MultipartPartURLResponse struct {
	URL       string `json:"url"`
	ExpiresIn int    `json:"expires_in"`
}

// MultipartPartStatus is one already-registered part as reported by /status.
type MultipartPartStatus struct {
	PartNumber int       `json:"part_number"`
	Etag       string    `json:"etag"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	UploadedAt time.Time `json:"uploaded_at"`
}

// MultipartStatus is returned by GET /multipart/status.
type MultipartStatus struct {
	UploadID      string                `json:"upload_id"`
	State         string                `json:"state"`
	PartSize      int64                 `json:"part_size"`
	MaxPartNumber int                   `json:"max_part_number"`
	Parts         []MultipartPartStatus `json:"parts"`
	StartedAt     *time.Time            `json:"started_at,omitempty"`
}

// completePart is one entry in the /multipart/complete request body.
type completePart struct {
	PartNumber int    `json:"part_number"`
	Etag       string `json:"etag"`
}

// ── Low-level API methods ───────────────────────────────────────────────────

// MultipartInit starts a multipart upload for the revision. Idempotent: a
// second call on an already-initialized revision returns the same UploadID.
func (c *Client) MultipartInit(revisionID string) (*MultipartInitResponse, error) {
	resp, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/init", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("multipart init: %w", err)
	}
	var out MultipartInitResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("parse multipart init: %w", err)
	}
	return &out, nil
}

// MultipartPartURL fetches a presigned UploadPart URL for a single part.
func (c *Client) MultipartPartURL(revisionID string, partNumber int) (*MultipartPartURLResponse, error) {
	resp, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/part-url", map[string]any{
		"part_number": partNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("multipart part-url: %w", err)
	}
	var out MultipartPartURLResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("parse part-url: %w", err)
	}
	return &out, nil
}

// MultipartRegisterPart records a successfully uploaded part with the server.
// The server cross-checks the declared ETag against S3 ListParts before
// persisting.
func (c *Client) MultipartRegisterPart(revisionID string, partNumber int, etag string, size int64, sha256Hex string) error {
	_, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/parts", map[string]any{
		"part_number": partNumber,
		"etag":        etag,
		"size":        size,
		"sha256":      sha256Hex,
	})
	if err != nil {
		return fmt.Errorf("multipart register part %d: %w", partNumber, err)
	}
	return nil
}

// MultipartComplete finalizes the upload. Parts must be ordered ascending and
// contiguous from 1.
func (c *Client) MultipartComplete(revisionID string, parts []MultipartPartStatus) error {
	body := make([]completePart, len(parts))
	for i, p := range parts {
		body[i] = completePart{PartNumber: p.PartNumber, Etag: p.Etag}
	}
	_, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/complete", map[string]any{
		"parts": body,
	})
	if err != nil {
		return fmt.Errorf("multipart complete: %w", err)
	}
	return nil
}

// MultipartAbort cancels an in-flight multipart upload. Idempotent on
// already-aborted revisions.
func (c *Client) MultipartAbort(revisionID string) error {
	_, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/abort", map[string]any{})
	if err != nil {
		return fmt.Errorf("multipart abort: %w", err)
	}
	return nil
}

// MultipartStatus loads the current multipart upload state and registered parts.
func (c *Client) MultipartStatus(revisionID string) (*MultipartStatus, error) {
	resp, err := c.Get("/api/v1/secrets/revisions/" + revisionID + "/multipart/status")
	if err != nil {
		return nil, fmt.Errorf("multipart status: %w", err)
	}
	var out MultipartStatus
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("parse multipart status: %w", err)
	}
	return &out, nil
}

// humanBytesLocal renders a byte count in IEC units for debug log lines.
// Tiny duplicate of the helper in the parent sdk package — sdk/api can't
// import sdk (would create a cycle).
func humanBytesLocal(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const (
		kib = int64(1 << 10)
		mib = int64(1 << 20)
		gib = int64(1 << 30)
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ── High-level helper ──────────────────────────────────────────────────────

// MultipartUpload uploads `data` to a revision using the multipart flow:
// init -> per-part PUT (parallel, with retry) -> register -> complete.
//
// Resumability: if the revision is already partially uploaded, MultipartUpload
// queries /multipart/status, validates each already-registered part's SHA256
// against the local data, and skips re-uploading those parts. A part with a
// mismatched SHA256 is treated as corrupt and re-uploaded.
//
// On any unrecoverable failure the upload is left in 'in_progress' so a later
// call can resume; the orphan-cleanup cron eventually aborts it server-side
// if it stays stale beyond the configured TTL.
//
// Security: SHA256 is computed over each *ciphertext* chunk and submitted to
// the server alongside the S3 ETag (which is MD5 — collision-prone for
// adversarial inputs). The server cross-checks the ETag against S3 ListParts
// before recording the part, so a compromised or malicious client cannot
// register an ETag that wasn't actually written.
func (c *Client) MultipartUpload(revisionID string, data []byte, onProgress func(int64, int64)) error {
	return c.MultipartUploadOpts(revisionID, data, MultipartUploadOptions{OnProgress: onProgress})
}

// MultipartUploadOptions configures the multipart-upload helper.
type MultipartUploadOptions struct {
	// Threads bounds in-flight part uploads. 0 = default (multipartUploadConcurrency).
	// Clamped to [1, 32].
	Threads int
	// OnProgress is called with (transferredBytes, totalBytes).
	OnProgress func(int64, int64)
	// OnDebug is called with structured debug events.
	OnDebug func(step, message string)
}

// MultipartUploadWithDebug is the legacy callback-style entry. New callers
// should prefer MultipartUploadOpts so they can also set Threads.
func (c *Client) MultipartUploadWithDebug(revisionID string, data []byte, onProgress func(int64, int64), onDebug func(step, message string)) error {
	return c.MultipartUploadOpts(revisionID, data, MultipartUploadOptions{OnProgress: onProgress, OnDebug: onDebug})
}

// MultipartUploadOpts uploads data via the multipart flow with explicit
// concurrency, progress, and debug controls.
func (c *Client) MultipartUploadOpts(revisionID string, data []byte, opts MultipartUploadOptions) error {
	onProgress := opts.OnProgress
	onDebug := opts.OnDebug
	if len(data) == 0 {
		return fmt.Errorf("multipart upload: empty data")
	}

	debugf := func(step, format string, args ...any) {
		if onDebug == nil {
			return
		}
		onDebug(step, fmt.Sprintf(format, args...))
	}

	init, err := c.MultipartInit(revisionID)
	if err != nil {
		return err
	}
	uidShort := init.UploadID
	if len(uidShort) > 12 {
		uidShort = uidShort[:12] + "…"
	}
	debugf("multipart.init", "upload_id=%s parts=%d × %s expires=%s",
		uidShort, init.MaxPartNumber, humanBytesLocal(init.PartSize),
		init.ExpiresAt.Format("15:04:05"))

	if init.PartSize < S3MinPartSize || init.PartSize > S3MaxPartSize {
		return fmt.Errorf("multipart upload: server returned invalid part size %d", init.PartSize)
	}

	totalSize := int64(len(data))
	expectedParts := int(totalSize / init.PartSize)
	if totalSize%init.PartSize != 0 {
		expectedParts++
	}
	if expectedParts < 1 {
		expectedParts = 1
	}
	if expectedParts != init.MaxPartNumber {
		// Server's ceil(rev.Size/part_size) must equal what we just computed.
		// A mismatch means the revision's declared size doesn't match the
		// data we're uploading — refuse rather than upload garbage.
		return fmt.Errorf("multipart upload: data size %d yields %d parts but server expects %d (revision size mismatch)", totalSize, expectedParts, init.MaxPartNumber)
	}
	if expectedParts > S3MaxParts {
		return fmt.Errorf("multipart upload: %d parts exceeds S3 limit of %d", expectedParts, S3MaxParts)
	}

	// Pre-compute every part's slice + SHA256. Done up front so resume
	// validation and parallel upload share the same authoritative table.
	parts := make([]multipartLocalPart, expectedParts)
	for i := 0; i < expectedParts; i++ {
		start := int64(i) * init.PartSize
		end := start + init.PartSize
		if end > totalSize {
			end = totalSize
		}
		chunk := data[start:end]
		h := sha256.Sum256(chunk)
		parts[i] = multipartLocalPart{
			Number: i + 1,
			Data:   chunk,
			SHA256: hex.EncodeToString(h[:]),
		}
	}

	// Resumability: ask the server which parts are already registered, drop
	// matches by SHA256 from the work list. Retry transient + 429 errors so
	// a brief rate-limit hit at the start doesn't cost us the resume window.
	var status *MultipartStatus
	{
		var statusErr error
		for attempt := 0; attempt <= multipartPartMaxRetries; attempt++ {
			if attempt > 0 {
				multipartBackoff(attempt, statusErr)
			}
			status, statusErr = c.MultipartStatus(revisionID)
			if statusErr == nil {
				break
			}
			if !isMultipartRetryableErr(statusErr) {
				break
			}
		}
		if status == nil {
			status = &MultipartStatus{}
		}
	}
	registered := make(map[int]MultipartPartStatus, len(status.Parts))
	for _, p := range status.Parts {
		registered[p.PartNumber] = p
	}

	type completedPart struct {
		Number int
		Etag   string
	}
	completedCh := make(chan completedPart, expectedParts)

	// Seed already-registered+verified parts into the completed channel.
	skipped := 0
	var skippedBytes int64
	work := make([]int, 0, expectedParts)
	for i := range parts {
		p := parts[i]
		reg, ok := registered[p.Number]
		if ok && reg.SHA256 == p.SHA256 && reg.Size == int64(len(p.Data)) {
			completedCh <- completedPart{Number: p.Number, Etag: reg.Etag}
			skipped++
			skippedBytes += int64(len(p.Data))
			continue
		}
		work = append(work, i)
	}

	if onProgress != nil {
		onProgress(skippedBytes, totalSize)
	}
	if skipped > 0 {
		debugf("multipart.resume", "skipped %d already-registered parts (%d bytes); uploading %d remaining", skipped, skippedBytes, len(work))
	}

	if len(work) > 0 {
		// Bounded parallelism. Workers pull part indices off `workCh` and
		// write completed parts onto `completedCh`. First error short-circuits.
		workCh := make(chan int, len(work))
		for _, idx := range work {
			workCh <- idx
		}
		close(workCh)

		var wg sync.WaitGroup
		errCh := make(chan error, multipartUploadConcurrency)

		var mu sync.Mutex
		var transferred int64 = skippedBytes

		concurrency := multipartUploadConcurrency
		if opts.Threads > 0 {
			concurrency = opts.Threads
		}
		// Cap at a sane ceiling to avoid runaway socket pressure even if a
		// caller passes something silly like 1000.
		if concurrency > 32 {
			concurrency = 32
		}
		if concurrency > len(work) {
			concurrency = len(work)
		}
		debugf("multipart.upload", "starting %d worker(s), %d part(s) to upload", concurrency, len(work))
		ctx := c.reqCtx()
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				for idx := range workCh {
					// Drain the channel quickly when the user hits Ctrl+C
					// so we don't keep starting new HTTP attempts after
					// the cancellation signal arrives.
					select {
					case <-ctx.Done():
						select {
						case errCh <- ctx.Err():
						default:
						}
						return
					default:
					}
					p := parts[idx]
					t0 := time.Now()
					// Stream-level progress: ticks as bytes flow over the
					// wire (every TCP chunk), not just when a whole part
					// lands. Negative deltas appear on retry rewinds.
					chunkCb := func(n int) {
						if onProgress == nil {
							return
						}
						mu.Lock()
						transferred += int64(n)
						if transferred < skippedBytes {
							transferred = skippedBytes
						}
						if transferred > totalSize {
							transferred = totalSize
						}
						t := transferred
						mu.Unlock()
						onProgress(t, totalSize)
					}
					etag, putErr := c.uploadPartWithRetry(revisionID, p, chunkCb)
					if putErr != nil {
						debugf("multipart.upload", "worker=%d part=%d FAILED err=%v", workerID, p.Number, putErr)
						select {
						case errCh <- putErr:
						default:
						}
						return
					}
					if regErr := c.registerPartWithRetry(revisionID, p.Number, etag, int64(len(p.Data)), p.SHA256); regErr != nil {
						debugf("multipart.upload", "worker=%d part=%d register FAILED err=%v", workerID, p.Number, regErr)
						select {
						case errCh <- regErr:
						default:
						}
						return
					}
					elapsed := time.Since(t0)
					etagShort := etag
					if len(etagShort) > 12 {
						etagShort = etagShort[:12]
					}
					debugf("multipart.upload", "part %d/%d uploaded — size=%s etag=%s in %s (worker=%d)",
						p.Number, len(parts), humanBytesLocal(int64(len(p.Data))), etagShort,
						elapsed.Round(time.Millisecond), workerID)
					completedCh <- completedPart{Number: p.Number, Etag: etag}
				}
			}(i)
		}
		wg.Wait()
		close(errCh)
		if err, ok := <-errCh; ok && err != nil {
			return fmt.Errorf("multipart upload: %w", err)
		}
	}

	close(completedCh)

	final := make([]MultipartPartStatus, 0, expectedParts)
	for cp := range completedCh {
		final = append(final, MultipartPartStatus{PartNumber: cp.Number, Etag: cp.Etag})
	}
	if len(final) != expectedParts {
		return fmt.Errorf("multipart upload: expected %d completed parts, got %d", expectedParts, len(final))
	}
	sort.Slice(final, func(i, j int) bool { return final[i].PartNumber < final[j].PartNumber })

	tComp := time.Now()
	if err := c.MultipartComplete(revisionID, final); err != nil {
		return err
	}
	debugf("multipart.complete", "finalized %d parts in %s", len(final), time.Since(tComp).Round(time.Millisecond))
	return nil
}

// multipartLocalPart pairs a part's payload bytes with metadata used for both
// resume-validation and upload.
type multipartLocalPart struct {
	Number int
	Data   []byte
	SHA256 string
}

// uploadPartWithRetry PUTs one part to a freshly-presigned URL, retrying on
// transient transport / 5xx / 429 errors. Each retry asks for a *new*
// presigned URL so a stale one (e.g. expired during long backoff) doesn't
// poison the retry. On 429 the limiter's Retry-After is honored if present;
// otherwise the standard exponential-jittered backoff applies.
//
// Non-retryable errors (4xx other than 429) are surfaced immediately.
//
// Returns the unquoted ETag from S3 on success.
func (c *Client) uploadPartWithRetry(revisionID string, p multipartLocalPart, onChunk func(int)) (string, error) {
	md5Sum := md5.Sum(p.Data)
	contentMD5 := base64.StdEncoding.EncodeToString(md5Sum[:])

	var lastErr error
	for attempt := 0; attempt <= multipartPartMaxRetries; attempt++ {
		if attempt > 0 {
			multipartBackoff(attempt, lastErr)
		}
		urlResp, err := c.MultipartPartURL(revisionID, p.Number)
		if err != nil {
			if !isMultipartRetryableErr(err) {
				return "", err
			}
			lastErr = err
			continue
		}

		// Per-attempt counter so a mid-stream failure can rewind the
		// caller's progress bar before the retry begins re-streaming.
		// Without this, a partial upload's bytes would be counted twice.
		var attemptBytes int64
		attemptCb := func(n int) {
			attemptBytes += int64(n)
			if onChunk != nil {
				onChunk(n)
			}
		}
		etag, err := c.putPart(urlResp.URL, p.Data, contentMD5, attemptCb)
		if err != nil {
			if onChunk != nil && attemptBytes > 0 {
				onChunk(-int(attemptBytes))
			}
			lastErr = err
			continue
		}
		return etag, nil
	}
	return "", fmt.Errorf("after %d attempts: %w", multipartPartMaxRetries, lastErr)
}

// registerPartWithRetry wraps MultipartRegisterPart so the same 429-aware
// backoff that protects part-url protects the registration call. Without
// this, a /multipart/parts call that hits the rate limit fails the whole
// upload even though the part itself was successfully PUT to S3.
func (c *Client) registerPartWithRetry(revisionID string, partNumber int, etag string, size int64, sha256Hex string) error {
	var lastErr error
	for attempt := 0; attempt <= multipartPartMaxRetries; attempt++ {
		if attempt > 0 {
			multipartBackoff(attempt, lastErr)
		}
		err := c.MultipartRegisterPart(revisionID, partNumber, etag, size, sha256Hex)
		if err == nil {
			return nil
		}
		if !isMultipartRetryableErr(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("register part %d after %d attempts: %w", partNumber, multipartPartMaxRetries, lastErr)
}

// isMultipartRetryableErr reports whether err is worth retrying. We retry on:
//   - transport errors (no APIError wrapped) — likely network blip.
//   - 5xx server errors.
//   - 429 rate-limit responses.
// Everything else (auth, validation, conflict) is fatal and surfaced
// immediately so we don't burn the whole retry budget on a permanent failure.
func isMultipartRetryableErr(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	if apiErr.StatusCode >= 500 {
		return true
	}
	if apiErr.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return false
}

// multipartBackoff sleeps before the next retry. If the most recent error was
// a 429 with a Retry-After hint, honor it (clamped); otherwise fall back to
// the standard exponential-jittered backoff.
func multipartBackoff(attempt int, lastErr error) {
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
		d := apiErr.RetryAfter
		// Clamp at 30s so a misbehaving server can't stall us indefinitely.
		if d > 30*time.Second {
			d = 30 * time.Second
		}
		// Add a small jitter (±10%) so a fleet of clients hitting the same
		// 429 don't all retry on the same wall-clock instant.
		j := float64(d) * 0.1 * secureJitter()
		time.Sleep(d + time.Duration(j))
		return
	}
	retryBackoff(attempt)
}

// putPart PUTs a single part to the presigned URL and returns the ETag.
// The presign client refuses redirects, so a 30x is fatal.
// progressReader wraps an io.Reader and invokes cb with the byte count of
// each successful Read. Lets putPart stream a multipart chunk to S3 while
// the caller updates a transferred-bytes counter on every TCP chunk, so
// the CLI's progress bar advances during long part uploads instead of
// jumping in 8-MiB increments only when each part completes.
type progressReader struct {
	r  io.Reader
	cb func(int)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.cb != nil {
		p.cb(n)
	}
	return n, err
}

func (c *Client) putPart(presignedURL string, data []byte, contentMD5 string, onChunk func(int)) (string, error) {
	var body io.Reader = bytes.NewReader(data)
	if onChunk != nil {
		body = &progressReader{r: bytes.NewReader(data), cb: onChunk}
	}
	req, err := http.NewRequestWithContext(c.reqCtx(), "PUT", presignedURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-MD5", contentMD5)
	req.ContentLength = int64(len(data))

	c.presignClient.Timeout = presignTimeout(int64(len(data)))
	resp, err := c.presignClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("PUT part: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PUT part transient (status %d): %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PUT part failed (status %d): %s", resp.StatusCode, string(body))
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", fmt.Errorf("PUT part: S3 returned no ETag")
	}
	// S3 wraps ETags in quotes; strip them so the value matches what
	// ListParts returns server-side and what /multipart/parts expects.
	if len(etag) >= 2 && etag[0] == '"' && etag[len(etag)-1] == '"' {
		etag = etag[1 : len(etag)-1]
	}
	return etag, nil
}
