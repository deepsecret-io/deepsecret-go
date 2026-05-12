// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ── Parallel Range download ─────────────────────────────────────────────────
//
// One presigned GET URL is requested up front. We fan out N concurrent
// `Range: bytes=A-B` requests against that single URL — S3 supports Range
// natively on every GET, so no server-side change is required.
//
// Per-part retry is independent: a stalled part doesn't block its peers,
// and a transient failure on one byte range only re-fetches that range
// instead of restarting the whole download.

const (
	// DefaultDownloadConcurrency is what callers get when they don't pass
	// an explicit thread count. 4 is a conservative default — high enough
	// to mask per-stream slow starts on long-RTT links, low enough to be
	// polite to free-tier S3-compatible backends.
	DefaultDownloadConcurrency = 4

	// MaxDownloadConcurrency caps the parallelism a caller can request.
	// 64 is well below the open-fd / TCP-stream-per-host limits on every
	// supported OS, and well above the point of diminishing returns for
	// any realistic backbone.
	MaxDownloadConcurrency = 64

	// downloadPartMaxRetries is how many times one byte range is retried
	// before the whole download fails.
	downloadPartMaxRetries = 4

	// minDownloadChunkSize keeps per-request overhead under control by
	// avoiding sub-MB ranges; smaller objects fall back to single-shot.
	minDownloadChunkSize = 1024 * 1024

	// DefaultMaxDownloadBuffer caps the in-memory buffer the SDK is willing
	// to pre-allocate for a single download. Mirrors the server-side
	// CreateSecret upper bound (5 GiB) so a server-side trust boundary
	// violation (compromised API returning a wildly inflated `size`) cannot
	// trigger a multi-tens-of-GiB allocation that crashes the host.
	// Callers may override via MultipartDownloadOptions.MaxBufferBytes; set
	// to a smaller value on memory-constrained clients.
	DefaultMaxDownloadBuffer = int64(5 * 1024 * 1024 * 1024)
)

// MultipartDownloadOptions configures parallel Range downloads.
type MultipartDownloadOptions struct {
	// Threads is the maximum number of concurrent Range GETs. 0 means use
	// DefaultDownloadConcurrency. Values are clamped to [1, MaxDownloadConcurrency].
	Threads int

	// PartSize overrides the server-suggested part size. 0 means use the
	// value the API returned. Values below minDownloadChunkSize are clamped up.
	PartSize int64

	// MaxBufferBytes caps the in-memory buffer the SDK will pre-allocate
	// for the assembled object. 0 = use DefaultMaxDownloadBuffer (5 GiB).
	// Set lower on memory-constrained hosts (CI runners, edge devices).
	// Defends against a server-side trust boundary violation where a
	// compromised API claims a wildly inflated revision size.
	MaxBufferBytes int64

	// OnProgress is called with (transferredBytes, totalBytes) as parts complete.
	OnProgress func(transferred, total int64)

	// OnDebug is called with structured debug events. Optional.
	OnDebug func(step, message string)

	// PresignExpiryMinutes requests presigned URL lifetime in minutes.
	// Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30).
	PresignExpiryMinutes int
}

// MultipartDownload fetches the entire object using N concurrent Range GETs.
// totalSize MUST match the object's actual size or the caller's expectation —
// it gates the byte budget and short-read detection.
//
// Resilience: each range is retried up to downloadPartMaxRetries times on
// transient errors (5xx, transport drops, short reads). A single failed
// range never blocks its peers. URL stays valid for the full presign TTL
// (DefaultPresignExpiryMinutes, currently 30 min), so the entire fan-out
// shares one signature.
//
// Security: the assembled bytes are still authenticated end-to-end by the
// caller's HPKE AEAD verification — Range stitching does not bypass
// integrity. Range responses are size-bounded, so a compromised S3 cannot
// over-read into adjacent objects' data.
func (c *Client) MultipartDownload(presignedURL string, totalSize, partSize int64, opts MultipartDownloadOptions) ([]byte, error) {
	if totalSize <= 0 {
		return nil, fmt.Errorf("multipart download: invalid total size %d", totalSize)
	}
	maxBuf := opts.MaxBufferBytes
	if maxBuf <= 0 {
		maxBuf = DefaultMaxDownloadBuffer
	}
	if totalSize > maxBuf {
		return nil, fmt.Errorf("multipart download: object size %d exceeds buffer cap %d (set MultipartDownloadOptions.MaxBufferBytes if intentional)", totalSize, maxBuf)
	}
	if partSize <= 0 {
		if opts.PartSize > 0 {
			partSize = opts.PartSize
		} else {
			partSize = 8 * 1024 * 1024
		}
	}
	if partSize < minDownloadChunkSize {
		partSize = minDownloadChunkSize
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = DefaultDownloadConcurrency
	}
	if threads > MaxDownloadConcurrency {
		threads = MaxDownloadConcurrency
	}

	debugf := func(step, format string, args ...any) {
		if opts.OnDebug == nil {
			return
		}
		opts.OnDebug(step, fmt.Sprintf(format, args...))
	}

	// Compute ranges. The last part may be smaller than partSize.
	type span struct {
		idx        int
		start, end int64 // [start, end] inclusive (HTTP Range semantics)
	}
	var spans []span
	for start, idx := int64(0), 0; start < totalSize; idx++ {
		end := start + partSize - 1
		if end >= totalSize {
			end = totalSize - 1
		}
		spans = append(spans, span{idx: idx, start: start, end: end})
		start = end + 1
	}
	if len(spans) == 1 {
		// One span = no benefit from parallelism. Caller should have used
		// the single-shot path; we still service it correctly here.
		threads = 1
	}
	if threads > len(spans) {
		threads = len(spans)
	}

	debugf("plan", "object=%s", humanBytesLocal(totalSize))
	debugf("plan", "parts=%d", len(spans))
	debugf("plan", "part_size=%s", humanBytesLocal(partSize))
	debugf("plan", "threads=%d", threads)

	buf := make([]byte, totalSize)
	var transferred int64
	var transferredMu sync.Mutex

	workCh := make(chan span, len(spans))
	for _, s := range spans {
		workCh <- s
	}
	close(workCh)

	errCh := make(chan error, threads)
	var wg sync.WaitGroup
	ctx := c.reqCtx()
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for s := range workCh {
				select {
				case <-ctx.Done():
					// User hit Ctrl+C (or a parent context fired). Stop
					// pulling new ranges and surface the cancel as the
					// upload error so the caller doesn't see a partial
					// success.
					select {
					case errCh <- ctx.Err():
					default:
					}
					return
				case <-errCh:
					// Another worker already failed — don't pile on with
					// more requests; fast-exit. The first error wins.
					return
				default:
				}
				if err := c.downloadRange(presignedURL, s.start, s.end, buf[s.start:s.end+1], debugf, workerID, s.idx); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if opts.OnProgress != nil {
					transferredMu.Lock()
					transferred += s.end - s.start + 1
					t := transferred
					transferredMu.Unlock()
					opts.OnProgress(t, totalSize)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	if err, ok := <-errCh; ok && err != nil {
		return nil, err
	}
	debugf("done", "got=%d bytes", totalSize)
	return buf, nil
}

// downloadRange fetches one byte range into the supplied destination slice,
// retrying on transient errors. dst MUST already be sized to len = end-start+1.
func (c *Client) downloadRange(presignedURL string, start, end int64, dst []byte, debugf func(step, format string, args ...any), workerID, partIdx int) error {
	expected := end - start + 1
	if int64(len(dst)) != expected {
		return fmt.Errorf("downloadRange: dst size %d != expected %d", len(dst), expected)
	}

	ctx := c.reqCtx()
	var lastErr error
	for attempt := 0; attempt <= downloadPartMaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			if err := retryBackoff(ctx, attempt); err != nil {
				return err
			}
			debugf("retry", "worker=%d part=%d attempt=%d range=%d-%d err=%v", workerID, partIdx, attempt, start, end, lastErr)
		}
		t0 := time.Now()
		if err := c.doRangeGET(presignedURL, start, end, dst); err != nil {
			if !isDownloadRetryable(err) {
				return err
			}
			lastErr = err
			continue
		}
		debugf("range", "part %d range=%d-%d size=%s in %s (worker=%d)", partIdx+1, start, end, humanBytesLocal(expected), time.Since(t0).Round(time.Millisecond), workerID)
		return nil
	}
	return fmt.Errorf("range %d-%d after %d attempts: %w", start, end, downloadPartMaxRetries, lastErr)
}

// doRangeGET performs a single Range request and writes the bytes into dst.
// dst is filled exactly len(dst) bytes or an error is returned. We use a
// fresh request per attempt so retries don't see stale connection state.
func (c *Client) doRangeGET(presignedURL string, start, end int64, dst []byte) error {
	req, err := http.NewRequestWithContext(c.reqCtx(), "GET", presignedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	c.presignClient.Timeout = presignTimeout(int64(len(dst)))
	resp, err := c.presignClient.Do(req)
	if err != nil {
		return fmt.Errorf("Range GET: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent: // 206 — what we expect
	case http.StatusOK:
		// Server returned the whole object instead of honoring Range. We
		// can still satisfy this single-range case if the slice fits, but
		// it defeats parallelism — surface as a transient so the next
		// attempt can be cleaner. Falling back silently would mask a
		// misconfigured backend.
		body, _ := io.ReadAll(resp.Body)
		_ = body
		return fmt.Errorf("server ignored Range and returned full object (status 200)")
	default:
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			return fmt.Errorf("Range GET transient (status %d): %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("Range GET failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Strict: the response must report Content-Length matching the requested
	// span. A short read here is a serious enough signal to surface.
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n != int64(len(dst)) {
			return fmt.Errorf("Range GET length mismatch: got %d, want %d", n, len(dst))
		}
	}

	if _, err := io.ReadFull(resp.Body, dst); err != nil {
		return fmt.Errorf("Range GET body: %w", err)
	}
	return nil
}

// isDownloadRetryable distinguishes transient network/server failures from
// hard errors that won't get better on retry. Context cancellation is NOT
// retryable so Ctrl+C surfaces immediately without burning the retry budget.
func isDownloadRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500 || apiErr.StatusCode == http.StatusTooManyRequests
	}
	// Unwrapped errors from doRangeGET — transport blips, server-ignored-Range,
	// transient 5xx — all retryable.
	return true
}

// PresignDownloadParallel resolves the presigned URL plus size hints, picks a
// strategy based on size and the supplied options, and returns the fully
// assembled bytes.
//
// Strategy:
//   - object < ~2 × DefaultPartSize OR Threads == 1: single-shot Range-resume
//     via the existing getFromPresignedURL path (already retry-resilient).
//   - otherwise: parallel multipart download with Threads concurrent Range GETs.
//
// onProgress, if provided, is called with (transferred, total).
func (c *Client) PresignDownloadParallel(revisionID string, opts MultipartDownloadOptions) ([]byte, error) {
	plan, err := c.presignDownloadPlan(revisionID, resolveExpiryMinutes(opts.PresignExpiryMinutes))
	if err != nil {
		return nil, err
	}
	maxBuf := opts.MaxBufferBytes
	if maxBuf <= 0 {
		maxBuf = DefaultMaxDownloadBuffer
	}
	// Reject obviously-wrong sizes from the server before the single-shot
	// path also tries to allocate. The MultipartDownload fast-path enforces
	// the same cap, but the single-shot path uses io.ReadAll which would
	// happily fill memory until OOM. This is the trust-boundary defense
	// covering the rare case where a compromised API claims a wildly
	// inflated revision size.
	if plan.Size > 0 && plan.Size > maxBuf {
		return nil, fmt.Errorf("download: server-declared size %d exceeds buffer cap %d (set MultipartDownloadOptions.MaxBufferBytes if intentional)", plan.Size, maxBuf)
	}
	debugf := func(step, format string, args ...any) {
		if opts.OnDebug == nil {
			return
		}
		opts.OnDebug(step, fmt.Sprintf(format, args...))
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = DefaultDownloadConcurrency
	}
	partSize := opts.PartSize
	if partSize <= 0 {
		partSize = plan.PartSize
	}

	// Size unknown or below the parallelism threshold → single-shot.
	threshold := int64(2 * 1024 * 1024) // 2 MiB
	if partSize > 0 {
		threshold = 2 * partSize
	}
	if plan.Size <= 0 || plan.Size < threshold || threads <= 1 {
		debugf("download", "mode=single-shot")
		debugf("download", "size=%s", humanBytesLocal(plan.Size))
		debugf("download", "threshold=%s", humanBytesLocal(threshold))
		return c.getFromPresignedURL(plan.URL, opts.OnProgress)
	}

	debugf("download", "mode=parallel")
	debugf("download", "size=%s", humanBytesLocal(plan.Size))
	debugf("download", "part_size=%s", humanBytesLocal(partSize))
	debugf("download", "threads=%d", threads)
	return c.MultipartDownload(plan.URL, plan.Size, partSize, opts)
}
