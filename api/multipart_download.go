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
// `Range: bytes=A-B` requests against that single URL; S3 supports Range
// natively on every GET, so no server-side change is required.
//
// Per-part retry is independent: a stalled part doesn't block its peers,
// and a transient failure on one byte range only re-fetches that range
// instead of restarting the whole download.

const (
	// DefaultDownloadConcurrency is what callers get when they don't pass
	// an explicit thread count. 4 is a conservative default: high enough
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
	// avoiding sub-MB ranges.
	minDownloadChunkSize = 1024 * 1024

	// defaultDownloadPartSize is the range size when neither the caller nor
	// the server suggests one.
	defaultDownloadPartSize = 8 * 1024 * 1024

	// maxDownloadPartSize caps a range, and so each worker's buffer,
	// whatever the server suggests.
	maxDownloadPartSize = 64 * 1024 * 1024
)

// MultipartDownloadOptions configures parallel Range downloads.
type MultipartDownloadOptions struct {
	// Threads is the maximum number of concurrent Range GETs. 0 means use
	// DefaultDownloadConcurrency. Values are clamped to [1, MaxDownloadConcurrency].
	Threads int

	// PartSize overrides the server-suggested part size. 0 means use the
	// value the API returned. Values below minDownloadChunkSize are clamped up.
	PartSize int64

	// OnProgress is called with (transferredBytes, totalBytes) as parts complete.
	OnProgress func(transferred, total int64)

	// OnDebug is called with structured debug events. Optional.
	OnDebug func(step, message string)

	// PresignExpiryMinutes requests presigned URL lifetime in minutes.
	// Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30). A download that outlives
	// it presigns again.
	PresignExpiryMinutes int
}

// errPresignRefused is a Range GET answered with 403: the presigned URL
// expired or was revoked. The download presigns again and retries.
var errPresignRefused = errors.New("presigned URL refused (403)")

// DownloadToFile downloads a revision's stored object into dst, writing
// each byte range at its offset, so memory stays at one range buffer per
// thread whatever the object's size. size is what the caller expects, the
// manifest's ciphertext_size: the download refuses an object the server
// reports with any other size, before fetching anything.
//
// One presigned URL serves every range. It is presigned again when a range
// is refused with 403, or when it is close to expiring, so a download can
// run longer than the URL's lifetime.
//
// Security: dst holds ciphertext that the caller checks against the signed
// manifest's digest before any plaintext is released, so Range stitching
// does not bypass integrity. Range responses are size-bounded, so a
// compromised S3 cannot over-read into adjacent objects' data.
func (c *Client) DownloadToFile(revisionID string, dst io.WriterAt, size int64, opts MultipartDownloadOptions) error {
	if size <= 0 {
		return fmt.Errorf("download: invalid size %d", size)
	}
	debugf := func(step, format string, args ...any) {
		if opts.OnDebug == nil {
			return
		}
		opts.OnDebug(step, fmt.Sprintf(format, args...))
	}

	urls := &presignedDownload{c: c, revisionID: revisionID, expiry: resolveExpiryMinutes(opts.PresignExpiryMinutes)}
	plan, err := urls.renew("")
	if err != nil {
		return err
	}
	if plan.Size > 0 && plan.Size != size {
		return fmt.Errorf("download: the server reports %d bytes, the signed manifest says %d", plan.Size, size)
	}

	partSize := opts.PartSize
	if partSize <= 0 {
		partSize = plan.PartSize
	}
	if partSize <= 0 {
		partSize = defaultDownloadPartSize
	}
	partSize = min(max(partSize, minDownloadChunkSize), maxDownloadPartSize, size)
	threads := opts.Threads
	if threads <= 0 {
		threads = DefaultDownloadConcurrency
	}
	threads = min(threads, MaxDownloadConcurrency)

	type span struct {
		idx        int
		start, end int64 // [start, end] inclusive (HTTP Range semantics)
	}
	var spans []span
	for start, idx := int64(0), 0; start < size; idx++ {
		end := min(start+partSize, size) - 1
		spans = append(spans, span{idx: idx, start: start, end: end})
		start = end + 1
	}
	threads = min(threads, len(spans))

	debugf("plan", "object=%s", humanBytesLocal(size))
	debugf("plan", "parts=%d", len(spans))
	debugf("plan", "part_size=%s", humanBytesLocal(partSize))
	debugf("plan", "threads=%d", threads)

	var transferred int64
	var transferredMu sync.Mutex
	workCh := make(chan span, len(spans))
	for _, s := range spans {
		workCh <- s
	}
	close(workCh)

	errCh := make(chan error, threads)
	failed := make(chan struct{})
	var failOnce sync.Once
	fail := func(err error) {
		failOnce.Do(func() {
			errCh <- err
			close(failed)
		})
	}
	var wg sync.WaitGroup
	ctx := c.reqCtx()
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			buf := make([]byte, partSize)
			for s := range workCh {
				select {
				case <-ctx.Done():
					fail(ctx.Err())
					return
				case <-failed:
					return
				default:
				}
				part := buf[:s.end-s.start+1]
				if err := c.downloadRange(urls, s.start, s.end, part, debugf, workerID, s.idx); err != nil {
					fail(err)
					return
				}
				if _, err := dst.WriteAt(part, s.start); err != nil {
					fail(fmt.Errorf("write range %d-%d: %w", s.start, s.end, err))
					return
				}
				if opts.OnProgress != nil {
					transferredMu.Lock()
					transferred += int64(len(part))
					t := transferred
					transferredMu.Unlock()
					opts.OnProgress(t, size)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	if err, ok := <-errCh; ok && err != nil {
		return err
	}
	debugf("done", "got=%d bytes", size)
	return nil
}

// presignedDownload holds the presigned URL a download shares, and renews
// it once for every worker that finds it expired.
type presignedDownload struct {
	c          *Client
	revisionID string
	expiry     int // minutes

	mu      sync.Mutex
	url     string
	renewAt time.Time
}

// current returns the URL to use, renewing it first when it is close to
// expiring.
func (p *presignedDownload) current() (string, error) {
	p.mu.Lock()
	url, renewAt := p.url, p.renewAt
	p.mu.Unlock()
	if time.Now().Before(renewAt) {
		return url, nil
	}
	plan, err := p.renew(url)
	if err != nil {
		return "", err
	}
	return plan.URL, nil
}

// renew presigns again unless another worker already replaced stale.
func (p *presignedDownload) renew(stale string) (*PresignDownloadPlan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.url != "" && p.url != stale && time.Now().Before(p.renewAt) {
		return &PresignDownloadPlan{URL: p.url}, nil
	}
	plan, err := p.c.presignDownloadPlan(p.revisionID, p.expiry)
	if err != nil {
		return nil, err
	}
	// Renew two minutes before expiry, or at three quarters of a short
	// lifetime.
	lifetime := time.Duration(p.expiry) * time.Minute
	margin := min(2*time.Minute, lifetime/4)
	p.url, p.renewAt = plan.URL, time.Now().Add(lifetime-margin)
	return plan, nil
}

// downloadRange fetches one byte range into dst, retrying on transient
// errors and presigning again when the URL is refused. dst MUST already be
// sized to len = end-start+1.
func (c *Client) downloadRange(urls *presignedDownload, start, end int64, dst []byte, debugf func(step, format string, args ...any), workerID, partIdx int) error {
	expected := end - start + 1
	if int64(len(dst)) != expected {
		return fmt.Errorf("downloadRange: dst size %d != expected %d", len(dst), expected)
	}

	ctx := c.reqCtx()
	var lastErr error
	renewed := false
	for attempt := 0; attempt <= downloadPartMaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			// A freshly presigned URL is retried at once; anything else
			// backs off first.
			if !renewed {
				if err := retryBackoff(ctx, attempt); err != nil {
					return err
				}
			}
			debugf("retry", "worker=%d part=%d attempt=%d range=%d-%d err=%v", workerID, partIdx, attempt, start, end, lastErr)
		}
		renewed = false
		url, err := urls.current()
		if err != nil {
			return err
		}
		t0 := time.Now()
		if err := c.doRangeGET(url, start, end, dst); err != nil {
			// A range that ran out its own deadline is retried; a
			// cancelled download is not.
			stalled := errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil
			if errors.Is(err, errPresignRefused) {
				debugf("presign", "range %d-%d refused, presigning again", start, end)
				if _, rerr := urls.renew(url); rerr != nil {
					return rerr
				}
				renewed = true
			} else if !stalled && !isDownloadRetryable(err) {
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
	// A per-request deadline, so a stalled range fails and is retried.
	ctx, cancel := context.WithTimeout(c.reqCtx(), presignTimeout(int64(len(dst))))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", presignedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := c.presignClient.Do(req)
	if err != nil {
		return fmt.Errorf("Range GET: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent: // 206: what we expect
	case http.StatusOK:
		// Server returned the whole object instead of honoring Range.
		// Surface as a transient so the next attempt can be cleaner.
		// Falling back silently would mask a misconfigured backend.
		return fmt.Errorf("server ignored Range and returned full object (status 200)")
	case http.StatusForbidden:
		return errPresignRefused
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
	// Unwrapped errors from doRangeGET (transport blips, server-ignored-Range,
	// transient 5xx) are all retryable.
	return true
}
