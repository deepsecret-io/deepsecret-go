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
	"sync/atomic"
	"time"
)

// ── Parallel Range download ─────────────────────────────────────────────────
//
// One presigned GET URL is requested up front. We fan out concurrent
// `Range: bytes=A-B` requests against that single URL; S3 supports Range
// natively on every GET, so no server-side change is required. How many
// run at once adapts to the link (adaptive.go).
//
// Per-part retry is independent: a stalled part doesn't block its peers,
// and a transient failure on one byte range only re-fetches that range
// instead of restarting the whole download.

const (
	// MaxDownloadConcurrency caps concurrent Range GETs. 64 is well below
	// the open-fd / TCP-stream-per-host limits on every supported OS, and
	// well above the point of diminishing returns for any realistic
	// backbone.
	MaxDownloadConcurrency = 64

	// minDownloadChunkSize keeps per-request overhead under control by
	// avoiding sub-MB ranges.
	minDownloadChunkSize = 1024 * 1024

	// maxDownloadPartSize caps a range whatever the server suggests.
	maxDownloadPartSize = 64 * 1024 * 1024
)

// downloadPartSize is the range size for an object of size bytes: larger
// objects get larger ranges, which means fewer requests and better
// throughput per connection, as uploads get larger parts.
func downloadPartSize(size int64) int64 {
	switch {
	case size >= 16<<30:
		return 64 << 20
	case size >= 1<<30:
		return 32 << 20
	default:
		return 8 << 20
	}
}

// MultipartDownloadOptions configures parallel Range downloads.
type MultipartDownloadOptions struct {
	// Threads fixes the number of concurrent Range GETs, at most
	// MaxDownloadConcurrency. 0 adapts it to the link.
	Threads int

	// PartSize overrides the range size. 0 picks it from the object's
	// size, or the server's suggestion when that is larger. Values below
	// minDownloadChunkSize are clamped up.
	PartSize int64

	// OnProgress is called with (transferredBytes, totalBytes) as ranges
	// complete, one call at a time.
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
		partSize = max(downloadPartSize(size), plan.PartSize)
	}
	partSize = min(max(partSize, minDownloadChunkSize), maxDownloadPartSize, size)

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

	ctx, cancel := context.WithCancelCause(c.reqCtx())
	defer cancel(nil)
	lim := newLimiter(ctx, opts.Threads, min(MaxDownloadConcurrency, len(spans)), 0)
	rule := PieceSizeRule
	if opts.PartSize > 0 {
		rule = "requested"
	}
	debugf("plan", "download: %s in %d range(s) of %s (%s)", humanBytesLocal(size), len(spans), humanBytesLocal(partSize), rule)
	debugf("plan", "threads: %s", threadsPlan(lim, opts.Threads, MaxDownloadConcurrency, "range"))
	debugf("plan", "URL: one presigned URL for every range, valid %dm, presigned again %s before it expires or when storage refuses it",
		urls.expiry, roundDuration(urls.renewMargin()))
	debugf("plan", "retries: %s", retryPlan())
	go lim.tune(ctx, func(from, to int, rate float64, reason string) {
		debugf("threads", "%s", threadsChange(from, to, rate, reason))
	})

	var transferred atomic.Int64
	var next atomic.Int64
	var progressMu sync.Mutex
	var wg sync.WaitGroup
	for range lim.max {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if lim.acquire(ctx) != nil {
					return
				}
				k := int(next.Add(1)) - 1
				if k >= len(spans) {
					lim.release()
					return
				}
				s := spans[k]
				err := c.downloadRange(ctx, urls, lim, s.start, s.end, dst, debugf, s.idx)
				lim.release()
				if err != nil {
					cancel(err)
					return
				}
				if opts.OnProgress != nil {
					progressMu.Lock()
					opts.OnProgress(transferred.Add(s.end-s.start+1), size)
					progressMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
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
	lifetime := time.Duration(p.expiry) * time.Minute
	p.url, p.renewAt = plan.URL, time.Now().Add(lifetime-p.renewMargin())
	return plan, nil
}

// renewMargin is how long before the URL expires it is presigned again:
// two minutes, or a quarter of a short lifetime.
func (p *presignedDownload) renewMargin() time.Duration {
	return min(2*time.Minute, time.Duration(p.expiry)*time.Minute/4)
}

// downloadRange fetches one byte range into dst at its offset, retrying on
// transient errors and presigning again when the URL is refused. A retry
// overwrites what a failed attempt wrote.
func (c *Client) downloadRange(ctx context.Context, urls *presignedDownload, lim *limiter, start, end int64, dst io.WriterAt, debugf func(step, format string, args ...any), partIdx int) error {
	expected := end - start + 1

	var lastErr error
	renewed := false
	for attempt := 0; attempt < multipartAttempts; attempt++ {
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
			debugf("retry", "part=%d attempt=%d range=%d-%d err=%v", partIdx, attempt, start, end, lastErr)
		}
		renewed = false
		url, err := urls.current()
		if err != nil {
			return err
		}
		t0 := time.Now()
		if err := c.doRangeGET(ctx, url, start, end, dst, lim.add); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, errPresignRefused) {
				debugf("presign", "range %d-%d refused, presigning again", start, end)
				if _, rerr := urls.renew(url); rerr != nil {
					return rerr
				}
				renewed = true
			} else if isDownloadRetryable(err) {
				lim.failed()
			} else {
				return err
			}
			lastErr = err
			continue
		}
		debugf("range", "part %d range=%d-%d size=%s in %s", partIdx+1, start, end, humanBytesLocal(expected), time.Since(t0).Round(time.Millisecond))
		return nil
	}
	return fmt.Errorf("range %d-%d after %d attempts: %w", start, end, multipartAttempts, lastErr)
}

// doRangeGET performs a single Range request and streams the bytes into
// dst at start, so memory does not grow with the range size. It writes
// exactly end-start+1 bytes or returns an error. We use a fresh request per
// attempt so retries don't see stale connection state. onBytes sees the
// bytes as they arrive. A range that moves no bytes for stallTimeout is
// cancelled; a slow one that keeps moving is not.
func (c *Client) doRangeGET(ctx context.Context, presignedURL string, start, end int64, dst io.WriterAt, onBytes func(int)) error {
	expected := end - start + 1
	guard := newStallGuard(ctx)
	defer guard.stop()
	req, err := http.NewRequestWithContext(guard.ctx, "GET", presignedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := c.doPresigned(req)
	if err != nil {
		if guard.stalled() {
			return fmt.Errorf("Range GET: %w", errStalled)
		}
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
			return errors.New(storageFailure("Range GET transient", resp.StatusCode, body))
		}
		return errors.New(storageFailure("Range GET failed", resp.StatusCode, body))
	}

	// Strict: the response must report Content-Length matching the requested
	// span. A short read here is a serious enough signal to surface.
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n != expected {
			return fmt.Errorf("Range GET length mismatch: got %d, want %d", n, expected)
		}
	}

	body := &progressReader{r: resp.Body, cb: func(n int) {
		guard.moved()
		onBytes(n)
	}}
	out := &writeTracker{w: io.NewOffsetWriter(dst, start)}
	n, err := io.CopyN(out, body, expected)
	switch {
	case out.err != nil:
		return &writeError{err: out.err}
	case err != nil && guard.stalled():
		return fmt.Errorf("Range GET body: %w", errStalled)
	case err != nil:
		return fmt.Errorf("Range GET body (%d of %d bytes): %w", n, expected, err)
	}
	return nil
}

// writeTracker remembers a failed write, so a full disk is told apart from
// a dropped connection.
type writeTracker struct {
	w   io.Writer
	err error
}

func (t *writeTracker) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	if err != nil {
		t.err = err
	}
	return n, err
}

// writeError is a range that arrived but could not be written: not worth
// retrying.
type writeError struct{ err error }

func (e *writeError) Error() string { return "write download: " + e.err.Error() }
func (e *writeError) Unwrap() error { return e.err }

// isDownloadRetryable distinguishes transient network/server failures from
// hard errors that won't get better on retry. Context cancellation is NOT
// retryable so Ctrl+C surfaces immediately without burning the retry budget.
func isDownloadRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errStalled) {
		return true
	}
	var we *writeError
	if errors.As(err, &we) {
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
