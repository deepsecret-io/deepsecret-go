// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"cmp"
	"context"
	"crypto/md5" // #nosec G501 -- MD5 only as S3 requires it: Content-MD5 and part ETags, transfer checksums, never a security control.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

	// MaxUploadThreads caps concurrent part PUTs. Uploads adapt below it
	// (adaptive.go) unless the caller fixes the number.
	MaxUploadThreads = 32

	// multipartAttempts is how many times a part PUT, or an API call of
	// the upload, is tried before the upload fails. With backoff capped at
	// a minute, a part rides out a few minutes of outage.
	multipartAttempts = 8

	// partURLBatch is how many part URLs one API call presigns: the part a
	// worker needs and the ones queued after it.
	partURLBatch = 100

	// partURLRenewMargin is how long before a part URL expires it is
	// fetched again.
	partURLRenewMargin = 30 * time.Second
)

// ── Wire types ──────────────────────────────────────────────────────────────

// MultipartInitResponse is returned by POST /multipart/init.
type MultipartInitResponse struct {
	UploadID      string    `json:"upload_id"`
	PartSize      int64     `json:"part_size"`
	MaxPartNumber int       `json:"max_part_number"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// MultipartPartURLsResponse is returned by POST /multipart/part-urls: one
// URL per requested part, each signing the part's exact size.
type MultipartPartURLsResponse struct {
	Parts     []MultipartPartURL `json:"parts"`
	ExpiresIn int                `json:"expires_in"` // seconds
}

// MultipartPartURL is the presigned upload URL of one part.
type MultipartPartURL struct {
	PartNumber int    `json:"part_number"`
	URL        string `json:"url"`
}

// MultipartPartStatus is one part that storage holds.
type MultipartPartStatus struct {
	PartNumber int    `json:"part_number"`
	Etag       string `json:"etag"`
	Size       int64  `json:"size"`
}

// MultipartStatus is returned by GET /multipart/status. Parts are what
// storage holds for the upload.
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

// MultipartPartURLs presigns upload URLs for up to 100 distinct parts.
func (c *Client) MultipartPartURLs(revisionID string, partNumbers []int) (*MultipartPartURLsResponse, error) {
	resp, err := c.Post("/api/v1/secrets/revisions/"+revisionID+"/multipart/part-urls", map[string]any{
		"part_numbers": partNumbers,
	})
	if err != nil {
		return nil, fmt.Errorf("multipart part-urls: %w", err)
	}
	var out MultipartPartURLsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, fmt.Errorf("parse part-urls: %w", err)
	}
	return &out, nil
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

// MultipartStatus loads the upload's state and the parts storage holds.
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
// Tiny duplicate of the helper in the parent sdk package: sdk/api can't
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

// MultipartUploadOptions configures the multipart-upload helper.
type MultipartUploadOptions struct {
	// Threads fixes the number of concurrent part PUTs, at most
	// MaxUploadThreads. 0 adapts it to the link (adaptive.go).
	Threads int
	// OnProgress is called with (transferredBytes, totalBytes) as bytes
	// go out, one call at a time. The count drops back when a failed part
	// is retried.
	OnProgress func(int64, int64)
	// OnDebug is called with structured debug events.
	OnDebug func(step, message string)
	// Status, when set, follows the upload part by part for a progress
	// display.
	Status *TransferStatus
}

// uploadPart is one part's range of the source.
type uploadPart struct {
	Number int
	Offset int64
	Size   int64
}

// MultipartUploadOpts uploads the size bytes of src to the revision through
// the multipart flow: init, part URLs a hundred at a time, parallel part
// PUTs, complete. The server reads the uploaded parts from storage, so no
// part is registered on its own.
//
// It resumes. Parts that storage already holds from an earlier attempt are
// kept when they have the right size and, when storage reports an MD5
// ETag (S3 and R2 do for these uploads), the same bytes as src; the rest
// are sent. A failed upload stays in progress for a later call to resume,
// until the server's orphan cleanup aborts it after a day without
// activity.
//
// Parts stream from src to the network, read once for their Content-MD5
// and again as they are sent, so src can be a file of any size and memory
// does not grow with the part size or the number of threads.
func (c *Client) MultipartUploadOpts(revisionID string, src io.ReaderAt, totalSize int64, opts MultipartUploadOptions) error {
	if totalSize <= 0 {
		return fmt.Errorf("multipart upload: empty data")
	}
	debugf := func(step, format string, args ...any) {
		if opts.OnDebug != nil {
			opts.OnDebug(step, fmt.Sprintf(format, args...))
		}
	}
	ctx, cancel := context.WithCancelCause(c.reqCtx())
	defer cancel(nil)

	var init *MultipartInitResponse
	if err := c.retryAPI(ctx, func() (err error) {
		init, err = c.MultipartInit(revisionID)
		return err
	}); err != nil {
		return err
	}
	if init.PartSize < S3MinPartSize || init.PartSize > S3MaxPartSize {
		return fmt.Errorf("multipart upload: server returned invalid part size %d", init.PartSize)
	}
	count := int((totalSize + init.PartSize - 1) / init.PartSize)
	if count != init.MaxPartNumber {
		// The revision's declared size does not match the data: refuse
		// rather than upload garbage.
		return fmt.Errorf("multipart upload: data size %d yields %d parts but server expects %d (revision size mismatch)", totalSize, count, init.MaxPartNumber)
	}
	if count > S3MaxParts {
		return fmt.Errorf("multipart upload: %d parts exceeds S3 limit of %d", count, S3MaxParts)
	}
	parts := make([]uploadPart, count)
	for i := range parts {
		off := int64(i) * init.PartSize
		parts[i] = uploadPart{Number: i + 1, Offset: off, Size: min(init.PartSize, totalSize-off)}
	}

	// Parts from an earlier attempt.
	var status *MultipartStatus
	if err := c.retryAPI(ctx, func() (err error) {
		status, err = c.MultipartStatus(revisionID)
		return err
	}); err != nil {
		return err
	}
	etags, kept, err := keepStoredParts(ctx, src, parts, status.Parts)
	if err != nil {
		return fmt.Errorf("multipart upload: %w", err)
	}
	var work []int
	for i := range parts {
		if etags[i] == "" {
			work = append(work, i)
		}
	}
	debugf("plan", "upload: multipart, %s in %d part(s) of %s (the server sizes parts: %s)",
		humanBytesLocal(totalSize), count, humanBytesLocal(init.PartSize), PieceSizeRule)
	if kept > 0 {
		debugf("plan", "resume: %d part(s) (%s) already in storage are kept; %d to upload", count-len(work), humanBytesLocal(kept), len(work))
	}

	var sent atomic.Int64
	sent.Store(kept)
	if opts.OnProgress != nil {
		opts.OnProgress(kept, totalSize)
	}
	var lim *limiter
	if len(work) > 0 {
		lim = newLimiter(ctx, opts.Threads, min(MaxUploadThreads, len(work)), init.PartSize)
	}
	opts.Status.start(totalSize, count, kept, count-len(work), lim)
	if len(work) > 0 {
		debugf("plan", "threads: %s", threadsPlan(lim, opts.Threads, MaxUploadThreads, "part"))
		debugf("plan", "part URLs: %d per request, fetched again %s before they expire or when storage refuses one", partURLBatch, roundDuration(partURLRenewMargin))
		debugf("plan", "retries: %s", retryPlan())
		go lim.tune(ctx, func(from, to int, rate float64, reason string) {
			debugf("threads", "%s", threadsChange(from, to, rate, reason))
		})
		var progressMu sync.Mutex
		progress := func(n int) {
			lim.add(n)
			t := min(max(sent.Add(int64(n)), 0), totalSize)
			if opts.OnProgress != nil {
				progressMu.Lock()
				opts.OnProgress(t, totalSize)
				progressMu.Unlock()
			}
		}
		queue := &partQueue{parts: parts, items: work}
		urls := &partURLCache{c: c, revisionID: revisionID, queue: queue, urls: map[int]cachedURL{}}
		var wg sync.WaitGroup
		for range lim.max {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					if lim.acquire(ctx) != nil {
						return
					}
					idx, ok := queue.pop()
					if !ok {
						lim.release()
						return
					}
					p := parts[idx]
					conn := opts.Status.begin(p.Number, p.Size)
					t0 := time.Now()
					sum, err := partMD5(src, p)
					if err == nil {
						etags[idx], err = c.uploadPart(ctx, urls, lim, conn, p, src, base64.StdEncoding.EncodeToString(sum), progress)
					}
					lim.release()
					opts.Status.end(conn, err == nil)
					if err != nil {
						cancel(fmt.Errorf("part %d: %w", p.Number, err))
						return
					}
					debugf("multipart.upload", "part %d/%d size=%s in %s", p.Number, count, humanBytesLocal(p.Size), time.Since(t0).Round(time.Millisecond))
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return fmt.Errorf("multipart upload: %w", context.Cause(ctx))
		}
	}

	final := make([]MultipartPartStatus, count)
	for i, p := range parts {
		final[i] = MultipartPartStatus{PartNumber: p.Number, Etag: etags[i], Size: p.Size}
	}
	tComp := time.Now()
	if err := c.retryAPI(ctx, func() error { return c.MultipartComplete(revisionID, final) }); err != nil {
		return err
	}
	debugf("multipart.complete", "finalized %d parts in %s", count, time.Since(tComp).Round(time.Millisecond))
	return nil
}

// keepStoredParts decides which of the parts storage already holds can
// stay, returning their ETags by part index and their total size. A stored
// part stays when it has the part's size and, when its ETag is an MD5 of
// the part, the same bytes as src: checking means reading those parts of
// src again, which is cheap next to uploading them.
func keepStoredParts(ctx context.Context, src io.ReaderAt, parts []uploadPart, stored []MultipartPartStatus) ([]string, int64, error) {
	etags := make([]string, len(parts))
	var candidates []int
	byNumber := make(map[int]MultipartPartStatus, len(stored))
	for _, s := range stored {
		byNumber[s.PartNumber] = s
	}
	for i, p := range parts {
		if s, ok := byNumber[p.Number]; ok && s.Size == p.Size && s.Etag != "" {
			candidates = append(candidates, i)
		}
	}
	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
		next    atomic.Int64
	)
	for range min(4, len(candidates)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				k := int(next.Add(1)) - 1
				if k >= len(candidates) || ctx.Err() != nil {
					return
				}
				i := candidates[k]
				p := parts[i]
				etag := strings.ToLower(strings.Trim(byNumber[p.Number].Etag, `"`))
				if isMD5Hex(etag) {
					sum, err := partMD5(src, p)
					if err != nil {
						mu.Lock()
						firstEr = cmp.Or(firstEr, err)
						mu.Unlock()
						return
					}
					if hex.EncodeToString(sum) != etag {
						continue
					}
				}
				etags[i] = etag
			}
		}()
	}
	wg.Wait()
	if firstEr != nil {
		return nil, 0, firstEr
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	var kept int64
	for i, e := range etags {
		if e != "" {
			kept += parts[i].Size
		}
	}
	return etags, kept, nil
}

func isMD5Hex(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// partMD5 reads part p of src and returns its MD5. A source shorter than
// the declared size is an error.
func partMD5(src io.ReaderAt, p uploadPart) ([]byte, error) {
	h := md5.New() // #nosec G401 -- the Content-MD5 S3 checks and the ETag a kept part is matched by; the signed manifest covers the payload's SHA-256.
	n, err := io.Copy(h, io.NewSectionReader(src, p.Offset, p.Size))
	if err == nil && n != p.Size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, fmt.Errorf("read part %d: %w", p.Number, err)
	}
	return h.Sum(nil), nil
}

// partQueue hands out the parts left to upload, in order.
type partQueue struct {
	mu    sync.Mutex
	parts []uploadPart
	items []int // indexes into parts
	next  int
}

func (q *partQueue) pop() (int, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.next >= len(q.items) {
		return 0, false
	}
	q.next++
	return q.items[q.next-1], true
}

// near returns the numbers of the last back parts handed out, which may be
// in flight, and of up to ahead parts not handed out yet.
func (q *partQueue) near(back, ahead int) []int {
	q.mu.Lock()
	defer q.mu.Unlock()
	window := q.items[max(0, q.next-back):min(len(q.items), q.next+ahead)]
	out := make([]int, len(window))
	for i, idx := range window {
		out[i] = q.parts[idx].Number
	}
	return out
}

// partURLCache holds presigned part URLs. A miss presigns the part with
// the parts in flight and queued after it, so an upload makes one API call
// per hundred parts rather than one per part.
type partURLCache struct {
	c          *Client
	revisionID string
	queue      *partQueue

	mu   sync.Mutex
	urls map[int]cachedURL

	fetchMu sync.Mutex // one batch request at a time
}

type cachedURL struct {
	url     string
	renewAt time.Time
}

func (u *partURLCache) lookup(n int) (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	e, ok := u.urls[n]
	if !ok || !time.Now().Before(e.renewAt) {
		return "", false
	}
	return e.url, true
}

// get returns a URL for part n, presigning a batch when n has none or its
// URL is about to expire.
func (u *partURLCache) get(ctx context.Context, n int) (string, error) {
	if url, ok := u.lookup(n); ok {
		return url, nil
	}
	u.fetchMu.Lock()
	defer u.fetchMu.Unlock()
	if url, ok := u.lookup(n); ok {
		return url, nil
	}
	numbers := []int{n}
	for _, m := range u.queue.near(MaxUploadThreads, 2*partURLBatch) {
		if len(numbers) == partURLBatch {
			break
		}
		if _, fresh := u.lookup(m); !fresh && m != n {
			numbers = append(numbers, m)
		}
	}
	var resp *MultipartPartURLsResponse
	if err := u.c.retryAPI(ctx, func() (err error) {
		resp, err = u.c.MultipartPartURLs(u.revisionID, numbers)
		return err
	}); err != nil {
		return "", err
	}
	// Renew 30 seconds before expiry: storage checks the expiry when a
	// request starts, so a long PUT on a URL near its end still completes.
	lifetime := time.Duration(resp.ExpiresIn) * time.Second
	renewAt := time.Now().Add(lifetime - min(partURLRenewMargin, lifetime/4))
	asked := make(map[int]bool, len(numbers))
	for _, m := range numbers {
		asked[m] = true
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, p := range resp.Parts {
		if asked[p.PartNumber] && p.URL != "" {
			u.urls[p.PartNumber] = cachedURL{url: p.URL, renewAt: renewAt}
		}
	}
	e, ok := u.urls[n]
	if !ok {
		return "", fmt.Errorf("the server did not presign part %d", n)
	}
	return e.url, nil
}

// drop forgets url for part n, after storage refused it.
func (u *partURLCache) drop(n int, url string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.urls[n].url == url {
		delete(u.urls, n)
	}
}

// retryAPI runs an API call of the upload, retrying transient failures.
func (c *Client) retryAPI(ctx context.Context, call func() error) error {
	var err error
	for attempt := 0; attempt < multipartAttempts; attempt++ {
		if attempt > 0 {
			if berr := multipartBackoff(ctx, attempt, err); berr != nil {
				return berr
			}
		}
		if err = call(); err == nil || !isMultipartRetryableErr(err) {
			return err
		}
	}
	return err
}

// uploadPart PUTs one part, retrying transient failures with backoff. A
// URL storage refuses (403, usually expired) is presigned again and
// retried at once; refused again, the upload fails, since a fresh URL
// being refused is not an expiry. Returns the part's unquoted ETag.
func (c *Client) uploadPart(ctx context.Context, urls *partURLCache, lim *limiter, conn *connRun, p uploadPart, src io.ReaderAt, contentMD5 string, onChunk func(int)) (string, error) {
	var lastErr error
	refused := false
	for attempt := 0; attempt < multipartAttempts; attempt++ {
		if attempt > 0 {
			conn.retry(attempt+1, 0) // a part is sent again whole
			if !refused {
				if err := multipartBackoff(ctx, attempt, lastErr); err != nil {
					return "", err
				}
			}
		}
		url, err := urls.get(ctx, p.Number)
		if err != nil {
			return "", err
		}
		if attempt > 0 {
			conn.resume()
		}
		var moved atomic.Int64
		sent := time.Now()
		etag, err := c.putPart(ctx, url, io.NewSectionReader(src, p.Offset, p.Size), p.Size, contentMD5, func(n int) {
			moved.Add(int64(n))
			conn.add(n)
			onChunk(n)
		})
		if err == nil {
			lim.partDone(p.Size, time.Since(sent))
			return etag, nil
		}
		// Take back the progress of the failed attempt.
		if n := moved.Load(); n > 0 {
			onChunk(-int(n))
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		switch {
		case errors.Is(err, errPresignRefused):
			if refused {
				return "", fmt.Errorf("a freshly presigned URL was refused: %w", err)
			}
			urls.drop(p.Number, url)
			refused = true
		case isPartRetryable(err):
			lim.failed()
			refused = false
		default:
			return "", err
		}
		lastErr = err
	}
	return "", fmt.Errorf("after %d attempts: %w", multipartAttempts, lastErr)
}

// storageError is a part PUT that storage answered with an error: its
// status and error code, never the body, which can echo signatures.
type storageError struct {
	status int
	code   string
}

func (e *storageError) Error() string {
	if e.code != "" {
		return fmt.Sprintf("PUT part failed (status %d, %s)", e.status, e.code)
	}
	return fmt.Sprintf("PUT part failed (status %d)", e.status)
}

// isPartRetryable reports whether a failed part PUT is worth retrying:
// transport errors, stalls, storage 5xx and throttling, and the request
// timeout S3 reports as a 400.
func isPartRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Is(err, errStalled)
	}
	var se *storageError
	if errors.As(err, &se) {
		return se.status >= 500 || se.status == http.StatusTooManyRequests ||
			(se.status == http.StatusBadRequest && se.code == "RequestTimeout")
	}
	return true
}

// isMultipartRetryableErr reports whether an API call of the upload is
// worth retrying: transport errors, 5xx and 429. Cancellation and every
// other API error (auth, validation, conflict) fail at once.
func isMultipartRetryableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.StatusCode >= 500 || apiErr.StatusCode == http.StatusTooManyRequests
}

// multipartBackoff sleeps before the next retry. A 429's Retry-After is
// honored, up to a minute; otherwise the exponential backoff applies.
// Returns ctx.Err() if the context ends during the sleep.
func multipartBackoff(ctx context.Context, attempt int, lastErr error) error {
	var apiErr *APIError
	if errors.As(lastErr, &apiErr) && apiErr.RetryAfter > 0 {
		d := min(apiErr.RetryAfter, maxBackoff)
		// ±10% jitter so clients hitting the same 429 spread out.
		d += time.Duration(float64(d) * 0.1 * secureJitter())
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	return retryBackoff(ctx, attempt)
}

// progressReader wraps an io.Reader and invokes cb with the byte count of
// each successful Read, so progress and throughput follow the bytes on the
// wire rather than whole parts.
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

// putPart PUTs one part to its presigned URL and returns the ETag. There is
// no overall deadline: a slow part keeps going as long as bytes move, and
// one that stalls for stallTimeout is cancelled. The presign client
// refuses redirects, so a 30x is fatal.
func (c *Client) putPart(ctx context.Context, presignedURL string, data io.Reader, size int64, contentMD5 string, onChunk func(int)) (string, error) {
	guard := newStallGuard(ctx)
	defer guard.stop()
	body := &progressReader{r: data, cb: func(n int) {
		guard.moved()
		onChunk(n)
	}}
	req, err := http.NewRequestWithContext(guard.ctx, "PUT", presignedURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-MD5", contentMD5)
	req.ContentLength = size

	resp, err := c.doPresigned(req)
	if err != nil {
		if guard.stalled() {
			return "", fmt.Errorf("PUT part: %w", errStalled)
		}
		return "", fmt.Errorf("PUT part: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return "", errPresignRefused
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorExcerpt))
		return "", &storageError{status: resp.StatusCode, code: storageErrorCode(msg)}
	}
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	if etag == "" {
		return "", fmt.Errorf("PUT part: storage returned no ETag")
	}
	return etag, nil
}
