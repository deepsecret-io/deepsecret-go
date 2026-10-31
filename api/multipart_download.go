// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
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

	// Logger receives the transfer's logs. Optional: nil logs nothing.
	Logger *slog.Logger

	// Status, when set, follows the download range by range for a
	// progress display.
	Status *TransferStatus

	// PresignExpiryMinutes requests presigned URL lifetime in minutes.
	// Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30). A download that outlives
	// it presigns again.
	PresignExpiryMinutes int

	// Have lists the byte ranges dst already holds from an earlier
	// download of the same object, as [from, to) offsets: only the rest is
	// fetched. The caller checks the whole object against its digest, as
	// after any download.
	Have [][2]int64

	// OnRange is called once a range is written to dst, with its [from,
	// to) offsets, one call at a time.
	OnRange func(from, to int64)
}

// MergeRanges sorts byte ranges, given as [from, to) offsets, and merges
// those that overlap or touch. It refuses a range that is empty or lies
// outside an object of size bytes. The result is a new slice.
func MergeRanges(ranges [][2]int64, size int64) ([][2]int64, error) {
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b [2]int64) int { return cmp.Compare(a[0], b[0]) })
	var out [][2]int64
	for _, r := range sorted {
		if r[0] < 0 || r[0] >= r[1] || r[1] > size {
			return nil, fmt.Errorf("byte range [%d, %d) is not within %d bytes", r[0], r[1], size)
		}
		if n := len(out); n > 0 && r[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], r[1])
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// missingRanges is what [0, size) holds beyond have, which MergeRanges
// sorted and merged.
func missingRanges(have [][2]int64, size int64) [][2]int64 {
	var out [][2]int64
	from := int64(0)
	for _, r := range have {
		if r[0] > from {
			out = append(out, [2]int64{from, r[0]})
		}
		from = r[1]
	}
	if from < size {
		out = append(out, [2]int64{from, size})
	}
	return out
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
// run longer than the URL's lifetime. It is presigned even when dst holds
// every range already (opts.Have): the server applies the secret's
// policies there and records the download.
//
// Security: dst holds ciphertext that the caller checks against the signed
// manifest's digest before any plaintext is released, so Range stitching
// does not bypass integrity, and neither do ranges kept from an earlier
// download. Range responses are size-bounded, so a compromised S3 cannot
// over-read into adjacent objects' data.
func (c *Client) DownloadToFile(revisionID string, dst io.WriterAt, size int64, opts MultipartDownloadOptions) error {
	if size <= 0 {
		return fmt.Errorf("download: invalid size %d", size)
	}
	have, err := MergeRanges(opts.Have, size)
	if err != nil {
		return fmt.Errorf("download: held %w", err)
	}
	var held int64
	for _, r := range have {
		held += r[1] - r[0]
	}
	log := Module(Logger(opts.Logger), "download")
	started := time.Now()
	complete := func(fetched int64) {
		elapsed := time.Since(started)
		log.Info("download complete", "size", Bytes(size), "fetched", Bytes(fetched),
			"elapsed", elapsed.Round(time.Millisecond), "rate", RateOf(fetched, elapsed))
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

	var spans [][2]int64 // [from, to)
	for _, gap := range missingRanges(have, size) {
		for from := gap[0]; from < gap[1]; from += partSize {
			spans = append(spans, [2]int64{from, min(from+partSize, gap[1])})
		}
	}

	if len(spans) == 0 {
		opts.Status.start(size, 0, size, 0, nil)
		if opts.OnProgress != nil {
			opts.OnProgress(size, size)
		}
		complete(0)
		return nil
	}

	// What sized the ranges: the caller, the server's suggestion when it
	// is larger than the rule's, or the rule.
	sizing := PieceSizeRule
	switch {
	case opts.PartSize > 0:
		sizing = "requested"
	case plan.PartSize > downloadPartSize(size):
		sizing = "server"
	}
	ctx, cancel := context.WithCancelCause(c.reqCtx())
	defer cancel(nil)
	lim := newLimiter(ctx, opts.Threads, min(MaxDownloadConcurrency, len(spans)), 0)
	sched := newRangeScheduler(spans, opts.Status, minSplit)
	// One presigned URL serves every range; once every range has started,
	// an idle connection splits the range in flight with the most left
	// (split_min is the smallest half).
	planArgs := []any{"size", Bytes(size)}
	if held > 0 {
		planArgs = append(planArgs, "held", Bytes(held))
	}
	log.Debug("plan", append(planArgs, "ranges", len(spans), "range_size", Bytes(partSize), "sizing", sizing,
		"url_expiry", time.Duration(urls.expiry)*time.Minute, "url_renew_before", urls.renewMargin(), "split_min", Bytes(sched.minSplit))...)
	threads := Module(log, "threads")
	threads.Debug("plan", threadsPlan(lim, opts.Threads, MaxDownloadConcurrency, "range")...)
	log.Debug("retry plan", retryPlan()...)
	go lim.tune(ctx, func(from, to int, rate float64, reason string) {
		logThreads(threads, from, to, rate, reason)
	})
	opts.Status.start(size, len(spans), held, 0, lim)

	var transferred atomic.Int64
	transferred.Store(held)
	if held > 0 && opts.OnProgress != nil {
		opts.OnProgress(held, size)
	}
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
				p := sched.take(log)
				if p == nil {
					lim.release()
					return
				}
				err := c.downloadPiece(ctx, log, urls, lim, p, dst)
				lim.release()
				sched.done(p)
				opts.Status.end(p.conn, err == nil)
				if err != nil {
					cancel(err)
					return
				}
				from, to := p.extent()
				progressMu.Lock()
				done := transferred.Add(to - from)
				if opts.OnRange != nil {
					opts.OnRange(from, to)
				}
				if opts.OnProgress != nil {
					opts.OnProgress(done, size)
				}
				progressMu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	complete(size - held)
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

// ── Tail splitting ──────────────────────────────────────────────────────────
//
// Ranges go out in order. Once every range has started, a connection that
// finishes has nothing left to fetch, and the download waits on the last
// few ranges, however slow their connections. So a connection with
// nothing to do takes the second half of what the range in flight with
// the most left has not fetched yet: that range's end moves down, its
// connection stops there, and the half becomes a range of its own. Halves
// are at least minSplit bytes, so a split is worth its request.

// minSplit is the smallest half a split leaves on either connection;
// tests shorten it.
var minSplit int64 = 4 << 20

// piece is a byte range one connection fetches: one of the download's
// ranges, or a half split off one. Its end moves down when another
// connection takes the rest.
type piece struct {
	n     int   // its number in the status and logs, from 1
	start int64 // its first byte
	conn  *connRun

	mu   sync.Mutex
	next int64 // the first byte not yet written, or claimed by the write in progress
	end  int64 // one past its last byte
}

// claim takes up to n bytes of p, from its first byte not yet written, for
// the write about to happen. It returns where they start and how many it
// took: fewer than n once p's end is reached.
func (p *piece) claim(n int) (int64, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := p.next
	k := int(min(int64(n), p.end-at))
	p.next += int64(k)
	return at, k
}

// rest is what p has left to fetch, as [from, to).
func (p *piece) rest() (int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.next, p.end
}

// extent is all of p, as [from, to), with its end as it stands.
func (p *piece) extent() (int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.start, p.end
}

// written is how many of p's bytes are written, or claimed by the write in
// progress.
func (p *piece) written() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.next - p.start
}

// left is how many of p's bytes are not claimed yet.
func (p *piece) left() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.end - p.next
}

// split moves p's end down to the middle of what it has not claimed, when
// each half is at least minSize, and returns the second half as [from, to).
// A write already claimed stays below the middle, so the two connections
// never write the same byte.
func (p *piece) split(minSize int64) (from, to int64, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Halved rather than minSize doubled, which overflows for a huge
	// minSize; and never below a byte, so no half is empty.
	half := (p.end - p.next) / 2
	if half < max(minSize, 1) {
		return 0, 0, false
	}
	mid := p.next + half
	from, to, p.end = mid, p.end, mid
	p.conn.shrink(mid - p.start)
	return from, to, true
}

// rangeScheduler hands out a download's ranges in order, then, once none is
// left, halves of the ranges in flight.
type rangeScheduler struct {
	spans    [][2]int64 // [from, to)
	status   *TransferStatus
	minSplit int64

	mu       sync.Mutex
	next     int // the next span to hand out
	numbered int // the pieces handed out so far
	inFlight map[*piece]struct{}
}

func newRangeScheduler(spans [][2]int64, status *TransferStatus, minSplit int64) *rangeScheduler {
	return &rangeScheduler{spans: spans, status: status, minSplit: minSplit, inFlight: map[*piece]struct{}{}}
}

// take returns the next range, or once every range has started, the second
// half of the range in flight with the most left to fetch, and logs the
// split. It returns nil when nothing is worth taking: what is in flight
// only shrinks, so nothing will be later either.
func (s *rangeScheduler) take(log *slog.Logger) *piece {
	p, victim, size := s.pick()
	if victim != nil {
		log.Debug("range split", "part", victim.n, "new_part", p.n, "size", Bytes(size))
	}
	return p
}

// pick is take without its log record, which waits until the lock is
// released. For a split it also returns the piece the half came from, and
// the half's size.
func (s *rangeScheduler) pick() (*piece, *piece, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var from, to int64
	var victim *piece
	if s.next < len(s.spans) {
		from, to = s.spans[s.next][0], s.spans[s.next][1]
		s.next++
	} else {
		var most int64
		for p := range s.inFlight {
			if left := p.left(); left > most {
				victim, most = p, left
			}
		}
		if victim == nil {
			return nil, nil, 0
		}
		var ok bool
		if from, to, ok = victim.split(s.minSplit); !ok {
			return nil, nil, 0
		}
		s.status.addPart()
	}
	s.numbered++
	p := &piece{n: s.numbered, start: from, next: from, end: to}
	p.conn = s.status.begin(p.n, to-from)
	s.inFlight[p] = struct{}{}
	return p, victim, to - from
}

// done takes p out of the pieces that can be split.
func (s *rangeScheduler) done(p *piece) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, p)
}

// downloadPiece fetches p into dst, retrying transient failures from the
// first byte not yet written and presigning again when the URL is
// refused, and logs each retry. It stops at p's end as it stands, which a
// split can move down.
func (c *Client) downloadPiece(ctx context.Context, log *slog.Logger, urls *presignedDownload, lim *limiter, p *piece, dst io.WriterAt) error {
	var lastErr error
	renewed := false
	t0 := time.Now()
	complete := func() {
		start, end := p.extent()
		Trace(log, "range complete", "part", p.n, "offset", start, "size", Bytes(end-start), "elapsed", time.Since(t0).Round(time.Millisecond))
	}
	for attempt := 0; attempt < multipartAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			p.conn.retry(attempt+1, p.written())
			// A freshly presigned URL is retried at once; anything else
			// backs off first.
			if !renewed {
				if err := retryBackoff(ctx, attempt); err != nil {
					return err
				}
			}
		}
		renewed = false
		from, to := p.rest()
		if from >= to {
			break
		}
		url, err := urls.current()
		if err != nil {
			return err
		}
		if attempt > 0 {
			p.conn.resume()
		}
		if err := c.doRangeGET(ctx, url, p, from, to, dst, lim.add); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, errPresignRefused) {
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
			if attempt+1 < multipartAttempts {
				next, end := p.rest()
				log.Warn("retrying request", "part", p.n, "attempt", attempt+2, "attempts", multipartAttempts,
					"offset", next, "size", Bytes(end-next), "error", err)
			}
			continue
		}
		complete()
		return nil
	}
	if from, to := p.rest(); from >= to {
		complete()
		return nil
	}
	start, end := p.extent()
	return fmt.Errorf("range %d-%d after %d attempts: %w", start, end-1, multipartAttempts, lastErr)
}

// doRangeGET requests [from, to) of the object and streams it into dst
// through p, so memory does not grow with the range size: it writes what
// arrives up to p's end as it stands, and returns nil once p is written.
// A fresh request per attempt keeps retries clear of stale connection
// state. onBytes sees the bytes as they arrive. A range that moves no
// bytes for stallTimeout is cancelled; a slow one that keeps moving is
// not.
func (c *Client) doRangeGET(ctx context.Context, presignedURL string, p *piece, from, to int64, dst io.WriterAt, onBytes func(int)) error {
	expected := to - from
	guard := newStallGuard(ctx)
	defer guard.stop()
	req, err := http.NewRequestWithContext(guard.ctx, "GET", presignedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", from, to-1))

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorExcerpt))
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
	out := &pieceWriter{p: p, dst: dst}
	n, err := io.Copy(out, body)
	switch {
	case out.err != nil:
		return &writeError{err: out.err}
	case errors.Is(err, errPieceDone):
		return nil // p's end moved down, and it is written
	case err != nil && guard.stalled():
		return fmt.Errorf("Range GET body: %w", errStalled)
	case err != nil:
		return fmt.Errorf("Range GET body (%d of %d bytes): %w", n, expected, err)
	}
	if next, end := p.rest(); next < end {
		return fmt.Errorf("short Range GET body: %d of %d bytes", n, expected)
	}
	return nil
}

// errPieceDone stops a range's copy at its end, which a split may have
// moved down while the response was arriving.
var errPieceDone = errors.New("range written")

// pieceWriter writes what a range's response brings into dst at its
// offsets, up to the piece's end as it stands at each write. It remembers
// a failed write, so a full disk is told apart from a dropped connection.
type pieceWriter struct {
	p   *piece
	dst io.WriterAt
	err error
}

func (w *pieceWriter) Write(b []byte) (int, error) {
	at, n := w.p.claim(len(b))
	if n > 0 {
		m, err := w.dst.WriteAt(b[:n], at)
		w.p.conn.add(m)
		if err != nil {
			w.err = err
			return m, err
		}
	}
	if n < len(b) {
		return n, errPieceDone
	}
	return n, nil
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
