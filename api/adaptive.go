// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ── Adaptive concurrency ────────────────────────────────────────────────────
//
// Uploads and downloads move parts over as many parallel connections as
// actually help. One connection rarely fills a link (TCP window, per-flow
// limits at the storage edge), but past some point more connections only
// add contention. Rather than guess, a transfer starts with a few
// connections and measures: it doubles them while throughput rises by more
// than 10%, steps back when a doubling does not pay off, and halves them
// when requests start failing or are throttled. It probes again now and
// then, since links change during a long transfer.
//
// Uploads also bound the parts in flight. Storage keeps only finished
// parts, so an interrupted upload loses the parts it was sending, and the
// parts in flight share the link: on a slow link, many at once means none
// finishes for minutes and a resume finds nothing to keep. So an upload
// starts with one part, takes adaptiveStartThreads after the first window
// only if the link can finish that many in time, and never runs more parts
// than finish within partTimeLimit at the measured rate. On a fast link
// that bound is far above the ceiling.
//
// The ceiling is the smallest of the transfer's own cap, what its part
// buffers allow in memory, and the number of parts.

const (
	// adaptiveStartThreads is where every adaptive transfer starts.
	adaptiveStartThreads = 4
	// adaptiveGainPct is the throughput rise, in percent, a doubling must
	// bring to be kept.
	adaptiveGainPct = 10
	adaptiveGain    = 1 + adaptiveGainPct/100.0
	// adaptiveHoldWindows is how long a level is kept before probing again.
	adaptiveHoldWindows = 6
)

// adaptiveWindow is how often throughput is measured.
var adaptiveWindow = 5 * time.Second

// partTimeLimit is how long an upload's parts may take at the measured
// rate: parts in flight × part size stays within rate × partTimeLimit, so
// an interruption loses about this much of the upload at most.
var partTimeLimit = time.Minute

// errStalled is a request that moved no bytes for stallTimeout.
var errStalled = errors.New("no data moved for too long")

// stallTimeout is how long a part transfer may move no bytes before it is
// cancelled and retried. A slow but moving transfer is never cut off.
var stallTimeout = 90 * time.Second

// limiter gates a transfer's concurrent requests. Workers acquire a slot
// for each part; tune adjusts the number of slots.
type limiter struct {
	mu       sync.Mutex
	cond     *sync.Cond
	active   int
	limit    int
	max      int
	partSize int64 // an upload's part size, which bounds its parts in flight

	moved  atomic.Int64 // bytes moved, for throughput
	errors atomic.Int64 // retryable failures and throttling
}

// newLimiter gates requests at fixed slots when threads > 0, and otherwise
// adapts up to ceiling: an upload of partSize parts from one part, a
// download (partSize 0) from adaptiveStartThreads. Waiters wake when ctx
// ends.
func newLimiter(ctx context.Context, threads, ceiling int, partSize int64) *limiter {
	ceiling = max(1, ceiling)
	l := &limiter{max: ceiling, limit: min(adaptiveStartThreads, ceiling)}
	switch {
	case threads > 0:
		l.max = min(threads, ceiling)
		l.limit = l.max
	case partSize > 0:
		l.limit, l.partSize = 1, partSize
	}
	l.cond = sync.NewCond(&l.mu)
	context.AfterFunc(ctx, func() {
		l.mu.Lock()
		l.cond.Broadcast()
		l.mu.Unlock()
	})
	return l
}

// acquire waits for a free slot.
func (l *limiter) acquire(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for l.active >= l.limit && ctx.Err() == nil {
		l.cond.Wait()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	l.active++
	return nil
}

func (l *limiter) release() {
	l.mu.Lock()
	l.active--
	l.cond.Broadcast()
	l.mu.Unlock()
}

func (l *limiter) current() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

func (l *limiter) set(n int) {
	l.mu.Lock()
	l.limit = n
	l.cond.Broadcast()
	l.mu.Unlock()
}

// add records bytes moved.
func (l *limiter) add(n int) {
	if n > 0 {
		l.moved.Add(int64(n))
	}
}

// failed records a retryable failure, which makes the next window back off.
func (l *limiter) failed() { l.errors.Add(1) }

// tune adapts the slots every adaptiveWindow until ctx ends, and reports
// each change with the window's throughput and the reason. A fixed limiter
// (max reached at the start, or threads set) does nothing.
func (l *limiter) tune(ctx context.Context, report func(from, to int, bytesPerSec float64, reason string)) {
	if l.current() >= l.max {
		return
	}
	t := &tuner{limit: l.current(), max: l.max, partSize: l.partSize, settle: true}
	if l.partSize > 0 {
		t.start, t.settle = true, false
	}
	ticker := time.NewTicker(adaptiveWindow)
	defer ticker.Stop()
	lastMoved, lastErrs, lastAt := l.moved.Load(), l.errors.Load(), time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			moved, errs := l.moved.Load(), l.errors.Load()
			rate := float64(moved-lastMoved) / now.Sub(lastAt).Seconds()
			before := t.limit
			l.set(t.next(rate, errs-lastErrs))
			if t.limit != before && report != nil {
				report(before, t.limit, rate, t.reason)
			}
			lastMoved, lastErrs, lastAt = moved, errs, now
		}
	}
}

// tuner decides the next number of slots from each window's throughput.
type tuner struct {
	limit, max int
	partSize   int64   // an upload's part size, else 0
	start      bool    // an upload's first window, at one part
	prev       int     // the level before an increase being judged, else 0
	base       float64 // throughput at prev
	settle     bool    // the window after a change is ramp-up: not judged
	hold       int     // windows left before probing again
	reason     string  // why the last change was made
}

func (t *tuner) next(rate float64, errs int64) int {
	top := t.partCap(rate)
	switch {
	case errs > 0:
		// Failures or throttling: halve, and wait before probing again.
		t.limit = max(1, t.limit/2)
		t.prev, t.settle, t.hold, t.start = 0, true, adaptiveHoldWindows, false
		t.reason = fmt.Sprintf("%d request(s) failed or were throttled", errs)
	case t.start:
		// An upload's first window, at one part: take the usual start if
		// the link finishes that many parts in time, else stay at one and
		// probe. A whole window, since a new connection's first second
		// counts the socket buffers it fills as sent.
		t.start, t.settle = false, true
		if top >= adaptiveStartThreads {
			t.limit = min(t.max, adaptiveStartThreads)
			t.reason = fmt.Sprintf("the link can finish %d parts at once within %s", adaptiveStartThreads, roundDuration(partTimeLimit))
		}
	case t.limit > top:
		// Too many parts for the rate: each would take over
		// partTimeLimit. Halve toward the bound, so one slow window does
		// not undo a fast link's level, and hold there.
		t.limit = max(top, t.limit/2)
		t.prev, t.settle, t.hold = 0, true, adaptiveHoldWindows
		t.reason = fmt.Sprintf("at this rate parts would take over %s each", roundDuration(partTimeLimit))
	case t.settle:
		t.settle = false
	case t.prev > 0 && rate > t.base*adaptiveGain:
		// The doubling paid off: keep it and try the next one.
		t.prev = 0
		t.probe(rate, top)
		t.reason = "the last doubling raised throughput, trying more"
	case t.prev > 0:
		// It did not: go back and hold there for a while.
		t.limit, t.prev, t.settle, t.hold = t.prev, 0, true, adaptiveHoldWindows
		t.reason = fmt.Sprintf("the doubling did not raise throughput by %d%%, stepping back", adaptiveGainPct)
	case t.hold > 0:
		t.hold--
	default:
		t.probe(rate, top)
		t.reason = "probing for more throughput"
	}
	return t.limit
}

// probe doubles the slots, up to top, remembering the level and its
// throughput.
func (t *tuner) probe(rate float64, top int) {
	top = min(t.max, top)
	if t.limit >= top {
		t.hold = adaptiveHoldWindows
		return
	}
	t.prev, t.base = t.limit, rate
	t.limit = min(top, t.limit*2)
	t.settle = true
}

// partCap is how many of an upload's parts can be in flight at rate while
// each finishes within partTimeLimit, at least one. A download has no such
// bound.
func (t *tuner) partCap(rate float64) int {
	if t.partSize <= 0 {
		return t.max
	}
	n := rate * partTimeLimit.Seconds() / float64(t.partSize)
	if !(n < float64(t.max)) {
		return t.max
	}
	return max(1, int(n))
}

// stallGuard cancels a request that moves no bytes for stallTimeout. Call
// moved on progress and stop when the request is done; stalled reports
// whether the guard cancelled it.
type stallGuard struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	last   atomic.Int64
	done   chan struct{}
}

func newStallGuard(parent context.Context) *stallGuard {
	g := &stallGuard{done: make(chan struct{})}
	g.ctx, g.cancel = context.WithCancelCause(parent)
	g.moved()
	check := min(5*time.Second, stallTimeout/4)
	go func() {
		ticker := time.NewTicker(check)
		defer ticker.Stop()
		for {
			select {
			case <-g.done:
				return
			case <-g.ctx.Done():
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, g.last.Load())) > stallTimeout {
					g.cancel(errStalled)
					return
				}
			}
		}
	}()
	return g
}

func (g *stallGuard) moved() { g.last.Store(time.Now().UnixNano()) }

func (g *stallGuard) stop() {
	close(g.done)
	g.cancel(nil)
}

func (g *stallGuard) stalled() bool { return errors.Is(context.Cause(g.ctx), errStalled) }
