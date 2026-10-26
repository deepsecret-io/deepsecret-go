// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"errors"
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
// The ceiling is the smallest of the transfer's own cap, what its part
// buffers allow in memory, and the number of parts.

const (
	// adaptiveStartThreads is where every adaptive transfer starts.
	adaptiveStartThreads = 4
	// adaptiveGain is the throughput rise a doubling must bring to be kept.
	adaptiveGain = 1.10
	// adaptiveHoldWindows is how long a level is kept before probing again.
	adaptiveHoldWindows = 6
)

// adaptiveWindow is how often throughput is measured.
var adaptiveWindow = 5 * time.Second

// errStalled is a request that moved no bytes for stallTimeout.
var errStalled = errors.New("no data moved for too long")

// stallTimeout is how long a part transfer may move no bytes before it is
// cancelled and retried. A slow but moving transfer is never cut off.
var stallTimeout = 90 * time.Second

// limiter gates a transfer's concurrent requests. Workers acquire a slot
// for each part; tune adjusts the number of slots.
type limiter struct {
	mu     sync.Mutex
	cond   *sync.Cond
	active int
	limit  int
	max    int

	moved  atomic.Int64 // bytes moved, for throughput
	errors atomic.Int64 // retryable failures and throttling
}

// newLimiter gates requests at fixed slots when threads > 0, and otherwise
// starts at adaptiveStartThreads and adapts up to ceiling. Waiters wake when
// ctx ends.
func newLimiter(ctx context.Context, threads, ceiling int) *limiter {
	ceiling = max(1, ceiling)
	l := &limiter{max: ceiling, limit: min(adaptiveStartThreads, ceiling)}
	if threads > 0 {
		l.max = min(threads, ceiling)
		l.limit = l.max
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

// tune adapts the slots every adaptiveWindow until ctx ends. A fixed
// limiter (max reached at the start, or threads set) only reports.
func (l *limiter) tune(ctx context.Context, report func(threads int, bytesPerSec float64)) {
	if l.current() >= l.max {
		return
	}
	t := &tuner{limit: l.current(), max: l.max, settle: true}
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
				report(t.limit, rate)
			}
			lastMoved, lastErrs, lastAt = moved, errs, now
		}
	}
}

// tuner decides the next number of slots from each window's throughput.
type tuner struct {
	limit, max int
	prev       int     // the level before an increase being judged, else 0
	base       float64 // throughput at prev
	settle     bool    // the window after a change is ramp-up: not judged
	hold       int     // windows left before probing again
}

func (t *tuner) next(rate float64, errs int64) int {
	switch {
	case errs > 0:
		// Failures or throttling: halve, and wait before probing again.
		t.limit = max(1, t.limit/2)
		t.prev, t.settle, t.hold = 0, true, adaptiveHoldWindows
	case t.settle:
		t.settle = false
	case t.prev > 0 && rate > t.base*adaptiveGain:
		// The doubling paid off: keep it and try the next one.
		t.prev = 0
		t.probe(rate)
	case t.prev > 0:
		// It did not: go back and hold there for a while.
		t.limit, t.prev, t.settle, t.hold = t.prev, 0, true, adaptiveHoldWindows
	case t.hold > 0:
		t.hold--
	default:
		t.probe(rate)
	}
	return t.limit
}

// probe doubles the slots, remembering the level and its throughput.
func (t *tuner) probe(rate float64) {
	if t.limit >= t.max {
		t.hold = adaptiveHoldWindows
		return
	}
	t.prev, t.base = t.limit, rate
	t.limit = min(t.max, t.limit*2)
	t.settle = true
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
