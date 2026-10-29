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
// starts with one part, and takes adaptiveStartThreads only if the link
// can finish that many in time, and never runs more parts than finish
// within partTimeLimit at the measured rate. On a fast link that bound is
// far above the ceiling. The first decision waits for the first part to
// finish, whose rate is exact, or for adaptiveStartWindow: a shorter window
// would count the socket buffer filling as bytes sent.
//
// The bound takes the rate of the parts in flight as the link's, which
// holds when they share it. A path that limits each connection on its own
// (latency to storage, some VPNs, per-flow shaping) breaks that at one
// part: one connection measures slow, the bound holds the upload there,
// and it never learns that a second part would not slow the first. So the
// step from one part to two is a trial, judged on throughput rather than
// on the bound: the second part is kept when throughput rises by more than
// adaptiveGainPct, and then the bound may not take the upload below two.
// When it does not, one part fills the link, and the upload tries again
// after secondPartRetry.
//
// A window after each change lets new connections ramp up, and the next
// one judges the change. Windows are short on a fast link, so it reaches
// its level within seconds, and longer on a slow one, where a short window
// would measure noise. Short windows also catch brief stalls, so the bound
// on parts in flight is judged over adaptiveWindow at least, and a
// doubling whose window falls far below the level before it is judged
// again on the next window rather than undone at once.
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
	// adaptiveDip is how far below its base a doubling's window must fall
	// to be judged again rather than undone: more connections rarely cost
	// a fifth of the throughput, a brief stall often does.
	adaptiveDip = 0.8
	// adaptiveHold is how long a level is kept before probing again.
	adaptiveHold = 30 * time.Second
	// adaptiveFastRate is the rate from which windows are short: at
	// 4 MB/s and more, two seconds hold enough of the link to measure it.
	adaptiveFastRate = 4e6
	// secondPartRetry is how long an upload held at one part waits, after
	// a second part did not raise throughput, before trying one again.
	secondPartRetry = 5 * time.Minute
)

// adaptiveWindow is how often throughput is measured below
// adaptiveFastRate, and adaptiveFastWindow how often from it.
var (
	adaptiveWindow     = 5 * time.Second
	adaptiveFastWindow = 2 * time.Second
)

// windowFor is the measuring window after a window or part at rate.
func windowFor(rate float64) time.Duration {
	return windows{slow: adaptiveWindow, fast: adaptiveFastWindow}.after(rate)
}

// windows are the window lengths of one transfer, read once when it
// starts: its tuner may outlive it by a window.
type windows struct{ slow, fast time.Duration }

func (w windows) after(rate float64) time.Duration {
	if rate >= adaptiveFastRate {
		return w.fast
	}
	return w.slow
}

// adaptiveStartWindow is the longest an upload waits for its first part
// before its first decision.
var adaptiveStartWindow = 5 * time.Second

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

	firstPart chan float64 // an upload's first finished part's rate, bytes/s

	// The tuning's timings, read when the transfer starts: its tuner can
	// outlive it by a window, and tests change them between transfers.
	win      windows
	startWin time.Duration
	partTime time.Duration
}

// newLimiter gates requests at fixed slots when threads > 0, and otherwise
// adapts up to ceiling: an upload of partSize parts from one part, a
// download (partSize 0) from adaptiveStartThreads. Waiters wake when ctx
// ends.
func newLimiter(ctx context.Context, threads, ceiling int, partSize int64) *limiter {
	ceiling = max(1, ceiling)
	l := &limiter{max: ceiling, limit: min(adaptiveStartThreads, ceiling),
		win: windows{slow: adaptiveWindow, fast: adaptiveFastWindow}, startWin: adaptiveStartWindow, partTime: partTimeLimit}
	switch {
	case threads > 0:
		l.max = min(threads, ceiling)
		l.limit = l.max
	case partSize > 0:
		l.limit, l.partSize = 1, partSize
		l.firstPart = make(chan float64, 1)
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

// partDone records a part that finished, of size bytes sent in d. The
// first one gives an upload's tuner an exact rate for its first decision.
func (l *limiter) partDone(size int64, d time.Duration) {
	if l.firstPart == nil || d <= 0 {
		return
	}
	select {
	case l.firstPart <- float64(size) / d.Seconds():
	default:
	}
}

// tune adapts the slots each window until ctx ends, and reports each
// change with the window's throughput and the reason, and why it keeps the
// count when that is news. A fixed limiter (max
// reached at the start, or threads set) does nothing. An upload's first
// decision comes from its first part, or from adaptiveStartWindow; a
// download starts on short windows, which its first one corrects on a
// slow link.
func (l *limiter) tune(ctx context.Context, report func(from, to int, bytesPerSec float64, reason string)) {
	if l.current() >= l.max {
		return
	}
	win, start := l.win, l.startWin
	t := &tuner{limit: l.current(), max: l.max, partSize: l.partSize, partTime: l.partTime, settle: true, steady: win.slow}
	lastMoved, lastErrs, lastAt := l.moved.Load(), l.errors.Load(), time.Now()
	lastRate := 0.0
	if l.partSize == 0 {
		lastRate = adaptiveFastRate
	}
	decide := func(rate float64, now time.Time) {
		moved, errs := l.moved.Load(), l.errors.Load()
		if rate < 0 {
			rate = float64(moved-lastMoved) / now.Sub(lastAt).Seconds()
		}
		before := t.limit
		l.set(t.next(rate, errs-lastErrs))
		if why, ok := t.said(before); ok && report != nil {
			report(before, t.limit, rate, why)
		}
		lastMoved, lastErrs, lastAt, lastRate = moved, errs, now, rate
	}
	if l.partSize > 0 {
		t.start, t.settle, t.window = true, false, win.slow
		timer := time.NewTimer(start)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case rate := <-l.firstPart:
			timer.Stop()
			decide(rate, time.Now())
		case now := <-timer.C:
			decide(-1, now)
		}
	}
	for {
		t.window = win.after(lastRate)
		timer := time.NewTimer(t.window)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case now := <-timer.C:
			decide(-1, now)
		}
	}
}

// tuner decides the next number of slots from each window's throughput.
type tuner struct {
	limit, max int
	partSize   int64         // an upload's part size, else 0
	partTime   time.Duration // the transfer's partTimeLimit; partTimeLimit when unset
	start      bool          // an upload's first window, at one part
	prev       int           // the level before an increase being judged, else 0
	base       float64       // throughput at prev
	rejudged   bool          // the increase being judged already had a dipped window
	settle     bool          // the window after a change is ramp-up: not judged
	hold       int           // windows left before probing again
	reason     string        // why the last change was made
	// floor is the fewest parts the time bound may hold an upload at: 2
	// while a second part is tried (trying) and once one paid off, else
	// 0. held says the bound held the upload at one part when the trial
	// began.
	floor        int
	trying, held bool
	// stay is why the window just judged kept the count, when that is
	// worth saying; lastStay is the one said last, so a hold is said once.
	stay, lastStay string
	// window is the length of the window being judged; adaptiveWindow
	// when unset.
	window time.Duration
	// steady is how long the bound on parts in flight is judged over, at
	// least one window, so a short stall does not shed a fast link's
	// parts; recent holds the windows it spans.
	steady time.Duration
	recent []rateSpan
}

// rateSpan is one window's rate and length.
type rateSpan struct {
	rate float64
	d    time.Duration
}

// steadyRate records a window at rate and returns the rate over the
// latest windows that cover steady.
func (t *tuner) steadyRate(rate float64) float64 {
	w := t.window
	if w <= 0 {
		w = adaptiveWindow
	}
	t.recent = append(t.recent, rateSpan{rate, w})
	horizon := max(t.steady, w)
	for len(t.recent) > 1 {
		var rest time.Duration
		for _, s := range t.recent[1:] {
			rest += s.d
		}
		if rest < horizon {
			break
		}
		t.recent = t.recent[1:]
	}
	var moved float64
	var span time.Duration
	for _, s := range t.recent {
		moved += s.rate * s.d.Seconds()
		span += s.d
	}
	return moved / span.Seconds()
}

// holdWindows is adaptiveHold in windows of the current length.
func (t *tuner) holdWindows() int { return t.windowsIn(adaptiveHold) }

// windowsIn is d in windows of the current length, at least one.
func (t *tuner) windowsIn(d time.Duration) int {
	w := t.window
	if w <= 0 {
		w = adaptiveWindow
	}
	return max(1, int(d/w))
}

// said is what to log for the window next just judged, from a count of
// before: its change and why, or why it kept the count when that is news.
func (t *tuner) said(before int) (string, bool) {
	switch {
	case t.limit != before:
		t.lastStay = ""
		return t.reason, true
	case t.stay != "" && t.stay != t.lastStay:
		t.lastStay = t.stay
		return t.stay, true
	}
	return "", false
}

func (t *tuner) next(rate float64, errs int64) int {
	t.stay = ""
	top := max(t.floor, t.partCap(t.steadyRate(rate)))
	switch {
	case errs > 0:
		// Failures or throttling: halve, and wait before probing again.
		t.limit = max(1, t.limit/2)
		t.prev, t.settle, t.hold, t.start = 0, true, t.holdWindows(), false
		if t.trying {
			t.trying, t.floor = false, 0
		}
		t.reason = fmt.Sprintf("%d request(s) failed or were throttled", errs)
	case t.start:
		// An upload's first decision, at one part: take the usual start
		// if the link finishes that many parts in time, else stay at one
		// and probe.
		t.start, t.settle = false, true
		switch {
		case top >= adaptiveStartThreads:
			t.limit = min(t.max, adaptiveStartThreads)
			t.reason = fmt.Sprintf("the link can finish %d parts at once within %s", adaptiveStartThreads, roundDuration(t.partLimit()))
		case top > 1:
			t.stay = fmt.Sprintf("starting from one part: at this rate %d at once would not each finish within %s", adaptiveStartThreads, roundDuration(t.partLimit()))
		default:
			t.stay = fmt.Sprintf("one part at a time: at this rate a second would make each take over %s", roundDuration(t.partLimit()))
		}
	case t.limit > top:
		// Too many parts for the rate: each would take over
		// partTimeLimit. Halve toward the bound, so one slow window does
		// not undo a fast link's level, and hold there.
		t.limit = max(top, t.limit/2)
		t.prev, t.settle, t.hold = 0, true, t.holdWindows()
		t.reason = fmt.Sprintf("at this rate parts would take over %s each", roundDuration(t.partLimit()))
	case t.settle:
		t.settle = false
	case t.prev > 0 && rate > t.base*adaptiveGain:
		// The doubling paid off: keep it and try the next one. A second
		// part that paid off shows one part does not fill the link, so
		// the time bound no longer takes the upload back to one.
		t.prev = 0
		held := t.trying && t.held
		t.trying = false
		before := t.limit
		t.probe(rate, top)
		switch {
		case t.limit != before && held:
			t.reason = "the second part raised throughput: one connection, not the link, was the limit; trying more"
		case t.limit != before:
			t.reason = "the last doubling raised throughput, trying more"
		case held:
			t.stay = "the second part raised throughput: one connection, not the link, was the limit; keeping two"
		default:
			t.stay = t.atTop()
		}
	case t.prev > 0 && rate < t.base*adaptiveDip && !t.rejudged:
		// Far below the level before it: likely a stall in this window
		// rather than the doubling's doing. Judge the next one.
		t.rejudged = true
		t.stay = "this window fell far below the level before the doubling, likely a stall: judging the next one"
	case t.prev > 0:
		// It did not: go back and hold there for a while. A second part
		// that did not pay off shows one part fills the link.
		t.limit, t.prev, t.settle, t.hold = t.prev, 0, true, t.holdWindows()
		t.reason = fmt.Sprintf("the doubling did not raise throughput by %d%%, stepping back", adaptiveGainPct)
		if t.trying {
			t.trying, t.floor, t.hold = false, 0, t.windowsIn(secondPartRetry)
			t.reason = fmt.Sprintf("a second part did not raise throughput by %d%%: one part fills the link; trying again in %s",
				adaptiveGainPct, roundDuration(secondPartRetry))
		}
	case t.hold > 0:
		t.hold--
	case t.limit == 1 && t.partSize > 0 && t.max > 1:
		// From one part, a second is a trial judged on throughput: the
		// time bound, which assumes parts share the link, may not undo it
		// before then (floor), and when the bound holds the upload at one
		// it is the only way past.
		t.floor, t.trying, t.held = 2, true, top == 1
		t.probe(rate, 2)
		t.reason = "probing for more throughput"
		if t.held {
			t.reason = fmt.Sprintf("the %s bound holds one part; trying a second in case one connection, not the link, is the limit", roundDuration(t.partLimit()))
		}
	default:
		before := t.limit
		t.probe(rate, top)
		if t.limit != before {
			t.reason = "probing for more throughput"
		} else {
			t.stay = t.atTop()
		}
	}
	return t.limit
}

// atTop says why a probe found no room: the transfer's ceiling, or an
// upload's time bound.
func (t *tuner) atTop() string {
	if t.limit >= t.max {
		return "at the most this transfer allows"
	}
	return fmt.Sprintf("at this rate more parts would each take over %s", roundDuration(t.partLimit()))
}

// partLimit is how long an upload's parts may take: the transfer's
// partTimeLimit.
func (t *tuner) partLimit() time.Duration {
	if t.partTime > 0 {
		return t.partTime
	}
	return partTimeLimit
}

// probe doubles the slots, up to top, remembering the level and its
// throughput.
func (t *tuner) probe(rate float64, top int) {
	top = min(t.max, top)
	if t.limit >= top {
		t.hold = t.holdWindows()
		return
	}
	t.prev, t.base, t.rejudged = t.limit, rate, false
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
	n := rate * t.partLimit().Seconds() / float64(t.partSize)
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
	// Read once: the goroutine may outlive the request by a tick.
	limit := stallTimeout
	check := min(5*time.Second, limit/4)
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
				if time.Since(time.Unix(0, g.last.Load())) > limit {
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
