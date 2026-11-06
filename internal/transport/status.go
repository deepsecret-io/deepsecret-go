// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepsecret-io/deepsecret-go/transfer"
)

// ── Live transfer status ────────────────────────────────────────────────────
//
// A TransferStatus lets a progress display follow an upload or a download
// as it runs: the bytes moved, how many connections it may use now, and
// what each connection is doing. The transfer writes it, and the display
// reads it with Snapshot as often as it redraws. It holds part numbers,
// sizes and counts only, never a URL.

// TransferStatus is the live state of one upload or download. The zero
// value is ready to pass in a transfer's options; the transfer resets it
// when it starts. It is safe for concurrent use, and a nil TransferStatus
// records nothing.
type TransferStatus struct {
	mu        sync.Mutex
	started   bool
	total     int64
	parts     int
	partsDone int
	doneBytes int64      // bytes of finished parts, kept ones included
	lim       *limiter   // nil for a single request, or when nothing is left to send
	conns     []*connRun // by connection number - 1; nil while free
}

// Snapshot returns the transfer's state now.
func (s *TransferStatus) Snapshot() transfer.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := transfer.Snapshot{
		Started: s.started, Total: s.total, Done: s.doneBytes,
		Parts: s.parts, PartsDone: s.partsDone, Threads: 1, MaxThreads: 1,
	}
	if s.lim != nil {
		out.Threads, out.MaxThreads = s.lim.current(), s.lim.max
	}
	last := len(s.conns)
	for last > 0 && s.conns[last-1] == nil {
		last--
	}
	out.Connections = make([]transfer.ConnectionStatus, last)
	for i, c := range s.conns[:last] {
		if c == nil {
			continue
		}
		moved := min(max(c.moved.Load(), 0), c.size)
		out.Connections[i] = transfer.ConnectionStatus{Part: c.part, Size: c.size, Moved: moved,
			Attempt: c.attempt, Since: c.since, Waiting: c.waiting}
		out.Done += moved
	}
	out.Done = min(out.Done, out.Total)
	return out
}

// start resets s for a transfer of total bytes in parts, of which done
// bytes in partsDone parts are already in place. lim is the transfer's
// limiter, nil for a single request.
func (s *TransferStatus) start(total int64, parts int, done int64, partsDone int, lim *limiter) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started, s.total, s.parts = true, total, parts
	s.doneBytes, s.partsDone, s.lim, s.conns = done, partsDone, lim, nil
}

// begin puts part, of size bytes, on the lowest free connection, so the
// connections a display shows stay put while their parts change.
func (s *TransferStatus) begin(part int, size int64) *connRun {
	if s == nil {
		return nil
	}
	c := &connRun{s: s, part: part, size: size, attempt: 1, since: time.Now()}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, free := range s.conns {
		if free == nil {
			s.conns[i] = c
			return c
		}
	}
	s.conns = append(s.conns, c)
	return c
}

// addPart counts one more part: a half split off a range in flight.
func (s *TransferStatus) addPart() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parts++
}

// end frees c's connection, counting its part as done when ok.
func (s *TransferStatus) end(c *connRun, ok bool) {
	if s == nil || c == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.doneBytes += c.size
		s.partsDone++
	}
	for i, x := range s.conns {
		if x == c {
			s.conns[i] = nil
		}
	}
}

// connRun is one part on a connection. Its methods do nothing on nil, so
// a transfer without a status calls them freely.
type connRun struct {
	s     *TransferStatus
	part  int
	size  int64
	moved atomic.Int64

	// Guarded by s.mu.
	attempt int
	since   time.Time
	waiting bool
}

// add counts n more bytes of the part moved.
func (c *connRun) add(n int) {
	if c != nil {
		c.moved.Add(int64(n))
	}
}

// set records that the attempt has moved n bytes of the part.
func (c *connRun) set(n int64) {
	if c != nil {
		c.moved.Store(n)
	}
}

// retry follows a failed attempt: kept bytes of the part stay moved (0
// for a part sent again whole), and it waits until the next attempt,
// numbered from 1, begins.
func (c *connRun) retry(attempt int, kept int64) {
	if c == nil {
		return
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.moved.Store(kept)
	c.attempt, c.waiting = attempt, true
}

// shrink sets the part's size after another connection took the rest of
// it (tail splitting, multipart_download.go).
func (c *connRun) shrink(size int64) {
	if c == nil {
		return
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.size = size
}

// resume marks the next attempt as moving.
func (c *connRun) resume() {
	if c == nil {
		return
	}
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.since, c.waiting = time.Now(), false
}
