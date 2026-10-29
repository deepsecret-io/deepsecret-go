// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// On a link that saturates at 12 connections, the tuner climbs from 4,
// keeps 16 (the last doubling that paid off), and backs off when requests
// fail.
func TestTuner_FindsTheSaturationPoint(t *testing.T) {
	link := func(threads int) float64 { return float64(min(threads, 12)) * 10e6 }
	tu := &tuner{limit: adaptiveStartThreads, max: 32, settle: true}
	var seen []int
	for range 40 {
		before := tu.limit
		if tu.next(link(before), 0) != before {
			seen = append(seen, tu.limit)
		}
	}
	if tu.limit != 16 {
		t.Fatalf("settled at %d threads (changes %v), want 16", tu.limit, seen)
	}
	if seen[0] != 8 || seen[1] != 16 || seen[2] != 32 || seen[3] != 16 {
		t.Fatalf("changes %v, want 8, 16, 32, back to 16", seen)
	}
	if tu.next(link(16), 3) != 8 {
		t.Fatalf("failures left %d threads, want 8", tu.limit)
	}
	for range 3 {
		tu.next(link(8), 1)
	}
	if tu.limit != 1 {
		t.Fatalf("repeated failures left %d threads, want 1", tu.limit)
	}
}

// A level that cannot go higher is held, not probed past the maximum.
func TestTuner_StaysWithinTheMaximum(t *testing.T) {
	tu := &tuner{limit: 4, max: 6, settle: true}
	for i := range 20 {
		tu.next(float64(i+1)*1e9, 0)
		if tu.limit > 6 {
			t.Fatalf("went to %d threads, maximum 6", tu.limit)
		}
	}
	if tu.limit != 6 {
		t.Fatalf("ended at %d threads, want 6", tu.limit)
	}
}

func TestLimiter_FixedAndCapped(t *testing.T) {
	ctx := context.Background()
	if l := newLimiter(ctx, 3, 10, 0); l.current() != 3 || l.max != 3 {
		t.Fatalf("fixed: limit %d max %d", l.current(), l.max)
	}
	if l := newLimiter(ctx, 50, 10, 0); l.current() != 10 {
		t.Fatalf("a fixed count above the ceiling: %d", l.current())
	}
	if l := newLimiter(ctx, 0, 2, 0); l.current() != 2 || l.max != 2 {
		t.Fatalf("adaptive under a low ceiling: limit %d max %d", l.current(), l.max)
	}
	if l := newLimiter(ctx, 0, 32, 0); l.current() != adaptiveStartThreads {
		t.Fatalf("adaptive start: %d", l.current())
	}
	if l := newLimiter(ctx, 0, 32, 8<<20); l.current() != 1 || l.max != 32 {
		t.Fatalf("an upload's start: limit %d max %d, want 1 of 32", l.current(), l.max)
	}
	if l := newLimiter(ctx, 6, 32, 8<<20); l.current() != 6 {
		t.Fatalf("an upload's fixed count: %d", l.current())
	}
}

func TestLimiter_GatesAndWakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := newLimiter(ctx, 2, 4, 0)
	for range 2 {
		if err := l.acquire(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := make(chan error, 2)
	go func() { got <- l.acquire(ctx) }()
	select {
	case <-got:
		t.Fatal("a third request ran with two slots")
	case <-time.After(50 * time.Millisecond):
	}
	l.set(3)
	if err := <-got; err != nil {
		t.Fatalf("raising the limit did not let the waiter in: %v", err)
	}
	go func() { got <- l.acquire(ctx) }()
	cancel()
	if err := <-got; err == nil {
		t.Fatal("a waiter was not released by cancellation")
	}
}

// Every change the tuner makes says why, so a debug log can explain it.
func TestTuner_ExplainsEachChange(t *testing.T) {
	link := func(threads int) float64 { return float64(min(threads, 6)) * 10e6 }
	tu := &tuner{limit: adaptiveStartThreads, max: 32, settle: true}
	reasons := map[string]bool{}
	for range 20 {
		before := tu.limit
		if tu.next(link(before), 0) != before {
			reasons[tu.reason] = true
		}
	}
	tu.next(link(tu.limit), 2)
	reasons[tu.reason] = true
	for _, want := range []string{
		"probing for more throughput",
		"the doubling did not raise throughput by 10%, stepping back",
		"2 request(s) failed or were throttled",
	} {
		if !reasons[want] {
			t.Errorf("no change explained as %q (got %v)", want, reasons)
		}
	}
}

// Windows are short from 4 MB/s, where two seconds measure the link, and
// stay five seconds below, where a short window would measure noise; a
// level is held 30 seconds before the next probe either way.
func TestTuner_WindowFollowsTheRate(t *testing.T) {
	if windowFor(260e3) != 5*time.Second || windowFor(3.9e6) != 5*time.Second || windowFor(4e6) != 2*time.Second || windowFor(120e6) != 2*time.Second {
		t.Fatalf("windows: %v at 260 KB/s, %v at 3.9 MB/s, %v at 4 MB/s, %v at 120 MB/s",
			windowFor(260e3), windowFor(3.9e6), windowFor(4e6), windowFor(120e6))
	}
	if (&tuner{}).holdWindows() != 6 || (&tuner{window: 2 * time.Second}).holdWindows() != 15 {
		t.Fatalf("hold: %d slow windows, %d fast ones", (&tuner{}).holdWindows(), (&tuner{window: 2 * time.Second}).holdWindows())
	}
	tu := &tuner{limit: 8, max: 32, prev: 4, base: 100e6, window: 2 * time.Second}
	tu.next(100e6, 0)
	if tu.limit != 4 || tu.hold != 15 {
		t.Fatalf("a doubling that did not pay: limit %d, hold %d windows of 2s", tu.limit, tu.hold)
	}
}

// On short windows, one window in which nothing moved (a brief stall)
// does not shed a fast link's parts: the bound on parts in flight is
// judged over 5 seconds. A link that stays slow for that long is shed.
func TestTuner_OneStalledWindowDoesNotShed(t *testing.T) {
	tu := &tuner{limit: 16, max: 32, partSize: 32 << 20, window: 2 * time.Second, steady: 5 * time.Second, hold: 100}
	for range 3 {
		tu.next(120e6, 0)
	}
	if tu.next(0, 0) != 16 {
		t.Fatalf("one stalled window shed to %d parts (%s)", tu.limit, tu.reason)
	}
	tu.next(0, 0)
	if tu.next(0, 0) != 8 || tu.reason != "at this rate parts would take over 1m each" {
		t.Fatalf("a stall over the 5 seconds left %d parts (%s)", tu.limit, tu.reason)
	}
}

// A doubling whose window falls far below the level before it (a brief
// stall) is judged again on the next window instead of undone at once; a
// doubling that keeps falling short is undone.
func TestTuner_RejudgesADippedDoubling(t *testing.T) {
	doubled := func() *tuner {
		tu := &tuner{limit: 4, max: 32}
		tu.probe(68e6, 32) // to 8, judged after its settling window
		tu.next(70e6, 0)
		return tu
	}
	tu := doubled()
	if tu.next(31e6, 0) != 8 {
		t.Fatalf("a dipped window undid the doubling: %d (%s)", tu.limit, tu.reason)
	}
	if tu.next(95e6, 0) != 16 {
		t.Fatalf("the next window's gain was not kept: %d (%s)", tu.limit, tu.reason)
	}
	tu = doubled()
	tu.next(31e6, 0)
	if tu.next(30e6, 0) != 4 {
		t.Fatalf("two short windows left %d (%s)", tu.limit, tu.reason)
	}
	tu = doubled()
	if tu.next(66e6, 0) != 4 {
		t.Fatalf("a doubling with no gain, and no dip, left %d (%s)", tu.limit, tu.reason)
	}
}

// uploadTuner is the tuner of an upload of 8 MiB parts, before its first
// window.
func uploadTuner() *tuner {
	return &tuner{limit: 1, max: 32, partSize: 8 << 20, start: true}
}

// On a link that one part fills (260 KB/s, where a part alone takes 32
// seconds), a second part only slows the first, and storage keeps
// finished parts only. The upload tries one for its settling and judging
// windows, goes back to one part, and tries again five minutes later.
func TestTuner_SlowLinkSendsOnePartAtATime(t *testing.T) {
	tu := uploadTuner()
	var two []int
	for i := 1; i <= 130; i++ {
		switch tu.next(260e3, 0) {
		case 1:
		case 2:
			two = append(two, i)
		default:
			t.Fatalf("window %d: %d parts in flight on a link one part fills (%s)", i, tu.limit, tu.reason)
		}
	}
	// Back at one, a settling window, then five minutes of 5s windows.
	if fmt.Sprint(two) != "[3 4 67 68]" {
		t.Fatalf("two parts in windows %v, want 3 and 4, then 67 and 68", two)
	}
}

// Where each connection is limited on its own (250 KB/s each), one part
// measures slow and the time bound would hold the upload at one for good.
// The second part it tries raises throughput, and from there the bound,
// judged on the parts in flight, lets it climb: each part still finishes in
// 33 seconds however many run.
func TestTuner_SecondPartUnlocksAPerConnectionLimit(t *testing.T) {
	tu := uploadTuner()
	var said []string
	for range 200 {
		before := tu.limit
		tu.next(float64(tu.limit)*250e3, 0)
		if why, ok := tu.said(before); ok {
			said = append(said, fmt.Sprintf("%d->%d %s", before, tu.limit, why))
		}
	}
	if tu.limit != 32 {
		t.Fatalf("settled at %d parts, want 32: %q", tu.limit, said)
	}
	if !slices.ContainsFunc(said, func(s string) bool { return strings.Contains(s, "the second part raised throughput") }) {
		t.Fatalf("the second part's payoff was not said: %q", said)
	}
}

// Even where a part alone takes over a minute (100 KB/s per connection),
// a second part that doubles throughput is kept: it does not slow the
// first. The bound still stops the upload from adding more.
func TestTuner_KeepsASecondPartThatPaysOff(t *testing.T) {
	tu := uploadTuner()
	for range 100 {
		tu.next(float64(tu.limit)*100e3, 0)
	}
	if tu.limit != 2 {
		t.Fatalf("settled at %d parts, want 2", tu.limit)
	}
}

// A debug log says each change, and why a count holds, once: a hold that
// repeats is not said again until the count changes.
func TestTuner_SaysWhyItHolds(t *testing.T) {
	tu := uploadTuner()
	var said []string
	for range 130 {
		before := tu.limit
		tu.next(260e3, 0)
		if why, ok := tu.said(before); ok {
			said = append(said, fmt.Sprintf("%d->%d %s", before, tu.limit, why))
		}
	}
	want := []string{
		"1->1 one part at a time: at this rate a second would make each take over 1m",
		"1->2 the 1m bound holds one part; trying a second in case one connection, not the link, is the limit",
		"2->1 a second part did not raise throughput by 10%: one part fills the link; trying again in 5m",
		"1->2 the 1m bound holds one part; trying a second in case one connection, not the link, is the limit",
		"2->1 a second part did not raise throughput by 10%: one part fills the link; trying again in 5m",
	}
	if !slices.Equal(said, want) {
		t.Fatalf("said %q\nwant %q", said, want)
	}

	top := &tuner{limit: 8, max: 8}
	var holds int
	for range 40 {
		before := top.limit
		top.next(80e6, 0)
		if why, ok := top.said(before); ok {
			holds++
			if why != "at the most this transfer allows" {
				t.Fatalf("at its ceiling it said %q", why)
			}
		}
	}
	if holds != 1 {
		t.Fatalf("a transfer at its ceiling said so %d times, want once", holds)
	}
	if got := threadsChange(8, 8, 80e6, "at the most this transfer allows"); got != "stays at 8 at 76.29 MiB/s: at the most this transfer allows" {
		t.Fatalf("a hold reads %q", got)
	}
}

// On a fast link the bound is far above the ceiling: the upload takes the
// usual start after its first window and climbs as a download does.
func TestTuner_FastLinkClimbsAsBefore(t *testing.T) {
	link := func(threads int) float64 { return float64(min(threads, 12)) * 10e6 }
	tu := uploadTuner()
	var seen []int
	for range 40 {
		before := tu.limit
		if tu.next(link(before), 0) != before {
			seen = append(seen, tu.limit)
		}
	}
	if fmt.Sprint(seen[:5]) != "[4 8 16 32 16]" || tu.limit != 16 {
		t.Fatalf("changes %v ending at %d, want 4, 8, 16, 32, back to 16", seen, tu.limit)
	}
}

// When every connection is slow on its own (1 MB/s each, a lossy path),
// more parts do raise throughput, and a part still finishes in time, so
// the upload climbs to the ceiling.
func TestTuner_SlowConnectionsStillClimb(t *testing.T) {
	tu := uploadTuner()
	for range 60 {
		tu.next(float64(tu.limit)*1e6, 0)
	}
	if tu.limit != 32 {
		t.Fatalf("settled at %d parts, want 32", tu.limit)
	}
}

// A link that slows mid-upload (fiber to a phone's hotspot) sheds parts,
// halving each window until they finish in time again.
func TestTuner_ShedsPartsWhenTheLinkSlows(t *testing.T) {
	tu := &tuner{limit: 16, max: 32, partSize: 8 << 20}
	var seen []int
	for range 6 {
		seen = append(seen, tu.next(500e3, 0))
	}
	// 500 KB/s finishes 3 parts of 8 MiB a minute.
	if fmt.Sprint(seen) != "[8 4 3 3 3 3]" {
		t.Fatalf("parts in flight %v, want 8, 4, then 3", seen)
	}
	if tu.reason != "at this rate parts would take over 1m each" {
		t.Fatalf("reason %q", tu.reason)
	}
}
