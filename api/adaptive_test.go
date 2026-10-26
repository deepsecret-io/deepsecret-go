// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"fmt"
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

// uploadTuner is the tuner of an upload of 8 MiB parts, before its first
// window.
func uploadTuner() *tuner {
	return &tuner{limit: 1, max: 32, partSize: 8 << 20, start: true}
}

// On a link that one part fills (260 KB/s, where a part alone takes 32
// seconds), an upload never runs a second part: it would only slow the
// first, and storage keeps finished parts only.
func TestTuner_SlowLinkSendsOnePartAtATime(t *testing.T) {
	tu := uploadTuner()
	for i := range 60 {
		if tu.next(260e3, 0) != 1 {
			t.Fatalf("window %d: %d parts in flight on a link one part fills (%s)", i, tu.limit, tu.reason)
		}
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
