// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
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
	if l := newLimiter(ctx, 3, 10); l.current() != 3 || l.max != 3 {
		t.Fatalf("fixed: limit %d max %d", l.current(), l.max)
	}
	if l := newLimiter(ctx, 50, 10); l.current() != 10 {
		t.Fatalf("a fixed count above the ceiling: %d", l.current())
	}
	if l := newLimiter(ctx, 0, 2); l.current() != 2 || l.max != 2 {
		t.Fatalf("adaptive under a low ceiling: limit %d max %d", l.current(), l.max)
	}
	if l := newLimiter(ctx, 0, 32); l.current() != adaptiveStartThreads {
		t.Fatalf("adaptive start: %d", l.current())
	}
}

func TestLimiter_GatesAndWakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := newLimiter(ctx, 2, 4)
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
