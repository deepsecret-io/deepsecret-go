// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk/api"
)

// record is one log record: its module, message and fields.
type record struct {
	module, msg string
	fields      map[string]slog.Value
}

func (r record) String() string {
	keys := make([]string, 0, len(r.fields))
	for k := range r.fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s:", r.module, r.msg)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%v", k, r.fields[k])
	}
	return b.String()
}

// logBook keeps the records of the logger it gives, from any goroutine.
type logBook struct {
	mu      sync.Mutex
	records []record
}

func (b *logBook) logger() *slog.Logger {
	return recordLogs(func(module, msg string, fields map[string]slog.Value) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.records = append(b.records, record{module, msg, fields})
	})
}

// all returns the records of module with message msg.
func (b *logBook) all(module, msg string) []record {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []record
	for _, r := range b.records {
		if r.module == module && r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

// has checks that a record of module with message msg was logged, the
// first one holding the fields in want.
func (b *logBook) has(t *testing.T, module, msg string, want map[string]any) record {
	t.Helper()
	found := b.all(module, msg)
	if len(found) == 0 {
		b.mu.Lock()
		defer b.mu.Unlock()
		t.Fatalf("no %q record in %q among:\n%v", msg, module, b.records)
	}
	r := found[0]
	for k, w := range want {
		if got, ok := r.fields[k]; !ok || !got.Equal(slog.AnyValue(w)) {
			t.Errorf("%v\n  want %s=%v", r, k, w)
		}
	}
	return r
}

// A download's threads plan gives its settings, without the bound on parts
// in flight that only an upload has.
func TestThreadsPlan_Download(t *testing.T) {
	var book logBook
	lim := newLimiter(t.Context(), 0, 8, 0)
	book.logger().Debug("plan", threadsPlan(lim, 0, api.MaxDownloadConcurrency, "range")...)
	r := book.has(t, "", "plan", map[string]any{
		"mode": "adaptive", "start": 4, "max": 8, "cap": 64, "window": 5 * time.Second,
		"fast_window": 2 * time.Second, "fast_rate": api.Rate(4e6), "gain_pct": 10,
	})
	if _, ok := r.fields["part_time"]; ok {
		t.Fatalf("a download's plan has an upload's bound: %v", r)
	}
}

// A count too small to adapt, and one the caller fixed, say so and why.
func TestThreadsPlan_Fixed(t *testing.T) {
	var book logBook
	few := newLimiter(t.Context(), 0, 3, 0)
	book.logger().Debug("too few", threadsPlan(few, 0, api.MaxDownloadConcurrency, "range")...)
	book.has(t, "", "too few", map[string]any{"mode": "fixed", "threads": 3, "cap": 64, "reason": "too few ranges to adapt: one per range"})

	capped := newLimiter(t.Context(), 8, 2, 8<<20)
	book.logger().Debug("capped", threadsPlan(capped, 8, api.MaxUploadThreads, "part")...)
	book.has(t, "", "capped", map[string]any{"mode": "fixed", "threads": 2, "requested": 8, "reason": "at most one per part"})
}

// The tuner's decisions read as a change of count, up or down, or a hold
// with its count, each with the window's rate and the reason.
func TestLogThreads(t *testing.T) {
	var book logBook
	log := book.logger()
	logThreads(log, 1, 2, 1e6, "probing for more throughput")
	logThreads(log, 8, 4, 2e6, "1 request(s) failed or were throttled")
	logThreads(log, 8, 8, 80e6, "at the most this transfer allows")
	book.has(t, "", "increasing", map[string]any{"from": 1, "to": 2, "rate": api.Rate(1e6), "reason": "probing for more throughput"})
	book.has(t, "", "decreasing", map[string]any{"from": 8, "to": 4, "rate": api.Rate(2e6)})
	r := book.has(t, "", "holding", map[string]any{"threads": 8, "rate": api.Rate(80e6), "reason": "at the most this transfer allows"})
	if got := r.fields["rate"].String(); got != "76.29MiB/s" {
		t.Fatalf("a hold's rate reads %q", got)
	}
}
