// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package logattr

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

// recordLogs is a logger that passes each record's module (nested ones
// joined with a dot), message and fields to on.
func recordLogs(on func(module, msg string, fields map[string]slog.Value)) *slog.Logger {
	return slog.New(&recorder{on: on})
}

type recorder struct {
	on    func(module, msg string, fields map[string]slog.Value)
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	fields := map[string]slog.Value{}
	var modules []string
	add := func(a slog.Attr) bool {
		if a.Key == ModuleKey {
			modules = append(modules, a.Value.String())
		} else {
			fields[a.Key] = a.Value.Resolve()
		}
		return true
	}
	for _, a := range r.attrs {
		add(a)
	}
	rec.Attrs(add)
	r.on(strings.Join(modules, "."), rec.Message, fields)
	return nil
}

func (r *recorder) WithAttrs(as []slog.Attr) slog.Handler {
	return &recorder{on: r.on, attrs: append(slices.Clip(r.attrs), as...)}
}

func (r *recorder) WithGroup(string) slog.Handler { return r }

// Sizes and rates print in binary units without a space, so a text log
// needs no quotes around them, and encode in JSON as exact numbers.
func TestBytesAndRate(t *testing.T) {
	for v, want := range map[Bytes]string{0: "0B", 512: "512B", 1536: "1.50KiB", 11545329: "11.01MiB", 20 << 30: "20.00GiB"} {
		if got := v.String(); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", v, got, want)
		}
	}
	if got := Rate(589567).String(); got != "575.75KiB/s" {
		t.Errorf("Rate = %q", got)
	}
	if got := RateOf(8<<20, 2*time.Second).String(); got != "4.00MiB/s" {
		t.Errorf("RateOf = %q", got)
	}
	if RateOf(0, time.Second) != 0 || RateOf(1, 0) != 0 {
		t.Error("a rate of nothing, or over no time, should be 0")
	}

	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("sent", "size", Bytes(11545329), "rate", Rate(589567.5))
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["size"] != 11545329.0 || got["rate"] != 589567.5 {
		t.Fatalf("JSON fields: size=%v rate=%v", got["size"], got["rate"])
	}
}

// Nested modules join with a dot, and a nil logger logs nothing.
func TestModule(t *testing.T) {
	var said []string
	log := recordLogs(func(module, msg string, _ map[string]slog.Value) {
		said = append(said, module+": "+msg)
	})
	Module(Module(log, "upload"), "threads").Debug("holding")
	Trace(Module(log, "upload"), "part sent")
	if want := []string{"upload.threads: holding", "upload: part sent"}; !slices.Equal(said, want) {
		t.Fatalf("said %q, want %q", said, want)
	}
	Logger(nil).Error("dropped")
}
