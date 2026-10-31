// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Logging. A flow logs through the *slog.Logger its options carry, and
// nowhere when that is nil. Every record names its module in the
// ModuleKey field: Module adds one, and a consumer joins nested ones with
// a dot, as hclog's named loggers do ("upload.threads"). The message says
// what happened in a few lowercase words and holds no values; the values
// go in fields with snake_case keys. Sizes and rates log as Bytes and
// Rate, and durations as time.Duration: readable in text, exact numbers in
// JSON.
//
// Levels: LevelTrace for each request and part; slog.LevelDebug for the
// decisions and plans of a flow; slog.LevelInfo for its milestones;
// slog.LevelWarn for what it recovers from, such as a failed request it
// retries; slog.LevelError for what it gives up on.

// ModuleKey is the field that names a record's module.
const ModuleKey = "module"

// LevelTrace is the level below slog.LevelDebug, for each request and
// part.
const LevelTrace = slog.Level(-8)

// Logger returns l, or a logger that discards every record when l is nil.
func Logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}

// Module returns l with name added as its module.
func Module(l *slog.Logger, name string) *slog.Logger {
	return l.With(ModuleKey, name)
}

// Trace logs msg at LevelTrace.
func Trace(l *slog.Logger, msg string, args ...any) {
	l.Log(context.Background(), LevelTrace, msg, args...)
}

// Bytes is a byte count. It prints in binary units ("11.01MiB") and
// encodes in JSON as the exact count.
type Bytes int64

func (b Bytes) String() string {
	return fmt.Sprintf("%s%s", scaled(float64(b)), unit(float64(b), "B"))
}

// Rate is a throughput in bytes per second. It prints in binary units per
// second ("575.75KiB/s") and encodes in JSON as the number.
type Rate float64

// RateOf is the rate of n bytes moved in d: 0 when either is not positive.
func RateOf(n int64, d time.Duration) Rate {
	if n <= 0 || d <= 0 {
		return 0
	}
	return Rate(float64(n) / d.Seconds())
}

func (r Rate) String() string {
	return fmt.Sprintf("%s%s/s", scaled(float64(r)), unit(float64(r), "B"))
}

// scaled is v in the largest binary unit it reaches, with two decimals
// from KiB up.
func scaled(v float64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.2f", v/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.2f", v/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.2f", v/(1<<10))
	}
	return fmt.Sprintf("%.0f", v)
}

// unit is the binary unit scaled picks for v.
func unit(v float64, base string) string {
	switch {
	case v >= 1<<30:
		return "Gi" + base
	case v >= 1<<20:
		return "Mi" + base
	case v >= 1<<10:
		return "Ki" + base
	}
	return base
}
