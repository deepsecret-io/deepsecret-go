// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
)

// ── Transfer plans ──────────────────────────────────────────────────────────
//
// Before a transfer moves data it logs its plan at debug level, as fields:
// what it moves and in what pieces ("plan" in the "upload" or "download"
// module), how many connections run them ("plan" in "upload.threads" or
// "download.threads"), and how it retries ("retry plan"). The threads
// module then logs each decision of the tuner, with its reason, as it is
// made.

// PieceSizeRule is how part and range sizes follow the payload's size.
const PieceSizeRule = "8 MiB under 1 GiB, 32 MiB to 16 GiB, 64 MiB from 16 GiB"

// LogSinglePutPlan logs, in the "upload" module of log, the plan of a
// payload of size bytes sent whole in one presigned PUT, as the server
// takes small payloads (PresignUploadFrom with expiryMinutes).
func LogSinglePutPlan(log *slog.Logger, size int64, expiryMinutes int) {
	up := logattr.Module(logattr.Logger(log), "upload")
	up.Debug("plan", "transfer", "single", "size", logattr.Bytes(size),
		"url_expiry", time.Duration(resolveExpiryMinutes(expiryMinutes))*time.Minute)
	up.Debug("retry plan", "attempts", maxRetries+1, "first_wait", 2*backoffUnit,
		"attempt_timeout", presignTimeout(size))
}

// threadsPlan is how lim runs a transfer's parts or ranges (piece), as log
// fields: at the caller's fixed count (requested), or adapting up to the
// transfer's cap. An adaptive plan gives the settings only; each decision
// is logged with its reason when it is made (logThreads).
func threadsPlan(lim *limiter, requested, ceiling int, piece string) []any {
	switch {
	case requested > 0:
		args := []any{"mode", "fixed", "threads", lim.max, "requested", requested}
		if lim.max < requested {
			args = append(args, "reason", "at most one per "+piece)
		}
		return args
	case lim.current() >= lim.max:
		return []any{"mode", "fixed", "threads", lim.max, "cap", ceiling, "reason", "too few " + piece + "s to adapt: one per " + piece}
	}
	args := []any{"mode", "adaptive", "start", lim.current(), "max", lim.max, "cap", ceiling,
		"window", lim.win.slow, "fast_window", lim.win.fast, "fast_rate", logattr.Rate(adaptiveFastRate), "gain_pct", adaptiveGainPct}
	if lim.partSize > 0 {
		args = append(args, "part_time", lim.partTime)
	}
	return args
}

// retryPlan is how a failed request of a transfer is retried, as log
// fields: how many attempts, the first and the longest wait between them,
// and how long a request may move no bytes before it restarts.
func retryPlan() []any {
	return []any{"attempts", multipartAttempts, "first_wait", 2 * backoffUnit, "max_wait", maxBackoff, "stall_timeout", stallTimeout}
}

// logThreads logs a decision the tuner made after a window, with the
// window's throughput: a change in the count, or why it holds.
func logThreads(log *slog.Logger, from, to int, rate float64, reason string) {
	switch {
	case to > from:
		log.Debug("increasing", "from", from, "to", to, "rate", logattr.Rate(rate), "reason", reason)
	case to < from:
		log.Debug("decreasing", "from", from, "to", to, "rate", logattr.Rate(rate), "reason", reason)
	default:
		log.Debug("holding", "threads", to, "rate", logattr.Rate(rate), "reason", reason)
	}
}

func roundDuration(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}
