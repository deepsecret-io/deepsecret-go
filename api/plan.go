// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"fmt"
	"time"
)

// ── Transfer plans ──────────────────────────────────────────────────────────
//
// Before a transfer moves data it reports its plan through OnDebug as
// "plan" events: what it moves and in what pieces, over how many
// connections, and how it retries. Changes it makes on the way are
// reported as "threads" events. A CLI shows them with its debug flag.

// PieceSizeRule is how part and range sizes follow the payload's size.
const PieceSizeRule = "8 MiB under 1 GiB, 32 MiB to 16 GiB, 64 MiB from 16 GiB"

// SinglePutPlan describes a payload sent whole in one presigned PUT, as
// the server takes small payloads.
func SinglePutPlan(size int64, expiryMinutes int) string {
	return fmt.Sprintf("single PUT of %s, URL valid %dm, up to %d attempts with waits doubling from %s",
		humanBytesLocal(size), resolveExpiryMinutes(expiryMinutes), maxRetries+1, roundDuration(2*backoffUnit))
}

// threadsPlan describes how a limiter runs a transfer's parts or ranges
// (piece): at the caller's fixed count, or adapting below limit.
func threadsPlan(lim *limiter, requested, limit int, piece string) string {
	if requested > 0 {
		if lim.max < requested {
			return fmt.Sprintf("fixed at %d (%d requested, at most one per %s)", lim.max, requested, piece)
		}
		return fmt.Sprintf("fixed at %d (requested)", lim.max)
	}
	if lim.current() >= lim.max {
		return fmt.Sprintf("%d, one per %s (too few %ss to adapt; up to %d otherwise)", lim.max, piece, piece, limit)
	}
	if lim.partSize > 0 {
		return fmt.Sprintf("adaptive: start 1, %d after %s if each %s finishes within %s at the measured rate, up to %d (limit %d, at most one per %s); every %s it doubles while throughput rises over %d%% and %ss still finish within %s, steps back when it does not, and halves on failures or throttling",
			min(adaptiveStartThreads, lim.max), adaptiveWindow, piece, roundDuration(partTimeLimit), lim.max, limit, piece, adaptiveWindow, adaptiveGainPct, piece, roundDuration(partTimeLimit))
	}
	return fmt.Sprintf("adaptive: start %d, up to %d (limit %d, at most one per %s); every %s it doubles while throughput rises over %d%%, steps back when it does not, and halves on failures or throttling",
		lim.current(), lim.max, limit, piece, adaptiveWindow, adaptiveGainPct)
}

// retryPlan describes how a failed request of a transfer is retried.
func retryPlan() string {
	return fmt.Sprintf("%d attempts per request, waits doubling from %s up to %s; a request that moves no bytes for %s restarts",
		multipartAttempts, roundDuration(2*backoffUnit), roundDuration(maxBackoff), roundDuration(stallTimeout))
}

// threadsChange describes a change the limiter made after a window.
func threadsChange(from, to int, rate float64, reason string) string {
	return fmt.Sprintf("%d -> %d at %s/s: %s", from, to, humanBytesLocal(int64(rate)), reason)
}

func roundDuration(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}
