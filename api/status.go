// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import "time"

// TransferSnapshot is the state of an upload or a download at one moment.
type TransferSnapshot struct {
	// Started is false until the transfer knows its parts.
	Started bool
	// Total is the bytes the transfer moves in all. Done is what has
	// moved: finished parts, including those an earlier attempt left in
	// storage, and what the parts in flight moved so far.
	Total, Done int64
	// Parts is the parts (an upload) or byte ranges (a download), and
	// PartsDone how many have finished.
	Parts, PartsDone int
	// Threads is how many connections the transfer may use now, and
	// MaxThreads the most it may adapt up to.
	Threads, MaxThreads int
	// Connections is what each connection is doing, by connection number
	// from 1. A free one has Part 0.
	Connections []ConnectionStatus
}

// ConnectionStatus is what one connection is doing.
type ConnectionStatus struct {
	Part    int       // the part or range it moves, numbered from 1; 0 when free
	Size    int64     // the part's bytes
	Moved   int64     // bytes of the part moved in this attempt
	Attempt int       // 1 on the first try, and TransferAttempts at most
	Since   time.Time // when this attempt started moving
	Waiting bool      // a failed attempt: waiting to try again
}

// The limits of a transfer.
const (
	// TransferAttempts is how many times a part or range is tried before
	// the transfer fails.
	TransferAttempts = 8

	// MaxUploadThreads caps concurrent part PUTs. Uploads adapt below it
	// unless the caller fixes the number.
	MaxUploadThreads = 32

	// MaxDownloadConcurrency caps concurrent Range GETs. 64 is well below
	// the open-fd / TCP-stream-per-host limits on every supported OS, and
	// well above the point of diminishing returns for any realistic
	// backbone.
	MaxDownloadConcurrency = 64
)
