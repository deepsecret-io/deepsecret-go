// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// humanBytes renders a byte count in IEC units ("12.5 MiB"). Returns "0 B"
// for zero or negative values so debug output is never blank.
func humanBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const (
		kib = int64(1 << 10)
		mib = int64(1 << 20)
		gib = int64(1 << 30)
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// threadLabel renders a thread-count value for debug logs. 0 means "use
// SDK default"; render that explicitly so the log doesn't read as "no
// threads".
func threadLabel(v, sdkDefault int) string {
	if v <= 0 {
		return fmt.Sprintf("default(%d)", sdkDefault)
	}
	return fmt.Sprintf("%d", v)
}

// formatRate returns a human-readable bytes-per-second rate ("12.4 MiB/s").
// Returns "n/a" for zero/negative durations or zero bytes so debug output
// never shows misleading "Inf" / "NaN" values when timing measurements are
// too coarse to be meaningful.
func formatRate(bytes int64, elapsed time.Duration) string {
	if elapsed <= 0 || bytes <= 0 {
		return "n/a"
	}
	bps := float64(bytes) / elapsed.Seconds()
	switch {
	case bps >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GiB/s", bps/(1024*1024*1024))
	case bps >= 1024*1024:
		return fmt.Sprintf("%.2f MiB/s", bps/(1024*1024))
	case bps >= 1024:
		return fmt.Sprintf("%.2f KiB/s", bps/1024)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

// sanitizeForLog escapes control characters in caller-supplied strings
// (secret names, recipient emails, TTL strings) before they reach the
// debug callback. ANSI escapes, NUL bytes, and other non-printable runes
// can corrupt terminal output if a debug consumer prints them verbatim,
// so we render them as Go-style escaped sequences.
//
// The result is intentionally NOT identical to %q output: we keep the
// original visible content but only escape what's actually unsafe to
// print. The caller still wraps the result in %q for display.
func sanitizeForLog(s string) string {
	if s == "" {
		return s
	}
	const maxLen = 256
	if len(s) > maxLen {
		s = s[:maxLen] + "...[truncated]"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`�`)
		case r < 0x20 || r == 0x7f:
			b.WriteString(`\x`)
			b.WriteString(strconv.FormatInt(int64(r), 16))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
