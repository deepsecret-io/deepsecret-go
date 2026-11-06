// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package trust is the keys this device knows for people: listing them, and
// accepting, verifying and forgetting them after comparing fingerprints. A send
// and a decrypt check every key against this record, and refuse one it does not
// know with a KeyChangedError.
package trust
