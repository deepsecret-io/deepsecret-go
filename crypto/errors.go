// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import "errors"

// ErrOutdatedManifest is a manifest with no secret name: one sealed before
// the name was signed (2026-11-01, still protocol version 4), since Seal
// refuses an empty name. It cannot be opened; its sender has to send the
// secret again.
var ErrOutdatedManifest = errors.New("this secret was made by an earlier version of DeepSecret and cannot be opened: ask the sender to send it again")
