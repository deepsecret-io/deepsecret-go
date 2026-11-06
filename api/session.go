// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import "time"

// SessionStore keeps a login session's token where the next run finds it.
// Refreshing rotates the token: the server revokes the old one, so a
// client set up with a store saves every refreshed token, and loads the
// stored one when its own is refused, since another process holding the
// same session may have refreshed it first.
type SessionStore struct {
	// Load returns the stored token, without the "bearer:" prefix.
	Load func() (string, error)
	// Save stores a refreshed token. An error does not fail the request
	// that triggered the refresh; the store should report it.
	Save func(token string, expiresAt time.Time) error
}
