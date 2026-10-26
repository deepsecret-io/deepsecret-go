// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A session token lasts an hour. The client refreshes it this long before
// it expires, so a send or receive that runs for hours keeps working.
const sessionRefreshBefore = 5 * time.Minute

const refreshPath = "/api/v1/auth/refresh"

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

// SetSessionStore makes the client persist its refreshed session tokens.
// It only matters for a client authenticated with "bearer:" and a token.
func (c *Client) SetSessionStore(s SessionStore) {
	c.authMu.Lock()
	c.session = &s
	c.authMu.Unlock()
}

func isBearer(key string) bool { return strings.HasPrefix(key, "bearer:") }

func (c *Client) credential() string {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.apiKey
}

// freshCredential returns the credential for a request, refreshing a
// session token that expires within sessionRefreshBefore. A failed refresh
// is left to the request: the server refuses it if the token is no good.
func (c *Client) freshCredential() string {
	key := c.credential()
	if !isBearer(key) {
		return key
	}
	if claims, ok := tokenClaims(strings.TrimPrefix(key, "bearer:")); ok && time.Until(claims.expires()) < sessionRefreshBefore {
		_ = c.renewSession(key)
		return c.credential()
	}
	return key
}

// renewSession replaces the session token stale: with a newer one of the
// same account from the store, or by refreshing it. Concurrent callers
// holding the same stale token renew it once.
func (c *Client) renewSession(stale string) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if c.credential() != stale {
		return nil // renewed meanwhile
	}
	if c.adoptStored(stale) {
		return nil
	}
	token, err := c.refreshToken(stale)
	if err != nil {
		// Another process with the same session may have refreshed first,
		// which revoked this token: give it a moment to save its new one.
		for range 3 {
			select {
			case <-c.reqCtx().Done():
				return err
			case <-time.After(500 * time.Millisecond):
			}
			if c.adoptStored(stale) {
				return nil
			}
		}
		return err
	}
	c.authMu.Lock()
	c.apiKey = "bearer:" + token
	store := c.session
	c.authMu.Unlock()
	if store != nil && store.Save != nil {
		claims, _ := tokenClaims(token)
		_ = store.Save(token, claims.expires())
	}
	return nil
}

// refreshToken exchanges the session token in key for a new one.
func (c *Client) refreshToken(key string) (string, error) {
	resp, err := c.send("POST", refreshPath, []byte("{}"), key)
	if err != nil {
		return "", fmt.Errorf("refresh session: %w", err)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Data, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("refresh session: unexpected response")
	}
	if err := validateAPIKey(out.Token); err != nil {
		return "", fmt.Errorf("refresh session: %w", err)
	}
	return out.Token, nil
}

// adoptStored switches to the stored token when it differs from stale,
// belongs to the same account and has not expired. A token of another
// account, from a login made meanwhile, is never picked up mid-operation.
func (c *Client) adoptStored(stale string) bool {
	c.authMu.Lock()
	store := c.session
	c.authMu.Unlock()
	if store == nil || store.Load == nil {
		return false
	}
	token, err := store.Load()
	if err != nil || token == "" || "bearer:"+token == stale || validateAPIKey(token) != nil {
		return false
	}
	stored, ok := tokenClaims(token)
	if !ok || !time.Now().Before(stored.expires()) {
		return false
	}
	current, ok := tokenClaims(strings.TrimPrefix(stale, "bearer:"))
	if !ok || current.Subject == "" || current.Subject != stored.Subject {
		return false
	}
	c.authMu.Lock()
	c.apiKey = "bearer:" + token
	c.authMu.Unlock()
	return true
}

// jwtClaims are the claims the client reads from its session token. The
// signature is the server's to check; the client only schedules refreshes.
type jwtClaims struct {
	Subject string `json:"sub"`
	Expiry  int64  `json:"exp"`
}

func (j jwtClaims) expires() time.Time { return time.Unix(j.Expiry, 0) }

func tokenClaims(token string) (jwtClaims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, false
	}
	var claims jwtClaims
	if json.Unmarshal(raw, &claims) != nil || claims.Expiry == 0 {
		return jwtClaims{}, false
	}
	return claims, true
}
