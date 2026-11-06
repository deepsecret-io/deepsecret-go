// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenLifetime is how long the API's session tokens last.
const tokenLifetime = time.Hour

// fakeToken is a JWT-shaped token issued tokenLifetime before it expires,
// as the API issues them: the client only reads its claims.
func fakeToken(sub string, exp time.Time, n int) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{"sub": sub, "iat": exp.Add(-tokenLifetime).Unix(), "exp": exp.Unix(), "jti": n})
	return enc([]byte(`{"alg":"HS256"}`)) + "." + enc(claims) + "." + enc([]byte(fmt.Sprint(n)))
}

// sessionServer accepts its current tokens and refreshes them the way the
// API does: the refreshed token is revoked, so refreshing it twice fails.
type sessionServer struct {
	mu        sync.Mutex
	valid     map[string]bool
	refreshes atomic.Int32
	issued    int
	lifetime  time.Duration
	onRefresh func() // called once a refresh has revoked the old token
}

func newSessionServer(t *testing.T, tokens ...string) (*sessionServer, *Client) {
	s := &sessionServer{valid: map[string]bool{}, lifetime: tokenLifetime}
	for _, tok := range tokens {
		s.valid[tok] = true
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "bearer:"+tokens[0])
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func (s *sessionServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	ok := s.valid[tok]
	var fresh string
	if ok && r.URL.Path == refreshPath {
		s.refreshes.Add(1)
		delete(s.valid, tok)
		s.issued++
		fresh = fakeToken("actor-1", time.Now().Add(s.lifetime), 100+s.issued)
		s.valid[fresh] = true
		if s.onRefresh != nil {
			s.onRefresh()
		}
	}
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"unauthorized"}`)
		return
	}
	if fresh != "" {
		fmt.Fprintf(w, `{"success":true,"data":{"token":%q}}`, fresh)
		return
	}
	fmt.Fprint(w, `{"success":true,"data":{}}`)
}

func TestSession_RefreshesShortlyBeforeExpiry(t *testing.T) {
	old := fakeToken("actor-1", time.Now().Add(2*time.Minute), 1)
	srv, c := newSessionServer(t, old)
	var saved []string
	c.SetSessionStore(SessionStore{Save: func(token string, exp time.Time) error {
		if time.Until(exp) < 50*time.Minute {
			t.Errorf("saved token expires in %s", time.Until(exp))
		}
		saved = append(saved, token)
		return nil
	}})
	for range 3 {
		if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
			t.Fatal(err)
		}
	}
	if srv.refreshes.Load() != 1 || len(saved) != 1 || c.credential() != "bearer:"+saved[0] {
		t.Fatalf("%d refreshes, saved %d tokens", srv.refreshes.Load(), len(saved))
	}
}

// A token in use renews once an eighth of its lifetime has passed, 7.5
// minutes of a one-hour token, long before it expires, so a session in use
// outlives its first token. A younger one is left alone.
func TestSession_RenewsOnUseAfterAnEighthOfItsLifetime(t *testing.T) {
	for _, tc := range []struct {
		name      string
		age       time.Duration
		refreshes int32
	}{
		{"five minutes old", 5 * time.Minute, 0},
		{"eight minutes old", 8 * time.Minute, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, c := newSessionServer(t, fakeToken("actor-1", time.Now().Add(tokenLifetime-tc.age), 1))
			for range 3 {
				if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
					t.Fatal(err)
				}
			}
			if n := srv.refreshes.Load(); n != tc.refreshes {
				t.Fatalf("%d refreshes over 3 requests, want %d", n, tc.refreshes)
			}
		})
	}
}

// A refresh that fails is not retried on every request: the requests go
// out with the current token, and the client asks again only a minute
// later.
func TestSession_FailingRefreshIsNotRetriedPerRequest(t *testing.T) {
	var refreshes, requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == refreshPath {
			refreshes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"success":false,"error":"Failed to refresh token"}`)
			return
		}
		requests.Add(1)
		fmt.Fprint(w, `{"success":true,"data":{}}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "bearer:"+fakeToken("actor-1", time.Now().Add(40*time.Minute), 1))
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
			t.Fatal(err)
		}
	}
	if refreshes.Load() != 1 || requests.Load() != 5 {
		t.Fatalf("%d refreshes and %d requests, want 1 and 5", refreshes.Load(), requests.Load())
	}
}

// Workers sharing a client refresh once: the second refresh of the same
// token would fail, since the first revoked it.
func TestSession_ConcurrentRequestsRefreshOnce(t *testing.T) {
	srv, c := newSessionServer(t, fakeToken("actor-1", time.Now().Add(time.Minute), 1))
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 || srv.refreshes.Load() != 1 {
		t.Fatalf("%d failed, %d refreshes", failed.Load(), srv.refreshes.Load())
	}
}

// Another process refreshed the shared session, which revoked this
// client's token: the client picks up the stored token and retries.
func TestSession_AdoptsTheStoredTokenOnUnauthorized(t *testing.T) {
	mine := fakeToken("actor-1", time.Now().Add(tokenLifetime), 1)
	theirs := fakeToken("actor-1", time.Now().Add(tokenLifetime), 2)
	srv, c := newSessionServer(t, mine)
	srv.mu.Lock()
	delete(srv.valid, mine)
	srv.valid[theirs] = true
	srv.mu.Unlock()
	c.SetSessionStore(SessionStore{Load: func() (string, error) { return theirs, nil }})
	if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if c.credential() != "bearer:"+theirs || srv.refreshes.Load() != 0 {
		t.Fatalf("not switched to the stored token (%d refreshes)", srv.refreshes.Load())
	}
}

// A stored token of another account, from a login made meanwhile, is
// never used for this client's requests.
func TestSession_IgnoresAnotherAccountsToken(t *testing.T) {
	mine := fakeToken("actor-1", time.Now().Add(tokenLifetime), 1)
	other := fakeToken("actor-2", time.Now().Add(tokenLifetime), 2)
	srv, c := newSessionServer(t, mine)
	srv.mu.Lock()
	delete(srv.valid, mine)
	srv.valid[other] = true
	srv.mu.Unlock()
	c.SetSessionStore(SessionStore{Load: func() (string, error) { return other, nil }})
	if _, err := c.Get(context.Background(), "/api/v1/me"); err == nil {
		t.Fatal("the request went through with another account's token")
	}
	if c.credential() != "bearer:"+mine {
		t.Fatal("switched to another account's token")
	}
}

func TestSession_APIKeysAreNotRefreshed(t *testing.T) {
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == refreshPath {
			refreshes.Add(1)
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"unauthorized"}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/api/v1/me"); err == nil {
		t.Fatal("expected 401")
	}
	if refreshes.Load() != 0 {
		t.Fatal("an API key client tried to refresh")
	}
}

// A call cancelled while it refreshes the session does not lose the new
// token: the server has revoked the old one, so losing it would end the
// session for every call sharing the client.
func TestSession_RefreshOutlivesACancelledCall(t *testing.T) {
	old := fakeToken("actor-1", time.Now().Add(2*time.Minute), 1)
	srv, c := newSessionServer(t, old)
	var saved []string
	c.SetSessionStore(SessionStore{Save: func(token string, _ time.Time) error {
		saved = append(saved, token)
		return nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.mu.Lock()
	srv.onRefresh = cancel
	srv.mu.Unlock()

	_, _ = c.Get(ctx, "/api/v1/me")
	if ctx.Err() == nil {
		t.Fatal("the call never reached a refresh")
	}
	if len(saved) != 1 || c.credential() != "bearer:"+saved[0] {
		t.Fatalf("saved %d tokens; the client holds the new one: %t", len(saved), len(saved) == 1 && c.credential() == "bearer:"+saved[0])
	}
	if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
		t.Fatalf("the session ended with the cancelled call: %v", err)
	}
	if n := srv.refreshes.Load(); n != 1 {
		t.Fatalf("%d refreshes", n)
	}
}

// A call's context ends that call only.
func TestCancelledCallEndsOnlyThatCall(t *testing.T) {
	srv, c := newSessionServer(t, fakeToken("actor-1", time.Now().Add(time.Hour), 1))
	_ = srv
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(ctx, "/api/v1/me"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call: %v", err)
	}
	if _, err := c.Get(context.Background(), "/api/v1/me"); err != nil {
		t.Fatalf("a later call: %v", err)
	}
}
