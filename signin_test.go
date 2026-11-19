// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package deepsecret_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
)

// SignInURL asks the sign-in route with the return URL and state, sends no
// credential, and returns the URL the API names.
func TestSignInURL(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"auth_url":"https://accounts.example.com/o?x=1"}}`))
	}))
	defer srv.Close()

	u, err := deepsecret.SignInURL(context.Background(), srv.URL, "http://127.0.0.1:5555/callback", "state-123")
	if err != nil || u != "https://accounts.example.com/o?x=1" {
		t.Fatalf("SignInURL = %q, %v", u, err)
	}
	if got.URL.Path != "/api/v1/auth/sso/google" || got.URL.Query().Get("return_url") != "http://127.0.0.1:5555/callback" || got.URL.Query().Get("client_state") != "state-123" {
		t.Errorf("request: %s", got.URL)
	}
	if got.Header.Get("Authorization") != "" || got.Header.Get("DS-API-KEY") != "" {
		t.Errorf("sent a credential: %v", got.Header)
	}
}

// A refusal comes back as the API's error, an answer with no URL is an
// error, and plaintext HTTP to a host that is not loopback is refused
// before any request.
func TestSignInURL_Errors(t *testing.T) {
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"success":false,"error":"Invalid return_url"}`))
	}))
	defer refuse.Close()
	if _, err := deepsecret.SignInURL(context.Background(), refuse.URL, "http://127.0.0.1:1/cb", "s"); err == nil || !strings.Contains(err.Error(), "Invalid return_url") {
		t.Errorf("refusal: %v", err)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
	}))
	defer empty.Close()
	if _, err := deepsecret.SignInURL(context.Background(), empty.URL, "http://127.0.0.1:1/cb", "s"); err == nil {
		t.Error("an answer with no URL was accepted")
	}

	if _, err := deepsecret.SignInURL(context.Background(), "http://api.example.com", "http://127.0.0.1:1/cb", "s"); err == nil {
		t.Error("plaintext HTTP to a remote host was accepted")
	}
}

// When the API cannot be reached, the error does not carry the state.
func TestSignInURL_ErrorHidesState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()
	_, err := deepsecret.SignInURL(context.Background(), addr, "http://127.0.0.1:1/cb", "secret-state-value")
	if err == nil || strings.Contains(err.Error(), "secret-state-value") {
		t.Errorf("err = %v", err)
	}
}
