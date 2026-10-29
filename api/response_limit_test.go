// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// A server that streams a response past the bound, without saying how
// long it is, fails the call instead of filling the client's memory.
func TestAPIResponseOverLimitFails(t *testing.T) {
	const limit = 1 << 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No Content-Length: the body streams until the server stops.
		fmt.Fprint(w, `{"success":true,"data":"`)
		for i := 0; i < 64; i++ {
			fmt.Fprint(w, strings.Repeat("a", limit))
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, `"}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	c.maxResponse = limit
	if _, err := c.Get("/api/v1/actors/me"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}

	// The same response within the bound is read whole.
	c.maxResponse = 65 * limit
	if _, err := c.Get("/api/v1/actors/me"); err != nil {
		t.Fatalf("a body under the bound failed: %v", err)
	}
}

// A response that declares a length past the bound is refused before it
// is read, with the client's real bound.
func TestAPIResponseDeclaredOverLimitFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxAPIResponseSize+1))
		fmt.Fprint(w, `{"success":true}`)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("/api/v1/actors/me"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

// The health probe has a bound of its own, far below an API response's.
func TestHealthProbeOverLimitFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.Copy(w, io.LimitReader(zeros{}, maxHealthResponseSize+1))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CheckMaintenance(); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

// zeros yields zero bytes forever.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
