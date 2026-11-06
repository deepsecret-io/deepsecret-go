// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/deepsecret-io/sdk/api"
)

func TestPathSegment(t *testing.T) {
	for id, want := range map[string]string{
		"7da383f1-0000-4000-8000-000000000000": "7da383f1-0000-4000-8000-000000000000",
		"../../actors/me":                      "..%2F..%2Factors%2Fme",
		"a/b":                                  "a%2Fb",
		"a?x=1":                                "a%3Fx=1",
		"a#b":                                  "a%23b",
		"%2E%2E":                               "%252E%252E",
		"alice+tag@example.com":                "alice+tag@example.com",
	} {
		if got := PathSegment(id); got != want {
			t.Errorf("PathSegment(%q) = %q, want %q", id, got, want)
		}
	}
}

// An empty, "." or ".." segment would reach another endpoint, so the request is
// refused and nothing is sent, whichever method it uses.
func TestRefusesPathsThatReachAnotherEndpoint(t *testing.T) {
	var sent atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]func(string) (*Response, error){
		"GET":    c.Get,
		"POST":   func(p string) (*Response, error) { return c.Post(p, nil) },
		"PUT":    func(p string) (*Response, error) { return c.Put(p, nil) },
		"DELETE": func(p string) (*Response, error) { return c.Delete(p, nil) },
	}
	for name, send := range methods {
		for _, path := range []string{
			"/api/v1/identities/",
			"/api/v1/identities/.",
			"/api/v1/identities/..",
			"/api/v1/secrets//revisions",
			"/api/v1/secrets/./revisions",
			"/api/v1/secrets/../revisions",
			"/api/v1/secrets/./recipients/..",
			"/api/v1/secrets/s/recipients/?limit=1",
			"/api/v1/secrets/s/recipients/..?limit=1",
		} {
			if _, err := send(path); !errors.Is(err, api.ErrInvalidID) {
				t.Errorf("%s %s: err = %v, want ErrInvalidID", name, path, err)
			}
		}
	}
	if n := sent.Load(); n != 0 {
		t.Errorf("%d requests were sent, want none", n)
	}
	for _, path := range []string{
		"/api/v1/identities",
		"/api/v1/secrets/s/revisions",
		"/api/v1/secrets/s/revisions?to=a/../b&from=",
		"/api/v1/secrets/..%2F..%2Factors%2Fme",
		"/api/v1/secrets/%252E%252E",
		"/api/v1/secrets/a..b",
		"/api/v1/secrets/...",
	} {
		if _, err := c.Get(path); err != nil {
			t.Errorf("GET %s: %v", path, err)
		}
	}
}

// However odd a revision or org ID is, it stays one segment of the request
// path.
func TestTransferPathsKeepIDsInOneSegment(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"error":"not found"}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	const id, seg = "../../actors/me", "..%2F..%2Factors%2Fme"
	for _, call := range []struct {
		path string
		call func()
	}{
		{"/api/v1/secrets/revisions/" + seg + "/multipart/init", func() { _, _ = c.MultipartInit(id) }},
		{"/api/v1/secrets/revisions/" + seg + "/multipart/part-urls", func() { _, _ = c.MultipartPartURLs(id, []int{1}) }},
		{"/api/v1/secrets/revisions/" + seg + "/multipart/complete", func() { _ = c.MultipartComplete(id, nil) }},
		{"/api/v1/secrets/revisions/" + seg + "/multipart/abort", func() { _ = c.MultipartAbort(id) }},
		{"/api/v1/secrets/revisions/" + seg + "/multipart/status", func() { _, _ = c.MultipartStatus(id) }},
		{"/api/v1/secrets/revisions/" + seg + "/confirm", func() { _ = c.ConfirmUpload(id) }},
		{"/api/v1/secrets/revisions/" + seg + "/presign", func() { _, _ = c.presignDownloadURL(id, 1) }},
		{"/api/v1/orgs/" + seg + "/storage/presign", func() { _, _ = c.presignUploadURL(id, "key", 1) }},
	} {
		mu.Lock()
		paths = nil
		mu.Unlock()
		call.call()
		mu.Lock()
		if !slices.Contains(paths, call.path) {
			t.Errorf("sent %q, want %q", paths, call.path)
		}
		mu.Unlock()
	}
}
