// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/internal/transport"
)

// However odd an ID is, it cannot reach another endpoint with the caller's
// credential: it stays one segment of the request path, or the call sends
// nothing.
func TestIDsCannotReachAnotherEndpoint(t *testing.T) {
	var mu sync.Mutex
	var paths, queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		queries = append(queries, r.URL.RawQuery)
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
	ctx := context.Background()
	ttl := 3600
	calls := []struct {
		name, path string
		call       func(id string)
	}{
		{"ListRevisions", "/api/v1/secrets/%s/revisions", func(id string) { _, _ = c.ListRevisions(ctx, id) }},
		{"UpdatePolicy", "/api/v1/secrets/%s/policies", func(id string) { _, _ = c.UpdatePolicy(ctx, id, PolicyUpdate{TTLSeconds: &ttl}) }},
		{"DescribeSecret", "/api/v1/secrets/%s", func(id string) { _, _ = c.DescribeSecret(ctx, id) }},
		{"ListGroups", "/api/v1/orgs/%s/groups", func(id string) { _, _ = c.ListGroups(ctx, id) }},
		{"ListStorages", "/api/v1/orgs/%s/storage", func(id string) { _, _ = c.ListStorages(ctx, id) }},
		{"SetPrimaryKey", "/api/v1/identities/%s/primary", func(id string) { _ = c.SetPrimaryKey(ctx, id) }},
		{"DeleteKey", "/api/v1/identities/%s", func(id string) { _ = c.DeleteKey(ctx, id) }},
		{"createSecret", "/api/v1/orgs/%s/secrets", func(id string) { _, _, _ = createSecret(c.api, &createRequest{OrgID: id}) }},
		{"listSecretsFor sent", "/api/v1/secrets/sender/%s", func(id string) { _, _, _ = listSecretsFor(c.api, id, "sent") }},
		{"listSecretsFor received", "/api/v1/secrets/recipient/%s", func(id string) { _, _, _ = listSecretsFor(c.api, id, "received") }},
	}
	reset := func() {
		mu.Lock()
		defer mu.Unlock()
		paths, queries = nil, nil
	}
	for _, id := range []string{"../../actors/me", "a/b", "a?x=1", "a#b"} {
		for _, call := range calls {
			reset()
			call.call(id)
			want := fmt.Sprintf(call.path, transport.PathSegment(id))
			mu.Lock()
			if !slices.Contains(paths, want) {
				t.Errorf("%s(%q): sent %q, want %q", call.name, id, paths, want)
			}
			for _, q := range queries {
				if q == "x=1" {
					t.Errorf("%s(%q): the ID became a query", call.name, id)
				}
			}
			mu.Unlock()
		}
	}
	for _, id := range []string{"..", ".", ""} {
		for _, call := range calls {
			reset()
			call.call(id)
			mu.Lock()
			if len(paths) != 0 {
				t.Errorf("%s(%q): sent %q, want nothing", call.name, id, paths)
			}
			mu.Unlock()
		}
	}
	if err := c.DeleteKey(ctx, ".."); !errors.Is(err, api.ErrInvalidID) {
		t.Errorf("DeleteKey(..): err = %v, want ErrInvalidID", err)
	}
}
