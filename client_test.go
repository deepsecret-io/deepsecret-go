// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package deepsecret

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/apierror"
)

// A session store may leave either func unset: a refused token then simply
// stays refused.
func TestWithSessionStoreAcceptsPartialStores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"unauthorized"}`)
	}))
	t.Cleanup(srv.Close)
	for name, store := range map[string]SessionStore{
		"empty":     {},
		"load only": {Load: func() (string, error) { return "", nil }},
		"save only": {Save: func(string, time.Time) error { return nil }},
	} {
		c, err := NewClient(srv.URL, "bearer:token", WithSessionStore(store))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Logout(context.Background()); !errors.Is(err, apierror.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want ErrUnauthorized", name, err)
		}
	}
}
