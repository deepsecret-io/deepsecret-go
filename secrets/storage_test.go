// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
)

// storageServer answers GET /api/v1/orgs/{id}/storage with status and body.
func storageServer(t *testing.T, status int, body string) (*Client, *string) {
	t.Helper()
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.Method + " " + r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	api, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	c := New(api, nil, nil, t.TempDir())
	return c, &asked
}

// ListStorages reads each storage's usage and cap, a missing cap as nil.
func TestListStorages(t *testing.T) {
	c, asked := storageServer(t, http.StatusOK, `{"success":true,"data":[
		{"id":"s1","name":"Managed","provider_name":"DeepSecret Managed Storage","is_primary":true,"is_managed":true,"is_verified":true,"quota_bytes":21474836480,"total_size":1073741824,"secrets_count":12,"bucket_name":""},
		{"id":"s2","name":"Our bucket","provider_name":"S3","is_primary":false,"is_managed":false,"is_verified":true,"quota_bytes":null,"total_size":5,"secrets_count":1}
	]}`)
	got, err := c.ListStorages(context.Background(), "org-1")
	if err != nil {
		t.Fatal(err)
	}
	if *asked != "GET /api/v1/orgs/org-1/storage" {
		t.Errorf("asked %q", *asked)
	}
	if len(got) != 2 {
		t.Fatalf("got %d storages, want 2", len(got))
	}
	m := got[0]
	if !m.Primary || !m.Managed || !m.Verified || m.UsedBytes != 1<<30 || m.QuotaBytes == nil || *m.QuotaBytes != 20<<30 || m.SecretsCount != 12 || m.Provider != "DeepSecret Managed Storage" {
		t.Errorf("managed storage %+v", m)
	}
	if own := got[1]; own.Primary || own.QuotaBytes != nil || own.UsedBytes != 5 {
		t.Errorf("own storage %+v", own)
	}
}

// The organization ID is one path segment, and a member without the role
// gets the server's refusal as an *apierror.Error.
func TestListStoragesRefusalAndPath(t *testing.T) {
	c, asked := storageServer(t, http.StatusForbidden, `{"success":false,"error":"forbidden"}`)
	_, err := c.ListStorages(context.Background(), "org/../x")
	var ae *apierror.Error
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusForbidden || !errors.Is(err, apierror.ErrForbidden) {
		t.Fatalf("err = %v, want a 403 APIError", err)
	}
	if *asked != "GET /api/v1/orgs/org%2F..%2Fx/storage" {
		t.Errorf("asked %q", *asked)
	}

	if _, err := c.ListStorages(context.Background(), ""); err == nil {
		t.Error("an empty organization ID was sent")
	}
}
