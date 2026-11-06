// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/trust"
)

// All three services use one known keys file, in any order of the options: a
// key accepted or forgotten through Trust must apply to the next send, or the
// user's decision would silently do nothing.
func TestOptionsReachEveryService(t *testing.T) {
	ctx := context.Background()
	send := func(c *deepsecret.Client, to string) error {
		_, err := c.Secrets.EncryptText(ctx, []string{to}, "hello", secrets.EncryptOptions{Name: "n"})
		return err
	}
	for _, tc := range []struct {
		name string
		opts func(keysDir, file string) []deepsecret.Option
		// given says the file was named, rather than beside the keys directory.
		given bool
	}{
		{"keys dir alone", func(keysDir, _ string) []deepsecret.Option {
			return []deepsecret.Option{deepsecret.WithKeysDir(keysDir)}
		}, false},
		{"keys dir first", func(keysDir, file string) []deepsecret.Option {
			return []deepsecret.Option{deepsecret.WithKeysDir(keysDir), deepsecret.WithKnownKeysFile(file)}
		}, true},
		{"known keys first", func(keysDir, file string) []deepsecret.Option {
			return []deepsecret.Option{deepsecret.WithKnownKeysFile(file), deepsecret.WithKeysDir(keysDir)}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, "alice@example.com", "bob@example.com")
			alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
			given := filepath.Join(t.TempDir(), "named.json")
			beside := filepath.Join(filepath.Dir(alice.keys), "known_keys.json")
			want, other := beside, given
			if tc.given {
				want, other = given, beside
			}
			c, err := deepsecret.NewClient(f.srv.URL, alice.email, tc.opts(alice.keys, given)...)
			if err != nil {
				t.Fatal(err)
			}

			if err := c.Identity.Sync(ctx, alice.kp, false); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(want); err != nil {
				t.Fatalf("Identity did not write the known keys file: %v", err)
			}
			if _, err := os.Stat(other); !os.IsNotExist(err) {
				t.Fatalf("a second known keys file exists at %s: %v", other, err)
			}
			mine, err := c.Trust.List(alice.email)
			if err != nil || len(mine) != 1 || mine[0].State != trust.Own {
				t.Fatalf("Trust does not see what Identity recorded: %+v, %v", mine, err)
			}

			if err := send(c, bob.email); err != nil {
				t.Fatal(err)
			}
			theirs, err := c.Trust.List(bob.email)
			if err != nil || len(theirs) != 1 || theirs[0].Fingerprint != bob.fp {
				t.Fatalf("Trust does not see what Secrets recorded: %+v, %v", theirs, err)
			}

			rotate(t, bob)
			var changed *trust.KeyChangedError
			if err := send(c, bob.email); !errors.As(err, &changed) {
				t.Fatalf("send to a changed key: %v", err)
			}
			if _, err := c.Trust.Forget(bob.email, ""); err != nil {
				t.Fatal(err)
			}
			if err := send(c, bob.email); err != nil {
				t.Fatalf("Secrets did not see what Trust forgot: %v", err)
			}
		})
	}
}

// Delete sends all its IDs in one request.
func TestDeleteSendsEveryID(t *testing.T) {
	var got [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/secrets" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		got = append(got, body.IDs)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{}})
	}))
	t.Cleanup(srv.Close)
	c, err := deepsecret.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Delete(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	if err := c.Secrets.Delete(context.Background(), "a", "b"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !slices.Equal(got[0], []string{"a"}) || !slices.Equal(got[1], []string{"a", "b"}) {
		t.Errorf("requests = %v", got)
	}
}

// A TransferStatus needs no setup: the zero value works, and a nil one is
// ignored.
func TestTransferStatusZeroAndNil(t *testing.T) {
	var zero secrets.TransferStatus
	if got := zero.Snapshot(); got.Started || got.Done != 0 {
		t.Errorf("zero snapshot = %+v", got)
	}
	var none *secrets.TransferStatus
	if got := none.Snapshot(); got.Started {
		t.Errorf("nil snapshot = %+v", got)
	}

	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize = 5<<20, 5<<20
	src := filepath.Join(t.TempDir(), "big.bin")
	writeFile(t, src, randomBytes(t, 6<<20), 0o600)
	_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src},
		secrets.EncryptOptions{UploadStatus: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if got := zero.Snapshot(); !got.Started || got.Done == 0 || got.Done != got.Total {
		t.Errorf("after a send: %+v", got)
	}
}
