// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/directory"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

const bob = "bob@example.com"

func newPair(t *testing.T) (*keys.Pair, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return kp, fp
}

type fixture struct {
	c        *Client
	store    *knownkeys.Store
	file     string
	requests *atomic.Int64
}

// newFixture is a Client whose server lists listed, signed, for everyone.
func newFixture(t *testing.T, listed *keys.Pair) fixture {
	t.Helper()
	fp, err := keys.Fingerprint(listed)
	if err != nil {
		t.Fatal(err)
	}
	edSig, mldsaSig, err := directory.SignKeyBundle(listed)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/api/v1/identities/actor/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"keys": []map[string]any{{
			"ed25519": listed.ED25519Public, "x25519": listed.X25519Public, "mlkem768": listed.MLKEM768PK,
			"mldsa65": listed.MLDSA65PK, "fingerprint": fp, "signature": edSig, "signature_mldsa65": mldsaSig,
			"is_primary": true,
		}}}})
	}))
	t.Cleanup(srv.Close)
	api, err := transport.NewClient(srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "known_keys.json")
	store := knownkeys.New(file, srv.URL, t.TempDir())
	return fixture{New(api, store), store, file, &requests}
}

// A key the server does not list is never accepted, whatever the caller says.
func TestAcceptRefusesAKeyTheServerDoesNotList(t *testing.T) {
	listed, _ := newPair(t)
	_, other := newPair(t)
	f := newFixture(t, listed)
	if err := f.c.Accept(context.Background(), bob, other); err == nil {
		t.Fatal("accepted a key the server does not list")
	}
	if got, err := f.c.List(""); err != nil || len(got) != 0 {
		t.Errorf("the store changed: %v, %v", got, err)
	}
}

// Bad input is refused before anything is sent.
func TestAcceptChecksItsInputFirst(t *testing.T) {
	listed, fp := newPair(t)
	f := newFixture(t, listed)
	if err := f.c.Accept(context.Background(), "../../actors/me", fp); err == nil {
		t.Error("accepted an odd email")
	}
	if err := f.c.Verify(context.Background(), bob, fp[:16]); err == nil {
		t.Error("verified a short fingerprint")
	}
	if n := f.requests.Load(); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

func TestAcceptAndVerifyRecordTheirState(t *testing.T) {
	listed, fp := newPair(t)
	f := newFixture(t, listed)
	old := strings.Repeat("a", 64)
	if err := f.store.RecordFirstUse([]knownkeys.Person{{Email: bob, Fingerprint: old}}, false); err != nil {
		t.Fatal(err)
	}
	state := func() (State, bool) {
		t.Helper()
		got, err := f.c.List(bob)
		if err != nil || len(got) != 2 {
			t.Fatalf("List = %v, %v", got, err)
		}
		var st State
		var replaced bool
		for _, k := range got {
			switch k.Fingerprint {
			case fp:
				st = k.State
			case old:
				replaced = k.Replaced
			}
		}
		return st, replaced
	}
	if err := f.c.Accept(context.Background(), bob, fp); err != nil {
		t.Fatal(err)
	}
	if st, replaced := state(); st != Accepted || !replaced {
		t.Errorf("after Accept: state %q, old key replaced %v", st, replaced)
	}
	if err := f.c.Verify(context.Background(), bob, fp); err != nil {
		t.Fatal(err)
	}
	if st, replaced := state(); st != Verified || !replaced {
		t.Errorf("after Verify: state %q, old key replaced %v", st, replaced)
	}
}

func TestAcceptRefusesAnOwnAccount(t *testing.T) {
	listed, fp := newPair(t)
	f := newFixture(t, listed)
	if _, err := f.store.RecordOwnAccount(bob, strings.Repeat("a", 64), true); err != nil {
		t.Fatal(err)
	}
	err := f.c.Accept(context.Background(), bob, fp)
	if err == nil || !strings.Contains(err.Error(), "your own account") {
		t.Fatalf("Accept = %v", err)
	}
}

// What the server lists is only its claim: reading it decides nothing.
func TestServerListedKeysLeavesTheStoreAlone(t *testing.T) {
	listed, fp := newPair(t)
	f := newFixture(t, listed)
	pub, err := f.c.ServerListedKeys(context.Background(), bob)
	if err != nil || pub.Fingerprint != fp {
		t.Fatalf("ServerListedKeys = %+v, %v", pub, err)
	}
	if got, err := f.c.List(""); err != nil || len(got) != 0 {
		t.Errorf("the store changed: %v, %v", got, err)
	}
	if _, err := os.Stat(f.file); !os.IsNotExist(err) {
		t.Errorf("the known keys file was written: %v", err)
	}
}

func TestForgetLeavesNothingBehind(t *testing.T) {
	listed, fp := newPair(t)
	f := newFixture(t, listed)
	if err := f.c.Accept(context.Background(), bob, fp); err != nil {
		t.Fatal(err)
	}
	if n, err := f.c.Forget(bob, ""); err != nil || n != 1 {
		t.Fatalf("Forget = %d, %v", n, err)
	}
	if got, err := f.c.List(bob); err != nil || len(got) != 0 {
		t.Errorf("List after Forget = %v, %v", got, err)
	}
}
