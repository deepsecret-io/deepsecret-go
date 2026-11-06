// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/transfer"
)

// phaseRecorder follows OnPhase: the phases in order, and how many unlocks
// the security key had answered when each began.
type phaseRecorder struct {
	key      *testSecurityKey
	phases   []transfer.Phase
	unlocked []int
}

func (r *phaseRecorder) record(p transfer.Phase) {
	r.phases = append(r.phases, p)
	if r.key != nil {
		r.unlocked = append(r.unlocked, r.key.derives)
	}
}

func (r *phaseRecorder) check(t *testing.T, what string, want ...transfer.Phase) {
	t.Helper()
	if !slices.Equal(r.phases, want) {
		t.Errorf("%s: phases %v, want %v", what, r.phases, want)
	}
}

// A send reports encrypting, then uploading, whether it goes in one
// request or in parts; a local file is encrypting alone. An open reports
// downloading, or reading for a local file.
func TestPhases(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize = 5<<20, 5<<20
	alice, bob := f.client("alice@example.com"), f.client("bob@example.com")

	src := filepath.Join(t.TempDir(), "backup.bin")
	writeFile(t, src, randomBytes(t, 6<<20), 0o600)
	var sent phaseRecorder
	large, err := alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{OnPhase: sent.record})
	if err != nil {
		t.Fatal(err)
	}
	sent.check(t, "multipart send", transfer.PhaseEncrypting, transfer.PhaseUploading)

	sent = phaseRecorder{}
	small, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{OnPhase: sent.record})
	if err != nil {
		t.Fatal(err)
	}
	sent.check(t, "single request send", transfer.PhaseEncrypting, transfer.PhaseUploading)

	var opened phaseRecorder
	if _, _, err := bob.Secrets.DecryptToDir(context.Background(), large.Secret.ID, t.TempDir(), secrets.DecryptOptions{OnPhase: opened.record}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	opened.check(t, "download", transfer.PhaseDownloading)

	opened = phaseRecorder{}
	if _, err := bob.Secrets.Decrypt(context.Background(), small.Secret.ID, secrets.DecryptOptions{OnPhase: opened.record}); err != nil {
		t.Fatal(err)
	}
	opened.check(t, "download in memory", transfer.PhaseDownloading)

	path := filepath.Join(t.TempDir(), "note"+secrets.LocalFileExt)
	sent = phaseRecorder{}
	if _, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "offline", secrets.EncryptOptions{Name: "note", LocalFile: path, OnPhase: sent.record}); err != nil {
		t.Fatal(err)
	}
	sent.check(t, "local file", transfer.PhaseEncrypting)

	opened = phaseRecorder{}
	o, err := bob.Secrets.OpenLocalFile(context.Background(), path, secrets.DecryptOptions{OnPhase: opened.record})
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
	opened.check(t, "local file open", transfer.PhaseReading)
}

// The first phase begins only after the key pair is unlocked, so a prompt
// for a PIN or a touch never runs inside a phase.
func TestPhasesBeginAfterTheUnlock(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice := f.actors["alice@example.com"]
	key := &testSecurityKey{secrets: map[string][]byte{}}
	e, err := keystore.Edit(context.Background(), alice.keys, alice.fp, keystore.Unlock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddSecurityKey(context.Background(), key, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Commit(true); err != nil { // one security key, no second way in: a test key
		t.Fatal(err)
	}
	e.Close()
	c := f.client(alice.email)

	sent := phaseRecorder{key: key}
	res, err := c.Secrets.EncryptText(context.Background(), []string{alice.email}, "note to self", secrets.EncryptOptions{SecurityKey: key, OnPhase: sent.record})
	if err != nil {
		t.Fatal(err)
	}
	sent.check(t, "send", transfer.PhaseEncrypting, transfer.PhaseUploading)
	if !slices.Equal(sent.unlocked, []int{1, 1}) {
		t.Errorf("send: unlocks when each phase began %v, want [1 1]", sent.unlocked)
	}

	key.derives = 0
	opened := phaseRecorder{key: key}
	if _, err := c.Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{SecurityKey: key, OnPhase: opened.record}); err != nil {
		t.Fatal(err)
	}
	opened.check(t, "open", transfer.PhaseDownloading)
	if !slices.Equal(opened.unlocked, []int{1}) {
		t.Errorf("open: unlocks when the download began %v, want [1]", opened.unlocked)
	}
}
