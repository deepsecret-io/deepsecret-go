// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package knownkeys

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/protocol"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

const (
	alice    = "alice@example.com"
	aliceNew = "alice.new@example.com"
	testFPA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testFPB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// testSecret is the id of the secret the rollback tests open, and
	// otherSecret that of another one.
	testSecret  = "10000000-0000-4000-8000-0000000000aa"
	otherSecret = "10000000-0000-4000-8000-0000000000bb"
)

var discard = slog.New(slog.DiscardHandler)

// newStore is a store on oldServer with an empty key pair directory, and its
// file.
func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_keys.json")
	return New(path, oldServer, t.TempDir()), path
}

// people is what s knows on its server.
func people(t *testing.T, s *Store) map[string][]Entry {
	t.Helper()
	d, err := s.file.read()
	if err != nil {
		t.Fatal(err)
	}
	return d.Servers[s.server]
}

// wantRelabelled fails unless err is a KeyRelabelledError for testFPA,
// recorded for alice on this device and presented for aliceNew.
func wantRelabelled(t *testing.T, what string, err error, sender bool) {
	t.Helper()
	var relabelled *KeyRelabelledError
	if !errors.As(err, &relabelled) {
		t.Fatalf("%s: %v, want a KeyRelabelledError", what, err)
	}
	if relabelled.Email != aliceNew || relabelled.RecordedEmail != alice || relabelled.Fingerprint != testFPA || relabelled.Sender != sender || relabelled.SameSend {
		t.Fatalf("%s: %+v", what, relabelled)
	}
	if !strings.Contains(err.Error(), "possible relabelling by the server") || !strings.Contains(err.Error(), "forget "+alice+"'s key") {
		t.Errorf("%s: the message does not name a relabelling and the record to forget: %v", what, err)
	}
}

// A key belongs to one address on a server: one recorded for a contact is
// refused under another address, for a sender and for a recipient, at check
// time and again when it would be recorded. The same address still passes,
// and forgetting the record lets the new address take the key.
func TestKeyRecordedForOneEmailIsRefusedForAnother(t *testing.T) {
	s, _ := newStore(t)
	if err := s.RecordFirstUse([]Person{{Email: alice, Fingerprint: testFPA}}, true); err != nil {
		t.Fatal(err)
	}

	_, err := s.CheckSenderKey(aliceNew, testFPA, discard)
	wantRelabelled(t, "sender", err, true)
	_, err = CheckKey(people(t, s), aliceNew, testFPA, false)
	wantRelabelled(t, "recipient", err, false)
	wantRelabelled(t, "record a sender", s.RecordFirstUse([]Person{{Email: aliceNew, Fingerprint: testFPA}}, true), true)
	wantRelabelled(t, "record a recipient", s.RecordFirstUse([]Person{{Email: aliceNew, Fingerprint: testFPA}}, false), false)
	wantRelabelled(t, "accept", s.Trust(aliceNew, testFPA, Accepted), false)
	if got := people(t, s)[aliceNew]; len(got) != 0 {
		t.Fatalf("%s's known keys %+v, want none", aliceNew, got)
	}

	if got, err := s.CheckSenderKey(alice, testFPA, discard); err != nil || got.First {
		t.Fatalf("sender under the recorded address: %+v, %v", got, err)
	}
	if first, err := CheckKey(people(t, s), alice, testFPA, false); err != nil || first {
		t.Fatalf("recipient under the recorded address: first %v, %v", first, err)
	}

	// A replaced key is still its owner's.
	if err := s.Trust(alice, testFPB, Accepted); err != nil {
		t.Fatal(err)
	}
	_, err = s.CheckSenderKey(aliceNew, testFPA, discard)
	wantRelabelled(t, "sender, once the key is replaced", err, true)

	// Someone who really changed address: forget the old record, try again.
	if n, err := s.Forget(alice, testFPA); err != nil || n != 1 {
		t.Fatalf("Forget = %d, %v", n, err)
	}
	if got, err := s.CheckSenderKey(aliceNew, testFPA, discard); err != nil || !got.First {
		t.Fatalf("sender under the new address, the old record forgotten: %+v, %v", got, err)
	}
}

// Two people new to this device cannot be recorded with one key by the same
// send: the second is refused, and nothing is recorded. The error says so
// (SameSend): it names both addresses and no record to forget, since there
// is none. Next to a real record the flag stays unset, also for a key
// refused in a call that names someone new before it.
func TestRecordFirstUseRefusesOneKeyForTwoPeople(t *testing.T) {
	s, _ := newStore(t)
	err := s.RecordFirstUse([]Person{{Email: alice, Fingerprint: testFPA}, {Email: aliceNew, Fingerprint: testFPA}}, false)
	var relabelled *KeyRelabelledError
	if !errors.As(err, &relabelled) {
		t.Fatalf("one key for two recipients: %v, want a KeyRelabelledError", err)
	}
	if relabelled.Email != aliceNew || relabelled.RecordedEmail != alice || relabelled.Fingerprint != testFPA || relabelled.Sender || !relabelled.SameSend {
		t.Fatalf("one key for two recipients: %+v", relabelled)
	}
	if msg := err.Error(); strings.Contains(msg, "forget") || strings.Contains(msg, "this device knows") ||
		!strings.Contains(msg, "for both "+alice+" and "+aliceNew+" in this send") || !strings.Contains(msg, "possible key substitution by the server") {
		t.Errorf("one key for two recipients: message %q", msg)
	}
	if got := people(t, s); len(got) != 0 {
		t.Fatalf("known keys %+v, want none", got)
	}

	if err := s.RecordFirstUse([]Person{{Email: alice, Fingerprint: testFPA}}, false); err != nil {
		t.Fatal(err)
	}
	err = s.RecordFirstUse([]Person{{Email: "bob@example.com", Fingerprint: testFPB}, {Email: aliceNew, Fingerprint: testFPA}}, false)
	wantRelabelled(t, "a recorded key, after someone new in the same call", err, false)
	if got := people(t, s); len(got) != 1 || len(got[alice]) != 1 {
		t.Fatalf("known keys %+v, want alice's alone", got)
	}
}

// A record on this device always counts as one: were a key both recorded for
// a contact and noted for a recipient of the send in progress, the refusal
// names the record, not the send, whatever their addresses' order.
func TestRecordedKeyIsNeverReportedAsTheSameSend(t *testing.T) {
	for _, noted := range []string{"aaron@example.com", "zoe@example.com"} {
		known := map[string][]Entry{alice: {{Fingerprint: testFPA, State: FirstUse}}}
		NoteFirstUse(known, noted, testFPA)
		_, err := CheckKey(known, aliceNew, testFPA, false)
		wantRelabelled(t, "noted for "+noted, err, false)
	}
}

// The rules for the user's own keys are as they were. A key recorded for one
// of the user's accounts is refused for another sender by the rule for own
// keys, and the server listing it for a contact on first contact still gets
// it recorded for them. A key pair on this device recorded for a contact is
// still refused for a sender this device does not know as unrecorded.
func TestOwnKeysKeepTheirRules(t *testing.T) {
	const me, bob, carol = "me@example.com", "bob@example.com", "carol@example.com"
	s, _ := newStore(t)
	if _, err := s.RecordOwnAccount(me, testFPA, true); err != nil {
		t.Fatal(err)
	}
	var relabelled *KeyRelabelledError
	_, err := s.CheckSenderKey(bob, testFPA, discard)
	if err == nil || errors.As(err, &relabelled) || !strings.Contains(err.Error(), "your account "+me+"'s key") {
		t.Fatalf("own key under another sender: %v, want the refusal for the user's own keys", err)
	}
	if first, err := CheckKey(people(t, s), bob, testFPA, false); err != nil || !first {
		t.Fatalf("own key listed for a new contact: first %v, %v", first, err)
	}
	if err := s.RecordFirstUse([]Person{{Email: bob, Fingerprint: testFPA}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CheckSenderKey(bob, testFPA, discard); err == nil || errors.As(err, &relabelled) || !strings.Contains(err.Error(), "your account "+me+"'s key") {
		t.Fatalf("own key under the contact it is recorded for: %v, want the refusal for the user's own keys", err)
	}

	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	local, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.Save(s.keysDir, local, kp, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFirstUse([]Person{{Email: carol, Fingerprint: local}}, false); err != nil {
		t.Fatal(err)
	}
	var unrecorded *UnrecordedSenderError
	if _, err := s.CheckSenderKey("dave@example.com", local, discard); !errors.As(err, &unrecorded) {
		t.Fatalf("a key pair here under a sender this device does not know: %v, want an UnrecordedSenderError", err)
	}
	if got, err := s.CheckSenderKey(me, local, discard); err != nil || !got.Local || !got.OwnAccount {
		t.Fatalf("a key pair here under the user's own account: %+v, %v", got, err)
	}
}

// manifest is what CheckNewest and NewestRecorder read of a revision signed
// with fp at signed.
func manifest(fp, revision string, signed time.Time) *protocol.Manifest {
	return &protocol.Manifest{SecretName: "api-token", RevisionID: revision, SenderFingerprint: fp, Timestamp: signed.Unix()}
}

// The newest signing time is kept under the key that signed, as well as
// under the sender's address: an older revision named as the latest is
// refused under an address this device has no record for, and forgetting the
// sender's key does not clear the record.
func TestNewestIsKeptPerSenderKey(t *testing.T) {
	s, _ := newStore(t)
	at := time.Unix(1793534400, 0)
	v1, v2 := manifest(testFPA, "rev-1", at), manifest(testFPA, "rev-2", at.Add(time.Hour))
	s.now = func() time.Time { return at.Add(2 * time.Hour) }
	if err := s.CheckNewest(alice, testSecret, v2); err != nil {
		t.Fatal(err)
	}
	if err := s.NewestRecorder(alice, testSecret, v2)(); err != nil {
		t.Fatal(err)
	}

	stale := func(what, email string, m *protocol.Manifest) {
		t.Helper()
		var refused *StaleRevisionError
		if err := s.CheckNewest(email, testSecret, m); !errors.As(err, &refused) {
			t.Fatalf("%s: %v, want a StaleRevisionError", what, err)
		}
		if refused.SenderEmail != email || refused.RevisionID != "rev-1" || refused.SecretName != "api-token" ||
			!refused.SignedAt.Equal(at) || !refused.NewestSeen.Equal(at.Add(time.Hour)) {
			t.Fatalf("%s: %+v", what, refused)
		}
	}
	stale("under the sender's address", alice, v1)
	stale("under a new address", aliceNew, v1)
	if _, err := s.Forget(alice, ""); err != nil {
		t.Fatal(err)
	}
	stale("under the sender's address, their key forgotten", alice, v1)
	stale("under a new address, their key forgotten", aliceNew, v1)

	if err := s.CheckNewest(aliceNew, testSecret, v2); err != nil {
		t.Fatalf("the newest revision under a new address: %v", err)
	}
	if err := s.CheckNewest(aliceNew, otherSecret, manifest(testFPB, "rev-1", at)); err != nil {
		t.Fatalf("another key's revision under a new address: %v", err)
	}
	other := manifest(testFPA, "rev-1", at)
	other.SecretName = "other-app"
	if err := s.CheckNewest(alice, otherSecret, other); err != nil {
		t.Fatalf("another secret from the same key: %v", err)
	}
}

// A file from before the record per sender key still loads, its record per
// address still refuses a rollback, and the next decrypt adds the new record
// without changing the file's version.
func TestOldFileWithoutNewestByKeyStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys.json")
	if err := os.WriteFile(path, []byte(oldFile), 0o600); err != nil {
		t.Fatal(err)
	}
	const sender = "accepted@example.com"
	recorded := time.Unix(1793534400, 0)
	s := New(path, oldServer, t.TempDir())
	s.now = func() time.Time { return recorded.Add(24 * time.Hour) }
	note := func(revision string, signed time.Time) *protocol.Manifest {
		m := manifest(testFPB, revision, signed)
		m.SecretName = "note"
		return m
	}
	var stale *StaleRevisionError
	if err := s.CheckNewest(sender, testSecret, note("rev-1", recorded.Add(-time.Second))); !errors.As(err, &stale) {
		t.Fatalf("a revision older than the old file's record: %v, want a StaleRevisionError", err)
	}
	newer := note("rev-3", recorded.Add(time.Hour))
	if err := s.CheckNewest(sender, testSecret, newer); err != nil {
		t.Fatal(err)
	}
	if err := s.NewestRecorder(sender, testSecret, newer)(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckNewest("someone.else@example.com", testSecret, note("rev-2", recorded)); !errors.As(err, &stale) {
		t.Fatalf("an older revision under another address: %v, want a StaleRevisionError", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"version": 1`) || !strings.Contains(string(raw), `"newest_by_key"`) {
		t.Fatalf("the file after a decrypt:\n%s", raw)
	}
	if got, err := s.List(""); err != nil || len(got) != 4 {
		t.Fatalf("List = %v, %v; want the 4 fixture keys", got, err)
	}
}

// The sender's clock is signed, not trusted. A revision signed far ahead of
// this device's clock opens, but it is recorded as signed at most five
// minutes from now, so the sender's next revision, signed with the clock set
// right, is not refused as stale.
func TestNewestRecordIsCappedByThisDevicesClock(t *testing.T) {
	s, _ := newStore(t)
	now := time.Unix(1793534400, 0)
	s.now = func() time.Time { return now }
	ahead := manifest(testFPA, "rev-1", now.AddDate(1, 0, 0))
	if err := s.CheckNewest(alice, testSecret, ahead); err != nil {
		t.Fatalf("a revision signed a year ahead: %v, want it opened", err)
	}
	if err := s.NewestRecorder(alice, testSecret, ahead)(); err != nil {
		t.Fatal(err)
	}

	// Ten minutes later the sender, their clock set right, signs again.
	now = now.Add(10 * time.Minute)
	honest := manifest(testFPA, "rev-2", now)
	if err := s.CheckNewest(alice, testSecret, honest); err != nil {
		t.Fatalf("an honest revision, by the address record: %v", err)
	}
	if err := s.CheckNewest(aliceNew, testSecret, honest); err != nil {
		t.Fatalf("an honest revision, by the key record: %v", err)
	}

	// The cap is on what is recorded, not on what is refused: a rollback
	// past a revision signed in time is still caught.
	if err := s.NewestRecorder(alice, testSecret, honest)(); err != nil {
		t.Fatal(err)
	}
	var stale *StaleRevisionError
	if err := s.CheckNewest(alice, testSecret, manifest(testFPA, "rev-0", now.Add(-time.Minute))); !errors.As(err, &stale) {
		t.Fatalf("a revision older than the honest one: %v, want a StaleRevisionError", err)
	}
}

// The two records above go by what the server and the manifest name: a
// revision whose sender address and signing key are both new to this device
// has neither. The record per secret id, which is what the caller asked for,
// still refuses it as a rollback, and does not touch another secret.
func TestNewestIsKeptPerSecretID(t *testing.T) {
	s, path := newStore(t)
	at := time.Unix(1793534400, 0)
	s.now = func() time.Time { return at.Add(2 * time.Hour) }
	v2 := manifest(testFPA, "rev-2", at.Add(time.Hour))
	if err := s.NewestRecorder(alice, testSecret, v2)(); err != nil {
		t.Fatal(err)
	}

	// The same secret id, served under an address and a key this device
	// has no record for, in any letter case.
	old := manifest(testFPB, "rev-1", at)
	var stale *StaleRevisionError
	for _, id := range []string{testSecret, strings.ToUpper(testSecret)} {
		if err := s.CheckNewest(aliceNew, id, old); !errors.As(err, &stale) {
			t.Fatalf("an older revision of %s under a new address and key: %v, want a StaleRevisionError", id, err)
		}
		if stale.RevisionID != "rev-1" || !stale.SignedAt.Equal(at) || !stale.NewestSeen.Equal(at.Add(time.Hour)) {
			t.Fatalf("%+v", stale)
		}
	}
	if err := s.CheckNewest(aliceNew, otherSecret, old); err != nil {
		t.Fatalf("another secret, under a new address and key: %v", err)
	}
	if err := s.CheckNewest(alice, testSecret, v2); err != nil {
		t.Fatalf("the newest revision again: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"version": 1`) || !strings.Contains(string(raw), `"newest_by_secret"`) || !strings.Contains(string(raw), `"revision_id": "rev-2"`) {
		t.Fatalf("the file after a decrypt:\n%s", raw)
	}
}

// Signing times are whole seconds, so two revisions can share one, and
// nothing else orders them: a sender's second send within a second must
// still open as the latest, so a revision signed in the same second as the
// newest opened passes. The record keeps the revision that set the time.
func TestARevisionSignedInTheSameSecondOpens(t *testing.T) {
	s, _ := newStore(t)
	at := time.Unix(1793534400, 0)
	s.now = func() time.Time { return at.Add(time.Hour) }
	first, second := manifest(testFPA, "rev-1", at), manifest(testFPA, "rev-2", at)
	if err := s.NewestRecorder(alice, testSecret, first)(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckNewest(alice, testSecret, second); err != nil {
		t.Fatalf("a second revision signed in the same second: %v", err)
	}
	if err := s.NewestRecorder(alice, testSecret, second)(); err != nil {
		t.Fatal(err)
	}
	d, err := s.file.read()
	if err != nil {
		t.Fatal(err)
	}
	if got := d.NewestBySecret[s.server][testSecret]; got != (newestRevision{At: at.Unix(), RevisionID: "rev-1"}) {
		t.Fatalf("the record per secret id: %+v, want the first revision at its signing time", got)
	}
	var stale *StaleRevisionError
	if err := s.CheckNewest(aliceNew, testSecret, manifest(testFPB, "rev-0", at.Add(-time.Second))); !errors.As(err, &stale) {
		t.Fatalf("a revision signed a second earlier: %v, want a StaleRevisionError", err)
	}
}

// CheckFirstUse answers as RecordFirstUse would and records nothing.
func TestCheckFirstUseRecordsNothing(t *testing.T) {
	s, path := newStore(t)
	bob := []Person{{Email: "bob@example.com", Fingerprint: testFPA}}
	if err := s.CheckFirstUse(bob, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a check wrote the file: %v", err)
	}
	if err := s.RecordFirstUse([]Person{{Email: "bob@example.com", Fingerprint: testFPB}}, false); err != nil {
		t.Fatal(err)
	}
	var changed *KeyChangedError
	if err := s.CheckFirstUse(bob, false); !errors.As(err, &changed) || changed.Got != testFPA {
		t.Fatalf("a key other than the one recorded: %v, want a KeyChangedError", err)
	}
	if got := people(t, s)["bob@example.com"]; len(got) != 1 || got[0].Fingerprint != testFPB {
		t.Fatalf("the record after a refused check: %+v", got)
	}
}
