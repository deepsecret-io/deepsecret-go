// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/deepsecret-io/sdk/crypto"
)

// forgetLocalKey removes a's key pair from this device, so it is someone
// else's key here: the fake keeps every actor's keys in one directory.
func forgetLocalKey(t *testing.T, a *fakeActor) {
	t.Helper()
	if err := os.Remove(filepath.Join(crypto.DefaultKeysDir(), a.fp+".json")); err != nil {
		t.Fatal(err)
	}
}

// rotate gives a a new primary key, on this device and on the server, which
// still lists the old one.
func rotate(t *testing.T, a *fakeActor) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := crypto.Fingerprint(kp)
	if err := crypto.SaveKeyPair(fp, kp, ""); err != nil {
		t.Fatal(err)
	}
	a.old = append(a.old, a.kp)
	a.kp, a.fp = kp, fp
}

// setPrimary makes kp, one of a's keys, its primary key on the server again.
func setPrimary(a *fakeActor, kp *crypto.KeyPair) {
	a.old = slices.DeleteFunc(a.old, func(o *crypto.KeyPair) bool { return o == kp })
	a.old = append(a.old, a.kp)
	a.kp = kp
	a.fp, _ = crypto.Fingerprint(kp)
}

// knownKeys returns what c's device knows for email, or for everyone when
// email is empty, by fingerprint.
func knownKeys(t *testing.T, c *Client, email string) map[string]KnownKey {
	t.Helper()
	keys, err := c.KnownKeys(email)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]KnownKey{}
	for _, k := range keys {
		out[k.Fingerprint] = k
	}
	return out
}

// The first send to someone accepts their key and says so; later sends use
// it quietly. Sending to yourself accepts nothing: it records the account
// as yours, with the key you sent with.
func TestFirstSendAcceptsRecipientKey(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	// The default file, under the user's home.
	c, err := NewClient(f.srv.URL, alice.email)
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.EncryptText([]string{alice.email, bob.email}, "hello", EncryptOptions{Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FirstUse) != 1 || res.FirstUse[0] != (Recipient{Email: bob.email, Fingerprint: bob.fp}) {
		t.Fatalf("first use %+v, want bob only", res.FirstUse)
	}
	if got := knownKeys(t, c, bob.email); len(got) != 1 || got[bob.fp].State != KeyFirstUse {
		t.Fatalf("bob's known keys %v, want his on first use", got)
	}
	if got := knownKeys(t, c, alice.email); len(got) != 1 || got[alice.fp].State != KeyOwn {
		t.Fatalf("alice's known keys %v, want her own", got)
	}
	if info, err := os.Stat(DefaultKnownKeysFile()); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("known keys file: %v, %v", info, err)
	}

	res, err = c.EncryptText([]string{bob.email}, "again", EncryptOptions{Name: "n2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FirstUse) != 0 {
		t.Fatalf("second send reports first use %+v", res.FirstUse)
	}
}

// When the server lists another key for someone this device knows, as
// after they rotated, a send to them is refused on both paths until the
// user accepts the new key by its full fingerprint.
func TestChangedRecipientKeyIsRefused(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	c := f.client(alice.email)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	creates := f.creates

	old := bob.fp
	rotate(t, bob)
	got := bob.fp
	_, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"})
	var changed *KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("send: %v, want a KeyChangedError", err)
	}
	if changed.Email != bob.email || changed.Got != got || changed.Sender || changed.Replaced || len(changed.Known) != 1 || changed.Known[0] != old {
		t.Fatalf("error %+v", changed)
	}
	path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{LocalFile: path}); !errors.As(err, &changed) {
		t.Fatalf("local send: %v, want a KeyChangedError", err)
	}
	if f.creates != creates {
		t.Fatal("a refused send created a secret")
	}

	// Only the full fingerprint of a key the server lists for them is
	// accepted.
	other, _ := crypto.GenerateKeyPair()
	otherFP, _ := crypto.Fingerprint(other)
	for _, fp := range []string{got[:16], "", otherFP, got + "0", strings.Repeat("z", 64)} {
		if err := c.AcceptKey(bob.email, fp); err == nil {
			t.Errorf("accepted %q", fp)
		}
	}
	if err := c.AcceptKey("not an email", got); err == nil {
		t.Error("accepted a key for a malformed email")
	}
	if err := c.AcceptKey(strings.ToUpper(bob.email), strings.ToUpper(got)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatalf("send after accepting: %v", err)
	}
	known := knownKeys(t, c, bob.email)
	if len(known) != 2 || known[old].State != KeyFirstUse || !known[old].Replaced || known[got].State != KeyAccepted || known[got].Replaced {
		t.Fatalf("known keys %+v", known)
	}

	// Verifying raises a key's state; accepting never lowers it.
	if err := c.VerifyKey(bob.email, got); err != nil {
		t.Fatal(err)
	}
	if err := c.AcceptKey(bob.email, got); err != nil {
		t.Fatal(err)
	}
	if known := knownKeys(t, c, bob.email); known[got].State != KeyVerified {
		t.Fatalf("known keys %+v, want %s verified", known, got)
	}

	// Your own account takes no accepted key.
	if err := c.AcceptKey(alice.email, alice.fp); err == nil || !strings.Contains(err.Error(), "your own account") {
		t.Fatalf("accepting a key for your own account: %v", err)
	}

	// Forgetting them makes the next send a first use again.
	if n, err := c.ForgetKey(bob.email, got[:16]); err == nil {
		t.Fatalf("forgot %d keys by a prefix", n)
	}
	if n, err := c.ForgetKey(bob.email, ""); err != nil || n != 2 {
		t.Fatalf("forget: %d, %v", n, err)
	}
	res, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"})
	if err != nil || len(res.FirstUse) != 1 {
		t.Fatalf("send after forgetting: %+v, %v", res, err)
	}
}

// Accepting a key replaces the others: the server cannot go back to a
// replaced key, one that leaked say, without the user accepting it again.
// Accepting or verifying a key makes it the one sends go to.
func TestAcceptReplacesOldKeys(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	c := f.client(alice.email)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	first, firstFP := bob.kp, bob.fp
	rotate(t, bob)
	second, secondFP := bob.kp, bob.fp
	if err := c.AcceptKey(bob.email, secondFP); err != nil {
		t.Fatal(err)
	}

	setPrimary(bob, first)
	creates := f.creates
	_, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"})
	var changed *KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("send to a replaced key: %v, want a KeyChangedError", err)
	}
	if !changed.Replaced || changed.Got != firstFP || len(changed.Known) != 1 || changed.Known[0] != secondFP || !strings.Contains(err.Error(), "changed back") {
		t.Fatalf("error %+v: %v", changed, err)
	}
	if f.creates != creates {
		t.Fatal("a refused send created a secret")
	}

	// Accepting it again makes it the key sends go to.
	if err := c.AcceptKey(bob.email, firstFP); err != nil {
		t.Fatal(err)
	}
	if known := knownKeys(t, c, bob.email); known[firstFP].Replaced || !known[secondFP].Replaced {
		t.Fatalf("known keys %+v, want the first key current", known)
	}
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatalf("send after accepting again: %v", err)
	}

	// So does verifying one.
	setPrimary(bob, second)
	if err := c.VerifyKey(bob.email, secondFP); err != nil {
		t.Fatal(err)
	}
	known := knownKeys(t, c, bob.email)
	if known[secondFP].State != KeyVerified || known[secondFP].Replaced || !known[firstFP].Replaced {
		t.Fatalf("known keys %+v, want the second key verified and current", known)
	}
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatalf("send after verifying: %v", err)
	}
}

// A secret from someone accepts their key on first receipt, on both
// decrypt paths. One signed with another key, after they rotated, is
// refused until the user accepts the new key. The replaced key still
// checks the secrets it signed, until it is forgotten.
func TestDecryptChecksSenderKey(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	send := func(text string) (string, string) {
		t.Helper()
		res, err := f.client(alice.email).EncryptText([]string{bob.email}, text, EncryptOptions{Name: text})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
		if _, err := f.client(alice.email).EncryptText([]string{bob.email}, text, EncryptOptions{LocalFile: path}); err != nil {
			t.Fatal(err)
		}
		forgetLocalKey(t, alice)
		return res.Secret.ID, path
	}
	cb := f.client(bob.email)

	firstID, path := send("one")
	res, err := cb.DecryptSecretFull(firstID, DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SenderFirstUse || res.SenderEmail != alice.email || res.SenderFingerprint != alice.fp {
		t.Fatalf("first decrypt %+v", res)
	}
	if res, err = cb.DecryptSecretFull(firstID, DecryptOptions{}); err != nil || res.SenderFirstUse {
		t.Fatalf("second decrypt %+v, %v", res, err)
	}
	if res, err = f.openLocal(bob.email, path); err != nil || res.SenderFirstUse {
		t.Fatalf("local file %+v, %v", res, err)
	}

	old := alice.fp
	rotate(t, alice)
	id, path := send("two")
	var changed *KeyChangedError
	if _, err := cb.DecryptSecretFull(id, DecryptOptions{}); !errors.As(err, &changed) {
		t.Fatalf("decrypt: %v, want a KeyChangedError", err)
	}
	if changed.Email != alice.email || !changed.Sender || changed.Got != alice.fp || len(changed.Known) != 1 || changed.Known[0] != old {
		t.Fatalf("error %+v", changed)
	}
	if _, err := f.openLocal(bob.email, path); !errors.As(err, &changed) {
		t.Fatalf("local file: %v, want a KeyChangedError", err)
	}

	if err := cb.AcceptKey(alice.email, alice.fp); err != nil {
		t.Fatal(err)
	}
	if res, err = cb.DecryptSecretFull(id, DecryptOptions{}); err != nil || res.SenderFirstUse {
		t.Fatalf("decrypt after accepting: %+v, %v", res, err)
	}
	if _, err = f.openLocal(bob.email, path); err != nil {
		t.Fatalf("local file after accepting: %v", err)
	}

	// The first secret is signed with the replaced key, which still checks
	// it until bob forgets that key.
	if _, err := cb.DecryptSecretFull(firstID, DecryptOptions{}); err != nil {
		t.Fatalf("decrypt a secret signed with the replaced key: %v", err)
	}
	if n, err := cb.ForgetKey(alice.email, old); err != nil || n != 1 {
		t.Fatalf("forget: %d, %v", n, err)
	}
	if _, err := cb.DecryptSecretFull(firstID, DecryptOptions{}); !errors.As(err, &changed) {
		t.Fatalf("decrypt with the replaced key forgotten: %v, want a KeyChangedError", err)
	}
}

// A secret you sent yourself is signed with a key on this device: yours.
// Nothing is accepted for it.
func TestDecryptOwnSecret(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.actors["alice@example.com"]
	c := f.client(alice.email)
	res, err := c.EncryptText([]string{alice.email}, "for me", EncryptOptions{Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.DecryptSecretFull(res.Secret.ID, DecryptOptions{})
	if err != nil || out.SenderFirstUse {
		t.Fatalf("decrypt %+v, %v", out, err)
	}
	if known := knownKeys(t, c, ""); len(known) != 1 || known[alice.fp].State != KeyOwn {
		t.Fatalf("known keys %+v, want only alice's own", known)
	}
}

// A key pair on this device does not let the server relabel the user's own
// secret as sent by someone this device knows: the claimed sender's pins
// still apply, on both the server path and local files. An email the
// server gives with spaces is refused before the pins are read.
func TestOwnKeyDoesNotPassAsKnownSender(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "mallory@example.com")
	alice, bob, mallory := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["mallory@example.com"]
	cb := f.client(bob.email)
	resA, err := f.client(alice.email).EncryptText([]string{bob.email}, "from alice", EncryptOptions{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	forgetLocalKey(t, alice)
	if _, err := cb.DecryptSecretFull(resA.Secret.ID, DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
	note, err := cb.EncryptText([]string{bob.email}, "bob's note", EncryptOptions{Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
	if _, err := cb.EncryptText([]string{bob.email}, "bob's note", EncryptOptions{LocalFile: path}); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.secrets[note.Secret.ID].senderID = alice.id
	alice.old = append(alice.old, bob.kp)
	f.mu.Unlock()
	var changed *KeyChangedError
	if res, err := cb.DecryptSecretFull(note.Secret.ID, DecryptOptions{}); !errors.As(err, &changed) {
		t.Fatalf("relabeled own secret: %+v, %v, want a KeyChangedError", res, err)
	}
	relabelLocalSender(t, path, alice.email)
	if res, err := f.openLocal(bob.email, path); !errors.As(err, &changed) {
		t.Fatalf("relabeled own local file: %+v, %v, want a KeyChangedError", res, err)
	}

	f.mu.Lock()
	mallory.email = "alice@example.com "
	f.actors[mallory.email] = mallory
	f.actors["alice@example.com%20"] = mallory
	mallory.old = append(mallory.old, bob.kp)
	f.secrets[note.Secret.ID].senderID = mallory.id
	f.mu.Unlock()
	if _, err := cb.DecryptSecretFull(note.Secret.ID, DecryptOptions{}); err == nil || !strings.Contains(err.Error(), "invalid sender email") {
		t.Fatalf("sender email with a space: %v, want it refused", err)
	}
}

// relabelLocalSender rewrites the unsigned sender label of a local file.
func relabelLocalSender(t *testing.T, path, email string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr, payloadSize, err := readLocalHeader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	hdr.SenderEmail = email
	enc, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw[:localPrefixLen+payloadSize:localPrefixLen+payloadSize], enc...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A key new to this device is recorded only once the send relying on it
// succeeded: a send refused for another recipient, or whose upload fails,
// leaves it unknown, and the next send that succeeds reports it.
func TestFirstUseRecordedOnlyAfterSend(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	bob, carol := f.actors["bob@example.com"], f.actors["carol@example.com"]
	c := f.client("alice@example.com")
	if _, err := c.EncryptText([]string{carol.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	rotate(t, carol)
	var changed *KeyChangedError
	if _, err := c.EncryptText([]string{bob.email, carol.email}, "hello", EncryptOptions{Name: "n2"}); !errors.As(err, &changed) {
		t.Fatalf("send: %v, want carol's key refused", err)
	}
	path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
	if _, err := c.EncryptText([]string{bob.email, carol.email}, "hello", EncryptOptions{LocalFile: path}); !errors.As(err, &changed) {
		t.Fatalf("local send: %v, want carol's key refused", err)
	}
	if known := knownKeys(t, c, bob.email); len(known) != 0 {
		t.Fatalf("a refused send recorded bob's key: %+v", known)
	}

	// An upload that fails records nothing either.
	_, interrupted := interruptedSend(t, f, t.TempDir())
	if interrupted == nil {
		t.Fatal("the upload did not fail")
	}
	if known := knownKeys(t, c, bob.email); len(known) != 0 {
		t.Fatalf("a failed upload recorded bob's key: %+v", known)
	}

	f.mu.Lock()
	f.refusePart = 0
	f.mu.Unlock()
	res, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n3"})
	if err != nil || len(res.FirstUse) != 1 || res.FirstUse[0].Email != bob.email {
		t.Fatalf("send: %+v, %v", res, err)
	}
	if known := knownKeys(t, c, bob.email); known[bob.fp].State != KeyFirstUse {
		t.Fatalf("bob's known keys %+v", known)
	}
}

// The same holds for a sender's key: a decrypt that fails after the sender
// check, as when the payload fails its check, records nothing.
func TestSenderFirstUseRecordedOnlyAfterDecrypt(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	res, err := f.client(alice.email).EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	forgetLocalKey(t, alice)
	stored, err := os.ReadDir(f.objects)
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored objects: %v, %v", stored, err)
	}
	object := filepath.Join(f.objects, stored[0].Name())
	data, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	damaged := slices.Clone(data)
	damaged[len(damaged)/2] ^= 1
	if err := os.WriteFile(object, damaged, 0o600); err != nil {
		t.Fatal(err)
	}

	cb := f.client(bob.email)
	if _, err := cb.DecryptSecretFull(res.Secret.ID, DecryptOptions{}); err == nil {
		t.Fatal("decrypt of a damaged payload succeeded")
	}
	if known := knownKeys(t, cb, alice.email); len(known) != 0 {
		t.Fatalf("a failed decrypt recorded alice's key: %+v", known)
	}

	if err := os.WriteFile(object, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := cb.DecryptSecretFull(res.Secret.ID, DecryptOptions{})
	if err != nil || !out.SenderFirstUse {
		t.Fatalf("decrypt: %+v, %v", out, err)
	}
	if known := knownKeys(t, cb, alice.email); known[alice.fp].State != KeyFirstUse {
		t.Fatalf("alice's known keys %+v", known)
	}
}

// Recording a first use re-checks under the lock: a key another process
// recorded for someone meanwhile is never overwritten, and nothing of that
// record is written.
func TestRecordFirstUseRefusesAKeyRecordedMeanwhile(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	c := f.client("alice@example.com")
	k1, k2, k3 := fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2), fmt.Sprintf("%064x", 3)
	if err := c.recordFirstUse([]Recipient{{Email: "bob@example.com", Fingerprint: k1}}, false); err != nil {
		t.Fatal(err)
	}
	err := c.recordFirstUse([]Recipient{{Email: "carol@example.com", Fingerprint: k3}, {Email: "bob@example.com", Fingerprint: k2}}, false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) || changed.Got != k2 {
		t.Fatalf("record: %v, want bob's key refused", err)
	}
	if known := knownKeys(t, c, ""); len(known) != 1 || known[k1].Email != "bob@example.com" {
		t.Fatalf("known keys %+v, want bob's first key only", known)
	}
}

// Keys known for one server do not pass for another: the same email there
// is a first use, not a change.
func TestKnownKeysArePerServer(t *testing.T) {
	file := filepath.Join(t.TempDir(), "known_keys.json")
	f1 := newFakeAPI(t, "alice@example.com", "bob@example.com")
	c1 := f1.client("alice@example.com")
	c1.SetKnownKeysFile(file)
	if _, err := c1.EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}

	f2 := newFakeAPI(t, "alice@example.com", "bob@example.com")
	c2 := f2.client("alice@example.com")
	c2.SetKnownKeysFile(file)
	res, err := c2.EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{Name: "n"})
	if err != nil || len(res.FirstUse) != 1 {
		t.Fatalf("send on another server: %+v, %v", res, err)
	}
	if len(knownKeys(t, c1, "bob@example.com")) != 1 || len(knownKeys(t, c2, "bob@example.com")) != 1 {
		t.Fatal("each server should know one key for bob")
	}
}

// A damaged known keys file, or one of another version, refuses sends
// rather than accepting any key again.
func TestDamagedKnownKeysFileRefusesSends(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	c := f.client("alice@example.com")
	server := strings.ToLower(f.srv.URL)
	for name, content := range map[string]string{
		"not json":      "{",
		"version":       `{"version": 2, "servers": {}}`,
		"short key":     fmt.Sprintf(`{"version": 1, "servers": {%q: {"bob@example.com": [{"fingerprint": "abcd", "state": "tofu"}]}}}`, server),
		"unknown state": fmt.Sprintf(`{"version": 1, "servers": {%q: {"bob@example.com": [{"fingerprint": %q, "state": "trusted"}]}}}`, server, strings.Repeat("a", 64)),
		"replaced own":  fmt.Sprintf(`{"version": 1, "servers": {%q: {"alice@example.com": [{"fingerprint": %q, "state": "own", "replaced": true}]}}}`, server, strings.Repeat("a", 64)),
	} {
		if err := os.WriteFile(f.knownFile("alice@example.com"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{Name: "n"}); err == nil {
			t.Errorf("%s: send accepted", name)
		}
	}
	if f.creates != 0 {
		t.Fatalf("refused sends created %d secrets", f.creates)
	}
}

// Processes and goroutines changing the file at once never lose each
// other's changes.
func TestKnownKeysConcurrentChanges(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	c := f.client("alice@example.com")
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := Recipient{Email: fmt.Sprintf("p%d@example.com", i), Fingerprint: fmt.Sprintf("%064x", i+1)}
			if err := c.recordFirstUse([]Recipient{p}, false); err != nil {
				errs <- fmt.Errorf("person %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if known := knownKeys(t, c, ""); len(known) != n {
		t.Fatalf("%d keys known, want %d", len(known), n)
	}
}
