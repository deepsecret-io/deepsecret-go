// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/sdk/crypto"
)

// substitute makes f list a self-signed bundle of a key it holds as the
// primary key of every email in emails, as a hostile server would, and
// returns that key's fingerprint.
func substitute(t *testing.T, f *fakeAPI, emails ...string) string {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := crypto.Fingerprint(kp)
	edSig, mldsaSig, err := crypto.SignKeyBundle(kp)
	if err != nil {
		t.Fatal(err)
	}
	f.editBundle = func(email string, b map[string]any) {
		for _, e := range emails {
			if e == email {
				b["ed25519"], b["x25519"], b["mlkem768"], b["mldsa65"] = kp.ED25519Public, kp.X25519Public, kp.MLKEM768PK, kp.MLDSA65PK
				b["fingerprint"], b["signature"], b["signature_mldsa65"] = fp, edSig, mldsaSig
			}
		}
	}
	return fp
}

// A recipient bundle without its fingerprint or either self-signature is
// refused before anything is sealed or sent, on both send paths.
func TestSendRefusesIncompleteRecipientBundle(t *testing.T) {
	for _, field := range []string{"fingerprint", "signature", "signature_mldsa65"} {
		t.Run(field, func(t *testing.T) {
			f := newFakeAPI(t, "alice@example.com", "bob@example.com")
			f.editBundle = func(email string, b map[string]any) {
				if email == "bob@example.com" {
					delete(b, field)
				}
			}
			c := f.client("alice@example.com")
			if _, err := c.EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{Name: "n"}); err == nil {
				t.Fatal("send accepted")
			}
			path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
			if _, err := c.EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{LocalFile: path}); err == nil {
				t.Fatal("local send accepted")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("refused local send wrote %s: %v", path, err)
			}
			if f.creates != 0 {
				t.Errorf("refused sends created %d secrets", f.creates)
			}
		})
	}
}

// When the sender is a recipient, the server cannot list a key of its own
// as theirs: the send is refused before anything is sealed, on both paths,
// while a send to someone else is unaffected.
func TestSelfSendRefusesSubstitutedKey(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	substitute(t, f, alice.email)
	c := f.client(alice.email)

	for _, to := range [][]string{{alice.email}, {bob.email, alice.email}} {
		_, err := c.EncryptText(to, "for me only", EncryptOptions{Name: "n"})
		if err == nil || !strings.Contains(err.Error(), "not a key on this device") {
			t.Fatalf("send to %v: %v, want refused", to, err)
		}
		path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
		_, err = c.EncryptText(to, "for me only", EncryptOptions{LocalFile: path})
		if err == nil || !strings.Contains(err.Error(), "not a key on this device") {
			t.Fatalf("local send to %v: %v, want refused", to, err)
		}
	}
	if f.creates != 0 {
		t.Fatalf("refused sends created %d secrets", f.creates)
	}

	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatalf("send to bob: %v", err)
	}
}

// An address the server resolves to the sender's own account is a self-send
// too, checked the same way.
func TestSelfSendByAliasRefusesSubstitutedKey(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.actors["alice@example.com"]
	f.actors["alice.alias@example.com"] = alice
	substitute(t, f, "alice.alias@example.com")

	_, err := f.client(alice.email).EncryptText([]string{"alice.alias@example.com"}, "for me only", EncryptOptions{Name: "n"})
	if err == nil || !strings.Contains(err.Error(), "not a key on this device") {
		t.Fatalf("send: %v, want refused", err)
	}
	if f.creates != 0 {
		t.Fatalf("refused send created %d secrets", f.creates)
	}
}

// Sending to yourself with another of your keys works: the primary key the
// server lists is on this device, and is checked without its password.
func TestSelfSendWithAnotherLocalIdentity(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.actors["alice@example.com"]
	if err := crypto.SaveKeyPair(alice.fp, alice.kp, "correct horse"); err != nil {
		t.Fatal(err)
	}
	second, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	secondFP, _ := crypto.Fingerprint(second)
	if err := crypto.SaveKeyPair(secondFP, second, ""); err != nil {
		t.Fatal(err)
	}

	res, err := f.client(alice.email).EncryptText([]string{alice.email}, "for me", EncryptOptions{Name: "n", Identity: secondFP})
	if err != nil {
		t.Fatal(err)
	}
	if res.SenderFingerprint != secondFP || len(f.lastReq.Recipients) != 1 || f.lastReq.Recipients[0].KeyFingerprint != alice.fp {
		t.Fatalf("sent with %s to %+v", res.SenderFingerprint, f.lastReq.Recipients)
	}
}

// A server that answers /actors/me as someone else cannot pass off a key of
// its own as the caller's: their account was recorded as theirs on this
// device, so a send to it still takes only a key pair here, on both paths,
// and the server's key is recorded nowhere. Claiming an account this device
// does not know records nothing.
func TestSelfSendWhenServerLiesAboutCaller(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["carol@example.com"]
	c := f.client(alice.email)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	creates := f.creates

	f.whoAmI = carol.email
	fake := substitute(t, f, alice.email)
	for _, opt := range []EncryptOptions{{Name: "n2"}, {LocalFile: filepath.Join(t.TempDir(), "note"+LocalFileExt)}} {
		_, err := c.EncryptText([]string{alice.email}, "for me only", opt)
		if err == nil || !strings.Contains(err.Error(), "not a key on this device") {
			t.Fatalf("send to yourself (local file %q): %v, want refused", opt.LocalFile, err)
		}
	}
	if f.creates != creates {
		t.Fatalf("refused sends created %d secrets", f.creates-creates)
	}
	for _, k := range knownKeysList(t, c) {
		if k.Fingerprint == fake || k.Email == carol.email {
			t.Fatalf("recorded %+v", k)
		}
	}
}

// The two-phase probe: after an honest send to bob, a server answering
// /actors/me as bob cannot make bob one of alice's own accounts, which
// would block every send to him and secret from him. Each send, and
// registering a key, is refused, saying the server claims to be bob, and
// bob's key stays as it was.
func TestServerCannotClaimAContactIsYou(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	c := f.client(alice.email)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	creates := f.creates

	f.whoAmI = bob.email
	for _, opt := range []EncryptOptions{{Name: "n2"}, {LocalFile: filepath.Join(t.TempDir(), "note"+LocalFileExt)}} {
		for _, to := range [][]string{{alice.email}, {bob.email}} {
			_, err := c.EncryptText(to, "hello", opt)
			if err == nil || !strings.Contains(err.Error(), "the server says you are "+bob.email) {
				t.Fatalf("send to %v (local file %q): %v, want refused", to, opt.LocalFile, err)
			}
		}
	}
	if err := c.SyncIdentity(alice.kp); err == nil || !strings.Contains(err.Error(), "the server says you are "+bob.email) {
		t.Fatalf("register a key: %v, want refused", err)
	}
	if f.creates != creates {
		t.Fatalf("refused sends created %d secrets", f.creates-creates)
	}
	if known := knownKeys(t, c, bob.email); len(known) != 1 || known[bob.fp].State != KeyFirstUse {
		t.Fatalf("bob's known keys %+v, want his on first use only", known)
	}

	f.whoAmI = ""
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n3"}); err != nil {
		t.Fatalf("send to bob once the server is honest: %v", err)
	}
}

// An email marked as yours by mistake, as by an older client a server lied
// to, shows in KnownKeys and is undone by forgetting that entry.
func TestForgetUndoesAContactMarkedAsYours(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	forgetLocalKey(t, bob)
	c := f.client(alice.email)
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	poisoned := fmt.Sprintf(`{"version": 1, "servers": {%q: {
		%q: [{"fingerprint": %q, "state": "own", "first_seen": "2026-10-30T00:00:00Z"}],
		%q: [{"fingerprint": %q, "state": "tofu", "first_seen": "2026-10-30T00:00:00Z"},
		     {"fingerprint": %q, "state": "own", "first_seen": "2026-10-31T00:00:00Z"}]}}}`,
		strings.ToLower(f.srv.URL), alice.email, alice.fp, bob.email, bob.fp, alice.fp)
	if err := os.WriteFile(f.knownFile(alice.email), []byte(poisoned), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n2"}); err == nil || !strings.Contains(err.Error(), "forget it") {
		t.Fatalf("send to bob: %v, want refused as your own account", err)
	}
	if known := knownKeys(t, c, bob.email); known[alice.fp].State != KeyOwn || known[bob.fp].State != KeyFirstUse {
		t.Fatalf("bob's known keys %+v, want the mistaken entry listed", known)
	}
	if n, err := c.ForgetKey(bob.email, alice.fp); err != nil || n != 1 {
		t.Fatalf("forget: %d, %v", n, err)
	}
	if _, err := c.EncryptText([]string{bob.email}, "hello", EncryptOptions{Name: "n2"}); err != nil {
		t.Fatalf("send to bob after forgetting: %v", err)
	}
}

// Registering a key records the account as the user's own on this device,
// so a server lying about the caller is caught even before the first send.
func TestSyncIdentityRecordsOwnAccount(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.actors["alice@example.com"], f.actors["bob@example.com"]
	c := f.client(alice.email)
	if err := c.SyncIdentity(alice.kp); err != nil {
		t.Fatal(err)
	}
	if known := knownKeys(t, c, alice.email); len(known) != 1 || known[alice.fp].State != KeyOwn {
		t.Fatalf("known keys %+v, want alice's own", known)
	}

	f.whoAmI = bob.email
	substitute(t, f, alice.email)
	_, err := c.EncryptText([]string{alice.email}, "for me only", EncryptOptions{Name: "n"})
	if err == nil || !strings.Contains(err.Error(), "not a key on this device") {
		t.Fatalf("send to yourself: %v, want refused", err)
	}
	if f.creates != 0 {
		t.Fatalf("refused send created %d secrets", f.creates)
	}
}

// A secret from one of your own accounts must be signed with a key on this
// device: a key the server lists as yours, held elsewhere, cannot forge one,
// on either decrypt path.
func TestDecryptRefusesSecretSignedAsYouElsewhere(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.actors["alice@example.com"]
	c := f.client(alice.email)
	if err := c.SyncIdentity(alice.kp); err != nil {
		t.Fatal(err)
	}

	// A key the server lists as alice's, used on another device.
	forged, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	forgedFP, _ := crypto.Fingerprint(forged)
	if err := crypto.SaveKeyPair(forgedFP, forged, ""); err != nil {
		t.Fatal(err)
	}
	alice.old = append(alice.old, forged)
	elsewhere := f.client(alice.email)
	elsewhere.SetKnownKeysFile(filepath.Join(t.TempDir(), "known_keys.json"))
	res, err := elsewhere.EncryptText([]string{alice.email}, "pay mallory", EncryptOptions{Name: "n", Identity: forgedFP})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "note"+LocalFileExt)
	if _, err := elsewhere.EncryptText([]string{alice.email}, "pay mallory", EncryptOptions{LocalFile: path, Identity: forgedFP}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(crypto.DefaultKeysDir(), forgedFP+".json")); err != nil {
		t.Fatal(err)
	}

	if _, err := c.DecryptSecretFull(res.Secret.ID, DecryptOptions{}); err == nil || !strings.Contains(err.Error(), "possible forgery") {
		t.Fatalf("decrypt: %v, want refused", err)
	}
	if _, err := f.openLocal(alice.email, path); err == nil || !strings.Contains(err.Error(), "possible forgery") {
		t.Fatalf("local file: %v, want refused", err)
	}
	for _, k := range knownKeysList(t, c) {
		if k.Fingerprint == forgedFP {
			t.Fatalf("the other key was recorded: %+v", k)
		}
	}
}

func knownKeysList(t *testing.T, c *Client) []KnownKey {
	t.Helper()
	keys, err := c.KnownKeys("")
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
