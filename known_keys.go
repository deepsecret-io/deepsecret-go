// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
)

// ── Known keys: trust on first use ──────────────────────────────────────────
//
// The server lists everyone's public keys, and a key bundle's
// self-signatures prove only that it is whole, not whose it is. So this
// device remembers the key it first used for each person, per server, and
// refuses a send to them, or a secret from them, under any other key until
// the user accepts it (AcceptKey or VerifyKey, after comparing fingerprints
// with them). Accepting a key replaces the others: sends go to it alone,
// while the replaced keys still check secrets they signed. A key new to
// this device is recorded once the send or decrypt relying on it succeeds.
//
// The user's own accounts are recorded too, so the server cannot pass off
// another key as theirs by lying about who the caller is: only key pairs on
// this device pass for them. One is recorded when a key is registered for
// it, or by this device's first send on the server; a later send adds only
// the key it used to an account already recorded. An account the server
// claims for the caller that this device knows as someone else is refused,
// never recorded.

// knownKeysVersion is the version of the known keys file. Files with any
// other version are refused.
const knownKeysVersion = 1

// knownKeysLockWait is how long a change to the known keys file waits for
// another process to finish its own.
const knownKeysLockWait = 10 * time.Second

// DefaultKnownKeysFile returns the default known keys file, beside the
// keys directory: ~/.deepsecret/known_keys.json.
func DefaultKnownKeysFile() string {
	return filepath.Join(filepath.Dir(crypto.DefaultKeysDir()), "known_keys.json")
}

// KeyState says how a known key came to be accepted.
type KeyState string

const (
	// KeyFirstUse is a key accepted on first contact, not compared with its
	// owner.
	KeyFirstUse KeyState = "tofu"
	// KeyAccepted is a key the user accepted, after it changed.
	KeyAccepted KeyState = "accepted"
	// KeyVerified is a key the user compared with its owner.
	KeyVerified KeyState = "verified"
	// KeyOwn is a key pair on this device used with one of the user's own
	// accounts: only keys on this device pass for that email.
	KeyOwn KeyState = "own"
)

// rank orders key states from least to most checked, so accepting a key
// never lowers its state.
func (s KeyState) rank() int {
	switch s {
	case KeyFirstUse:
		return 1
	case KeyAccepted:
		return 2
	case KeyVerified:
		return 3
	case KeyOwn:
		return 4
	}
	return 0
}

// KnownKey is a key this device accepted for someone, or used with one of
// the user's own accounts (State KeyOwn).
type KnownKey struct {
	Email       string    `json:"email" yaml:"email"`
	Fingerprint string    `json:"fingerprint" yaml:"fingerprint"`
	State       KeyState  `json:"state" yaml:"state"`
	FirstSeen   time.Time `json:"first_seen" yaml:"first_seen"`
	// Replaced is set once the user accepted a newer key for Email: sends
	// no longer go to this one, but it still checks secrets it signed.
	Replaced bool `json:"replaced,omitempty" yaml:"replaced,omitempty"`
}

// KeyChangedError refuses a send to Email, or a secret from them, under a
// key this device has not accepted for them. Known lists the keys it sends
// to. The user compares Got with them before accepting it.
type KeyChangedError struct {
	Email    string
	Known    []string // the keys accepted for Email that sends go to
	Got      string   // the key the server lists for Email now, or the one that signed the secret
	Sender   bool     // Got signed a secret being decrypted; otherwise it is the recipient's key
	Replaced bool     // Got is a key this device accepted for Email before, replaced since
}

func (e *KeyChangedError) Error() string {
	known := make([]string, len(e.Known))
	for i, fp := range e.Known {
		known[i] = crypto.ShortFingerprint(fp)
	}
	got := crypto.ShortFingerprint(e.Got)
	switch {
	case e.Replaced:
		by := ""
		if len(known) > 0 {
			by = " with " + strings.Join(known, ", ")
		}
		return fmt.Sprintf("%s's key changed back: the server now lists key %s for them, which this device replaced%s (confirm it with them before accepting it again)",
			e.Email, got, by)
	case e.Sender:
		return fmt.Sprintf("%s's key changed: this device knows %s, but this secret is signed with key %s (confirm the new key with them before accepting it)",
			e.Email, strings.Join(known, ", "), got)
	}
	return fmt.Sprintf("%s's key changed: this device knows %s, but the server now lists key %s for them (confirm the new key with them before accepting it)",
		e.Email, strings.Join(known, ", "), got)
}

// SetKnownKeysFile makes c keep known keys in path instead of
// DefaultKnownKeysFile.
func (c *Client) SetKnownKeysFile(path string) { c.knownKeysFile = path }

// KnownKeys returns the keys this device accepted for email on c's server,
// or for everyone when email is empty, sorted by email, with the keys it
// used with the user's own accounts.
func (c *Client) KnownKeys(email string) ([]KnownKey, error) {
	email = strings.ToLower(email)
	disk, err := c.knownKeys().read()
	if err != nil {
		return nil, err
	}
	var out []KnownKey
	for e, keys := range disk.Servers[c.knownServer()] {
		if email != "" && e != email {
			continue
		}
		for _, k := range keys {
			out = append(out, KnownKey{Email: e, Fingerprint: k.Fingerprint, State: k.State, FirstSeen: k.FirstSeen, Replaced: k.Replaced})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out, nil
}

// AcceptKey accepts fingerprint as email's key on this device, as after a
// KeyChangedError, once the user has confirmed it with them. It replaces
// their other keys: sends go to it alone, and the others only check
// secrets they signed. It must be a full fingerprint of a key the server
// lists for email, with valid self-signatures, and email must not be one of
// the user's own accounts.
func (c *Client) AcceptKey(email, fingerprint string) error {
	return c.trustKey(email, fingerprint, KeyAccepted)
}

// VerifyKey records that the user compared fingerprint, one of email's
// keys, with them. It accepts it as AcceptKey does, replacing their other
// keys, and has the same requirements.
func (c *Client) VerifyKey(email, fingerprint string) error {
	return c.trustKey(email, fingerprint, KeyVerified)
}

// ForgetKey removes fingerprint from the keys this device accepted for
// email, or all of them when fingerprint is empty, and returns how many it
// removed. Once none is left, the next send to them, or secret from them,
// accepts their key on first use again. For one of the user's own accounts
// it forgets that the account is theirs.
func (c *Client) ForgetKey(email, fingerprint string) (int, error) {
	email = strings.ToLower(email)
	fingerprint = strings.ToLower(fingerprint)
	if fingerprint != "" && !fullFingerprint(fingerprint) {
		return 0, errFullFingerprint
	}
	server := c.knownServer()
	removed := 0
	err := c.knownKeys().update(func(d *knownKeysDisk) bool {
		keys := d.Servers[server][email]
		kept := slices.DeleteFunc(slices.Clone(keys), func(k knownKeyDisk) bool {
			return fingerprint == "" || k.Fingerprint == fingerprint
		})
		removed = len(keys) - len(kept)
		if removed == 0 {
			return false
		}
		if len(kept) == 0 {
			delete(d.Servers[server], email)
		} else {
			d.Servers[server][email] = kept
		}
		return true
	})
	return removed, err
}

func (c *Client) trustKey(email, fingerprint string, state KeyState) error {
	email = strings.ToLower(email)
	fingerprint = strings.ToLower(fingerprint)
	if !plausibleEmail(email) {
		return fmt.Errorf("invalid email %q", email)
	}
	if !fullFingerprint(fingerprint) {
		return errFullFingerprint
	}
	if _, err := identity.ResolveED25519ByEmail(c.api, email, fingerprint); err != nil {
		return err
	}
	server := c.knownServer()
	var refused error
	err := c.knownKeys().update(func(d *knownKeysDisk) bool {
		people := d.peopleOn(server)
		keys := people[email]
		if ownAccount(keys) {
			refused = fmt.Errorf("%s is your own account on this device: only key pairs on this device pass for it (if it is not yours, forget it first)", email)
			return false
		}
		changed := false
		i := slices.IndexFunc(keys, func(k knownKeyDisk) bool { return k.Fingerprint == fingerprint })
		if i < 0 {
			keys = append(keys, knownKeyDisk{Fingerprint: fingerprint, State: state, FirstSeen: time.Now().UTC()})
			i, changed = len(keys)-1, true
		}
		if keys[i].State.rank() < state.rank() {
			keys[i].State, changed = state, true
		}
		// Sends go to the key accepted: every other one is replaced, and
		// only checks secrets it signed.
		for j := range keys {
			if replaced := j != i; keys[j].Replaced != replaced {
				keys[j].Replaced, changed = replaced, true
			}
		}
		people[email] = keys
		return changed
	})
	if err == nil {
		err = refused
	}
	return err
}

// recordOwnAccount records email, the account the server says c uses, as
// one of the user's own, used with fp, a key pair on this device, and
// returns the people this device knows on the server. Once recorded, only
// key pairs on this device pass for email, whatever the server says later.
//
// An email this device knows as someone else (any key accepted for them)
// is refused: the server is claiming the caller is them. Otherwise email is
// recorded when registering (a key is being registered for it), when it is
// already recorded (fp is added), or when it is the first account recorded
// on the server. A send on a device with other accounts recorded leaves a
// new one unrecorded: the server's claim alone does not make it the user's.
func (c *Client) recordOwnAccount(email, fp string, registering bool) (map[string][]knownKeyDisk, error) {
	email = strings.ToLower(email)
	if !plausibleEmail(email) {
		return nil, fmt.Errorf("the server gave no valid email for this account: %q", email)
	}
	server := c.knownServer()
	var people map[string][]knownKeyDisk
	var refused error
	err := c.knownKeys().update(func(d *knownKeysDisk) bool {
		people = d.peopleOn(server)
		keys := people[email]
		if i := slices.IndexFunc(keys, func(k knownKeyDisk) bool { return k.State != KeyOwn }); i >= 0 {
			refused = fmt.Errorf("the server says you are %s, but this device knows %s as someone else (key %s): refusing to continue (possible impersonation by the server)",
				email, email, crypto.ShortFingerprint(keys[i].Fingerprint))
			return false
		}
		switch {
		case slices.ContainsFunc(keys, func(k knownKeyDisk) bool { return k.Fingerprint == fp }):
			return false
		case !registering && len(keys) == 0 && hasOwnAccount(people):
			return false
		}
		people[email] = append(keys, knownKeyDisk{Fingerprint: fp, State: KeyOwn, FirstSeen: time.Now().UTC()})
		return true
	})
	if err == nil {
		err = refused
	}
	return people, err
}

// hasOwnAccount reports whether any of people is one of the user's own
// accounts.
func hasOwnAccount(people map[string][]knownKeyDisk) bool {
	for _, keys := range people {
		if ownAccount(keys) {
			return true
		}
	}
	return false
}

// recordFirstUse records the keys new to this device that a send to
// people, or a secret from them when sender is set, relied on once it
// succeeded. Should another process have recorded a different key for one
// of them meanwhile, it records nothing and returns that KeyChangedError.
func (c *Client) recordFirstUse(people []Recipient, sender bool) error {
	if len(people) == 0 {
		return nil
	}
	server := c.knownServer()
	var refused error
	err := c.knownKeys().update(func(d *knownKeysDisk) bool {
		known := d.peopleOn(server)
		changed := false
		for _, p := range people {
			email := strings.ToLower(p.Email)
			first, err := checkKey(known, email, p.Fingerprint, sender)
			if err != nil {
				refused = err
				return false
			}
			if first {
				known[email] = []knownKeyDisk{{Fingerprint: p.Fingerprint, State: KeyFirstUse, FirstSeen: time.Now().UTC()}}
				changed = true
			}
		}
		return changed
	})
	if err == nil {
		err = refused
	}
	return err
}

// checkSenderKey checks fp, the key whose signatures on a secret from email
// just verified. A key on this device is the user's own and passes;
// anyone else's must pass checkKey. It changes nothing: a key new to this
// device is reported as first, for recordFirstUse once the decrypt
// succeeds.
func (c *Client) checkSenderKey(email, fp string, debugf func(step, format string, args ...any)) (bool, error) {
	if isLocalKey(fp) {
		debugf("verify", "sender key %s is on this device: yours", crypto.ShortFingerprint(fp))
		return false, nil
	}
	disk, err := c.knownKeys().read()
	if err != nil {
		return false, err
	}
	first, err := checkKey(disk.Servers[c.knownServer()], strings.ToLower(email), fp, true)
	switch {
	case err != nil:
	case first:
		debugf("verify", "sender key %s is new to this device: accepted on first use once the decrypt succeeds (compare fingerprints with them)", crypto.ShortFingerprint(fp))
	default:
		debugf("verify", "sender key %s is one this device accepted for them", crypto.ShortFingerprint(fp))
	}
	return first, err
}

// checkKey checks fp, the key the server lists for email (or, when sender
// is set, the key whose signatures on a secret from them verified), against
// people, what this device knows on the server. A key new to this device,
// for someone it knows no key of, is reported as first; any key fails for
// one of the user's own accounts, whose keys are the key pairs on this
// device; anyone else's must pass keyCheck.
func checkKey(people map[string][]knownKeyDisk, email, fp string, sender bool) (first bool, err error) {
	keys := people[email]
	switch {
	case ownAccount(keys) && sender:
		return false, fmt.Errorf("this secret is signed as %s, your own account on this device, with key %s, which is not a key on this device: refusing it (possible forgery; if %s is not yours, forget it)",
			email, crypto.ShortFingerprint(fp), email)
	case ownAccount(keys):
		return false, fmt.Errorf("the server lists key %s for %s, your own account on this device, but it is not a key on this device: refusing to encrypt to it (possible key substitution; if %s is not yours, forget it)",
			crypto.ShortFingerprint(fp), email, email)
	case len(keys) == 0:
		return true, nil
	}
	return false, keyCheck(email, fp, sender, keys)
}

// keyCheck passes fp when it is a key known for email that sends go to,
// or, for a sender, any key known for them, replaced ones included. It
// refuses any other key.
func keyCheck(email, fp string, sender bool, keys []knownKeyDisk) error {
	var current, all []string
	replaced := false
	for _, k := range keys {
		if k.Fingerprint == fp {
			if sender || !k.Replaced {
				return nil
			}
			replaced = true
		}
		all = append(all, k.Fingerprint)
		if !k.Replaced {
			current = append(current, k.Fingerprint)
		}
	}
	if len(current) == 0 && !replaced {
		current = all
	}
	return &KeyChangedError{Email: email, Known: current, Got: fp, Sender: sender, Replaced: replaced}
}

// ownAccount reports whether keys, what this device knows for an email,
// mark it as one of the user's own accounts.
func ownAccount(keys []knownKeyDisk) bool {
	return slices.ContainsFunc(keys, func(k knownKeyDisk) bool { return k.State == KeyOwn })
}

// isLocalKey reports whether fp is a key pair stored on this device: the
// user's own.
func isLocalKey(fp string) bool {
	_, err := crypto.LoadPublicKeys(fp)
	return err == nil
}

// knownServer is the name c's known keys are kept under: its API base URL,
// so keys known for one server never pass for another.
func (c *Client) knownServer() string { return strings.ToLower(c.api.BaseURL()) }

func (c *Client) knownKeys() knownKeysFile {
	if c.knownKeysFile != "" {
		return knownKeysFile(c.knownKeysFile)
	}
	return knownKeysFile(DefaultKnownKeysFile())
}

var errFullFingerprint = errors.New("a full key fingerprint is 64 hex characters")

// fullFingerprint reports whether fp is a full lower-case fingerprint.
func fullFingerprint(fp string) bool {
	if len(fp) != crypto.FingerprintLen {
		return false
	}
	for i := 0; i < len(fp); i++ {
		if c := fp[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// knownKeysFile is the path of a known keys file. Readers see the old file
// or the new one, never part of either: a change replaces it with one
// rename, under a lock beside it so two processes never lose each other's
// changes.
type knownKeysFile string

type knownKeysDisk struct {
	Version int `json:"version"`
	// Servers holds, by API base URL, each person's accepted keys by
	// lower-case email.
	Servers map[string]map[string][]knownKeyDisk `json:"servers"`
}

type knownKeyDisk struct {
	Fingerprint string    `json:"fingerprint"`
	State       KeyState  `json:"state"`
	FirstSeen   time.Time `json:"first_seen"`
	Replaced    bool      `json:"replaced,omitempty"`
}

// peopleOn returns the people known on server, adding the server when it is
// new.
func (d *knownKeysDisk) peopleOn(server string) map[string][]knownKeyDisk {
	if d.Servers[server] == nil {
		d.Servers[server] = map[string][]knownKeyDisk{}
	}
	return d.Servers[server]
}

// read reads the file, empty when it does not exist yet. A damaged file is
// refused, never treated as empty: that would accept any key again.
func (f knownKeysFile) read() (*knownKeysDisk, error) {
	data, err := os.ReadFile(string(f)) // #nosec G304 -- the known keys file the caller configured, or the default under the user's home.
	if errors.Is(err, os.ErrNotExist) {
		return &knownKeysDisk{Version: knownKeysVersion, Servers: map[string]map[string][]knownKeyDisk{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known keys: %w", err)
	}
	var d knownKeysDisk
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("known keys file %s is damaged: %w", f, err)
	}
	if d.Version != knownKeysVersion {
		return nil, fmt.Errorf("known keys file %s has version %d; this SDK reads version %d only", f, d.Version, knownKeysVersion)
	}
	if d.Servers == nil {
		d.Servers = map[string]map[string][]knownKeyDisk{}
	}
	for server, people := range d.Servers {
		for email, keys := range people {
			for _, k := range keys {
				if !fullFingerprint(k.Fingerprint) || k.State.rank() == 0 || (k.Replaced && k.State == KeyOwn) {
					return nil, fmt.Errorf("known keys file %s is damaged: a key of %s on %s is malformed", f, email, server)
				}
			}
		}
	}
	return &d, nil
}

// update applies change to the file under its lock, and writes it when
// change reports it changed something.
func (f knownKeysFile) update(change func(*knownKeysDisk) bool) error {
	path := string(f)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- beside the known keys file the caller configured.
	if err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	defer func() { _ = lock.Close() }() // closing releases the lock.
	for deadline := time.Now().Add(knownKeysLockWait); ; {
		err := lockFile(lock)
		if err == nil {
			break
		}
		if !errors.Is(err, errLocked) || time.Now().After(deadline) {
			return fmt.Errorf("lock known keys: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	d, err := f.read()
	if err != nil {
		return err
	}
	if !change(d) {
		return nil
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("known keys: %w", err)
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic replaces path with data through a new 0600 file in the
// same directory, synced and renamed over it.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	// After the rename this finds nothing; after a failure it removes the
	// temporary file.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is returned and the file removed.
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // the sync error is returned and the file removed.
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
