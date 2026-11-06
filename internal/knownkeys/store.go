// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package knownkeys

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
	"github.com/deepsecret-io/deepsecret-go/internal/protocol"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// knownKeysVersion is the version of the known keys file. Files with any
// other version are refused.
const knownKeysVersion = 1

// knownKeysLockWait is how long a change to the known keys file waits for
// another process to finish its own.
const knownKeysLockWait = 10 * time.Second

// State says how a known key came to be accepted.
type State string

const (
	// FirstUse is a key accepted on first contact, not compared with its
	// owner.
	FirstUse State = "tofu"
	// Accepted is a key the user accepted, after it changed.
	Accepted State = "accepted"
	// Verified is a key the user compared with its owner.
	Verified State = "verified"
	// Own is a key pair on this device used with one of the user's own
	// accounts: only keys on this device pass for that email.
	Own State = "own"
)

// rank orders key states from least to most checked, so accepting a key
// never lowers its state.
func (s State) rank() int {
	switch s {
	case FirstUse:
		return 1
	case Accepted:
		return 2
	case Verified:
		return 3
	case Own:
		return 4
	}
	return 0
}

// KnownKey is a key this device accepted for someone, or used with one of
// the user's own accounts (State Own).
type KnownKey struct {
	Email       string    `json:"email" yaml:"email"`
	Fingerprint string    `json:"fingerprint" yaml:"fingerprint"`
	State       State     `json:"state" yaml:"state"`
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
		known[i] = keys.ShortFingerprint(fp)
	}
	got := keys.ShortFingerprint(e.Got)
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

// StaleRevisionError refuses the revision the server gives as a secret's
// latest when this device already opened a revision of that secret, from
// the same sender, signed later: the server may be rolling the secret back.
// Requesting RevisionID explicitly opens it anyway.
type StaleRevisionError struct {
	SecretName  string
	SenderEmail string
	RevisionID  string    // the revision refused
	SignedAt    time.Time // when it was signed
	NewestSeen  time.Time // the signing time of the newest revision of the secret this device opened
}

func (e *StaleRevisionError) Error() string {
	return fmt.Sprintf("the server gives revision %s, signed %s, as the latest of %q from %s, but this device already opened a revision of it signed %s: refusing a possible rollback (request the revision by id to open it anyway)",
		e.RevisionID, e.SignedAt.UTC().Format(time.RFC3339), e.SecretName, e.SenderEmail, e.NewestSeen.UTC().Format(time.RFC3339))
}

// List returns the keys this device accepted for email on the store's server,
// or for everyone when email is empty, sorted by email, with the keys it
// used with the user's own accounts.
func (s *Store) List(email string) ([]KnownKey, error) {
	email = strings.ToLower(email)
	disk, err := s.file.read()
	if err != nil {
		return nil, err
	}
	var out []KnownKey
	for e, entries := range disk.Servers[s.server] {
		if email != "" && e != email {
			continue
		}
		for _, k := range entries {
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

// Forget removes fingerprint from the keys this device accepted for
// email, or all of them when fingerprint is empty, and returns how many it
// removed. Once none is left, the next send to them, or secret from them,
// accepts their key on first use again. For one of the user's own accounts
// it forgets that the account is theirs.
func (s *Store) Forget(email, fingerprint string) (int, error) {
	email = strings.ToLower(email)
	fingerprint = strings.ToLower(fingerprint)
	if fingerprint != "" && !fullFingerprint(fingerprint) {
		return 0, errFullFingerprint
	}
	server := s.server
	removed := 0
	err := s.file.update(func(d *knownKeysDisk) bool {
		entries := d.Servers[server][email]
		kept := slices.DeleteFunc(slices.Clone(entries), func(k Entry) bool {
			return fingerprint == "" || k.Fingerprint == fingerprint
		})
		removed = len(entries) - len(kept)
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

// NormalizeKeyRef lower-cases email and fingerprint and checks them, before
// anything is looked up or stored.
func NormalizeKeyRef(email, fingerprint string) (string, string, error) {
	email = strings.ToLower(email)
	fingerprint = strings.ToLower(fingerprint)
	if !PlausibleEmail(email) {
		return "", "", fmt.Errorf("invalid email %q", email)
	}
	if !fullFingerprint(fingerprint) {
		return "", "", errFullFingerprint
	}
	return email, fingerprint, nil
}

// Trust accepts fingerprint as email's key on this device with state,
// replacing their other keys: sends go to it alone, and the others only check
// secrets they signed. It refuses one of the user's own accounts. The caller
// must have normalized both with NormalizeKeyRef and already fetched and
// verified the key through package directory: this only records the decision.
func (s *Store) Trust(email, fingerprint string, state State) error {
	server := s.server
	var refused error
	err := s.file.update(func(d *knownKeysDisk) bool {
		people := d.peopleOn(server)
		entries := people[email]
		if OwnAccount(entries) {
			refused = fmt.Errorf("%s is your own account on this device: only key pairs on this device pass for it (if it is not yours, forget it first)", email)
			return false
		}
		changed := false
		i := slices.IndexFunc(entries, func(k Entry) bool { return k.Fingerprint == fingerprint })
		if i < 0 {
			entries = append(entries, Entry{Fingerprint: fingerprint, State: state, FirstSeen: time.Now().UTC()})
			i, changed = len(entries)-1, true
		}
		if entries[i].State.rank() < state.rank() {
			entries[i].State, changed = state, true
		}
		// Sends go to the key accepted: every other one is replaced, and
		// only checks secrets it signed.
		for j := range entries {
			if replaced := j != i; entries[j].Replaced != replaced {
				entries[j].Replaced, changed = replaced, true
			}
		}
		people[email] = entries
		return changed
	})
	if err == nil {
		err = refused
	}
	return err
}

// RecordOwnAccount records email, the account the server says c uses, as
// one of the user's own, used with fp, a key pair on this device, and
// returns the people this device knows on the server. Once recorded, only
// key pairs on this device pass for email, whatever the server says later.
//
// A key belongs to one account: fp is never recorded for email while it is
// recorded for another of the user's accounts, whose key the server would
// be passing off as email's; that is refused. An email this device knows
// as someone else is refused too: the server is claiming the caller is
// them. Someone else's is a key accepted for email that is not a key pair
// on this device, or that is recorded for another of the user's accounts.
// Any other key pair on this device accepted for email, as when another of
// the user's accounts sent to this one before this device knew it was
// theirs, is taken as the user's own and recorded as such with email. That
// trusts how the key was first used: a server that listed such a key for a
// contact on first contact, and now says the caller is them, gets them
// recorded as the user's own, so sends to them refuse their real key until
// the user forgets it. The same server could instead have listed a key of
// its own for them on that first contact and read what was sent to them,
// the trade-off trust on first use accepts. Otherwise email is recorded
// when registering (a key is being registered for it), when it is already
// recorded (fp is added), or when it is the first account recorded on the
// server. A send on a device with other accounts recorded leaves a new one
// unrecorded: the server's claim alone does not make it the user's.
func (s *Store) RecordOwnAccount(email, fp string, registering bool) (map[string][]Entry, error) {
	email = strings.ToLower(email)
	if !PlausibleEmail(email) {
		return nil, fmt.Errorf("the server gave no valid email for this account: %q", email)
	}
	server := s.server
	var people map[string][]Entry
	var refused error
	err := s.file.update(func(d *knownKeysDisk) bool {
		people = d.peopleOn(server)
		entries := people[email]
		for _, k := range entries {
			why := ""
			switch other := ownerOf(people, k.Fingerprint, email); {
			case k.State == Own:
				continue
			case other != "":
				why = "your account " + other + "'s key"
			case !s.isLocalKey(k.Fingerprint):
				why = "which is not on this device"
			default:
				continue
			}
			refused = fmt.Errorf("the server says you are %s, but this device knows %s as someone else (key %s, %s): refusing to continue (possible impersonation by the server; if %s is your own account, forget that key first)",
				email, email, keys.ShortFingerprint(k.Fingerprint), why, email)
			return false
		}
		add := !slices.ContainsFunc(entries, func(k Entry) bool { return k.Fingerprint == fp }) &&
			(registering || len(entries) > 0 || !hasOwnAccount(people))
		if other := ownerOf(people, fp, email); add && other != "" {
			refused = fmt.Errorf("the server says you are %s, but the key used here, %s, is your account %s's key: refusing to continue (possible impersonation by the server)",
				email, keys.ShortFingerprint(fp), other)
			return false
		}
		changed := add
		for i, k := range entries {
			if k.State != Own {
				entries[i] = Entry{Fingerprint: k.Fingerprint, State: Own, FirstSeen: k.FirstSeen}
				changed = true
			}
		}
		if add {
			entries = append(entries, Entry{Fingerprint: fp, State: Own, FirstSeen: time.Now().UTC()})
		}
		if changed {
			people[email] = entries
		}
		return changed
	})
	if err == nil {
		err = refused
	}
	return people, err
}

// ownerOf returns the user's own account, other than email, that fp is
// recorded for in people, or "". A key belongs to one account: the server
// listing it for another is lying.
func ownerOf(people map[string][]Entry, fp, email string) string {
	for e, entries := range people {
		if e != email && slices.ContainsFunc(entries, func(k Entry) bool { return k.State == Own && k.Fingerprint == fp }) {
			return e
		}
	}
	return ""
}

// hasOwnAccount reports whether any of people is one of the user's own
// accounts.
func hasOwnAccount(people map[string][]Entry) bool {
	for _, entries := range people {
		if OwnAccount(entries) {
			return true
		}
	}
	return false
}

// RecordFirstUse records the keys new to this device that a send to
// people, or a secret from them when sender is set, relied on once it
// succeeded. Should another process have recorded a different key for one
// of them meanwhile, it records nothing and returns that KeyChangedError.
func (s *Store) RecordFirstUse(people []Person, sender bool) error {
	if len(people) == 0 {
		return nil
	}
	server := s.server
	var refused error
	err := s.file.update(func(d *knownKeysDisk) bool {
		known := d.peopleOn(server)
		changed := false
		for _, p := range people {
			email := strings.ToLower(p.Email)
			first, err := CheckKey(known, email, p.Fingerprint, sender)
			if err != nil {
				refused = err
				return false
			}
			if first {
				known[email] = []Entry{{Fingerprint: p.Fingerprint, State: FirstUse, FirstSeen: time.Now().UTC()}}
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

// CheckSenderKey checks fp, the key whose signatures on a secret from email
// just verified, and logs why it is trusted. The server names the sender, so
// the user's key must not make the user's own secret pass as someone else's,
// known or new. A key recorded for one of the user's accounts passes for no
// other email, on this device or not: a key belongs to one account, whatever
// the server listed for email. Any other key on this device passes for one of
// the user's accounts recorded here, or for someone this device knows by that
// very key.
//
// One limit remains. A key on this device recorded for none of the user's
// accounts, that this device knows for email, passes as theirs. This device
// cannot tell a server that listed such a key for a contact on first contact
// from another of the user's accounts it does not know is theirs yet (see
// RecordOwnAccount), and refusing it would refuse that account's secrets too.
// A key is recorded once it is registered, or signs a send, from an account
// recorded here, so this takes a key that only signed elsewhere or for an
// account not recorded.
//
// Anyone else's key must pass CheckKey. It changes nothing: a key new to this
// device is reported as first, for RecordFirstUse once the decrypt succeeds.
func (s *Store) CheckSenderKey(email, fp string, log *slog.Logger) (bool, error) {
	verified := func(own, first bool) {
		logattr.Module(log, "verify").Debug("sender key verified", "email", email, "fingerprint", fp, "trust", KeyTrust(own, first))
	}
	disk, err := s.file.read()
	if err != nil {
		return false, err
	}
	people := disk.Servers[s.server]
	lower := strings.ToLower(email)
	entries := people[lower]
	local := s.isLocalKey(fp)
	first := false
	if !local || (len(entries) > 0 && !OwnAccount(entries)) {
		if first, err = CheckKey(people, lower, fp, true); err != nil {
			return false, err
		}
	}
	if other := ownerOf(people, fp, lower); other != "" {
		return false, fmt.Errorf("this secret is signed with %s, your account %s's key, but the server names %s as its sender: refusing it (possible relabelling by the server)",
			keys.ShortFingerprint(fp), other, email)
	}
	if local && len(entries) == 0 {
		return false, fmt.Errorf("this secret is signed with %s, a key on this device, but the server names %s as its sender, an account this device does not know as yours: refusing it (possible relabelling by the server; if %s is your own account, sync your identity for it first)",
			keys.ShortFingerprint(fp), email, email)
	}
	verified(local, first)
	return first, nil
}

// CheckNewest refuses m, the revision the server gives as its secret's
// latest, when this device already opened a revision of the same secret
// from email that was signed later.
func (s *Store) CheckNewest(email string, m *protocol.Manifest) error {
	disk, err := s.file.read()
	if err != nil {
		return err
	}
	newest, ok := disk.Newest[s.server][strings.ToLower(email)][m.SecretName]
	if ok && m.Timestamp < newest {
		return &StaleRevisionError{SecretName: m.SecretName, SenderEmail: email, RevisionID: m.RevisionID,
			SignedAt: time.Unix(m.Timestamp, 0), NewestSeen: time.Unix(newest, 0)}
	}
	return nil
}

// NewestRecorder records m's signing time as the newest of its secret from
// email, once a decrypt of it succeeded. It never lowers a recorded time.
func (s *Store) NewestRecorder(email string, m *protocol.Manifest) func() error {
	server, sender, name, signed := s.server, strings.ToLower(email), m.SecretName, m.Timestamp
	return func() error {
		return s.file.update(func(d *knownKeysDisk) bool {
			if newest, ok := d.Newest[server][sender][name]; ok && newest >= signed {
				return false
			}
			if d.Newest == nil {
				d.Newest = map[string]map[string]map[string]int64{}
			}
			if d.Newest[server] == nil {
				d.Newest[server] = map[string]map[string]int64{}
			}
			if d.Newest[server][sender] == nil {
				d.Newest[server][sender] = map[string]int64{}
			}
			d.Newest[server][sender][name] = signed
			return true
		})
	}
}

// CheckKey checks fp, the key the server lists for email (or, when sender
// is set, the key whose signatures on a secret from them verified), against
// people, what this device knows on the server. A key new to this device,
// for someone it knows no key of, is reported as first; any key fails for
// one of the user's own accounts, whose keys are the key pairs on this
// device; anyone else's must pass keyCheck.
func CheckKey(people map[string][]Entry, email, fp string, sender bool) (first bool, err error) {
	entries := people[email]
	switch {
	case OwnAccount(entries) && sender:
		return false, fmt.Errorf("this secret is signed as %s, your own account on this device, with key %s, which is not a key on this device: refusing it (possible forgery; if %s is not yours, forget it)",
			email, keys.ShortFingerprint(fp), email)
	case OwnAccount(entries):
		return false, fmt.Errorf("the server lists key %s for %s, your own account on this device, but it is not a key on this device: refusing to encrypt to it (possible key substitution; if %s is not yours, forget it)",
			keys.ShortFingerprint(fp), email, email)
	case len(entries) == 0:
		return true, nil
	}
	return false, keyCheck(email, fp, sender, entries)
}

// keyCheck passes fp when it is a key known for email that sends go to,
// or, for a sender, any key known for them, replaced ones included. It
// refuses any other key.
func keyCheck(email, fp string, sender bool, entries []Entry) error {
	var current, all []string
	replaced := false
	for _, k := range entries {
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

// OwnAccount reports whether keys, what this device knows for an email,
// mark it as one of the user's own accounts.
func OwnAccount(entries []Entry) bool {
	return slices.ContainsFunc(entries, func(k Entry) bool { return k.State == Own })
}

// isLocalKey reports whether fp is a key pair stored on this device, in the
// store's key pair directory: the user's own.
func (s *Store) isLocalKey(fp string) bool {
	_, err := keystore.LoadPublic(s.keysDir, fp)
	return err == nil
}

var errFullFingerprint = errors.New("a full key fingerprint is 64 hex characters")

// fullFingerprint reports whether fp is a full lower-case fingerprint.
func fullFingerprint(fp string) bool {
	if len(fp) != keys.FingerprintLen {
		return false
	}
	for i := 0; i < len(fp); i++ {
		if c := fp[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Person names a key to record for someone.
type Person struct {
	Email, Fingerprint string
}

// Store is this device's known keys file on one server. Package trust is its
// public face; a send and a decrypt call it directly.
type Store struct {
	file    knownKeysFile
	server  string // the name keys are kept under, so keys known for one server never pass for another
	keysDir string // this device's key pairs, the user's own
}

// New returns the store in file on server, the API base URL, for the user
// whose key pairs are in keysDir. An empty file means known_keys.json beside
// keysDir.
func New(file, server, keysDir string) *Store {
	if file == "" {
		file = filepath.Join(filepath.Dir(keysDir), "known_keys.json")
	}
	return &Store{file: knownKeysFile(file), server: strings.ToLower(server), keysDir: keysDir}
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
	Servers map[string]map[string][]Entry `json:"servers"`
	// Newest holds, by API base URL, sender's lower-case email and secret
	// name, the signing time (Unix seconds) of the newest revision this
	// device opened. A latest revision signed earlier is refused.
	Newest map[string]map[string]map[string]int64 `json:"newest,omitempty"`
}

type Entry struct {
	Fingerprint string    `json:"fingerprint"`
	State       State     `json:"state"`
	FirstSeen   time.Time `json:"first_seen"`
	Replaced    bool      `json:"replaced,omitempty"`
}

// peopleOn returns the people known on server, adding the server when it is
// new.
func (d *knownKeysDisk) peopleOn(server string) map[string][]Entry {
	if d.Servers[server] == nil {
		d.Servers[server] = map[string][]Entry{}
	}
	return d.Servers[server]
}

// read reads the file, empty when it does not exist yet. A damaged file is
// refused, never treated as empty: that would accept any key again.
func (f knownKeysFile) read() (*knownKeysDisk, error) {
	data, err := os.ReadFile(string(f)) // #nosec G304 -- the known keys file the caller configured, or the default under the user's home.
	if errors.Is(err, os.ErrNotExist) {
		return &knownKeysDisk{Version: knownKeysVersion, Servers: map[string]map[string][]Entry{}}, nil
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
		d.Servers = map[string]map[string][]Entry{}
	}
	for server, people := range d.Servers {
		for email, entries := range people {
			for _, k := range entries {
				if !fullFingerprint(k.Fingerprint) || k.State.rank() == 0 || (k.Replaced && k.State == Own) {
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
		err := disk.Lock(lock)
		if err == nil {
			break
		}
		if !errors.Is(err, disk.ErrLocked) || time.Now().After(deadline) {
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

// KeyTrust says, for the log, why a key was accepted: it is the user's
// own, on this device; it is new to this device, accepted on first use
// once the send or decrypt succeeds; or this device accepted it before.
func KeyTrust(own, first bool) string {
	switch {
	case own:
		return "own"
	case first:
		return "first_use"
	}
	return "known"
}

// maxEmailLen is the longest email address (RFC 5321).
const maxEmailLen = 254

// PlausibleEmail accepts what could be an email address and nothing that
// could change the path it is looked up under or the terminal it is
// printed to, or pass for another address: only printable ASCII, as the
// server accepts, so no spaces, controls, formatting marks or lookalike
// letters from other scripts.
func PlausibleEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if len(s) > maxEmailLen || at < 1 || at == len(s)-1 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' || strings.IndexByte("/\\?#%", c) >= 0 {
			return false
		}
	}
	return true
}
