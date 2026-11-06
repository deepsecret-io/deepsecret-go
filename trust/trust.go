// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package trust

import (
	"context"

	"github.com/deepsecret-io/deepsecret-go/internal/directory"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// KnownKey is a key this device accepted for someone, or used with one of the
// user's own accounts (State Own). Its fields are Email, Fingerprint, State,
// FirstSeen and Replaced, which is set once the user accepted a newer key for
// Email: sends no longer go to this one, but it still checks secrets it signed.
type KnownKey = knownkeys.KnownKey

// State says how far a known key was checked: FirstUse, Accepted, Verified or
// Own.
type State = knownkeys.State

// The states of a known key, from least to most checked.
const (
	FirstUse = knownkeys.FirstUse // accepted when it was first used
	Accepted = knownkeys.Accepted // accepted by the user
	Verified = knownkeys.Verified // compared with its owner by the user
	Own      = knownkeys.Own      // a key pair of the user, on this device
)

// KeyChangedError refuses a send to someone, or a secret from them, under a key
// this device has not accepted for them. Its fields are Email, Known (the keys
// accepted for Email that sends go to), Got (the key the server lists now, or
// the one that signed the secret), Sender (Got signed a secret being decrypted)
// and Replaced (Got is a key accepted for Email before, replaced since). The
// user compares Got with Email before accepting it.
type KeyChangedError = knownkeys.KeyChangedError

// StaleRevisionError refuses the revision the server gives as a secret's latest
// when this device already opened a revision of it, from the same sender, signed
// later: the server may be rolling the secret back. Its fields are SecretName,
// SenderEmail, RevisionID, SignedAt and NewestSeen. Requesting RevisionID
// explicitly opens it anyway.
type StaleRevisionError = knownkeys.StaleRevisionError

// Client reaches the keys this device knows. Get one from deepsecret.NewClient,
// as its Trust field.
type Client struct {
	api   *transport.Client
	store *knownkeys.Store
}

// New returns a Client. It takes internal types, so use deepsecret.NewClient.
func New(api *transport.Client, store *knownkeys.Store) *Client {
	return &Client{api: api, store: store}
}

// List returns the keys this device accepted for email on this server, or for
// everyone when email is empty, sorted by email, with the keys it used with the
// user's own accounts.
func (c *Client) List(email string) ([]KnownKey, error) {
	return c.store.List(email)
}

// Accept accepts fingerprint as email's key on this device, as after a
// KeyChangedError, once the user has confirmed it with them. It replaces their
// other keys: sends go to it alone, and the others only check secrets they
// signed. It must be a full fingerprint of a key the server lists for email,
// with valid self-signatures, and email must not be one of the user's own
// accounts.
func (c *Client) Accept(ctx context.Context, email, fingerprint string) error {
	return c.record(ctx, email, fingerprint, Accepted)
}

// Verify records that the user compared fingerprint, one of email's keys, with
// them. It accepts it as Accept does, replacing their other keys, and has the
// same requirements.
func (c *Client) Verify(ctx context.Context, email, fingerprint string) error {
	return c.record(ctx, email, fingerprint, Verified)
}

// record checks the key against what the server lists, then records it: the
// store takes the key on trust, so nothing else may call it.
func (c *Client) record(ctx context.Context, email, fingerprint string, state State) error {
	email, fingerprint, err := knownkeys.NormalizeKeyRef(email, fingerprint)
	if err != nil {
		return err
	}
	if _, err := directory.ResolveED25519ByEmail(ctx, c.api, email, fingerprint); err != nil {
		return err
	}
	return c.store.Trust(email, fingerprint, state)
}

// Forget removes fingerprint from the keys this device accepted for email, or
// all of them when fingerprint is empty, and returns how many it removed. Once
// none is left, the next send to them, or secret from them, accepts their key
// on first use again. For one of the user's own accounts it forgets that the
// account is theirs.
func (c *Client) Forget(email, fingerprint string) (int, error) {
	return c.store.Forget(email, fingerprint)
}

// ServerListedKeys fetches the keys the server lists as email's primary. They
// are whole and self-signed, but they are only the server's claim: nothing
// checks them against the keys this device knows, as a send and a decrypt do.
// Use them to compare, never to decide whom to trust.
func (c *Client) ServerListedKeys(ctx context.Context, email string) (*keys.PublicKeys, error) {
	return directory.GetRecipientKeys(ctx, c.api, email)
}
