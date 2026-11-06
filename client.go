// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/internal/transport"
)

// Client is the high-level DeepSecret SDK client.
type Client struct {
	api *transport.Client

	// keysDir is this device's key pair directory: crypto.DefaultKeysDir
	// when empty. See WithKeysDir.
	keysDir string

	// knownKeysFile is where the keys accepted for other people are kept:
	// known_keys.json beside keysDir when empty. See WithKnownKeysFile.
	knownKeysFile string
}

// with is c for one call: its requests, and the security key prompts they
// lead to, end with ctx.
func (c *Client) with(ctx context.Context) *Client {
	view := *c
	view.api = c.api.WithContext(ctx)
	return &view
}

// keys returns c's key pair directory.
func (c *Client) keys() string {
	if c.keysDir != "" {
		return c.keysDir
	}
	return crypto.DefaultKeysDir()
}

// Option configures a Client when it is created.
type Option func(*Client)

// WithKeysDir makes the client keep this device's key pairs in dir instead of
// crypto.DefaultKeysDir. Only key pairs in dir are the user's own: they sign,
// decrypt, and pass for the user's own accounts.
func WithKeysDir(dir string) Option {
	return func(c *Client) { c.keysDir = dir }
}

// WithKnownKeysFile makes the client keep known keys in path instead of
// known_keys.json beside the keys directory.
func WithKnownKeysFile(path string) Option {
	return func(c *Client) { c.knownKeysFile = path }
}

// WithSessionStore makes a client authenticated with "bearer:" and a session
// token save each token it refreshes. The client refreshes the token shortly
// before it expires, so long transfers outlive its one-hour lifetime; the
// server revokes the old token, which is why it must be saved. When the token
// is refused, the client loads the stored one, in case another process
// refreshed the session first.
func WithSessionStore(s SessionStore) Option {
	return func(c *Client) { c.api.SetSessionStore(s) }
}

// NewClient creates a new DeepSecret SDK client. Every call that can block
// takes a context, and ends when it does.
func NewClient(apiURL, apiKey string, opts ...Option) (*Client, error) {
	c, err := transport.NewClient(apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	return newClient(c, opts), nil
}

// NewClientFromEnv creates a client from DS_API_URL and DS_API_KEY env vars.
func NewClientFromEnv(opts ...Option) (*Client, error) {
	c, err := transport.NewClientFromEnv()
	if err != nil {
		return nil, err
	}
	return newClient(c, opts), nil
}

func newClient(transport *transport.Client, opts []Option) *Client {
	c := &Client{api: transport}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string { return c.api.BaseURL() }

// SessionStore keeps a login session's token where the next run finds it;
// see [WithSessionStore].
type SessionStore = api.SessionStore

// ── Identity ─────────────────────────────────────────────────────────────────

// Logout revokes the Bearer token this client authenticates with, so a
// copy of it stops working immediately. API-key clients have no session
// and the call is a no-op on the server.
func (c *Client) Logout(ctx context.Context) error {
	c = c.with(ctx)
	_, err := c.api.Post("/api/v1/auth/logout", nil)
	return err
}

// WhoAmI returns the authenticated user's info and tier limits.
func (c *Client) WhoAmI(ctx context.Context) (*ActorInfo, error) {
	c = c.with(ctx)
	return whoAmI(c.api)
}

// ResolveActorID returns the authenticated user's actor ID.
func (c *Client) ResolveActorID(ctx context.Context) (string, error) {
	c = c.with(ctx)
	return resolveActorID(c.api)
}

// ListRemoteKeys returns all identity keys registered on the server.
func (c *Client) ListRemoteKeys(ctx context.Context) ([]RemoteKey, error) {
	c = c.with(ctx)
	return listRemoteKeys(c.api)
}

// SyncIdentity records the account on this device as the user's own, used
// with kp: from then on only key pairs on this device pass for it (see
// AcceptKey). Then it uploads kp's public keys to the server, labelled as
// protected by a security key when securityKey is set (a label for the
// user's own key lists, see SetKeySecurityKey). Nothing is uploaded when
// the server says the account is someone this device knows as another
// person.
func (c *Client) SyncIdentity(ctx context.Context, kp *crypto.KeyPair, securityKey bool) error {
	c = c.with(ctx)
	fp, err := crypto.Fingerprint(kp)
	if err != nil {
		return fmt.Errorf("compute fingerprint: %w", err)
	}
	me, err := whoAmI(c.api)
	if err != nil {
		return fmt.Errorf("fetch your account: %w", err)
	}
	if _, err := c.recordOwnAccount(me.Email, fp, true); err != nil {
		return err
	}
	return syncIdentity(c.api, kp, securityKey)
}

// SetKeySecurityKey sets whether the registered key identityID (from
// ListRemoteKeys) is labelled as protected by a security key: what a
// client reports after protecting a key pair, or taking the protection
// off. The label is shown only in the user's own key lists; it is not
// signed and decides nothing.
func (c *Client) SetKeySecurityKey(ctx context.Context, identityID string, securityKey bool) error {
	c = c.with(ctx)
	return setKeySecurityKey(c.api, identityID, securityKey)
}

// LoadPrimaryIdentity fetches the primary identity from the server and loads
// the matching local key pair from disk. Pass a password if the key is encrypted.
func (c *Client) LoadPrimaryIdentity(ctx context.Context, password string) (*crypto.KeyPair, string, error) {
	c = c.with(ctx)
	return loadPrimaryIdentity(c.api, c.keys(), password)
}

// LoadPrimaryIdentityWith loads the primary key pair and unlocks it once
// with u: a password, a security key (package fido2) or a recovery code.
func (c *Client) LoadPrimaryIdentityWith(ctx context.Context, u crypto.Unlock) (*crypto.KeyPair, string, error) {
	c = c.with(ctx)
	return loadPrimaryIdentityWith(c.api.Context(), c.api, c.keys(), u)
}

// PrimaryFingerprint returns the fingerprint of the primary key registered
// on the server, without reading or unlocking the local key file.
func (c *Client) PrimaryFingerprint(ctx context.Context) (string, error) {
	c = c.with(ctx)
	return primaryFingerprint(c.api)
}

// ServerListedKeys fetches the keys the server lists as email's primary. They
// are whole and self-signed, but they are only the server's claim: nothing
// checks them against the keys this device knows, as a send and a decrypt do.
// Use them to compare, never to decide whom to trust.
func (c *Client) ServerListedKeys(ctx context.Context, email string) (*crypto.PublicKeys, error) {
	c = c.with(ctx)
	return getRecipientKeys(c.api, email)
}

// SetPrimaryKey marks a remote identity as the primary key.
func (c *Client) SetPrimaryKey(ctx context.Context, identityID string) error {
	c = c.with(ctx)
	return setPrimaryKey(c.api, identityID)
}

// DeleteKey removes a remote identity key from the server.
func (c *Client) DeleteKey(ctx context.Context, identityID string) error {
	c = c.with(ctx)
	return deleteKey(c.api, identityID)
}

// ListGroups returns all groups in the given org with their members.
func (c *Client) ListGroups(ctx context.Context, orgID string) ([]GroupInfo, error) {
	c = c.with(ctx)
	return listGroups(c.api, orgID)
}

// ── Secrets ──────────────────────────────────────────────────────────────────

// listSecrets returns secrets in the given direction ("sent" or "received").
func (c *Client) listSecrets(direction string, opts ...ListOptions) ([]SecretInfo, int, error) {
	actorID, err := resolveActorID(c.api)
	if err != nil {
		return nil, 0, err
	}
	return listSecretsFor(c.api, actorID, direction, opts...)
}

// ListSentSecrets returns sent secrets.
func (c *Client) ListSentSecrets(ctx context.Context, opts ...ListOptions) ([]SecretInfo, int, error) {
	c = c.with(ctx)
	return c.listSecrets("sent", opts...)
}

// ListReceivedSecrets returns received secrets.
func (c *Client) ListReceivedSecrets(ctx context.Context, opts ...ListOptions) ([]SecretInfo, int, error) {
	c = c.with(ctx)
	return c.listSecrets("received", opts...)
}

// DescribeSecret returns detailed metadata about a secret.
func (c *Client) DescribeSecret(ctx context.Context, secretID string) (*SecretInfo, error) {
	c = c.with(ctx)
	return describeSecret(c.api, secretID)
}

// DeleteSecret permanently deletes a single secret.
func (c *Client) DeleteSecret(ctx context.Context, secretID string) error {
	c = c.with(ctx)
	return deleteSecret(c.api, secretID)
}

// DeleteSecrets permanently deletes multiple secrets by their IDs.
func (c *Client) DeleteSecrets(ctx context.Context, ids []string) error {
	c = c.with(ctx)
	return deleteSecretBatch(c.api, ids)
}

// RevokeRecipient removes one recipient's access to a sent secret, with
// every wrap made for them. Only the sender may revoke. A recipient who
// already downloaded a revision keeps what they downloaded. Revoking the
// last recipient deletes the secret, which the result reports.
func (c *Client) RevokeRecipient(ctx context.Context, secretID, recipientEmail string) (*RevokeResult, error) {
	c = c.with(ctx)
	info, err := describeSecret(c.api, secretID)
	if err != nil {
		return nil, fmt.Errorf("fetch secret: %w", err)
	}
	r, ok := info.Recipient(recipientEmail)
	if !ok {
		return nil, fmt.Errorf("not a recipient of this secret")
	}
	deleted, err := revokeRecipient(c.api, secretID, r.ID)
	if err != nil {
		return nil, err
	}
	return &RevokeResult{RecipientID: r.ID, Email: r.Email, SecretDeleted: deleted}, nil
}

// ListRevisions returns all revisions for a secret.
func (c *Client) ListRevisions(ctx context.Context, secretID string) ([]RevisionInfo, error) {
	c = c.with(ctx)
	resp, err := c.api.Get("/api/v1/secrets/" + transport.PathSegment(secretID) + "/revisions")
	if err != nil {
		return nil, fmt.Errorf("get revisions: %w", err)
	}
	var list struct {
		Revisions []RevisionInfo `json:"revisions"`
	}
	if err := json.Unmarshal(resp.Data, &list); err != nil {
		return nil, fmt.Errorf("parse revisions: %w", err)
	}
	return list.Revisions, nil
}

// DescribeSecretFull returns a secret's metadata plus all its revisions in one call.
// Returns an error if either the secret or its revisions cannot be fetched.
func (c *Client) DescribeSecretFull(ctx context.Context, secretID string) (*SecretDetail, error) {
	c = c.with(ctx)
	info, err := c.DescribeSecret(c.api.Context(), secretID)
	if err != nil {
		return nil, err
	}
	revisions, err := c.ListRevisions(c.api.Context(), secretID)
	if err != nil {
		return nil, fmt.Errorf("describe: fetched secret metadata but failed to load revisions: %w", err)
	}
	return &SecretDetail{Secret: *info, Revisions: revisions}, nil
}

// UpdatePolicy updates the policies on an existing secret.
func (c *Client) UpdatePolicy(ctx context.Context, secretID string, update PolicyUpdate) (*PolicyResult, error) {
	c = c.with(ctx)
	body := make(map[string]any)
	if update.TTLSeconds != nil {
		body["ttl_seconds"] = *update.TTLSeconds
	}
	if update.AllowedIPs != nil {
		body["allowed_ips"] = *update.AllowedIPs
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("no policy changes specified")
	}

	resp, err := c.api.Put("/api/v1/secrets/"+transport.PathSegment(secretID)+"/policies", body)
	if err != nil {
		return nil, fmt.Errorf("update policies: %w", err)
	}
	var result PolicyResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse policy response: %w", err)
	}
	return &result, nil
}
