// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
	"github.com/deepsecret-io/sdk/secrets"
)

// Client is the high-level DeepSecret SDK client.
type Client struct {
	api *api.Client
}

// NewClient creates a new DeepSecret SDK client.
func NewClient(apiURL, apiKey string) (*Client, error) {
	c, err := api.NewClient(apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	return &Client{api: c}, nil
}

// NewClientFromEnv creates a client from DS_API_URL and DS_API_KEY env vars.
func NewClientFromEnv() (*Client, error) {
	c, err := api.NewClientFromEnv()
	if err != nil {
		return nil, err
	}
	return &Client{api: c}, nil
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string { return c.api.BaseURL() }

// SetRootContext installs a base context that every subsequent HTTP request
// from this Client (including object-storage uploads/downloads) derives
// from. Cancelling that context propagates to in-flight requests so the
// SDK doesn't keep blocking on Read/Write after the caller hits Ctrl+C.
// CLIs typically wire `signal.NotifyContext(...)` here.
func (c *Client) SetRootContext(ctx context.Context) { c.api.SetRootContext(ctx) }

// ── Identity ─────────────────────────────────────────────────────────────────

// Logout revokes the Bearer token this client authenticates with, so a
// copy of it stops working immediately. API-key clients have no session
// and the call is a no-op on the server.
func (c *Client) Logout() error {
	_, err := c.api.Post("/api/v1/auth/logout", nil)
	return err
}

// WhoAmI returns the authenticated user's info and tier limits.
func (c *Client) WhoAmI() (*ActorInfo, error) {
	return identity.WhoAmI(c.api)
}

// ResolveActorID returns the authenticated user's actor ID.
func (c *Client) ResolveActorID() (string, error) {
	return identity.ResolveActorID(c.api)
}

// ListRemoteKeys returns all identity keys registered on the server.
func (c *Client) ListRemoteKeys() ([]RemoteKey, error) {
	return identity.ListRemoteKeys(c.api)
}

// SyncIdentity uploads a key pair's public keys to the server.
func (c *Client) SyncIdentity(kp *crypto.KeyPair) error {
	return identity.SyncIdentity(c.api, kp)
}

// LoadPrimaryIdentity fetches the primary identity from the server and loads
// the matching local key pair from disk. Pass a password if the key is encrypted.
func (c *Client) LoadPrimaryIdentity(password string) (*crypto.KeyPair, string, error) {
	return identity.LoadPrimaryIdentity(c.api, password)
}

// GetRecipientKeys fetches a recipient's primary public keys by email.
func (c *Client) GetRecipientKeys(email string) (*crypto.PublicKeys, error) {
	return identity.GetRecipientKeys(c.api, email)
}

// SetPrimaryKey marks a remote identity as the primary key.
func (c *Client) SetPrimaryKey(identityID string) error {
	return identity.SetPrimaryKey(c.api, identityID)
}

// DeleteKey removes a remote identity key from the server.
func (c *Client) DeleteKey(identityID string) error {
	return identity.DeleteKey(c.api, identityID)
}

// ListGroups returns all groups in the given org with their members.
func (c *Client) ListGroups(orgID string) ([]GroupInfo, error) {
	return identity.ListGroups(c.api, orgID)
}

// ── Secrets ──────────────────────────────────────────────────────────────────

// ListSecrets returns secrets in the given direction ("sent" or "received").
func (c *Client) ListSecrets(direction string, opts ...ListOptions) ([]SecretInfo, int, error) {
	actorID, err := identity.ResolveActorID(c.api)
	if err != nil {
		return nil, 0, err
	}
	return secrets.List(c.api, actorID, direction, opts...)
}

// ListSentSecrets returns sent secrets.
func (c *Client) ListSentSecrets(opts ...ListOptions) ([]SecretInfo, int, error) {
	return c.ListSecrets("sent", opts...)
}

// ListReceivedSecrets returns received secrets.
func (c *Client) ListReceivedSecrets(opts ...ListOptions) ([]SecretInfo, int, error) {
	return c.ListSecrets("received", opts...)
}

// DescribeSecret returns detailed metadata about a secret.
func (c *Client) DescribeSecret(secretID string) (*SecretInfo, error) {
	return secrets.Describe(c.api, secretID)
}

// DeleteSecret permanently deletes a single secret.
func (c *Client) DeleteSecret(secretID string) error {
	return secrets.Delete(c.api, secretID)
}

// DeleteSecrets permanently deletes multiple secrets by their IDs.
func (c *Client) DeleteSecrets(ids []string) error {
	return secrets.DeleteBatch(c.api, ids)
}

// RevokeRecipient removes one recipient's access to a sent secret, with
// every wrap made for them. Only the sender may revoke. A recipient who
// already downloaded a revision keeps what they downloaded. Revoking the
// last recipient deletes the secret, which the result reports.
func (c *Client) RevokeRecipient(secretID, recipientEmail string) (*RevokeResult, error) {
	info, err := secrets.Describe(c.api, secretID)
	if err != nil {
		return nil, fmt.Errorf("fetch secret: %w", err)
	}
	r, ok := info.Recipient(recipientEmail)
	if !ok {
		return nil, fmt.Errorf("not a recipient of this secret")
	}
	deleted, err := secrets.RevokeRecipient(c.api, secretID, r.ID)
	if err != nil {
		return nil, err
	}
	return &RevokeResult{RecipientID: r.ID, Email: r.Email, SecretDeleted: deleted}, nil
}

// ListRevisions returns all revisions for a secret.
func (c *Client) ListRevisions(secretID string) ([]RevisionInfo, error) {
	resp, err := c.api.Get("/api/v1/secrets/" + secretID + "/revisions")
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
func (c *Client) DescribeSecretFull(secretID string) (*SecretDetail, error) {
	info, err := c.DescribeSecret(secretID)
	if err != nil {
		return nil, err
	}
	revisions, err := c.ListRevisions(secretID)
	if err != nil {
		return nil, fmt.Errorf("describe: fetched secret metadata but failed to load revisions: %w", err)
	}
	return &SecretDetail{Secret: *info, Revisions: revisions}, nil
}

// UpdatePolicy updates the policies on an existing secret.
func (c *Client) UpdatePolicy(secretID string, update PolicyUpdate) (*PolicyResult, error) {
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

	resp, err := c.api.Put("/api/v1/secrets/"+secretID+"/policies", body)
	if err != nil {
		return nil, fmt.Errorf("update policies: %w", err)
	}
	var result PolicyResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse policy response: %w", err)
	}
	return &result, nil
}
