// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
)

// Client sends and receives secrets. Get one from deepsecret.NewClient, as its
// Secrets field.
type Client struct {
	api      *transport.Client
	store    *knownkeys.Store
	identity *identity.Client
	keysDir  string
}

// New returns a Client. It takes internal types, so use deepsecret.NewClient.
func New(api *transport.Client, store *knownkeys.Store, id *identity.Client, keysDir string) *Client {
	return &Client{api: api, store: store, identity: id, keysDir: keysDir}
}

// keys returns c's key pair directory.
func (c *Client) keys() string { return c.keysDir }

// listSecrets returns secrets in the given direction ("sent" or "received").
func (c *Client) listSecrets(ctx context.Context, direction string, opts ...ListOptions) ([]Info, int, error) {
	actorID, err := c.identity.ResolveActorID(ctx)
	if err != nil {
		return nil, 0, err
	}
	return listSecretsFor(ctx, c.api, actorID, direction, opts...)
}

// ListSent returns sent secrets.
func (c *Client) ListSent(ctx context.Context, opts ...ListOptions) ([]Info, int, error) {
	return c.listSecrets(ctx, "sent", opts...)
}

// ListReceived returns received secrets.
func (c *Client) ListReceived(ctx context.Context, opts ...ListOptions) ([]Info, int, error) {
	return c.listSecrets(ctx, "received", opts...)
}

// Describe returns detailed metadata about a secret.
func (c *Client) Describe(ctx context.Context, secretID string) (*Info, error) {
	return describeSecret(ctx, c.api, secretID)
}

// Delete permanently deletes the secrets with these IDs, in one request.
func (c *Client) Delete(ctx context.Context, ids ...string) error {
	return deleteSecretBatch(ctx, c.api, ids)
}

// RevokeRecipient removes one recipient's access to a sent secret, with
// every wrap made for them. Only the sender may revoke. A recipient who
// already downloaded a revision keeps what they downloaded. Revoking the
// last recipient deletes the secret, which the result reports.
func (c *Client) RevokeRecipient(ctx context.Context, secretID, recipientEmail string) (*RevokeResult, error) {
	info, err := describeSecret(ctx, c.api, secretID)
	if err != nil {
		return nil, fmt.Errorf("fetch secret: %w", err)
	}
	r, ok := info.Recipient(recipientEmail)
	if !ok {
		return nil, fmt.Errorf("not a recipient of this secret")
	}
	deleted, err := revokeRecipient(ctx, c.api, secretID, r.ID)
	if err != nil {
		return nil, err
	}
	return &RevokeResult{RecipientID: r.ID, Email: r.Email, SecretDeleted: deleted}, nil
}

// ListRevisions returns all revisions for a secret.
func (c *Client) ListRevisions(ctx context.Context, secretID string) ([]RevisionInfo, error) {
	resp, err := c.api.Get(ctx, "/api/v1/secrets/"+transport.PathSegment(secretID)+"/revisions")
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

// DescribeFull returns a secret's metadata plus all its revisions in one call.
// Returns an error if either the secret or its revisions cannot be fetched.
func (c *Client) DescribeFull(ctx context.Context, secretID string) (*Detail, error) {
	info, err := c.Describe(ctx, secretID)
	if err != nil {
		return nil, err
	}
	revisions, err := c.ListRevisions(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("describe: fetched secret metadata but failed to load revisions: %w", err)
	}
	return &Detail{Secret: *info, Revisions: revisions}, nil
}

// UpdatePolicy updates the policies on an existing secret.
func (c *Client) UpdatePolicy(ctx context.Context, secretID string, update PolicyUpdate) (*PolicyResult, error) {
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

	resp, err := c.api.Put(ctx, "/api/v1/secrets/"+transport.PathSegment(secretID)+"/policies", body)
	if err != nil {
		return nil, fmt.Errorf("update policies: %w", err)
	}
	var result PolicyResult
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse policy response: %w", err)
	}
	return &result, nil
}
