// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package secrets provides secret CRUD operations for the DeepSecret SDK.
package secrets

import (
	"encoding/json"
	"fmt"
	"net/url"
	"github.com/deepsecret-io/sdk/api"
	"strconv"
	"time"
)

// Secret holds metadata about a created secret (returned by encrypt operations).
//
// IsMultipart and MultipartPartSize are populated from the server response for
// the just-created revision. When IsMultipart is true the caller MUST upload
// via the /multipart/* flow — the single-PUT presign endpoint will reject the
// revision with a 409 Conflict.
type Secret struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	RevisionID        string `json:"revision_id"`
	IsMultipart       bool   `json:"is_multipart"`
	MultipartPartSize int64  `json:"multipart_part_size,omitempty"`
}

// SecretInfo holds detailed metadata about a secret (returned by list/describe).
type SecretInfo struct {
	ID               string    `json:"id" yaml:"id"`
	Name             string    `json:"name" yaml:"name"`
	SenderID         string    `json:"sender_id" yaml:"sender_id"`
	SenderEmail      string    `json:"sender_email" yaml:"sender_email"`
	SenderName       string    `json:"sender_name,omitempty" yaml:"sender_name,omitempty"`
	RecipientID      string    `json:"recipient_id" yaml:"recipient_id"`
	RecipientEmail   string    `json:"recipient_email" yaml:"recipient_email"`
	RecipientName    string    `json:"recipient_name,omitempty" yaml:"recipient_name,omitempty"`
	RevisionCount    int       `json:"revision_count" yaml:"revision_count"`
	LatestRevisionID string    `json:"latest_revision_id" yaml:"latest_revision_id"`
	TotalSize        int64     `json:"total_size" yaml:"total_size"`
	FilesCount       int       `json:"files_count" yaml:"files_count"`
	CreatedAt        time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" yaml:"updated_at"`
	ExpiresAt  string   `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty" yaml:"allowed_ips,omitempty"`

	// Trust status for the latest revision's sender/recipient identity
	// keys. One of "primary" (current default identity), "secondary"
	// (registered but not primary), or "invalid" (identity deleted).
	// Omitted when the latest revision has no fingerprint set.
	SenderKeyStatus    string `json:"sender_key_status,omitempty" yaml:"sender_key_status,omitempty"`
	RecipientKeyStatus string `json:"recipient_key_status,omitempty" yaml:"recipient_key_status,omitempty"`
}

// ListOptions configures pagination and filtering for secret listing.
type ListOptions struct {
	Limit  int    // max results per page (default 20)
	Offset int    // skip N results
	Email  string // filter by sender (for received) or recipient (for sent)
}

// List returns secrets in the given direction ("sent" or "received")
// for the authenticated user. Returns the list, total count, and any error.
func List(c *api.Client, actorID, direction string, opts ...ListOptions) ([]SecretInfo, int, error) {
	opt := ListOptions{Limit: 20}
	if len(opts) > 0 {
		opt = opts[0]
		if opt.Limit == 0 {
			opt.Limit = 20
		}
	}

	var path string
	switch direction {
	case "sent":
		path = "/api/v1/secrets/sender/" + actorID
	case "received":
		path = "/api/v1/secrets/recipient/" + actorID
	default:
		return nil, 0, fmt.Errorf("direction must be \"sent\" or \"received\", got %q", direction)
	}

	q := url.Values{}
	q.Set("limit", strconv.Itoa(opt.Limit))
	if opt.Offset > 0 {
		q.Set("offset", strconv.Itoa(opt.Offset))
	}
	if opt.Email != "" {
		if direction == "sent" {
			q.Set("to", opt.Email)
		} else {
			q.Set("from", opt.Email)
		}
	}

	resp, err := c.Get(path + "?" + q.Encode())
	if err != nil {
		return nil, 0, err
	}

	var list struct {
		Secrets []SecretInfo `json:"secrets"`
		Total   int          `json:"total"`
	}
	if err := json.Unmarshal(resp.Data, &list); err != nil {
		return nil, 0, fmt.Errorf("parse secrets: %w", err)
	}
	return list.Secrets, list.Total, nil
}

// CreateRequest is the request body for creating a secret on the server.
// OrgID is used for the URL path, not sent in the body.
type CreateRequest struct {
	OrgID                   string          `json:"-"` // Used in URL path, not body
	Name                    string          `json:"name"`
	RecipientID             string          `json:"recipient_id"`
	RevisionID              string          `json:"revision_id"`
	ChecksumSHA256          string          `json:"checksum_sha256"`
	FilesCount              int             `json:"files_count"`
	Size                    int64           `json:"size"`
	Etag                    string          `json:"etag"`
	Compressed              bool            `json:"compressed,omitempty"`
	Compression             string          `json:"compression,omitempty"`
	KDF                     string          `json:"kdf"`
	CompressionRatio        float64         `json:"compression_ratio,omitempty"` // compressed_size / original_size * 100 (lower = better)
	OriginalSize            int64           `json:"original_size,omitempty"`
	ProtocolVersion         string          `json:"protocol_version"`
	CipherSuite             string          `json:"cipher_suite"`
	PayloadType             string          `json:"payload_type"`
	KeyFingerprint          string          `json:"key_fingerprint"`
	RecipientKeyFingerprint string          `json:"recipient_key_fingerprint"`
	FilesMeta               []FileMetaEntry `json:"files_meta,omitempty"`
	TTLSeconds              int             `json:"ttl_seconds,omitempty"`
	AllowedIPs              []string        `json:"allowed_ips,omitempty"`
}

// FileMetaEntry is per-file metadata sent to the server for the file tree UI.
type FileMetaEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// CreateResponse is the server's response to creating a secret.
type CreateResponse struct {
	Secret struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"secret"`
	Revision struct {
		ID                string `json:"id"`
		IsMultipart       bool   `json:"is_multipart"`
		MultipartState    string `json:"multipart_state,omitempty"`
		MultipartPartSize int64  `json:"multipart_part_size,omitempty"`
	} `json:"revision"`
}

// Create creates a new secret on the server via the org-scoped endpoint.
func Create(c *api.Client, req *CreateRequest) (*Secret, error) {
	if req.OrgID == "" {
		return nil, fmt.Errorf("org_id is required for secret creation")
	}
	resp, err := c.Post("/api/v1/orgs/"+req.OrgID+"/secrets", req)
	if err != nil {
		return nil, fmt.Errorf("create secret: %w", err)
	}
	var created CreateResponse
	if err := json.Unmarshal(resp.Data, &created); err != nil {
		return nil, fmt.Errorf("parse create response: %w", err)
	}
	return &Secret{
		ID:                created.Secret.ID,
		Name:              created.Secret.Name,
		RevisionID:        created.Revision.ID,
		IsMultipart:       created.Revision.IsMultipart,
		MultipartPartSize: created.Revision.MultipartPartSize,
	}, nil
}

// Describe returns detailed metadata about a secret by its ID.
func Describe(c *api.Client, secretID string) (*SecretInfo, error) {
	resp, err := c.Get("/api/v1/secrets/" + secretID)
	if err != nil {
		return nil, err
	}
	var secret SecretInfo
	if err := json.Unmarshal(resp.Data, &secret); err != nil {
		return nil, fmt.Errorf("parse secret: %w", err)
	}
	return &secret, nil
}

// Delete permanently deletes a single secret.
func Delete(c *api.Client, secretID string) error {
	return DeleteBatch(c, []string{secretID})
}

// DeleteBatch permanently deletes multiple secrets by their IDs.
func DeleteBatch(c *api.Client, ids []string) error {
	_, err := c.Delete("/api/v1/secrets/", map[string]any{
		"ids": ids,
	})
	return err
}
