// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package secrets provides secret CRUD operations for the DeepSecret SDK.
package secrets

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk/api"
)

// Secret holds metadata about a created secret (returned by encrypt operations).
//
// IsMultipart and MultipartPartSize are populated from the server response for
// the just-created revision. When IsMultipart is true the caller MUST upload
// via the /multipart/* flow: the single-PUT presign endpoint rejects the
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
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	SenderID    string `json:"sender_id" yaml:"sender_id"`
	SenderEmail string `json:"sender_email" yaml:"sender_email"`
	SenderName  string `json:"sender_name,omitempty" yaml:"sender_name,omitempty"`
	// Recipients is everyone with access now. Every recipient sees the
	// full list.
	Recipients       []SecretRecipient `json:"recipients" yaml:"recipients"`
	RevisionCount    int               `json:"revision_count" yaml:"revision_count"`
	LatestRevisionID string            `json:"latest_revision_id" yaml:"latest_revision_id"`
	TotalSize        int64             `json:"total_size" yaml:"total_size"`
	FilesCount       int               `json:"files_count" yaml:"files_count"`
	CreatedAt        time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at" yaml:"updated_at"`
	ExpiresAt        string            `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	AllowedIPs       []string          `json:"allowed_ips,omitempty" yaml:"allowed_ips,omitempty"`

	// DismissedAt is the caller's own dismissal, when the caller is a
	// recipient who hid the secret.
	DismissedAt string `json:"dismissed_at,omitempty" yaml:"dismissed_at,omitempty"`

	// Trust status of the sender's identity key on the latest revision.
	// One of "primary" (current default identity), "secondary"
	// (registered but not primary), or "invalid" (identity deleted).
	// Recipients' key statuses are per revision.
	SenderKeyStatus string `json:"sender_key_status,omitempty" yaml:"sender_key_status,omitempty"`
}

// SecretRecipient is one person with access to a secret.
type SecretRecipient struct {
	ID        string `json:"id" yaml:"id"`
	Email     string `json:"email" yaml:"email"`
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty" yaml:"avatar_url,omitempty"`
}

// IsVault reports whether the secret is a self-send: the sender is its
// only recipient.
func (s SecretInfo) IsVault() bool {
	return len(s.Recipients) == 1 && s.Recipients[0].ID == s.SenderID
}

// Recipient returns the recipient with the given email (case-insensitive),
// if any.
func (s SecretInfo) Recipient(email string) (SecretRecipient, bool) {
	for _, r := range s.Recipients {
		if strings.EqualFold(r.Email, email) {
			return r, true
		}
	}
	return SecretRecipient{}, false
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

// CreateRequest is the request body for sending a revision on the server.
// OrgID is used for the URL path, not sent in the body. The payload is
// encrypted once; Manifest is the sender's signed manifest and Recipients
// carry each recipient's wrap of the content key. Sending again under an
// existing name adds a revision to that secret.
type CreateRequest struct {
	OrgID            string           `json:"-"` // Used in URL path, not body
	Name             string           `json:"name"`
	RevisionID       string           `json:"revision_id"`
	ChecksumSHA256   string           `json:"checksum_sha256"` // the manifest's payload_digest, hex
	FilesCount       int              `json:"files_count"`
	Size             int64            `json:"size"` // the manifest's ciphertext_size
	Etag             string           `json:"etag"`
	Compressed       bool             `json:"compressed,omitempty"`
	Compression      string           `json:"compression,omitempty"`
	KDF              string           `json:"kdf"`
	CompressionRatio float64          `json:"compression_ratio,omitempty"` // compressed_size / original_size * 100 (lower = better)
	OriginalSize     int64            `json:"original_size,omitempty"`
	ProtocolVersion  string           `json:"protocol_version"`
	CipherSuite      string           `json:"cipher_suite"`
	PayloadType      string           `json:"payload_type"`
	KeyFingerprint   string           `json:"key_fingerprint"` // the sender's
	FilesMeta        []FileMetaEntry  `json:"files_meta,omitempty"`
	Manifest         []byte           `json:"manifest"`
	Recipients       []RecipientInput `json:"recipients"`
	// RevokeMissing confirms that a send under an existing name may leave
	// out people who have access now, revoking them. Without it the API
	// answers 409 and names them.
	RevokeMissing bool     `json:"revoke_missing,omitempty"`
	TTLSeconds    int      `json:"ttl_seconds,omitempty"`
	AllowedIPs    []string `json:"allowed_ips,omitempty"`
}

// RecipientInput is one recipient of a send, with their wrap.
type RecipientInput struct {
	RecipientID    string `json:"recipient_id"`
	RecipientOrgID string `json:"recipient_org_id,omitempty"` // empty lets the server resolve it
	KeyFingerprint string `json:"key_fingerprint"`
	Wrap           Wrap   `json:"wrap"`
}

// Wrap is a revision's content key sealed for one recipient: the HPKE
// encapsulated key and the sealed key, base64 in JSON.
type Wrap struct {
	Enc []byte `json:"enc"`
	Ct  []byte `json:"ct"`
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
	// Revoked lists the people a send with RevokeMissing removed.
	Revoked []SecretRecipient `json:"revoked,omitempty"`
}

// Create sends a revision via the org-scoped endpoint. It returns the
// created secret and anyone the send revoked.
func Create(c *api.Client, req *CreateRequest) (*Secret, []SecretRecipient, error) {
	if req.OrgID == "" {
		return nil, nil, fmt.Errorf("org_id is required for secret creation")
	}
	resp, err := c.Post("/api/v1/orgs/"+req.OrgID+"/secrets", req)
	if err != nil {
		return nil, nil, fmt.Errorf("create secret: %w", err)
	}
	var created CreateResponse
	if err := json.Unmarshal(resp.Data, &created); err != nil {
		return nil, nil, fmt.Errorf("parse create response: %w", err)
	}
	return &Secret{
		ID:                created.Secret.ID,
		Name:              created.Secret.Name,
		RevisionID:        created.Revision.ID,
		IsMultipart:       created.Revision.IsMultipart,
		MultipartPartSize: created.Revision.MultipartPartSize,
	}, created.Revoked, nil
}

// RevisionManifest is what a recipient opens before downloading a
// revision: the sender's signed manifest and the caller's own wrap.
type RevisionManifest struct {
	RevisionID     string `json:"revision_id"`
	Manifest       []byte `json:"manifest"`
	KeyFingerprint string `json:"key_fingerprint"` // the caller's key the wrap was made for
	Wrap           Wrap   `json:"wrap"`
}

// GetManifest fetches a revision's signed manifest and the caller's wrap.
func GetManifest(c *api.Client, revisionID string) (*RevisionManifest, error) {
	resp, err := c.Get("/api/v1/secrets/revisions/" + url.PathEscape(revisionID) + "/manifest")
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}
	var m RevisionManifest
	if err := json.Unmarshal(resp.Data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest response: %w", err)
	}
	return &m, nil
}

// RevokeRecipient removes one recipient's access to a secret, with every
// wrap made for them. It reports whether revoking the last recipient
// deleted the secret.
func RevokeRecipient(c *api.Client, secretID, recipientID string) (bool, error) {
	resp, err := c.Delete("/api/v1/secrets/"+url.PathEscape(secretID)+"/recipients/"+url.PathEscape(recipientID), nil)
	if err != nil {
		return false, fmt.Errorf("revoke recipient: %w", err)
	}
	var out struct {
		SecretDeleted bool `json:"secret_deleted"`
	}
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return false, fmt.Errorf("parse revoke response: %w", err)
	}
	return out.SecretDeleted, nil
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
