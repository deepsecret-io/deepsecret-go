// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/transport"
)

// Storage is one of an organization's storages and how much of it is
// used. New secrets go to the one marked Primary.
type Storage struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider_name"`
	Primary  bool   `json:"is_primary"`
	Managed  bool   `json:"is_managed"`
	Verified bool   `json:"is_verified"`
	// UsedBytes is the size of the revisions kept in the storage, the
	// figure the server checks QuotaBytes against before a send.
	UsedBytes int64 `json:"total_size"`
	// QuotaBytes caps UsedBytes; nil when the storage has no cap.
	QuotaBytes   *int64 `json:"quota_bytes"`
	SecretsCount int64  `json:"secrets_count"`
}

// ListStorages returns the organization's storages with their usage. Only
// the organization's owners and admins may list them: anyone else gets an
// *apierror.Error (403, or 402 when a plan would allow it).
func (c *Client) ListStorages(ctx context.Context, orgID string) ([]Storage, error) {
	if orgID == "" {
		return nil, errors.New("list storages: no organization")
	}
	resp, err := c.api.Get(ctx, "/api/v1/orgs/"+transport.PathSegment(orgID)+"/storage")
	if err != nil {
		return nil, fmt.Errorf("list storages: %w", err)
	}
	var storages []Storage
	if err := json.Unmarshal(resp.Data, &storages); err != nil {
		return nil, fmt.Errorf("parse storages: %w", err)
	}
	return storages, nil
}
