// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// checkOwnKeys checks keys the server returned for the caller's own
// account, as when they send to themselves: the keys must be the sending
// identity (senderFP) or another key pair stored on this device, in dir.
// Otherwise a server could list a key of its own as the caller's and read
// what they sealed for themselves.
func checkOwnKeys(dir string, pubKeys *keys.PublicKeys, senderFP string) error {
	fp, err := keys.FingerprintFromPubs(pubKeys.ED25519, pubKeys.X25519, pubKeys.MLKEM768, pubKeys.MLDSA65)
	if err != nil {
		return fmt.Errorf("compute own key fingerprint: %w", err)
	}
	if fp == senderFP {
		return nil
	}
	if _, err := keystore.LoadPublic(dir, fp); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("the server lists key %s as your own, but it is not a key on this device: refusing to encrypt to it (possible key substitution)",
				keys.ShortFingerprint(fp))
		}
		return fmt.Errorf("check your key %s on this device: %w", keys.ShortFingerprint(fp), err)
	}
	return nil
}

// resolveRecipientID fetches the member ID for an email.
func resolveRecipientID(ctx context.Context, c *transport.Client, email string) (string, error) {
	resp, err := c.Get(ctx, "/api/v1/members/email/"+transport.PathSegment(email))
	if err != nil {
		return "", fmt.Errorf("lookup recipient: %w", err)
	}
	var member struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Data, &member); err != nil {
		return "", fmt.Errorf("parse recipient: %w", err)
	}
	return member.ID, nil
}

// resolveMemberEmail returns the email of the member with id memberID.
func resolveMemberEmail(ctx context.Context, c *transport.Client, memberID string) (string, error) {
	resp, err := c.Get(ctx, "/api/v1/members/"+transport.PathSegment(memberID))
	if err != nil {
		return "", err
	}
	var member struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(resp.Data, &member); err != nil {
		return "", fmt.Errorf("parse member: %w", err)
	}
	if member.Email == "" {
		return "", fmt.Errorf("member %s has no email", memberID)
	}
	return member.Email, nil
}
