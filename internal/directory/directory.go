// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package directory fetches people's keys from the server and checks that each
// bundle is whole and self-signed. That does not make a key theirs: the server
// can list a bundle of its own, so callers check the result against package
// knownkeys. It stays internal so that no outside code takes the server's word.
package directory

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// SignedKeyBundle is the wire shape of a published identity bundle.
type SignedKeyBundle struct {
	ED25519          string `json:"ed25519"`
	X25519           string `json:"x25519"`
	MLKEM768         string `json:"mlkem768"`
	MLDSA65          string `json:"mldsa65"`
	Fingerprint      string `json:"fingerprint"`
	Signature        string `json:"signature"`
	SignatureMLDSA65 string `json:"signature_mldsa65"`
	IsPrimary        bool   `json:"is_primary"`
}

// VerifySignedBundle checks both of a bundle's self-signatures: each must
// be present, and each must verify.
func VerifySignedBundle(k SignedKeyBundle) error {
	switch {
	case k.Signature == "":
		return fmt.Errorf("key bundle has no Ed25519 self-signature")
	case k.SignatureMLDSA65 == "":
		return fmt.Errorf("key bundle has no ML-DSA-65 self-signature")
	}
	return VerifyKeyBundleSignature(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65, k.Signature, k.SignatureMLDSA65)
}

// GetRecipientKeys fetches a recipient's primary public keys by email. The
// bundle must carry its fingerprint and both self-signatures (Ed25519 and
// ML-DSA-65): the fingerprint must be the hash of its public keys, and both
// signatures must verify. A bundle missing any of them is refused.
//
// These checks prove the bundle is whole and self-consistent, not that it
// belongs to the recipient: a server can still list a bundle of its own.
// When the recipient is the caller, checkOwnKeys closes that gap.
func GetRecipientKeys(ctx context.Context, c *transport.Client, email string) (*keys.PublicKeys, error) {
	resp, err := c.Get(ctx, "/api/v1/identities/actor/"+transport.PathSegment(email))
	if err != nil {
		return nil, fmt.Errorf("lookup recipient keys: %w", err)
	}

	var pubKeys struct {
		Keys []SignedKeyBundle `json:"keys"`
	}
	if err := json.Unmarshal(resp.Data, &pubKeys); err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(pubKeys.Keys) == 0 {
		return nil, fmt.Errorf("recipient has no public keys registered")
	}

	rk := pubKeys.Keys[0]
	for _, k := range pubKeys.Keys {
		if k.IsPrimary {
			rk = k
			break
		}
	}

	if rk.Fingerprint == "" {
		return nil, fmt.Errorf("recipient key bundle has no fingerprint: refusing to use it")
	}
	computed, err := keys.FingerprintFromPubs(rk.ED25519, rk.X25519, rk.MLKEM768, rk.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("compute recipient fingerprint: %w", err)
	}
	if computed != rk.Fingerprint {
		return nil, fmt.Errorf("recipient key fingerprint mismatch (possible tampering)")
	}
	if err := VerifySignedBundle(rk); err != nil {
		return nil, fmt.Errorf("recipient key verification failed: %w", err)
	}

	return &keys.PublicKeys{
		ED25519:     rk.ED25519,
		X25519:      rk.X25519,
		MLKEM768:    rk.MLKEM768,
		MLDSA65:     rk.MLDSA65,
		Fingerprint: rk.Fingerprint,
	}, nil
}

// ResolveED25519ByEmail is for someone known by email:
// it returns the Ed25519 key of their registered key with fingerprint (the
// primary one when fingerprint is empty), after verifying that key
// bundle's self-signature, and fails when they registered no such key.
func ResolveED25519ByEmail(ctx context.Context, c *transport.Client, email, fingerprint string) (string, error) {
	keysResp, err := c.Get(ctx, "/api/v1/identities/actor/"+transport.PathSegment(email))
	if err != nil {
		return "", err
	}
	var pubKeys struct {
		Keys []SignedKeyBundle `json:"keys"`
	}
	if err := json.Unmarshal(keysResp.Data, &pubKeys); err != nil {
		return "", fmt.Errorf("parse keys: %w", err)
	}
	if len(pubKeys.Keys) == 0 {
		return "", fmt.Errorf("%s has no registered keys", email)
	}

	if fingerprint != "" {
		for _, k := range pubKeys.Keys {
			fp, err := keys.FingerprintFromPubs(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65)
			if err != nil || fp != fingerprint {
				continue
			}
			if err := VerifySignedBundle(k); err != nil {
				return "", fmt.Errorf("key %s of %s failed verification: %w", fingerprint, email, err)
			}
			return k.ED25519, nil
		}
		return "", fmt.Errorf("%s has no registered key %s", email, fingerprint)
	}

	for _, k := range pubKeys.Keys {
		if k.IsPrimary {
			if err := VerifySignedBundle(k); err != nil {
				return "", fmt.Errorf("primary key of %s failed verification: %w", email, err)
			}
			return k.ED25519, nil
		}
	}
	first := pubKeys.Keys[0]
	if err := VerifySignedBundle(first); err != nil {
		return "", fmt.Errorf("key of %s failed verification: %w", email, err)
	}
	return first.ED25519, nil
}
