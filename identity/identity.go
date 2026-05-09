// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package identity provides identity and key management operations for the
// DeepSecret SDK.
package identity

import (
	"encoding/json"
	"fmt"
	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
)

// MembershipInfo holds per-org membership details from the API.
type MembershipInfo struct {
	OrgID             string `json:"org_id"`
	OrgName           string `json:"org_name"`
	Role              string `json:"role"`
	TierName          string `json:"tier_name"`
	MaxFilesPerSecret int    `json:"max_files_per_secret,omitempty"`
	MaxUploadBytes    int64  `json:"max_upload_bytes,omitempty"`
	PolicyTTL         bool   `json:"policy_ttl,omitempty"`
	PolicyIPLock      bool   `json:"policy_ip_lock,omitempty"`
}

// ActorInfo holds the authenticated user's details and tier limits.
// Flat fields (OrgID, TierName, etc.) are derived from the first membership.
type ActorInfo struct {
	ID                 string           `json:"id"`
	Email              string           `json:"email"`
	FirstName          string           `json:"first_name"`
	LastName           string           `json:"last_name"`
	IsActive           bool             `json:"is_active"`
	SubscriptionStatus string           `json:"subscription_status"`
	Memberships        []MembershipInfo `json:"memberships"`

	// Derived from primary membership (populated by WhoAmI)
	OrgID             string `json:"-"`
	TierName          string `json:"-"`
	MaxFilesPerSecret int    `json:"-"`
	MaxUploadBytes    int64  `json:"-"`
	PolicyTTL         bool   `json:"-"`
	PolicyIPLock      bool   `json:"-"`
}

// RemoteKey represents an identity key registered on the server.
type RemoteKey struct {
	ID           string `json:"id"`
	Fingerprint  string `json:"fingerprint"`
	IdentityType string `json:"identity_type"`
	IsPrimary    bool   `json:"is_primary"`
	CreatedAt    string `json:"created_at"`
}

// WhoAmI returns the authenticated user's info and tier limits.
// Flat fields (OrgID, TierName, policy flags, limits) are derived from the
// first membership in the response.
func WhoAmI(c *api.Client) (*ActorInfo, error) {
	resp, err := c.Get("/api/v1/actors/me")
	if err != nil {
		return nil, err
	}
	var info ActorInfo
	if err := json.Unmarshal(resp.Data, &info); err != nil {
		return nil, fmt.Errorf("parse actor: %w", err)
	}
	// Derive flat fields from first membership
	if len(info.Memberships) > 0 {
		m := info.Memberships[0]
		info.OrgID = m.OrgID
		info.TierName = m.TierName
		info.MaxFilesPerSecret = m.MaxFilesPerSecret
		info.MaxUploadBytes = m.MaxUploadBytes
		info.PolicyTTL = m.PolicyTTL
		info.PolicyIPLock = m.PolicyIPLock
	}
	return &info, nil
}

// ListRemoteKeys returns all identity keys registered on the server.
func ListRemoteKeys(c *api.Client) ([]RemoteKey, error) {
	resp, err := c.Get("/api/v1/identities/")
	if err != nil {
		return nil, err
	}
	var list struct {
		Keys []RemoteKey `json:"keys"`
	}
	if err := json.Unmarshal(resp.Data, &list); err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	return list.Keys, nil
}

// SyncIdentity uploads a key pair's public keys to the server.
func SyncIdentity(c *api.Client, kp *crypto.KeyPair) error {
	edSig, mldsaSig, err := crypto.SignKeyBundle(kp)
	if err != nil {
		return fmt.Errorf("sign key bundle: %w", err)
	}
	_, err = c.Post("/api/v1/identities/", map[string]string{
		"ed25519":           kp.ED25519Public,
		"x25519":            kp.X25519Public,
		"mlkem768":          kp.MLKEM768PK,
		"mldsa65":           kp.MLDSA65PK,
		"signature":         edSig,
		"signature_mldsa65": mldsaSig,
	})
	return err
}

// SetPrimaryKey marks a remote identity as the primary key.
func SetPrimaryKey(c *api.Client, identityID string) error {
	_, err := c.Put("/api/v1/identities/"+identityID+"/primary", nil)
	return err
}

// DeleteKey removes a remote identity key from the server.
func DeleteKey(c *api.Client, identityID string) error {
	_, err := c.Delete("/api/v1/identities/"+identityID, nil)
	return err
}

// LoadPrimaryIdentity fetches the primary identity fingerprint from the server,
// then loads the matching local key pair from disk. If the key is
// password-encrypted, pass the password to decrypt it.
func LoadPrimaryIdentity(c *api.Client, password string) (*crypto.KeyPair, string, error) {
	keys, err := ListRemoteKeys(c)
	if err != nil {
		return nil, "", fmt.Errorf("fetch registered keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("no keys registered on the server")
	}

	var primaryFP string
	for _, k := range keys {
		if k.IsPrimary {
			primaryFP = k.Fingerprint
			break
		}
	}
	if primaryFP == "" {
		primaryFP = keys[0].Fingerprint
	}

	kp, err := crypto.LoadKeyPair(primaryFP, password)
	if err != nil {
		return nil, "", fmt.Errorf("primary key (%s) not found locally: %w", crypto.ShortFingerprint(primaryFP), err)
	}

	fp, err := crypto.Fingerprint(kp)
	if err != nil {
		return nil, "", fmt.Errorf("compute fingerprint: %w", err)
	}
	return kp, fp, nil
}

// GetRecipientKeys fetches a recipient's primary public keys by email.
func GetRecipientKeys(c *api.Client, email string) (*crypto.PublicKeys, error) {
	resp, err := c.Get("/api/v1/identities/actor/" + email)
	if err != nil {
		return nil, fmt.Errorf("lookup recipient keys: %w", err)
	}

	var keys struct {
		Keys []struct {
			ED25519          string `json:"ed25519"`
			X25519           string `json:"x25519"`
			MLKEM768         string `json:"mlkem768"`
			MLDSA65          string `json:"mldsa65"`
			Fingerprint      string `json:"fingerprint"`
			Signature        string `json:"signature"`
			SignatureMLDSA65 string `json:"signature_mldsa65"`
			IsPrimary        bool   `json:"is_primary"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(resp.Data, &keys); err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("recipient has no public keys registered")
	}

	rk := keys.Keys[0]
	for _, k := range keys.Keys {
		if k.IsPrimary {
			rk = k
			break
		}
	}

	if rk.Fingerprint != "" {
		computed, err := crypto.FingerprintFromPubs(rk.ED25519, rk.X25519, rk.MLKEM768, rk.MLDSA65)
		if err != nil {
			return nil, fmt.Errorf("compute recipient fingerprint: %w", err)
		}
		if computed != rk.Fingerprint {
			return nil, fmt.Errorf("recipient key fingerprint mismatch (possible tampering)")
		}
	}

	if rk.Signature != "" {
		if err := crypto.VerifyKeyBundleSignature(rk.ED25519, rk.X25519, rk.MLKEM768, rk.MLDSA65, rk.Signature, rk.SignatureMLDSA65); err != nil {
			return nil, fmt.Errorf("recipient key verification failed: %w", err)
		}
	}

	return &crypto.PublicKeys{
		ED25519:     rk.ED25519,
		X25519:      rk.X25519,
		MLKEM768:    rk.MLKEM768,
		MLDSA65:     rk.MLDSA65,
		Fingerprint: rk.Fingerprint,
	}, nil
}

// ResolveActorID returns the current authenticated user's actor ID.
func ResolveActorID(c *api.Client) (string, error) {
	info, err := WhoAmI(c)
	if err != nil {
		return "", err
	}
	return info.ID, nil
}

// GroupMemberInfo holds the email and identifying details of a group member.
type GroupMemberInfo struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

// GroupInfo represents an org group with its members.
type GroupInfo struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	OrgID   string            `json:"org_id"`
	Members []GroupMemberInfo `json:"members"`
}

// ListGroups returns all groups in the given org with their members.
// Caller must be a member of the org with can_send_secrets permission.
func ListGroups(c *api.Client, orgID string) ([]GroupInfo, error) {
	resp, err := c.Get("/api/v1/orgs/" + orgID + "/groups")
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	var groups []GroupInfo
	if err := json.Unmarshal(resp.Data, &groups); err != nil {
		return nil, fmt.Errorf("parse groups: %w", err)
	}
	return groups, nil
}

// ResolveRecipientID fetches the actor ID for an email.
func ResolveRecipientID(c *api.Client, email string) (string, error) {
	resp, err := c.Get("/api/v1/actors/email/" + email)
	if err != nil {
		return "", fmt.Errorf("lookup recipient: %w", err)
	}
	var actor struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Data, &actor); err != nil {
		return "", fmt.Errorf("parse recipient: %w", err)
	}
	return actor.ID, nil
}

// signedKeyBundle is the wire shape of a published identity bundle.
type signedKeyBundle struct {
	ED25519          string `json:"ed25519"`
	X25519           string `json:"x25519"`
	MLKEM768         string `json:"mlkem768"`
	MLDSA65          string `json:"mldsa65"`
	Signature        string `json:"signature"`
	SignatureMLDSA65 string `json:"signature_mldsa65"`
	IsPrimary        bool   `json:"is_primary"`
}

func verifySignedBundle(k signedKeyBundle) error {
	if k.Signature == "" {
		return fmt.Errorf("key bundle is unsigned")
	}
	return crypto.VerifyKeyBundleSignature(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65, k.Signature, k.SignatureMLDSA65)
}

// ResolveSenderED25519 fetches the sender's Ed25519 public key by actor ID,
// optionally matching a specific fingerprint. Each candidate key bundle is
// verified against the server-provided self-signature (Ed25519 + ML-DSA-65)
// before its Ed25519 component is returned, so a compromised identities
// endpoint cannot substitute an attacker key into the sender path.
func ResolveSenderED25519(c *api.Client, actorID, fingerprint string) (string, error) {
	resp, err := c.Get("/api/v1/actors/" + actorID)
	if err != nil {
		return "", err
	}
	var actor struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(resp.Data, &actor); err != nil {
		return "", fmt.Errorf("parse actor: %w", err)
	}

	keysResp, err := c.Get("/api/v1/identities/actor/" + actor.Email)
	if err != nil {
		return "", err
	}
	var keys struct {
		Keys []signedKeyBundle `json:"keys"`
	}
	if err := json.Unmarshal(keysResp.Data, &keys); err != nil {
		return "", fmt.Errorf("parse keys: %w", err)
	}
	if len(keys.Keys) == 0 {
		return "", fmt.Errorf("sender has no registered keys")
	}

	if fingerprint != "" {
		for _, k := range keys.Keys {
			fp, err := crypto.FingerprintFromPubs(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65)
			if err != nil || fp != fingerprint {
				continue
			}
			if err := verifySignedBundle(k); err != nil {
				return "", fmt.Errorf("sender key verification failed for %s: %w", fingerprint, err)
			}
			return k.ED25519, nil
		}
		return "", fmt.Errorf("sender has no key matching fingerprint %s", fingerprint)
	}

	for _, k := range keys.Keys {
		if k.IsPrimary {
			if err := verifySignedBundle(k); err != nil {
				return "", fmt.Errorf("sender primary key verification failed: %w", err)
			}
			return k.ED25519, nil
		}
	}
	first := keys.Keys[0]
	if err := verifySignedBundle(first); err != nil {
		return "", fmt.Errorf("sender key verification failed: %w", err)
	}
	return first.ED25519, nil
}
