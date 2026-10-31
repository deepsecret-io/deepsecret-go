// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package identity provides identity and key management operations for the
// DeepSecret SDK.
package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
)

// Membership is the single org membership pulled from /api/me. Per
// PERMISSIONS.md §2.3 an actor belongs to at most one org, so this is a
// pointer (nil when the actor is in ONBOARDING).
type Membership struct {
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
}

// Subscription mirrors /api/me's subscription block: the OWNER's
// authz row. Tier-display fields (name, price, limits) live on the
// `subscriptions` table per STRIPE_WEBHOOKS.md §6 and are surfaced
// separately via /api/v1/orgs (TierName below).
type Subscription struct {
	Status     string  `json:"status"`
	ExpiresAt  *string `json:"expires_at"`
	CanceledAt *string `json:"canceled_at"`
	// TrialEndsAt is the workspace's free trial end (RFC 3339), nil when it
	// has none. Status stays "inactive" during a trial with no
	// subscription; the trial gives access until this time.
	TrialEndsAt *string `json:"trial_ends_at"`
}

// Actor is the identity block from /api/me.
type Actor struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ActorInfo bundles everything WhoAmI returns: the raw /api/me payload
// plus a few flat fields derived from a follow-up /api/v1/orgs call so
// callers don't have to thread two requests through their own code.
//
// What changed from the pre-Phase-5 SDK:
//
//   - first_name / last_name → single Name field (PERMISSIONS.md §7).
//   - is_active dropped (effective_state encodes the same information).
//   - memberships []  → membership * (single-org-per-actor).
//   - tier limits (max_files_per_secret, max_upload_bytes, policy_ttl,
//     policy_ip_lock) are gone from /api/me. The backend enforces them;
//     the SDK no longer mirrors them client-side. Callers that want
//     tier metadata fetch /api/v1/tiers explicitly.
type ActorInfo struct {
	Actor          Actor           `json:"actor"`
	Membership     *Membership     `json:"membership"`
	EffectiveState string          `json:"effective_state"`
	Permissions    map[string]bool `json:"permissions"`
	Subscription   Subscription    `json:"subscription"`

	// Flat conveniences populated post-parse so existing call sites
	// (encrypt.go, the CLI, examples) keep reading actor.OrgID etc.
	// without traversing the new nested shape. Empty when the actor
	// has no membership.
	ID                 string `json:"-"`
	Email              string `json:"-"`
	Name               string `json:"-"`
	OrgID              string `json:"-"`
	TierName           string `json:"-"`
	SubscriptionStatus string `json:"-"`
}

// RemoteKey represents an identity key registered on the server.
type RemoteKey struct {
	ID           string `json:"id"`
	Fingerprint  string `json:"fingerprint"`
	IdentityType string `json:"identity_type"`
	IsPrimary    bool   `json:"is_primary"`
	CreatedAt    string `json:"created_at"`
}

// WhoAmI returns the authenticated user's info. Hits /api/v1/actors/me
// for the canonical authz state; if the actor has a membership, makes
// a second call to /api/v1/orgs to populate the flat TierName field
// (the spec moved tier display info off the actor row to the org
// response, and old SDK consumers expect it on ActorInfo). The /orgs
// call is best-effort: a failure leaves TierName empty rather than
// failing the whole call.
func WhoAmI(c *api.Client) (*ActorInfo, error) {
	resp, err := c.Get("/api/v1/actors/me")
	if err != nil {
		return nil, err
	}
	var info ActorInfo
	if err := json.Unmarshal(resp.Data, &info); err != nil {
		return nil, fmt.Errorf("parse actor: %w", err)
	}

	info.ID = info.Actor.ID
	info.Email = info.Actor.Email
	info.Name = info.Actor.Name
	info.SubscriptionStatus = info.Subscription.Status
	if info.Membership != nil {
		info.OrgID = info.Membership.OrgID
	}

	// Best-effort tier-name lookup. /api/v1/orgs returns the actor's
	// org with tier_name on it; if the call fails (no membership,
	// permissions issue, network), we just leave TierName empty.
	if info.OrgID != "" {
		orgResp, oerr := c.Get("/api/v1/orgs")
		if oerr == nil {
			var orgs []struct {
				ID       string `json:"id"`
				TierName string `json:"tier_name"`
			}
			if jerr := json.Unmarshal(orgResp.Data, &orgs); jerr == nil {
				for _, o := range orgs {
					if o.ID == info.OrgID {
						info.TierName = o.TierName
						break
					}
				}
			}
		}
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

// GetRecipientKeys fetches a recipient's primary public keys by email. The
// bundle must carry its fingerprint and both self-signatures (Ed25519 and
// ML-DSA-65): the fingerprint must be the hash of its public keys, and both
// signatures must verify. A bundle missing any of them is refused.
//
// These checks prove the bundle is whole and self-consistent, not that it
// belongs to the recipient: a server can still list a bundle of its own.
// When the recipient is the caller, CheckOwnKeys closes that gap.
func GetRecipientKeys(c *api.Client, email string) (*crypto.PublicKeys, error) {
	resp, err := c.Get("/api/v1/identities/actor/" + url.PathEscape(email))
	if err != nil {
		return nil, fmt.Errorf("lookup recipient keys: %w", err)
	}

	var keys struct {
		Keys []signedKeyBundle `json:"keys"`
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

	if rk.Fingerprint == "" {
		return nil, fmt.Errorf("recipient key bundle has no fingerprint: refusing to use it")
	}
	computed, err := crypto.FingerprintFromPubs(rk.ED25519, rk.X25519, rk.MLKEM768, rk.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("compute recipient fingerprint: %w", err)
	}
	if computed != rk.Fingerprint {
		return nil, fmt.Errorf("recipient key fingerprint mismatch (possible tampering)")
	}
	if err := verifySignedBundle(rk); err != nil {
		return nil, fmt.Errorf("recipient key verification failed: %w", err)
	}

	return &crypto.PublicKeys{
		ED25519:     rk.ED25519,
		X25519:      rk.X25519,
		MLKEM768:    rk.MLKEM768,
		MLDSA65:     rk.MLDSA65,
		Fingerprint: rk.Fingerprint,
	}, nil
}

// CheckOwnKeys checks keys the server returned for the caller's own
// account, as when they send to themselves: the keys must be the sending
// identity (senderFP) or another key pair stored on this device. Otherwise
// a server could list a key of its own as the caller's and read what they
// sealed for themselves.
func CheckOwnKeys(keys *crypto.PublicKeys, senderFP string) error {
	fp, err := crypto.FingerprintFromPubs(keys.ED25519, keys.X25519, keys.MLKEM768, keys.MLDSA65)
	if err != nil {
		return fmt.Errorf("compute own key fingerprint: %w", err)
	}
	if fp == senderFP {
		return nil
	}
	if _, err := crypto.LoadPublicKeys(fp); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("the server lists key %s as your own, but it is not a key on this device: refusing to encrypt to it (possible key substitution)",
				crypto.ShortFingerprint(fp))
		}
		return fmt.Errorf("check your key %s on this device: %w", crypto.ShortFingerprint(fp), err)
	}
	return nil
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
	resp, err := c.Get("/api/v1/actors/email/" + url.PathEscape(email))
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
	Fingerprint      string `json:"fingerprint"`
	Signature        string `json:"signature"`
	SignatureMLDSA65 string `json:"signature_mldsa65"`
	IsPrimary        bool   `json:"is_primary"`
}

// verifySignedBundle checks both of a bundle's self-signatures: each must
// be present, and each must verify.
func verifySignedBundle(k signedKeyBundle) error {
	switch {
	case k.Signature == "":
		return fmt.Errorf("key bundle has no Ed25519 self-signature")
	case k.SignatureMLDSA65 == "":
		return fmt.Errorf("key bundle has no ML-DSA-65 self-signature")
	}
	return crypto.VerifyKeyBundleSignature(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65, k.Signature, k.SignatureMLDSA65)
}

// ResolveSenderED25519 fetches the sender's Ed25519 public key by actor ID,
// optionally matching a specific fingerprint. Each candidate key bundle is
// verified against the server-provided self-signature (Ed25519 + ML-DSA-65)
// before its Ed25519 component is returned, so a compromised identities
// endpoint cannot substitute an attacker key into the sender path.
func ResolveSenderED25519(c *api.Client, actorID, fingerprint string) (string, error) {
	email, err := ResolveActorEmail(c, actorID)
	if err != nil {
		return "", err
	}
	return ResolveED25519ByEmail(c, email, fingerprint)
}

// ResolveActorEmail returns the email of the actor with id actorID.
func ResolveActorEmail(c *api.Client, actorID string) (string, error) {
	resp, err := c.Get("/api/v1/actors/" + url.PathEscape(actorID))
	if err != nil {
		return "", err
	}
	var actor struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(resp.Data, &actor); err != nil {
		return "", fmt.Errorf("parse actor: %w", err)
	}
	if actor.Email == "" {
		return "", fmt.Errorf("actor %s has no email", actorID)
	}
	return actor.Email, nil
}

// ResolveED25519ByEmail is ResolveSenderED25519 for someone known by email:
// it returns the Ed25519 key of their registered key with fingerprint (the
// primary one when fingerprint is empty), after verifying that key
// bundle's self-signature, and fails when they registered no such key.
func ResolveED25519ByEmail(c *api.Client, email, fingerprint string) (string, error) {
	keysResp, err := c.Get("/api/v1/identities/actor/" + url.PathEscape(email))
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
		return "", fmt.Errorf("%s has no registered keys", email)
	}

	if fingerprint != "" {
		for _, k := range keys.Keys {
			fp, err := crypto.FingerprintFromPubs(k.ED25519, k.X25519, k.MLKEM768, k.MLDSA65)
			if err != nil || fp != fingerprint {
				continue
			}
			if err := verifySignedBundle(k); err != nil {
				return "", fmt.Errorf("key %s of %s failed verification: %w", fingerprint, email, err)
			}
			return k.ED25519, nil
		}
		return "", fmt.Errorf("%s has no registered key %s", email, fingerprint)
	}

	for _, k := range keys.Keys {
		if k.IsPrimary {
			if err := verifySignedBundle(k); err != nil {
				return "", fmt.Errorf("primary key of %s failed verification: %w", email, err)
			}
			return k.ED25519, nil
		}
	}
	first := keys.Keys[0]
	if err := verifySignedBundle(first); err != nil {
		return "", fmt.Errorf("key of %s failed verification: %w", email, err)
	}
	return first.ED25519, nil
}
