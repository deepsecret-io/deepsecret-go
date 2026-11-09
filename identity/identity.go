// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/internal/directory"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// Client reaches the caller's account, org and groups, and the keys registered
// on the server. Get one from deepsecret.NewClient, as its Identity field.
type Client struct {
	api     *transport.Client
	store   *knownkeys.Store
	keysDir string
}

// New returns a Client. It takes internal types, so use deepsecret.NewClient.
func New(api *transport.Client, store *knownkeys.Store, keysDir string) *Client {
	return &Client{api: api, store: store, keysDir: keysDir}
}

// WhoAmI returns the authenticated user's info and tier limits.
func (c *Client) WhoAmI(ctx context.Context) (*Actor, error) {
	return whoAmI(ctx, c.api)
}

// ResolveActorID returns the authenticated user's actor ID.
func (c *Client) ResolveActorID(ctx context.Context) (string, error) {
	return resolveActorID(ctx, c.api)
}

// ListKeys returns all identity keys registered on the server.
func (c *Client) ListKeys(ctx context.Context) ([]Key, error) {
	return listRemoteKeys(ctx, c.api)
}

// Sync records the account on this device as the user's own, used with kp:
// from then on only key pairs on this device pass for it (see Accept in package
// trust). Then it uploads kp's public keys to the server, labelled as protected
// by a security key when securityKey is set (a label for the user's own key
// lists, see SetKeySecurityKey). Nothing is uploaded when the server says the
// account is someone this device knows as another person.
func (c *Client) Sync(ctx context.Context, kp *keys.Pair, securityKey bool) error {
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		return fmt.Errorf("compute fingerprint: %w", err)
	}
	me, err := whoAmI(ctx, c.api)
	if err != nil {
		return fmt.Errorf("fetch your account: %w", err)
	}
	if _, err := c.store.RecordOwnAccount(me.Email, fp, true); err != nil {
		return err
	}
	return syncIdentity(ctx, c.api, kp, securityKey)
}

// RecordOwnAccount records the account on this device as the user's own, used
// with fingerprint, a key pair on this device that is already registered for
// it (as from another device): what Sync records, without unlocking the key
// pair or uploading anything. Signed in as the sender of a secret refused with
// trust.UnrecordedSenderError, with the key that signed it, it lets that secret
// open. It refuses what Sync refuses: an account this device knows as someone
// else, and a key recorded for another of the user's accounts. The server must
// list fingerprint among the account's keys; that only catches a mistaken key,
// since the server says which account the caller is either way.
func (c *Client) RecordOwnAccount(ctx context.Context, fingerprint string) error {
	fp := strings.ToLower(fingerprint)
	short := keys.ShortFingerprint(fp)
	if _, err := keystore.LoadPublic(c.keysDir, fp); err != nil {
		return fmt.Errorf("read key pair %s on this device: %w", short, err)
	}
	registered, err := listRemoteKeys(ctx, c.api)
	if err != nil {
		return fmt.Errorf("fetch registered keys: %w", err)
	}
	if !slices.ContainsFunc(registered, func(k Key) bool { return strings.EqualFold(k.Fingerprint, fp) }) {
		return fmt.Errorf("key %s is not registered for this account: register it with Sync", short)
	}
	me, err := whoAmI(ctx, c.api)
	if err != nil {
		return fmt.Errorf("fetch your account: %w", err)
	}
	_, err = c.store.RecordOwnAccount(me.Email, fp, true)
	return err
}

// SetKeySecurityKey sets whether the registered key identityID (from ListKeys)
// is labelled as protected by a security key: what a client reports after
// protecting a key pair, or taking the protection off. The label is shown only
// in the user's own key lists; it is not signed and decides nothing.
func (c *Client) SetKeySecurityKey(ctx context.Context, identityID string, securityKey bool) error {
	return setKeySecurityKey(ctx, c.api, identityID, securityKey)
}

// PrimaryFingerprint returns the fingerprint of the primary key registered on
// the server, without reading or unlocking the local key file.
func (c *Client) PrimaryFingerprint(ctx context.Context) (string, error) {
	return primaryFingerprint(ctx, c.api)
}

// SetPrimaryKey marks a remote identity as the primary key.
func (c *Client) SetPrimaryKey(ctx context.Context, identityID string) error {
	return setPrimaryKey(ctx, c.api, identityID)
}

// DeleteKey removes a remote identity key from the server.
func (c *Client) DeleteKey(ctx context.Context, identityID string) error {
	return deleteKey(ctx, c.api, identityID)
}

// ListGroups returns all groups in the given org with their members. Only
// the org's owner and admins may list them; WhoAmI reports this as the
// "groups" permission.
func (c *Client) ListGroups(ctx context.Context, orgID string) ([]Group, error) {
	return listGroups(ctx, c.api, "/groups", orgID)
}

// ListMyGroups returns the groups of the given org that the caller belongs
// to, with their members, to send to. Any active member may call it. A
// member's Role is always empty here.
func (c *Client) ListMyGroups(ctx context.Context, orgID string) ([]Group, error) {
	return listGroups(ctx, c.api, "/my-groups", orgID)
}

// Membership is the single org membership pulled from /api/me. An actor
// belongs to at most one org, so this is a pointer (nil when the actor is in
// ONBOARDING).
type Membership struct {
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
	// OrgKind is "personal" for a one-person workspace, which has no
	// members, groups or audit log, or "organization".
	OrgKind string `json:"org_kind"`
}

// Org kinds, as OrgKind holds them.
const (
	OrgKindPersonal     = "personal"
	OrgKindOrganization = "organization"
)

// Subscription mirrors /api/me's subscription block: the org owner's
// subscription. Tier-display fields (name, price, limits) come separately
// from /api/v1/orgs (TierName below).
type Subscription struct {
	Status     string  `json:"status"`
	ExpiresAt  *string `json:"expires_at"`
	CanceledAt *string `json:"canceled_at"`
	// TrialEndsAt is the workspace's free trial end (RFC 3339), nil when it
	// has none. Status stays "inactive" during a trial with no
	// subscription; the trial gives access until this time.
	TrialEndsAt *string `json:"trial_ends_at"`
}

// Profile is the identity block from /api/me.
type Profile struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Actor bundles everything whoAmI returns: the raw /api/me payload
// plus a few flat fields derived from a follow-up /api/v1/orgs call so
// callers don't have to thread two requests through their own code.
//
// EffectiveState says whether the actor is active. The plan's limits are not
// here: the server enforces them, and callers that want them fetch
// /api/v1/tiers.
type Actor struct {
	Profile        Profile         `json:"actor"`
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

// Key represents an identity key registered on the server.
type Key struct {
	ID           string `json:"id"`
	Fingerprint  string `json:"fingerprint"`
	IdentityType string `json:"identity_type"`
	IsPrimary    bool   `json:"is_primary"`
	CreatedAt    string `json:"created_at"`
	// SecurityKey is the label a client of the owner set: the key pair is
	// protected by a security key on that device. Only the owner gets it.
	SecurityKey bool `json:"security_key"`
}

// whoAmI returns the authenticated user's info. Hits /api/v1/actors/me
// for the canonical authz state and, at the same time, /api/v1/orgs to
// populate the flat TierName field (the spec moved tier display info off
// the actor row to the org response, and old SDK consumers expect it on
// Actor). The two requests run together, so whoAmI takes one round
// trip. The /orgs call is best-effort: a failure leaves TierName empty
// rather than failing the whole call.
func whoAmI(ctx context.Context, c *transport.Client) (*Actor, error) {
	var (
		orgResp *transport.Response
		orgErr  error
		orgDone = make(chan struct{})
	)
	go func() {
		defer close(orgDone)
		orgResp, orgErr = c.Get(ctx, "/api/v1/orgs")
	}()
	info, err := actorMe(ctx, c)
	<-orgDone
	if err != nil {
		return nil, err
	}

	// Best-effort tier-name lookup. /api/v1/orgs returns the actor's
	// org with tier_name on it; if the call fails (no membership,
	// permissions issue, network), we just leave TierName empty.
	if info.OrgID != "" && orgErr == nil {
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
	return info, nil
}

// actorMe fetches /api/v1/actors/me alone and fills the flat fields that
// come from it (all but TierName).
func actorMe(ctx context.Context, c *transport.Client) (*Actor, error) {
	resp, err := c.Get(ctx, "/api/v1/actors/me")
	if err != nil {
		return nil, err
	}
	var info Actor
	if err := json.Unmarshal(resp.Data, &info); err != nil {
		return nil, fmt.Errorf("parse actor: %w", err)
	}
	info.ID = info.Profile.ID
	info.Email = info.Profile.Email
	info.Name = info.Profile.Name
	info.SubscriptionStatus = info.Subscription.Status
	if info.Membership != nil {
		info.OrgID = info.Membership.OrgID
	}
	return &info, nil
}

// listRemoteKeys returns all identity keys registered on the server.
func listRemoteKeys(ctx context.Context, c *transport.Client) ([]Key, error) {
	resp, err := c.Get(ctx, "/api/v1/identities")
	if err != nil {
		return nil, err
	}
	var list struct {
		Keys []Key `json:"keys"`
	}
	if err := json.Unmarshal(resp.Data, &list); err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	return list.Keys, nil
}

// syncIdentity uploads a key pair's public keys to the server, labelled
// as protected by a security key on this device when securityKey is set.
func syncIdentity(ctx context.Context, c *transport.Client, kp *keys.Pair, securityKey bool) error {
	edSig, mldsaSig, err := directory.SignKeyBundle(kp)
	if err != nil {
		return fmt.Errorf("sign key bundle: %w", err)
	}
	_, err = c.Post(ctx, "/api/v1/identities", map[string]any{
		"ed25519":           kp.ED25519Public,
		"x25519":            kp.X25519Public,
		"mlkem768":          kp.MLKEM768PK,
		"mldsa65":           kp.MLDSA65PK,
		"signature":         edSig,
		"signature_mldsa65": mldsaSig,
		"security_key":      securityKey,
	})
	return err
}

// setKeySecurityKey sets the label that says whether one of the caller's
// registered keys is protected by a security key.
func setKeySecurityKey(ctx context.Context, c *transport.Client, identityID string, securityKey bool) error {
	_, err := c.Put(ctx, "/api/v1/identities/"+transport.PathSegment(identityID)+"/security-key", map[string]bool{"security_key": securityKey})
	return err
}

// setPrimaryKey marks a remote identity as the primary key.
func setPrimaryKey(ctx context.Context, c *transport.Client, identityID string) error {
	_, err := c.Put(ctx, "/api/v1/identities/"+transport.PathSegment(identityID)+"/primary", nil)
	return err
}

// deleteKey removes a remote identity key from the server.
func deleteKey(ctx context.Context, c *transport.Client, identityID string) error {
	_, err := c.Delete(ctx, "/api/v1/identities/"+transport.PathSegment(identityID), nil)
	return err
}

// primaryFingerprint returns the fingerprint of the primary key registered
// on the server, or of the first key when none is marked primary.
func primaryFingerprint(ctx context.Context, c *transport.Client) (string, error) {
	pubKeys, err := listRemoteKeys(ctx, c)
	if err != nil {
		return "", fmt.Errorf("fetch registered keys: %w", err)
	}
	if len(pubKeys) == 0 {
		return "", fmt.Errorf("no keys registered on the server")
	}
	for _, k := range pubKeys {
		if k.IsPrimary {
			return k.Fingerprint, nil
		}
	}
	return pubKeys[0].Fingerprint, nil
}

// LoadPrimary loads the key pair on this device of the primary key registered
// on the server, unlocking it once with u: a password, a security key (package
// fido2) or a recovery code. It returns the pair and its full fingerprint.
func (c *Client) LoadPrimary(ctx context.Context, u keystore.Unlock) (*keys.Pair, string, error) {
	dir := c.keysDir
	primaryFP, err := primaryFingerprint(ctx, c.api)
	if err != nil {
		return nil, "", err
	}
	kp, err := keystore.Open(ctx, dir, primaryFP, u)
	if err != nil {
		if info, ierr := keystore.ReadInfo(dir, primaryFP); ierr == nil && info.Protection == keystore.ProtectionSecurityKey {
			return nil, "", fmt.Errorf("primary key (%s): %w", keys.ShortFingerprint(primaryFP), err)
		}
		return nil, "", fmt.Errorf("primary key (%s) not found locally: %w", keys.ShortFingerprint(primaryFP), err)
	}

	fp, err := keys.Fingerprint(kp)
	if err != nil {
		return nil, "", fmt.Errorf("compute fingerprint: %w", err)
	}
	return kp, fp, nil
}

// resolveActorID returns the current authenticated user's actor ID, from
// /api/v1/actors/me alone: one request, with no tier lookup. An answer
// without an ID is an error, so a caller never builds a path from "".
func resolveActorID(ctx context.Context, c *transport.Client) (string, error) {
	info, err := actorMe(ctx, c)
	if err != nil {
		return "", err
	}
	if info.ID == "" {
		return "", errors.New("the server's answer names no account")
	}
	return info.ID, nil
}

// GroupMember holds the email and identifying details of a group member.
// Role is set by ListGroups only.
type GroupMember struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

// Group represents an org group with its members.
type Group struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	OrgID   string        `json:"org_id"`
	Members []GroupMember `json:"members"`
}

// listGroups returns the groups an org's list endpoint, "/groups" or
// "/my-groups", gives the caller, with their members.
func listGroups(ctx context.Context, c *transport.Client, endpoint, orgID string) ([]Group, error) {
	resp, err := c.Get(ctx, "/api/v1/orgs/"+transport.PathSegment(orgID)+endpoint)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	var groups []Group
	if err := json.Unmarshal(resp.Data, &groups); err != nil {
		return nil, fmt.Errorf("parse groups: %w", err)
	}
	return groups, nil
}
