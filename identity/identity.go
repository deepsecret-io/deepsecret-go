// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/internal/directory"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// Client reaches the caller's account, org and teams, and the keys registered
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
func (c *Client) WhoAmI(ctx context.Context) (*Member, error) {
	return whoAmI(ctx, c.api)
}

// ResolveMemberID returns the signed-in member's ID.
func (c *Client) ResolveMemberID(ctx context.Context) (string, error) {
	return resolveMemberID(ctx, c.api)
}

// ListKeys returns all identity keys registered on the server.
func (c *Client) ListKeys(ctx context.Context) ([]Key, error) {
	return listRemoteKeys(ctx, c.api)
}

// Sync records the account on this device as the user's own, used with kp:
// from then on only key pairs on this device pass for it (see Accept in package
// trust). Then it uploads kp's public keys to the server, labelled with
// protection, how its key file on this device is protected (a label for the
// user's own key lists, see SetKeyProtection). A protection other than the four
// keystore.Protection values, such as "" for a key file that could not be
// read, leaves the key not labelled. Nothing is uploaded when the server says
// the account is someone this device knows as another person, or when the key
// file on this device is protected by KMS keys bound to another account.
func (c *Client) Sync(ctx context.Context, kp *keys.Pair, protection keystore.Protection) error {
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		return fmt.Errorf("compute fingerprint: %w", err)
	}
	me, err := whoAmI(ctx, c.api)
	if err != nil {
		return fmt.Errorf("fetch your account: %w", err)
	}
	if err := checkKMSAccount(c.keysDir, fp, me.ID); err != nil {
		return err
	}
	if _, err := c.store.RecordOwnAccount(me.Email, fp, true); err != nil {
		return err
	}
	return syncIdentity(ctx, c.api, kp, protection)
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

// SetKeyProtection sets how the registered key identityID (from ListKeys) is
// labelled as protected: what the client of the device that holds its key file
// reports after that file's protection changed. protection is one of the four
// keystore.Protection values; anything else, "" included, is refused with
// ErrUnknownProtection before any request. The label is shown only in the
// user's own key lists; it is not signed and decides nothing.
func (c *Client) SetKeyProtection(ctx context.Context, identityID string, protection keystore.Protection) error {
	return setKeyProtection(ctx, c.api, identityID, protection)
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

// ListTeams returns all teams in the given org with their members. Only
// the org's owner and admins may list them; WhoAmI reports this as the
// "teams" permission.
func (c *Client) ListTeams(ctx context.Context, orgID string) ([]Team, error) {
	return listTeams(ctx, c.api, "/teams", orgID)
}

// ListMyTeams returns the teams of the given org that the caller belongs
// to, with their members, to send to. Any active member may call it. A
// member's Role is always empty here.
func (c *Client) ListMyTeams(ctx context.Context, orgID string) ([]Team, error) {
	return listTeams(ctx, c.api, "/my-teams", orgID)
}

// Membership is the single org membership pulled from /api/me. A member
// belongs to at most one org, so this is a pointer (nil when the member is in
// ONBOARDING).
type Membership struct {
	OrgID string `json:"org_id"`
	// Role is "owner", "admin" or "member".
	Role string `json:"role"`
	// OrgKind is "personal" for a one-person workspace, which has no
	// members, teams or audit log, or "organization".
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

// Member bundles everything whoAmI returns: the raw /api/me payload
// plus a few flat fields derived from a follow-up /api/v1/orgs call so
// callers don't have to thread two requests through their own code.
//
// EffectiveState says whether the member is active. The plan's limits are not
// here: the server enforces them, and callers that want them fetch
// /api/v1/tiers.
type Member struct {
	Profile        Profile         `json:"member"`
	Membership     *Membership     `json:"membership"`
	EffectiveState string          `json:"effective_state"`
	Permissions    map[string]bool `json:"permissions"`
	Subscription   Subscription    `json:"subscription"`

	// Flat conveniences populated post-parse so existing call sites
	// (encrypt.go, the CLI, examples) keep reading member.OrgID etc.
	// without traversing the new nested shape. Empty when the member
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
	// Protection is the label a client of the owner set: how the key file
	// is protected on the device that holds it, one of the four
	// keystore.Protection values, or "" when no client has reported it. The
	// server does not check it. Only the owner gets it.
	Protection keystore.Protection `json:"protection"`
}

// whoAmI returns the authenticated user's info. Hits /api/v1/members/me
// for the canonical authz state and, at the same time, /api/v1/orgs to
// populate the flat TierName field (the spec moved tier display info off
// the member row to the org response, and old SDK consumers expect it on
// Member). The two requests run together, so whoAmI takes one round
// trip. The /orgs call is best-effort: a failure leaves TierName empty
// rather than failing the whole call.
func whoAmI(ctx context.Context, c *transport.Client) (*Member, error) {
	var (
		orgResp *transport.Response
		orgErr  error
		orgDone = make(chan struct{})
	)
	go func() {
		defer close(orgDone)
		orgResp, orgErr = c.Get(ctx, "/api/v1/orgs")
	}()
	info, err := memberMe(ctx, c)
	<-orgDone
	if err != nil {
		return nil, err
	}

	// Best-effort tier-name lookup. /api/v1/orgs returns the member's
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

// memberMe fetches /api/v1/members/me alone and fills the flat fields that
// come from it (all but TierName).
func memberMe(ctx context.Context, c *transport.Client) (*Member, error) {
	resp, err := c.Get(ctx, "/api/v1/members/me")
	if err != nil {
		return nil, err
	}
	var info Member
	if err := json.Unmarshal(resp.Data, &info); err != nil {
		return nil, fmt.Errorf("parse member: %w", err)
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

// ErrKMSAccountMismatch refuses to register a key pair whose KMS slots are
// bound to another DeepSecret account than the one signed in.
var ErrKMSAccountMismatch = errors.New("the key pair's AWS KMS protection is bound to another DeepSecret account")

// checkKMSAccount refuses a key pair whose key file here is protected by KMS
// keys bound to an account other than memberID: its encryption context names
// that account, so the key policies written for it would not match.
func checkKMSAccount(dir, fp, memberID string) error {
	info, err := keystore.ReadInfo(dir, fp)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil // no key file here to bind anything
	case err != nil:
		// A key file that does not read cannot be checked: refuse rather
		// than register a key pair whose binding is unknown.
		return fmt.Errorf("key file %s: %w", keys.ShortFingerprint(fp), err)
	case info.Protection != keystore.ProtectionKMS:
		return nil
	}
	for _, s := range info.Slots {
		if s.Account != "" && s.Account != memberID {
			return fmt.Errorf("%w: key pair %s is bound to account %s, and you are signed in as %s", ErrKMSAccountMismatch, keys.ShortFingerprint(fp), s.Account, memberID)
		}
	}
	return nil
}

// ErrUnknownProtection refuses a protection label that is not one of the
// four keystore.Protection values.
var ErrUnknownProtection = errors.New("unknown key pair protection")

// reportable says whether p is a protection the server takes as a label.
func reportable(p keystore.Protection) bool {
	switch p {
	case keystore.ProtectionNone, keystore.ProtectionPassword, keystore.ProtectionSecurityKey, keystore.ProtectionKMS:
		return true
	}
	return false
}

// syncIdentity uploads a key pair's public keys to the server, labelled
// with protection when it is one the server takes, and not labelled
// otherwise: a label decides nothing, so it never fails a registration.
func syncIdentity(ctx context.Context, c *transport.Client, kp *keys.Pair, protection keystore.Protection) error {
	edSig, mldsaSig, err := directory.SignKeyBundle(kp)
	if err != nil {
		return fmt.Errorf("sign key bundle: %w", err)
	}
	body := map[string]any{
		"ed25519":           kp.ED25519Public,
		"x25519":            kp.X25519Public,
		"mlkem768":          kp.MLKEM768PK,
		"mldsa65":           kp.MLDSA65PK,
		"signature":         edSig,
		"signature_mldsa65": mldsaSig,
	}
	if reportable(protection) {
		body["protection"] = string(protection)
	}
	_, err = c.Post(ctx, "/api/v1/identities", body)
	return err
}

// setKeyProtection sets the label that says how one of the caller's
// registered keys is protected.
func setKeyProtection(ctx context.Context, c *transport.Client, identityID string, protection keystore.Protection) error {
	if !reportable(protection) {
		return fmt.Errorf("%w: %q", ErrUnknownProtection, protection)
	}
	_, err := c.Put(ctx, "/api/v1/identities/"+transport.PathSegment(identityID)+"/protection", map[string]string{"protection": string(protection)})
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
// fido2), an AWS KMS key (package awskms) or a recovery code. It returns the
// pair and its full fingerprint.
func (c *Client) LoadPrimary(ctx context.Context, u keystore.Unlock) (*keys.Pair, string, error) {
	dir := c.keysDir
	primaryFP, err := primaryFingerprint(ctx, c.api)
	if err != nil {
		return nil, "", err
	}
	kp, err := keystore.Open(ctx, dir, primaryFP, u)
	if err != nil {
		// A file that reads but does not unlock is not a missing file.
		if _, ierr := keystore.ReadInfo(dir, primaryFP); ierr == nil {
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

// resolveMemberID returns the signed-in member's ID, from
// /api/v1/members/me alone: one request, with no tier lookup. An answer
// without an ID is an error, so a caller never builds a path from "".
func resolveMemberID(ctx context.Context, c *transport.Client) (string, error) {
	info, err := memberMe(ctx, c)
	if err != nil {
		return "", err
	}
	if info.ID == "" {
		return "", errors.New("the server's answer names no account")
	}
	return info.ID, nil
}

// TeamMember holds the email and identifying details of a team member.
// Role ("owner", "admin" or "member") is set by ListTeams only.
type TeamMember struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

// Team represents an org team with its members.
type Team struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	OrgID   string       `json:"org_id"`
	Members []TeamMember `json:"members"`
}

// listTeams returns the teams an org's list endpoint, "/teams" or
// "/my-teams", gives the caller, with their members.
func listTeams(ctx context.Context, c *transport.Client, endpoint, orgID string) ([]Team, error) {
	resp, err := c.Get(ctx, "/api/v1/orgs/"+transport.PathSegment(orgID)+endpoint)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	var teams []Team
	if err := json.Unmarshal(resp.Data, &teams); err != nil {
		return nil, fmt.Errorf("parse teams: %w", err)
	}
	return teams, nil
}
