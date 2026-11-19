// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package deepsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/trust"
)

// Client is the DeepSecret SDK client: one login, with a service per domain.
type Client struct {
	// Identity reaches the caller's account, org, teams and registered keys.
	Identity *identity.Client
	// Secrets sends and receives secrets.
	Secrets *secrets.Client
	// Trust reaches the keys this device knows for people.
	Trust *trust.Client

	api *transport.Client
}

// Option configures a Client when it is created.
type Option func(*options)

type options struct {
	keysDir       string
	knownKeysFile string
	session       *SessionStore
}

// WithKeysDir makes the client keep this device's key pairs in dir instead of
// keystore.DefaultKeysDir. Only key pairs in dir are the user's own: they sign,
// decrypt, and pass for the user's own accounts.
func WithKeysDir(dir string) Option {
	return func(o *options) { o.keysDir = dir }
}

// WithKnownKeysFile makes the client keep known keys in path instead of
// known_keys.json beside the keys directory.
func WithKnownKeysFile(path string) Option {
	return func(o *options) { o.knownKeysFile = path }
}

// WithSessionStore makes a client authenticated with "bearer:" and a session
// token save each token it refreshes. The client refreshes the token shortly
// before it expires, so long transfers outlive its one-hour lifetime; the
// server revokes the old token, which is why it must be saved. When the token
// is refused, the client loads the stored one, in case another process
// refreshed the session first.
func WithSessionStore(s SessionStore) Option {
	return func(o *options) { o.session = &s }
}

// NewClient creates a new DeepSecret SDK client. Every call that can block
// takes a context, and ends when it does. apiURL must be an https URL with
// no user info, query or fragment; plaintext HTTP, in any letter case, is
// taken only for a loopback host or one listed in DEEPSECRET_INSECURE_HOSTS.
func NewClient(apiURL, apiKey string, opts ...Option) (*Client, error) {
	api, err := transport.NewClient(apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.session != nil {
		api.SetSessionStore(transport.SessionStore(*o.session))
	}
	if o.keysDir == "" {
		o.keysDir = keystore.DefaultKeysDir()
	}
	// One store for all three services: a key accepted through Trust must
	// apply to the next send through Secrets.
	store := knownkeys.New(o.knownKeysFile, api.BaseURL(), o.keysDir)
	id := identity.New(api, store, o.keysDir)
	return &Client{
		Identity: id,
		Secrets:  secrets.New(api, store, id, o.keysDir),
		Trust:    trust.New(api, store),
		api:      api,
	}, nil
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string { return c.api.BaseURL() }

// SessionStore keeps a login session's token where the next run finds it;
// see [WithSessionStore]. Either func may be left unset.
type SessionStore struct {
	// Load returns the stored token, without the "bearer:" prefix.
	Load func() (string, error)
	// Save stores a refreshed token. An error does not fail the request
	// that triggered the refresh; the store should report it.
	Save func(token string, expiresAt time.Time) error
}

// Logout revokes the Bearer token this client authenticates with, so a
// copy of it stops working immediately. API-key clients have no session
// and the call is a no-op on the server.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.api.Post(ctx, "/api/v1/auth/logout", nil)
	return err
}

// The log conventions a program's log handler needs to read the SDK's records.
const (
	// LevelTrace is the level below slog.LevelDebug, for each request and part.
	LevelTrace = logattr.LevelTrace
	// LogModuleKey is the field that names a record's module.
	LogModuleKey = logattr.ModuleKey
)

// SignInURL asks the API at apiURL for the Google sign-in page that, once
// the user signs in, sends them back to returnURL with clientState, which
// a genuine redirect echoes. It goes through the SDK's transport, so it
// takes the same URLs and transport security as NewClient, and sends no
// credential. The error never names the request URL, whose query holds
// clientState.
func SignInURL(ctx context.Context, apiURL, returnURL, clientState string) (string, error) {
	api, err := transport.NewPublicClient(apiURL)
	if err != nil {
		return "", err
	}
	q := url.Values{"return_url": {returnURL}, "client_state": {clientState}}
	resp, err := api.Get(ctx, "/api/v1/auth/sso/google?"+q.Encode())
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return "", fmt.Errorf("could not reach the DeepSecret API: %w", ue.Err)
		}
		return "", err
	}
	var data struct {
		AuthURL string `json:"auth_url"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil || data.AuthURL == "" {
		return "", errors.New("the DeepSecret API's answer to the sign-in request holds no sign-in URL")
	}
	return data.AuthURL, nil
}
