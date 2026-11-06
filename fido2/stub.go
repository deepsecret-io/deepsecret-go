// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build nofido2 || !(darwin || linux) || !(amd64 || arm64)

package fido2

import (
	"context"

	"github.com/deepsecret-io/sdk/crypto"
)

// Enroll is not supported by this build.
func (a *Authenticator) Enroll(context.Context, crypto.EnrollRequest) (*crypto.EnrollResult, error) {
	return nil, crypto.ErrNoSecurityKeySupport
}

// Derive is not supported by this build.
func (a *Authenticator) Derive(context.Context, crypto.DeriveRequest) (*crypto.DeriveResult, error) {
	return nil, crypto.ErrNoSecurityKeySupport
}

// Check reports that this build has no security key support.
func Check() (Status, error) {
	return Status{}, crypto.ErrNoSecurityKeySupport
}
