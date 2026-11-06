// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build nofido2 || !(darwin || linux) || !(amd64 || arm64)

package fido2

import (
	"context"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// Enroll is not supported by this build.
func (a *Authenticator) Enroll(context.Context, keystore.EnrollRequest) (*keystore.EnrollResult, error) {
	return nil, keystore.ErrNoSecurityKeySupport
}

// Derive is not supported by this build.
func (a *Authenticator) Derive(context.Context, keystore.DeriveRequest) (*keystore.DeriveResult, error) {
	return nil, keystore.ErrNoSecurityKeySupport
}

// Check reports that this build has no security key support.
func Check() (Status, error) {
	return Status{}, keystore.ErrNoSecurityKeySupport
}
