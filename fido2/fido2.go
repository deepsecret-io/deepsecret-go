// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package fido2 lets a FIDO2 security key, such as a YubiKey, unlock a
// DeepSecret key file (sdk/docs/yubikey-design.md). It implements
// crypto.Authenticator on top of Yubico's libfido2.
//
// libfido2 is loaded at run time, the first time a security key is used,
// from the system's library directories only (Homebrew or MacPorts on
// macOS, the distribution's package on Linux). A program that never uses a
// security key never needs it. Builds with the nofido2 tag, and builds for
// other systems, have no security key support and return
// crypto.ErrNoSecurityKeySupport.
//
// Every request uses user verification (the security key PIN, or a
// fingerprint on a key with a built-in reader) and a touch.
package fido2

import (
	"context"
	"strings"
	"unicode"

	"github.com/deepsecret-io/sdk/crypto"
)

// Prompter shows the user what a security key needs. The CLI and the
// desktop app each implement it.
type Prompter interface {
	// PIN asks for the PIN of the named security key. retries is the
	// number of attempts left, or -1 when the device did not say; wrong
	// says the security key refused the PIN just given, so the prompt can
	// say why it asks again. An error (the user cancelling, say) stops the
	// request. The returned bytes are cleared after use.
	PIN(ctx context.Context, device string, retries int, wrong bool) ([]byte, error)
	// Touch tells the user to touch the named security key, and why.
	Touch(device, reason string)
	// TouchDone says the security key no longer waits for a touch.
	TouchDone()
	// Insert asks the user to plug in a security key; want says which,
	// such as `the security key "Keyring"`. The request then waits for it,
	// and the next prompt, or the request ending, replaces this one.
	Insert(want string)
}

// Authenticator is a crypto.Authenticator backed by libfido2.
type Authenticator struct {
	prompter Prompter
}

var _ crypto.Authenticator = (*Authenticator)(nil)

// New returns an Authenticator that asks the user through p.
func New(p Prompter) *Authenticator {
	return &Authenticator{prompter: p}
}

// Status describes security key support on this machine.
type Status struct {
	// Library is the libfido2 file loaded, empty when none was.
	Library string
	// Devices are the product names of the FIDO2 devices connected.
	Devices []string
}

// deviceName makes a device's product name safe to show: no control
// characters, at most 64 characters, "security key" when empty.
func deviceName(product string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(product, "") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == 64 {
			break
		}
		b.WriteRune(r)
		n++
	}
	if name := strings.TrimSpace(b.String()); name != "" {
		return name
	}
	return "security key"
}
