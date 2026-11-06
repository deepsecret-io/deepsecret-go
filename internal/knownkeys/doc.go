// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package knownkeys is this device's record of whose key is whose, and the
// checks a send and a decrypt run against it.
//
// The server lists everyone's public keys, and a key bundle's
// self-signatures prove only that it is whole, not whose it is. So this
// device remembers the key it first used for each person, per server, and
// refuses a send to them, or a secret from them, under any other key until
// the user accepts it (Accept or Verify in package trust, after comparing fingerprints
// with them). Accepting a key replaces the others: sends go to it alone,
// while the replaced keys still check secrets they signed. A key new to
// this device is recorded once the send or decrypt relying on it succeeds.
//
// The user's own accounts are recorded too, so the server cannot pass off
// another key as theirs by lying about who the caller is: only key pairs on
// this device pass for them. One is recorded when a key is registered for
// it, or by this device's first send on the server; a later send adds only
// the key it used to an account already recorded. An account the server
// claims for the caller that this device knows as someone else, by a key
// that is not on this device or is recorded for another of the user's
// accounts, is refused, never recorded; so is recording, for one of them, a
// key recorded for another. One known only by other key pairs on
// this device, as when another of the user's accounts sent to it before
// this device knew it was theirs, is taken as the user's own: it is
// recorded, those keys with it (RecordOwnAccount says what that trusts).
package knownkeys
