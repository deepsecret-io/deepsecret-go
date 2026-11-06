// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import "context"

// What the external tests in this package need from its private code. Tests
// that drive a real send and receive go through the root client, which a test
// inside this package cannot import.
var (
	DownloadCheckpoint = &downloadCheckpoint
	PruneAbandoned     = pruneAbandoned
	ReadLocalHeader    = readLocalHeader
	LocalMagicItem     = localMagicItem
	LocalPrefixLen     = localPrefixLen
)

const (
	StaleDownloadAfter = staleDownloadAfter
	AbandonedAfter     = abandonedAfter
)

// LocalHeader is a local file's header, for tests that tamper with one.
type LocalHeader = localHeader

// SendRaw sends data as a payload of payloadType, whatever it holds: for tests
// of how a receiver treats a payload no honest sender writes.
func (c *Client) SendRaw(recipients []string, payloadType string, data []byte, opt EncryptOptions) (*EncryptResult, error) {
	return c.encryptAndSend(context.Background(), recipients, memPlaintext(payloadType, data, nil), opt)
}

// OnDisk reports whether the ciphertext is spooled to a file.
func (o *OpenedSecret) OnDisk() bool { return o.spool.file != nil }
