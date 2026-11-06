// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
	"github.com/deepsecret-io/deepsecret-go/internal/protocol"
)

// humanBytes renders a byte count in IEC units ("12.50 MiB") for error
// messages. Returns "0 B" for zero or negative values so a message never
// shows a blank size.
func humanBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const (
		kib = int64(1 << 10)
		mib = int64(1 << 20)
		gib = int64(1 << 30)
	)
	switch {
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ── Logs the send and decrypt flows share ───────────────────────────────────

// logPayload logs what a send is about to seal: the payload's type, its
// size before compression (an estimate until it is written, since a file
// payload adds headers to the files), and for an archive the size of the
// files in it.
func logPayload(log *slog.Logger, p *plaintext) {
	args := []any{"type", p.payloadType, "estimated_size", logattr.Bytes(p.size), "archived", p.archived}
	if p.archived {
		args = append(args, "files_size", logattr.Bytes(p.originalSize))
	}
	logattr.Module(log, "encrypt").Debug("payload", args...)
}

// logKeyPair logs the key pair a flow uses, by its fingerprint: the one
// the caller asked for (requested), or the primary key the server lists.
func logKeyPair(log *slog.Logger, fp, requested string) {
	source := "primary"
	if requested != "" {
		source = "requested"
	}
	logattr.Module(log, "identity").Debug("key pair loaded", "fingerprint", fp, "source", source)
}

// logRecipientKeys logs the keys a send seals for a recipient: what was
// checked of the bundle the server lists, and why the key is trusted
// (keyTrust). actorID is "" when the send creates no secret.
func logRecipientKeys(log *slog.Logger, email, actorID, fp string, own, first bool) {
	args := []any{"email", email}
	if actorID != "" {
		args = append(args, "actor_id", actorID)
	}
	args = append(args, "fingerprint", fp, "checked", "fingerprint and both self-signatures", "trust", knownkeys.KeyTrust(own, first))
	logattr.Module(log, "recipient").Debug("recipient keys verified", args...)
}

// logEncryptPlan logs how a payload is sealed for n recipients: the
// protocol's cipher suite and chunk size, under a fresh content key.
func logEncryptPlan(log *slog.Logger, n int) {
	logattr.Module(log, "encrypt").Debug("plan", "cipher_suite", protocol.CipherSuite, "chunk_size", logattr.Bytes(protocol.ChunkSize), "recipients", n)
}

// logSealed logs a sealed payload: its compression, its encryption and the
// signed manifest. written is what the payload wrote before compression,
// in elapsed.
func logSealed(log *slog.Logger, algo compress.Algorithm, sealed *protocol.Sealed, written int64, elapsed time.Duration) {
	m := sealed.Manifest
	if algo != compress.None {
		logattr.Module(log, "compress").Debug("payload compressed", "algorithm", algo, "size", logattr.Bytes(written), "compressed", logattr.Bytes(m.PlaintextSize))
	}
	logattr.Module(log, "encrypt").Info("payload encrypted", "size", logattr.Bytes(written), "ciphertext", logattr.Bytes(m.CiphertextSize),
		"elapsed", elapsed.Round(time.Millisecond), "rate", logattr.RateOf(written, elapsed))
	logattr.Module(log, "manifest").Debug("manifest signed", "revision_id", m.RevisionID, "size", logattr.Bytes(int64(len(sealed.ManifestData))),
		"payload_sha256", hex.EncodeToString(m.PayloadDigest), "recipients", len(m.Recipients))
}

// logManifestVerified logs a manifest protocol.Open verified, and the wrap
// it opened for this device's key.
func logManifestVerified(log *slog.Logger, m *protocol.Manifest, size int) {
	logattr.Module(log, "manifest").Debug("manifest verified", "revision_id", m.RevisionID, "size", logattr.Bytes(int64(size)),
		"version", m.Version, "cipher_suite", m.CipherSuite, "payload_type", m.PayloadType,
		"sender_fingerprint", m.SenderFingerprint, "recipients", len(m.Recipients), "ciphertext", logattr.Bytes(m.CiphertextSize),
		"checked", "sender fingerprint, both signatures, sender key, revision and wrap")
}

// logPayloadVerified logs a payload whose ciphertext a decrypt pass
// checked against the signed manifest.
func logPayloadVerified(log *slog.Logger, m *protocol.Manifest) {
	logattr.Module(log, "verify").Debug("payload verified", "payload_sha256", hex.EncodeToString(m.PayloadDigest),
		"checked", "size and digest, then every chunk in order to the last-chunk flag")
}
