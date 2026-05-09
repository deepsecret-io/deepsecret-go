// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
	"github.com/deepsecret-io/sdk/payload"
)

// DecryptSecret downloads and decrypts a secret by its ID.
// Returns only the decrypted payload. For envelope metadata, use DecryptSecretFull.
func (c *Client) DecryptSecret(secretID string) (*payload.Decrypted, error) {
	result, err := c.DecryptSecretFull(secretID, DecryptOptions{})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptRevision downloads and decrypts a specific revision of a secret.
// Returns only the decrypted payload. For envelope metadata, use DecryptRevisionFull.
func (c *Client) DecryptRevision(secretID, revisionID string) (*payload.Decrypted, error) {
	result, err := c.DecryptRevisionFull(secretID, DecryptOptions{Revision: revisionID})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptSecretFull downloads and decrypts a secret, returning full metadata.
// It fetches revisions, validates recipient fingerprint, and includes envelope
// metadata (fingerprints, protocol version, cipher suite, etc.) in the result.
func (c *Client) DecryptSecretFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {

	return c.decryptWithRevisionResolution(secretID, opt)
}

// DecryptRevisionFull downloads and decrypts a specific revision, returning full metadata.
// Set opts.Revision to target a specific revision; empty means latest.
func (c *Client) DecryptRevisionFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {

	return c.decryptWithRevisionResolution(secretID, opt)
}

func (c *Client) decryptWithRevisionResolution(secretID string, opt DecryptOptions) (*DecryptResult, error) {
	if secretID == "" {
		return nil, fmt.Errorf("secret ID is required")
	}

	debugf := func(step, format string, args ...any) {
		if opt.OnDebug == nil {
			return
		}
		opt.OnDebug(step, fmt.Sprintf(format, args...))
	}

	debugf("fetch", "GET /secrets/%s", secretID)
	secretInfo, err := c.DescribeSecret(secretID)
	if err != nil {
		return nil, fmt.Errorf("fetch secret: %w", err)
	}
	debugf("fetch", "latest_revision=%s", secretInfo.LatestRevisionID)
	debugf("fetch", "sender_id=%s", secretInfo.SenderID)

	// Load recipient identity (explicit fingerprint or server-registered primary)
	var kp *crypto.KeyPair
	var localFP string
	if opt.Identity != "" {
		debugf("identity", "source=local keypair")
		debugf("identity", "fingerprint_prefix=%s", crypto.ShortFingerprint(opt.Identity))
		kp, err = crypto.LoadKeyPair(opt.Identity, opt.Password)
		if err != nil {
			return nil, fmt.Errorf("load identity %s: %w", crypto.ShortFingerprint(opt.Identity), err)
		}
		localFP, err = crypto.Fingerprint(kp)
		if err != nil {
			return nil, fmt.Errorf("compute fingerprint: %w", err)
		}
	} else {
		debugf("identity", "source=primary identity")
		kp, localFP, err = identity.LoadPrimaryIdentity(c.api, opt.Password)
		if err != nil {
			return nil, fmt.Errorf("load identity: %w", err)
		}
	}
	debugf("identity", "recipient fingerprint=%s", crypto.ShortFingerprint(localFP))

	// Resolve target revision and pre-validate fingerprint
	targetRevID, err := c.resolveRevision(secretID, secretInfo.LatestRevisionID, localFP, opt.Revision)
	if err != nil {
		return nil, err
	}
	debugf("revision", "target=%s", targetRevID)

	// Download ciphertext with optional progress.
	debugf("download", "revision=%s", targetRevID)
	t0 := time.Now()
	envelopeData, err := c.api.PresignDownloadParallel(targetRevID, api.MultipartDownloadOptions{
		Threads:              opt.DownloadThreads,
		OnProgress:           opt.OnDownloadProgress,
		OnDebug:              opt.OnDebug,
		PresignExpiryMinutes: opt.PresignExpiryMinutes,
	})
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	dlElapsed := time.Since(t0)
	debugf("download", "envelope=%s", humanBytes(int64(len(envelopeData))))
	debugf("download", "elapsed=%s", dlElapsed.Round(time.Millisecond))
	debugf("download", "rate=%s", formatRate(int64(len(envelopeData)), dlElapsed))

	// Compute envelope checksum
	checksum := sha256.Sum256(envelopeData)
	checksumHex := hex.EncodeToString(checksum[:])
	debugf("verify", "envelope sha256=%s…", checksumHex[:12])

	// Peek at envelope for metadata
	peekEnv, err := crypto.UnmarshalEnvelope(envelopeData)
	if err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	debugf("envelope", "version=%s", peekEnv.Version)
	debugf("envelope", "cipher=%s", peekEnv.CipherSuite)
	debugf("envelope", "payload_type=%s", peekEnv.PayloadType)
	debugf("envelope", "sender fingerprint=%s", crypto.ShortFingerprint(peekEnv.SenderFingerprint))
	debugf("envelope", "recipient fingerprint=%s", crypto.ShortFingerprint(peekEnv.RecipientFingerprint))

	// Validate recipient fingerprint against envelope
	if peekEnv.RecipientFingerprint != "" && !fingerprintMatch(localFP, peekEnv.RecipientFingerprint) {
		return nil, fmt.Errorf("secret was not encrypted for your primary key (%s)",
			crypto.ShortFingerprint(localFP))
	}
	debugf("verify", "recipient fingerprint matches local identity")

	// Resolve sender key (prefer fingerprint from envelope)
	senderED25519, err := identity.ResolveSenderED25519(c.api, secretInfo.SenderID, peekEnv.SenderFingerprint)
	if err != nil {
		return nil, fmt.Errorf("resolve sender key: %w", err)
	}
	debugf("verify", "sender Ed25519 public key resolved")

	// Decrypt
	debugf("decrypt", "algorithm=HPKE+ML-KEM-768+AES-256-GCM")
	debugf("decrypt", "signing=Ed25519+ML-DSA-65")
	debugf("decrypt", "envelope=%s", humanBytes(int64(len(envelopeData))))
	tDec := time.Now()
	result, err := crypto.HybridDecrypt(envelopeData, kp, senderED25519)
	if err != nil {
		return nil, err
	}
	decElapsed := time.Since(tDec)
	debugf("verify", "AEAD authentication succeeded (envelope unmodified)")
	debugf("verify", "sender signature verified")
	debugf("decrypt", "plaintext=%s", humanBytes(int64(len(result.Plaintext))))
	debugf("decrypt", "elapsed=%s", decElapsed.Round(time.Millisecond))
	debugf("decrypt", "rate=%s", formatRate(int64(len(result.Plaintext)), decElapsed))

	plaintext := result.Plaintext

	// Decompress
	if result.Compressed && result.Compression != "" {
		debugf("decompress", "algorithm=%s", result.Compression)
		debugf("decompress", "input=%s", humanBytes(int64(len(plaintext))))
		tDc := time.Now()
		decompressed, err := compress.Decompress(plaintext, compress.Algorithm(result.Compression), nil)
		if err != nil {
			return nil, fmt.Errorf("decompress (%s): %w", result.Compression, err)
		}
		dcElapsed := time.Since(tDc)
		ratio := float64(0)
		if len(decompressed) > 0 {
			ratio = float64(len(plaintext)) / float64(len(decompressed)) * 100
		}
		plaintext = decompressed
		debugf("decompress", "output=%s", humanBytes(int64(len(plaintext))))
		debugf("decompress", "ratio=%.1f%%", ratio)
		debugf("decompress", "elapsed=%s", dcElapsed.Round(time.Millisecond))
		debugf("decompress", "rate=%s", formatRate(int64(len(plaintext)), dcElapsed))
	}

	// Unmarshal payload
	var p payload.Payload
	if err := payload.Unmarshal(plaintext, &p); err != nil {
		return &DecryptResult{
			Decrypted:            &payload.Decrypted{Type: "raw", Raw: plaintext},
			RevisionID:           targetRevID,
			SenderFingerprint:    peekEnv.SenderFingerprint,
			RecipientFingerprint: peekEnv.RecipientFingerprint,
			Compressed:           result.Compressed,
			Compression:          result.Compression,
			PayloadType:          peekEnv.PayloadType,
			ProtocolVersion:      peekEnv.Version,
			CipherSuite:          peekEnv.CipherSuite,
			EnvelopeChecksum:     checksumHex,
			EncryptedSize:        int64(len(envelopeData)),
		}, nil
	}

	decrypted := &payload.Decrypted{Type: p.Type, Raw: plaintext}

	switch p.Type {
	case "message":
		decrypted.Message = p.Message
	case "files":
		if p.Archive && len(p.Files) == 1 {
			// Surface the archive blob to the caller untouched. In-memory
			// extraction (the previous behaviour) collapses for large
			// archives because it had to hold every entry in RAM. The CLI
			// stream-extracts directly to disk via archive.ExtractTar.
			decrypted.Archived = true
			decrypted.ArchiveCompression = p.ArchiveCompression
			decrypted.Files = []payload.DecryptedFile{{
				Name: p.Files[0].Name, Data: p.Files[0].Data,
				Size: p.Files[0].Size, SHA256: p.Files[0].SHA256,
				Mode: p.Files[0].Mode,
			}}
		} else {
			for _, f := range p.Files {
				decrypted.Files = append(decrypted.Files, payload.DecryptedFile{
					Name: f.Name, Data: f.Data, Size: f.Size, SHA256: f.SHA256,
					Mode: f.Mode,
				})
			}
		}
	case "data":
		for _, e := range p.Entries {
			decrypted.Entries = append(decrypted.Entries, payload.KeyValue{Key: e.Key, Value: e.Value})
		}
	}

	return &DecryptResult{
		Decrypted:            decrypted,
		RevisionID:           targetRevID,
		SenderFingerprint:    peekEnv.SenderFingerprint,
		RecipientFingerprint: peekEnv.RecipientFingerprint,
		Compressed:           result.Compressed,
		Compression:          result.Compression,
		PayloadType:          p.Type,
		ProtocolVersion:      peekEnv.Version,
		CipherSuite:          peekEnv.CipherSuite,
		EnvelopeChecksum:     checksumHex,
		EncryptedSize:        int64(len(envelopeData)),
	}, nil
}

// resolveRevision finds the target revision and pre-validates the recipient
// fingerprint before downloading. Uses ListRevisions internally.
func (c *Client) resolveRevision(secretID, latestRevID, localFP, requestedRevID string) (string, error) {
	revisions, err := c.ListRevisions(secretID)
	if err != nil {
		return "", err
	}
	if len(revisions) == 0 {
		return "", fmt.Errorf("secret has no revisions")
	}

	targetID := requestedRevID
	if targetID == "" {
		targetID = latestRevID
	}

	for _, rev := range revisions {
		if rev.ID == targetID {
			fp := rev.Integrity.RecipientKeyFingerprint
			if fp != "" && !fingerprintMatch(fp, localFP) {
				return "", fmt.Errorf("this secret was not encrypted for your key (%s) — revision expects recipient %s",
					crypto.ShortFingerprint(localFP), crypto.ShortFingerprint(fp))
			}
			return rev.ID, nil
		}
	}

	if targetID != "" {
		return "", fmt.Errorf("revision %s not found", targetID)
	}

	// Fallback: pick last revision
	last := revisions[len(revisions)-1]
	fp := last.Integrity.RecipientKeyFingerprint
	if fp != "" && !fingerprintMatch(fp, localFP) {
		return "", fmt.Errorf("this secret was not encrypted for your key (%s)",
			crypto.ShortFingerprint(localFP))
	}
	return last.ID, nil
}

// fingerprintMatch returns true iff a and b are byte-equal lower-case
// 64-character hex fingerprints. Comparison is constant-time. Mismatched
// lengths or non-64-char inputs always return false: prefix matching is
// rejected because a 1-character "match" would silently authenticate the
// wrong key.
func fingerprintMatch(a, b string) bool {
	const fpLen = 64
	if len(a) != fpLen || len(b) != fpLen {
		return false
	}
	la := strings.ToLower(a)
	lb := strings.ToLower(b)
	return subtle.ConstantTimeCompare([]byte(la), []byte(lb)) == 1
}

