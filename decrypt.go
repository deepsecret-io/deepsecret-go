// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
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
	"github.com/deepsecret-io/sdk/secrets"
)

// DecryptSecret downloads and decrypts a secret by its ID.
// Returns only the decrypted payload. For manifest metadata, use DecryptSecretFull.
func (c *Client) DecryptSecret(secretID string) (*payload.Decrypted, error) {
	result, err := c.DecryptSecretFull(secretID, DecryptOptions{})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptRevision downloads and decrypts a specific revision of a secret.
// Returns only the decrypted payload. For manifest metadata, use DecryptRevisionFull.
func (c *Client) DecryptRevision(secretID, revisionID string) (*payload.Decrypted, error) {
	result, err := c.DecryptRevisionFull(secretID, DecryptOptions{Revision: revisionID})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptSecretFull downloads and decrypts a secret, returning full metadata.
// It fetches revisions, checks that the revision was sealed for your key,
// and includes the verified manifest's metadata (fingerprints, recipients,
// protocol version, cipher suite, payload digest) in the result.
func (c *Client) DecryptSecretFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {

	return c.decryptWithRevisionResolution(secretID, opt)
}

// DecryptRevisionFull downloads and decrypts a specific revision, returning full metadata.
// Set opts.Revision to target a specific revision; empty means latest.
func (c *Client) DecryptRevisionFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {

	return c.decryptWithRevisionResolution(secretID, opt)
}

// decryptWithRevisionResolution opens one revision as protocol v4 §6
// orders it: fetch the manifest and the caller's wrap, verify the manifest
// and open the wrap, download the payload, check its digest, and only then
// decrypt.
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
	rev, err := c.resolveRevision(secretID, secretInfo.LatestRevisionID, localFP, opt.Revision)
	if err != nil {
		return nil, err
	}
	targetRevID := rev.ID
	debugf("revision", "target=%s", targetRevID)
	debugf("revision", "recipients=%d", len(rev.Integrity.Recipients))

	// Fetch the signed manifest and the caller's own wrap.
	debugf("manifest", "GET /secrets/revisions/%s/manifest", targetRevID)
	rm, err := secrets.GetManifest(c.api, targetRevID)
	if err != nil {
		return nil, err
	}
	if !fingerprintMatch(rm.KeyFingerprint, localFP) {
		return nil, fmt.Errorf("your wrap for this revision was made for key %s, not the key in use (%s)",
			crypto.ShortFingerprint(rm.KeyFingerprint), crypto.ShortFingerprint(localFP))
	}
	wrap := &crypto.Wrap{RecipientFingerprint: localFP, Enc: rm.Wrap.Enc, Ciphertext: rm.Wrap.Ct}

	// Resolve the sender's Ed25519 key from the identity service by the
	// manifest's sender fingerprint, so Open cross-checks the embedded key
	// against it. The manifest is parsed here for that fingerprint only;
	// Open verifies it in full.
	peek, err := crypto.UnmarshalManifest(rm.Manifest)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	debugf("manifest", "size=%s", humanBytes(int64(len(rm.Manifest))))
	debugf("manifest", "version=%s", peek.Version)
	debugf("manifest", "cipher=%s", peek.CipherSuite)
	debugf("manifest", "payload_type=%s", peek.PayloadType)
	debugf("manifest", "sender fingerprint=%s", crypto.ShortFingerprint(peek.SenderFingerprint))
	debugf("manifest", "recipients=%d", len(peek.Recipients))
	senderED25519, err := identity.ResolveSenderED25519(c.api, secretInfo.SenderID, peek.SenderFingerprint)
	if err != nil {
		return nil, fmt.Errorf("resolve sender key: %w", err)
	}
	debugf("verify", "sender Ed25519 public key resolved")

	opened, err := crypto.Open(rm.Manifest, wrap, kp, crypto.OpenParams{
		RevisionID:    targetRevID,
		SenderED25519: senderED25519,
	})
	if err != nil {
		return nil, err
	}
	defer opened.Close()
	m := opened.Manifest
	debugf("verify", "sender bundle bound to fingerprint, Ed25519 + ML-DSA-65 signatures verified")
	debugf("verify", "manifest is for this revision and lists your key")
	debugf("verify", "wrap matches the signed digest and opened (HPKE X25519 + ML-KEM-768)")

	// Download ciphertext with optional progress.
	debugf("download", "revision=%s", targetRevID)
	t0 := time.Now()
	payloadData, err := c.api.PresignDownloadParallel(targetRevID, api.MultipartDownloadOptions{
		Threads:              opt.DownloadThreads,
		OnProgress:           opt.OnDownloadProgress,
		OnDebug:              opt.OnDebug,
		PresignExpiryMinutes: opt.PresignExpiryMinutes,
	})
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	dlElapsed := time.Since(t0)
	debugf("download", "payload=%s", humanBytes(int64(len(payloadData))))
	debugf("download", "elapsed=%s", dlElapsed.Round(time.Millisecond))
	debugf("download", "rate=%s", formatRate(int64(len(payloadData)), dlElapsed))

	// Decrypt. The payload's size and digest are checked against the
	// signed manifest before any chunk is decrypted.
	debugf("decrypt", "algorithm=AES-256-GCM in 1 MiB chunks")
	debugf("decrypt", "payload=%s", humanBytes(int64(len(payloadData))))
	tDec := time.Now()
	plaintext, err := opened.Decrypt(payloadData)
	if err != nil {
		return nil, err
	}
	decElapsed := time.Since(tDec)
	digestHex := hex.EncodeToString(m.PayloadDigest)
	debugf("verify", "payload sha256=%s… matches the signed manifest", digestHex[:12])
	debugf("verify", "every chunk authenticated, in order, ending on the last-chunk flag")
	debugf("decrypt", "plaintext=%s", humanBytes(int64(len(plaintext))))
	debugf("decrypt", "elapsed=%s", decElapsed.Round(time.Millisecond))
	debugf("decrypt", "rate=%s", formatRate(int64(len(plaintext)), decElapsed))

	// Decompress
	if m.Compressed && m.Compression != "" {
		debugf("decompress", "algorithm=%s", m.Compression)
		debugf("decompress", "input=%s", humanBytes(int64(len(plaintext))))
		tDc := time.Now()
		decompressed, err := compress.Decompress(plaintext, compress.Algorithm(m.Compression), nil)
		if err != nil {
			return nil, fmt.Errorf("decompress (%s): %w", m.Compression, err)
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

	result := &DecryptResult{
		RevisionID:           targetRevID,
		SenderFingerprint:    m.SenderFingerprint,
		RecipientFingerprint: localFP,
		Recipients:           signedRecipients(m, rev),
		Compressed:           m.Compressed,
		Compression:          m.Compression,
		PayloadType:          m.PayloadType,
		ProtocolVersion:      m.Version,
		CipherSuite:          m.CipherSuite,
		PayloadDigest:        digestHex,
		EncryptedSize:        int64(len(payloadData)),
	}

	// Unmarshal payload
	var p payload.Payload
	if err := payload.Unmarshal(plaintext, &p); err != nil {
		result.Decrypted = &payload.Decrypted{Type: "raw", Raw: plaintext}
		return result, nil
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

	result.Decrypted = decrypted
	result.PayloadType = p.Type
	return result, nil
}

// signedRecipients lists every recipient fingerprint the sender signed
// for, in manifest order. Emails are the server's labels for those
// fingerprints, from the revision listing, and are empty when the server
// does not name one.
func signedRecipients(m *crypto.Manifest, rev *RevisionInfo) []Recipient {
	emails := make(map[string]string, len(rev.Integrity.Recipients))
	for _, r := range rev.Integrity.Recipients {
		emails[strings.ToLower(r.KeyFingerprint)] = r.Email
	}
	out := make([]Recipient, len(m.Recipients))
	for i, r := range m.Recipients {
		out[i] = Recipient{Email: emails[r.Fingerprint], Fingerprint: r.Fingerprint}
	}
	return out
}

// resolveRevision finds the target revision and pre-validates, before
// anything is downloaded, that the server lists the local fingerprint among
// the revision's recipients. Uses ListRevisions internally.
func (c *Client) resolveRevision(secretID, latestRevID, localFP, requestedRevID string) (*RevisionInfo, error) {
	revisions, err := c.ListRevisions(secretID)
	if err != nil {
		return nil, err
	}
	if len(revisions) == 0 {
		return nil, fmt.Errorf("secret has no revisions")
	}

	targetID := requestedRevID
	if targetID == "" {
		targetID = latestRevID
	}

	var target *RevisionInfo
	for i := range revisions {
		if revisions[i].ID == targetID {
			target = &revisions[i]
			break
		}
	}
	if target == nil {
		if targetID != "" {
			return nil, fmt.Errorf("revision %s not found", targetID)
		}
		// Fallback: pick last revision
		target = &revisions[len(revisions)-1]
	}

	for _, r := range target.Integrity.Recipients {
		if fingerprintMatch(r.KeyFingerprint, localFP) {
			return target, nil
		}
	}
	return nil, fmt.Errorf("revision %s was not encrypted for your key (%s)",
		target.ID, crypto.ShortFingerprint(localFP))
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
