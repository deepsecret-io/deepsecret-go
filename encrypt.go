// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/archive"
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
	"github.com/deepsecret-io/sdk/payload"
	"github.com/deepsecret-io/sdk/secrets"
)

// ── High-level Encrypt Functions ─────────────────────────────────────────────

// EncryptText encrypts a text message for one or more recipients and
// uploads it once.
//
//	result, _ := client.EncryptText([]string{"bob@example.com"}, "hello world", sdk.EncryptOptions{})
func (c *Client) EncryptText(recipients []string, text string, opt EncryptOptions) (*EncryptResult, error) {

	p := payload.Payload{Type: "message", Message: text}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "message", nil, false, opt)
}

// EncryptData encrypts key-value pairs for one or more recipients and
// uploads them once.
//
//	result, _ := client.EncryptData([]string{"bob@example.com"}, map[string]string{
//	    "DB_PASSWORD": "s3cret",
//	    "API_KEY":     "ak_123",
//	}, sdk.EncryptOptions{})
func (c *Client) EncryptData(recipients []string, kvPairs map[string]string, opt EncryptOptions) (*EncryptResult, error) {

	var entries []payload.KeyValuePair
	for k, v := range kvPairs {
		entries = append(entries, payload.KeyValuePair{Key: k, Value: v})
	}
	p := payload.Payload{Type: "data", Entries: entries}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "data", nil, false, opt)
}

// EncryptFile encrypts a single file for one or more recipients and
// uploads it once.
//
//	result, _ := client.EncryptFile([]string{"bob@example.com"}, "./report.pdf", sdk.EncryptOptions{})
func (c *Client) EncryptFile(recipients []string, filePath string, opt EncryptOptions) (*EncryptResult, error) {

	if opt.Name == "" {
		opt.Name = filepath.Base(filePath)
	}

	maxSize := opt.MaxPayloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxPayloadSize
	}
	if _, err := preflightFileSize([]string{filePath}, maxSize); err != nil {
		return nil, err
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	h := sha256.Sum256(content)
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	files := []payload.FileEntry{{
		Name:   filepath.Base(filePath),
		Data:   content,
		Size:   info.Size(),
		SHA256: hex.EncodeToString(h[:]),
		Mode:   info.Mode(),
	}}

	p := payload.Payload{Type: "files", Files: files}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "files", files, false, opt)
}

// EncryptFiles encrypts multiple files for one or more recipients and
// uploads them once.
//
//	result, _ := client.EncryptFiles([]string{"bob@example.com"}, []string{
//	    "./report.pdf",
//	    "./data.csv",
//	}, sdk.EncryptOptions{})
func (c *Client) EncryptFiles(recipients []string, filePaths []string, opt EncryptOptions) (*EncryptResult, error) {

	maxSize := opt.MaxPayloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxPayloadSize
	}
	if _, err := preflightFileSize(filePaths, maxSize); err != nil {
		return nil, err
	}

	var files []payload.FileEntry
	for _, fp := range filePaths {
		content, err := os.ReadFile(fp)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fp, err)
		}
		h := sha256.Sum256(content)
		info, err := os.Stat(fp)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", fp, err)
		}
		files = append(files, payload.FileEntry{
			Name:   filepath.Base(fp),
			Data:   content,
			Size:   info.Size(),
			SHA256: hex.EncodeToString(h[:]),
			Mode:   info.Mode(),
		})
	}

	p := payload.Payload{Type: "files", Files: files}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "files", files, false, opt)
}

// EncryptBytes encrypts raw binary data for one or more recipients as a
// single-file payload.
//
//	result, _ := client.EncryptBytes([]string{"bob@example.com"}, jsonBytes, sdk.EncryptOptions{})
func (c *Client) EncryptBytes(recipients []string, raw []byte, opt EncryptOptions) (*EncryptResult, error) {

	h := sha256.Sum256(raw)
	files := []payload.FileEntry{{
		Name:   "data.bin",
		Data:   raw,
		Size:   int64(len(raw)),
		SHA256: hex.EncodeToString(h[:]),
		Mode:   0644,
	}}
	p := payload.Payload{Type: "files", Files: files}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "files", files, false, opt)
}

// EncryptDir encrypts all files in a directory (recursively) for one or
// more recipients.
//
//	result, _ := client.EncryptDir([]string{"bob@example.com"}, "./project", sdk.EncryptOptions{
//	    Archive:    true,
//	    Compress:   compress.Zstd,
//	    SkipHidden: true,
//	})
func (c *Client) EncryptDir(recipients []string, dirPath string, opt EncryptOptions) (*EncryptResult, error) {

	if opt.Name == "" {
		opt.Name = filepath.Base(dirPath)
	}

	expanded, err := archive.ExpandPaths([]string{dirPath}, opt.SkipHidden)
	if err != nil {
		return nil, err
	}

	archiveOn, archiveReason, err := c.shouldArchive(expanded, opt)
	if err != nil {
		return nil, err
	}
	emitArchiveDecision(opt, archiveOn, archiveReason, expanded)
	if archiveOn {
		return c.encryptArchive(recipients, expanded, opt)
	}
	return c.encryptExpandedFiles(recipients, expanded, opt)
}

// EncryptPaths encrypts a mix of files and directories for one or more
// recipients. Directories are expanded recursively. Supports archive mode
// and auto-archive.
//
//	result, _ := client.EncryptPaths([]string{"bob@example.com"}, []string{
//	    "./src",
//	    "./README.md",
//	}, sdk.EncryptOptions{Archive: true})
func (c *Client) EncryptPaths(recipients []string, paths []string, opt EncryptOptions) (*EncryptResult, error) {

	expanded, err := archive.ExpandPaths(paths, opt.SkipHidden)
	if err != nil {
		return nil, err
	}

	archiveOn, archiveReason, err := c.shouldArchive(expanded, opt)
	if err != nil {
		return nil, err
	}
	emitArchiveDecision(opt, archiveOn, archiveReason, expanded)
	if archiveOn {
		return c.encryptArchive(recipients, expanded, opt)
	}
	return c.encryptExpandedFiles(recipients, expanded, opt)
}

// emitArchiveDecision logs the archive-mode decision through the OnDebug
// callback. Always emits, even when archive is off, so the user can see
// the decision was considered. The reason string is empty when archive is
// off; we synthesize a "flat path" message in that case.
func emitArchiveDecision(opt EncryptOptions, archiveOn bool, reason string, expanded []archive.ExpandedFile) {
	if opt.OnDebug == nil {
		return
	}
	regular := 0
	for _, ef := range expanded {
		if !ef.IsDir && !ef.IsSymlink {
			regular++
		}
	}
	if archiveOn {
		opt.OnDebug("archive", fmt.Sprintf("enabled: %s (entries=%d, regular_files=%d)", reason, len(expanded), regular))
	} else {
		opt.OnDebug("archive", fmt.Sprintf("disabled: flat per-file payload (regular_files=%d)", regular))
	}
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// preflightFileSize stats all files and returns total size. Returns an error if
// the projected size exceeds the limit, before any file contents are read.
func preflightFileSize(paths []string, limit int64) (int64, error) {
	var total int64
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return 0, fmt.Errorf("stat %s: %w", p, err)
		}
		total += info.Size()
		if limit > 0 && total > limit {
			return total, fmt.Errorf("projected size %d bytes exceeds limit %d bytes: reduce input or increase MaxPayloadSize", total, limit)
		}
	}
	return total, nil
}

// preflightExpandedSize stats all expanded files and returns total size.
// Uses Lstat so dangling symlinks don't error out the whole encrypt; only
// regular files contribute to the size budget.
func preflightExpandedSize(expanded []archive.ExpandedFile, limit int64) (int64, error) {
	var total int64
	for _, ef := range expanded {
		if ef.IsDir || ef.IsSymlink {
			continue
		}
		info, err := os.Lstat(ef.FullPath)
		if err != nil {
			return 0, fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		total += info.Size()
		if limit > 0 && total > limit {
			return total, fmt.Errorf("projected size %d bytes exceeds limit %d bytes: reduce input or increase MaxPayloadSize", total, limit)
		}
	}
	return total, nil
}

// shouldArchive determines whether files should be archived and returns the
// human-readable reason for the decision (used in debug logs to make the
// behavior transparent).
//
// Triggers (intentionally narrow):
//  1. opt.Archive (or its --hide-metadata alias): manually requested.
//  2. Any expanded entry is a SYMLINK: the flat per-file payload format
//     has no encoding for link targets, so a tree containing symlinks
//     can only round-trip through tar.
//  3. opt.AutoArchive is on AND the total file count exceeds the org's
//     tier MaxFilesPerSecret: auto-bundling lets users send larger
//     trees within their tier, at the cost of per-file metadata privacy.
//
// Notes intentionally NOT triggering archive:
//   - Plain directory entries: the flat path preserves directory structure
//     implicitly via each file's RelPath (e.g. "subdir/file.txt"), so a
//     tree of regular files with subdirectories rides the flat path with
//     full per-file metadata visible to the server.
//   - Empty directories: lost in the flat path. Operators who need them
//     preserved can pass --archive.
//
// Server-side tier enforcement still applies: CheckFilesQuota rejects any
// CreateSecret request whose declared files_count exceeds tier.MaxFilesPerSecret.
// A modified client that skips auto-archive and submits an over-tier file
// count is rejected at the API boundary.
//
// Returns (archive, reason, err). reason is "" when archive=false.
func (c *Client) shouldArchive(expanded []archive.ExpandedFile, opt EncryptOptions) (bool, string, error) {
	if opt.Archive {
		return true, "manual --archive / --hide-metadata flag", nil
	}
	for _, ef := range expanded {
		if ef.IsSymlink {
			return true, fmt.Sprintf("symlink detected in tree (%s); flat payload cannot encode link targets", ef.RelPath), nil
		}
	}
	if !opt.AutoArchive {
		return false, "", nil
	}
	info, err := identity.WhoAmI(c.api)
	if err != nil {
		return false, "", fmt.Errorf("fetch tier info: %w", err)
	}
	// Phase 5 removed per-tier limits from /api/me (the spec keeps the
	// authz state on actors, billing-display on subscriptions). The
	// SDK no longer mirrors max_files_per_secret client-side; the
	// server CreateSecret handler enforces the cap. Use a generous
	// default for the auto-archive heuristic so legitimate large
	// directories still trip auto-archive without an extra fetch.
	_ = info
	maxFiles := 50
	// Count only regular file entries against the tier cap; directory
	// entries are structural placeholders, not files the server would
	// charge.
	regularCount := 0
	for _, ef := range expanded {
		if !ef.IsDir {
			regularCount++
		}
	}
	if regularCount > maxFiles {
		return true, fmt.Sprintf("file count %d exceeds tier limit %d (auto-archive)", regularCount, maxFiles), nil
	}
	return false, "", nil
}

func (c *Client) encryptExpandedFiles(recipients []string, expanded []archive.ExpandedFile, opt EncryptOptions) (*EncryptResult, error) {
	maxSize := opt.MaxPayloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxPayloadSize
	}
	if _, err := preflightExpandedSize(expanded, maxSize); err != nil {
		return nil, err
	}

	var files []payload.FileEntry
	for _, ef := range expanded {
		// Skip directory entries: they have no byte content; the flat
		// payload preserves tree structure implicitly via each file's
		// RelPath (e.g. "subdir/file.txt"). Empty directories are lost on
		// this path; users who need them preserved should pass --archive.
		// Symlinks should never reach this path because shouldArchive
		// forces archive mode for any symlink-bearing tree.
		if ef.IsDir || ef.IsSymlink {
			continue
		}
		content, err := os.ReadFile(ef.FullPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", ef.FullPath, err)
		}
		h := sha256.Sum256(content)
		info, err := os.Stat(ef.FullPath)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		files = append(files, payload.FileEntry{
			Name:   ef.RelPath,
			Data:   content,
			Size:   info.Size(),
			SHA256: hex.EncodeToString(h[:]),
			Mode:   info.Mode(),
		})
	}

	p := payload.Payload{Type: "files", Files: files}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(recipients, data, "files", files, false, opt)
}

func (c *Client) encryptArchive(recipients []string, expanded []archive.ExpandedFile, opt EncryptOptions) (*EncryptResult, error) {
	algo := opt.Compress
	if algo == "" {
		algo = compress.Zstd
	}

	// Calculate original uncompressed total size from source files. Use
	// Lstat so dangling symlinks don't fail; skip non-regular entries
	// (dirs, symlinks); only file content contributes to the budget.
	var originalFilesSize int64
	for _, f := range expanded {
		if f.IsDir || f.IsSymlink {
			continue
		}
		info, err := os.Lstat(f.FullPath)
		if err == nil && info.Mode().IsRegular() {
			originalFilesSize += info.Size()
		}
	}

	archiveData, err := archive.CreateTar(expanded, algo)
	if err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}

	archiveName := "archive.tar"
	switch algo {
	case compress.Zstd:
		archiveName = "archive.tar.zst"
	}

	h := sha256.Sum256(archiveData)
	archiveFile := payload.FileEntry{
		Name:   archiveName,
		Data:   archiveData,
		Size:   int64(len(archiveData)),
		SHA256: hex.EncodeToString(h[:]),
	}

	p := payload.Payload{
		Type:               "files",
		Files:              []payload.FileEntry{archiveFile},
		Archive:            true,
		ArchiveCompression: string(algo),
	}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	// Pass archive sizes to encryptAndSend for accurate server metadata
	opt.archiveOriginalSize = originalFilesSize
	opt.archiveCompressedSize = int64(len(archiveData))

	result, err := c.encryptAndSend(recipients, data, "files", nil, true, opt)
	if err != nil {
		return nil, err
	}
	result.Archived = true
	result.ArchiveEntryCount = len(expanded)
	result.FilesCount = 0

	// Override result with correct archive compression metrics
	if originalFilesSize > 0 {
		result.OriginalSize = originalFilesSize
		result.CompressionRatio = float64(len(archiveData)) / float64(originalFilesSize) * 100
	}

	return result, nil
}

// ValidateRecipients checks a send's recipient list before any network
// call: 1 to MaxRecipientsPerSend plausible emails, none listed twice
// (compared case-insensitively). The sender is a recipient only when the
// list names them.
func ValidateRecipients(emails []string) error {
	if len(emails) == 0 {
		return fmt.Errorf("at least one recipient is required")
	}
	if len(emails) > MaxRecipientsPerSend {
		return fmt.Errorf("a send can have at most %d recipients, got %d", MaxRecipientsPerSend, len(emails))
	}
	seen := make(map[string]bool, len(emails))
	for _, email := range emails {
		if email == "" {
			return fmt.Errorf("recipient email is required")
		}
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			return fmt.Errorf("invalid recipient email %q", email)
		}
		key := strings.ToLower(email)
		if seen[key] {
			return fmt.Errorf("recipient %q is listed twice", email)
		}
		seen[key] = true
	}
	return nil
}

// encryptAndSend seals the plaintext once for every recipient (protocol
// v4) and sends it in one create call, one upload and one confirm.
func (c *Client) encryptAndSend(recipients []string, plaintext []byte, payloadType string, files []payload.FileEntry, archived bool, opt EncryptOptions) (*EncryptResult, error) {
	debugf := func(step, format string, args ...any) {
		if opt.OnDebug == nil {
			return
		}
		opt.OnDebug(step, fmt.Sprintf(format, args...))
	}

	// Input validation
	if err := ValidateRecipients(recipients); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	debugf("encrypt", "payload type=%s", payloadType)
	debugf("encrypt", "plaintext size=%s", humanBytes(int64(len(plaintext))))
	if archived {
		debugf("encrypt", "archived=true")
	} else if len(files) > 0 {
		debugf("encrypt", "files=%d", len(files))
	}

	// Enforce payload size limit before expensive operations
	maxSize := opt.MaxPayloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxPayloadSize
	}
	if int64(len(plaintext)) > maxSize {
		return nil, fmt.Errorf("payload size %d exceeds limit %d bytes: reduce input size or increase MaxPayloadSize",
			len(plaintext), maxSize)
	}

	// Resolve actor info (always needed for org_id; also used for tier validation)
	// Single line per phase. "Loading X..." pre-events were noise.
	actorInfo, err := identity.WhoAmI(c.api)
	if err != nil {
		return nil, fmt.Errorf("fetch actor info: %w", err)
	}
	if actorInfo.OrgID == "" {
		return nil, fmt.Errorf("no organization found: activate a plan first")
	}
	debugf("actor", "org=%s", actorInfo.OrgID)
	debugf("actor", "tier=%s", actorInfo.TierName)

	// Phase 5 removed per-tier limits from /api/me. The backend
	// authoritatively enforces max payload size, TTL policy, and IP
	// lock policy in CreateSecret + UpdatePolicies; the SDK no longer
	// duplicates the rules client-side. opt.ValidateTier is retained
	// in the API surface for source compatibility but is now a no-op:
	// any policy violation surfaces as an HTTP error from the server.
	_ = opt.ValidateTier

	var kp *crypto.KeyPair
	var senderFP string
	if opt.Identity != "" {
		// Loaded line below carries the actual fingerprint.
		kp, err = crypto.LoadKeyPair(opt.Identity, opt.Password)
		if err != nil {
			return nil, fmt.Errorf("load sender identity %s: %w", crypto.ShortFingerprint(opt.Identity), err)
		}
		senderFP, err = crypto.Fingerprint(kp)
		if err != nil {
			return nil, fmt.Errorf("compute fingerprint: %w", err)
		}
	} else {
		// Loaded line below carries the actual fingerprint.
		kp, senderFP, err = identity.LoadPrimaryIdentity(c.api, opt.Password)
		if err != nil {
			return nil, fmt.Errorf("load sender identity: %w", err)
		}
	}
	debugf("identity", "sender fingerprint=%s", crypto.ShortFingerprint(senderFP))
	debugf("verify", "sender identity loaded (X25519+Ed25519, ML-KEM-768+ML-DSA-65)")

	// Resolve every recipient's primary keys and actor id. The sender is a
	// recipient only when the caller listed them.
	pubs := make([]*crypto.PublicKeys, len(recipients))
	actorIDs := make([]string, len(recipients))
	for i, email := range recipients {
		keys, err := identity.GetRecipientKeys(c.api, email)
		if err != nil {
			return nil, fmt.Errorf("resolve recipient %s: %w", email, err)
		}
		if keys.Fingerprint == "" {
			if keys.Fingerprint, err = crypto.FingerprintFromPubs(keys.ED25519, keys.X25519, keys.MLKEM768, keys.MLDSA65); err != nil {
				return nil, fmt.Errorf("resolve recipient %s: compute fingerprint: %w", email, err)
			}
		}
		actorID, err := identity.ResolveRecipientID(c.api, email)
		if err != nil {
			return nil, fmt.Errorf("resolve recipient %s: %w", email, err)
		}
		pubs[i], actorIDs[i] = keys, actorID
		debugf("recipient", "email=%s fingerprint=%s actor_id=%s",
			sanitizeForLog(email), crypto.ShortFingerprint(keys.Fingerprint), actorID)
	}
	debugf("verify", "recipient public keys resolved from server (%d)", len(recipients))

	// Optionally compress plaintext.
	//
	// When `archived` is true the plaintext already wraps a tar.zst blob
	// (compression done inside encryptArchive). A second outer zstd pass
	// over already-compressed bytes saves single-digit KiB at best while
	// burning CPU and adding a redundant frame header, so skip it. The
	// archive's own compression metrics are reported by encryptArchive
	// and overridden onto the result there.
	compressed := false
	compressionLabel := ""
	originalSize := int64(len(plaintext))
	compressionRatio := 0.0
	switch {
	case archived:
		debugf("compress", "skipped (payload is already a tar.zst archive)")
	case opt.Compress != "" && opt.Compress != compress.None:
		debugf("compress", "algorithm=%s", opt.Compress)
		debugf("compress", "input=%s", humanBytes(int64(len(plaintext))))
		tCmp := time.Now()
		zcompressed, cerr := compress.Compress(plaintext, opt.Compress)
		cmpElapsed := time.Since(tCmp)
		if cerr == nil && len(zcompressed) < len(plaintext) {
			compressionRatio = float64(len(zcompressed)) / float64(len(plaintext)) * 100
			plaintext = zcompressed
			compressed = true
			compressionLabel = string(opt.Compress)
			debugf("compress", "output=%s", humanBytes(int64(len(plaintext))))
			debugf("compress", "ratio=%.1f%%", compressionRatio)
			debugf("compress", "saved=%s", humanBytes(originalSize-int64(len(plaintext))))
			debugf("compress", "elapsed=%s", cmpElapsed.Round(time.Millisecond))
			debugf("compress", "rate=%s", formatRate(originalSize, cmpElapsed))
		} else if cerr != nil {
			debugf("compress", "skipped: %v", cerr)
		} else {
			debugf("compress", "skipped (compressed size >= original)")
		}
	}

	// Seal once: one payload, a fresh content key, a wrap per recipient and
	// the signed manifest. The revision id is bound into all of them, so it
	// is chosen here, before the create call.
	revisionID := uuid.New().String()
	tEnc := time.Now()
	payloadData, sealed, err := crypto.SealBytes(plaintext, kp, pubs, crypto.SealParams{
		RevisionID:  revisionID,
		PayloadType: payloadType,
		Compressed:  compressed,
		Compression: compressionLabel,
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	encElapsed := time.Since(tEnc)
	m := sealed.Manifest
	digestHex := hex.EncodeToString(m.PayloadDigest)
	debugf("encrypt", "input=%s", humanBytes(int64(len(plaintext))))
	debugf("encrypt", "payload=%s", humanBytes(int64(len(payloadData))))
	debugf("encrypt", "manifest=%s", humanBytes(int64(len(sealed.ManifestData))))
	debugf("encrypt", "elapsed=%s", encElapsed.Round(time.Millisecond))
	debugf("encrypt", "rate=%s", formatRate(int64(len(plaintext)), encElapsed))
	debugf("verify", "content key=fresh per revision, wrapped for %d recipient%s", len(sealed.Wraps), pluralSuffix(len(sealed.Wraps)))
	debugf("verify", "key encapsulation=HPKE (X25519 + ML-KEM-768), fresh context per wrap")
	debugf("verify", "payload cipher=AES-256-GCM in 1 MiB chunks (AEAD)")
	debugf("verify", "signing=Ed25519 + ML-DSA-65 over the manifest (hybrid post-quantum)")
	debugf("verify", "manifest binds the payload digest and every recipient's wrap")
	debugf("verify", "payload sha256=%s…", digestHex[:12])

	inputs := make([]secrets.RecipientInput, len(recipients))
	sentTo := make([]Recipient, len(recipients))
	for i, pub := range pubs {
		w, ok := sealed.Wrap(pub.Fingerprint)
		if !ok {
			return nil, fmt.Errorf("encrypt: no wrap was made for %s", recipients[i])
		}
		in := secrets.RecipientInput{
			RecipientID:    actorIDs[i],
			KeyFingerprint: pub.Fingerprint,
			Wrap:           secrets.Wrap{Enc: w.Enc, Ct: w.Ciphertext},
		}
		if actorIDs[i] == actorInfo.ID {
			// The caller's own org is known. For anyone else the server
			// resolves it.
			in.RecipientOrgID = actorInfo.OrgID
		}
		inputs[i] = in
		sentTo[i] = Recipient{Email: recipients[i], Fingerprint: pub.Fingerprint}
	}

	name := opt.Name
	if name == "" {
		name = fmt.Sprintf("sdk-%d", time.Now().Unix())
	}

	// The server checks the manifest against revision_id, size,
	// checksum_sha256 and key_fingerprint, so they are taken from it.
	req := &secrets.CreateRequest{
		OrgID:           actorInfo.OrgID,
		Name:            name,
		RevisionID:      m.RevisionID,
		ChecksumSHA256:  digestHex,
		FilesCount:      len(files),
		Size:            m.CiphertextSize,
		Etag:            digestHex[:16],
		KDF:             crypto.KDF,
		ProtocolVersion: m.Version,
		CipherSuite:     m.CipherSuite,
		PayloadType:     payloadType,
		KeyFingerprint:  m.SenderFingerprint,
		Manifest:        sealed.ManifestData,
		Recipients:      inputs,
		RevokeMissing:   opt.RevokeMissing,
	}

	if len(files) > 0 {
		for _, f := range files {
			req.FilesMeta = append(req.FilesMeta, secrets.FileMetaEntry{
				Name: f.Name, Size: f.Size, SHA256: f.SHA256,
			})
		}
	}

	if compressed {
		req.Compressed = true
		req.Compression = compressionLabel
		req.CompressionRatio = compressionRatio
		req.OriginalSize = originalSize
	}

	// For archives, set accurate compression metadata from encryptArchive.
	if archived {
		req.Compressed = true
		req.Compression = "tar+zstd"
		if opt.archiveOriginalSize > 0 {
			req.OriginalSize = opt.archiveOriginalSize
			req.CompressionRatio = float64(opt.archiveCompressedSize) / float64(opt.archiveOriginalSize) * 100
		}
	}

	if opt.TTL != "" {
		ttlSecs, err := parseTTL(opt.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL %q: %w", opt.TTL, err)
		}
		req.TTLSeconds = ttlSecs
	}
	if len(opt.IPs) > 0 {
		req.AllowedIPs = opt.IPs
	}

	debugf("create", "POST /secrets")
	debugf("create", "name=%q", sanitizeForLog(req.Name))
	debugf("create", "recipients=%d", len(req.Recipients))
	debugf("create", "payload size=%s", humanBytes(req.Size))
	if archived {
		debugf("create", "files=archived")
	} else {
		debugf("create", "files=%d", req.FilesCount)
	}
	if opt.RevokeMissing {
		debugf("create", "revoke_missing=true")
	}
	if opt.TTL != "" {
		debugf("policy", "ttl=%s", sanitizeForLog(opt.TTL))
	}
	if len(opt.IPs) > 0 {
		debugf("policy", "ip_lock=%d entries", len(opt.IPs))
	}
	secret, revoked, err := secrets.Create(c.api, req)
	if err != nil {
		// A send under an existing name that leaves out people who have
		// access now is refused unless RevokeMissing is set. The server's
		// message names them, so surface it as is.
		var apiErr *api.APIError
		if errors.Is(err, api.ErrConflict) && errors.As(err, &apiErr) && apiErr.Message != "" {
			return nil, fmt.Errorf("send refused (%w): %s", api.ErrConflict, apiErr.Message)
		}
		return nil, err
	}
	debugf("create", "secret_id=%s", secret.ID)
	debugf("create", "revision_id=%s", revisionID)
	for _, r := range revoked {
		debugf("create", "revoked=%s", sanitizeForLog(r.Email))
	}

	// Upload AFTER the revision record exists so the backend's presign flow
	// can verify ownership + reject overwrites (S3 IfNoneMatch: *).
	//
	// The server decides which transport flow applies based on the revision's
	// declared Size at create time. When secret.IsMultipart is true, the
	// single-PUT presign endpoint is rejected with 409, so we MUST go through
	// the /multipart/* endpoints. The high-level MultipartUpload helper does
	// init + parallel-PUT-with-retry + register + complete, and is resumable
	// (on retry it queries /multipart/status and skips already-uploaded parts
	// whose SHA256 matches the local data).
	if secret.IsMultipart {
		expectedParts := int64(len(payloadData)) / secret.MultipartPartSize
		if int64(len(payloadData))%secret.MultipartPartSize != 0 {
			expectedParts++
		}
		// The server flips IsMultipart when the declared revision Size is
		// at or above its MultipartThresholdBytes config (default 10 MiB).
		// We don't get the exact threshold back, but we know it's the
		// reason the server picked this path; surface that explicitly so
		// the user understands "why multipart".
		debugf("upload", "mode=multipart")
		debugf("upload", "payload=%s", humanBytes(int64(len(payloadData))))
		debugf("upload", "parts=%d", expectedParts)
		debugf("upload", "part_size=%s", humanBytes(secret.MultipartPartSize))
		tUp := time.Now()
		if err := c.api.MultipartUploadOpts(revisionID, payloadData, api.MultipartUploadOptions{
			Threads:    opt.UploadThreads,
			OnProgress: opt.OnUploadProgress,
			OnDebug:    opt.OnDebug,
		}); err != nil {
			return nil, fmt.Errorf("multipart upload: %w", err)
		}
		upElapsed := time.Since(tUp)
		debugf("upload", "elapsed=%s", upElapsed.Round(time.Millisecond))
		debugf("upload", "rate=%s", formatRate(int64(len(payloadData)), upElapsed))
		debugf("verify", "server completed multipart upload (HEAD-verified size)")
	} else {
		debugf("upload", "mode=single-PUT")
		debugf("upload", "payload=%s", humanBytes(int64(len(payloadData))))
		tUp := time.Now()
		if opt.OnUploadProgress != nil {
			if err := c.api.PresignUploadWithProgress(actorInfo.OrgID, revisionID, payloadData, opt.OnUploadProgress, opt.PresignExpiryMinutes); err != nil {
				return nil, fmt.Errorf("upload: %w", err)
			}
		} else {
			if err := c.api.PresignUpload(actorInfo.OrgID, revisionID, payloadData, opt.PresignExpiryMinutes); err != nil {
				return nil, fmt.Errorf("upload: %w", err)
			}
		}
		upElapsed := time.Since(tUp)
		debugf("upload", "elapsed=%s", upElapsed.Round(time.Millisecond))
		debugf("upload", "rate=%s", formatRate(int64(len(payloadData)), upElapsed))

		// Confirm the upload so the backend HEAD-verifies size/etag and marks
		// the revision downloadable. Without this, downloads fall back to
		// on-demand verification at extra latency.
		debugf("confirm", "POST /secrets/revisions/%s/confirm", revisionID)
		if err := c.api.ConfirmUpload(revisionID); err != nil {
			return nil, fmt.Errorf("confirm upload: %w", err)
		}
		debugf("verify", "server confirmed upload (HEAD-verified size and etag)")
	}

	serverCompression := compressionLabel
	if archived {
		serverCompression = "tar+zstd"
	}

	return &EncryptResult{
		Secret:            *secret,
		EncryptedSize:     int64(len(payloadData)),
		SenderFingerprint: senderFP,
		Recipients:        sentTo,
		Revoked:           revoked,
		Compressed:        compressed || archived,
		Compression:       serverCompression,
		CompressionRatio:  compressionRatio,
		OriginalSize:      originalSize,
		PayloadType:       payloadType,
		FilesCount:        len(files),
		Archived:          archived,
	}, nil
}

// pluralSuffix returns "s" when n != 1.
func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// parseTTL parses a TTL string into seconds. Only accepts:
//   - "Nm" (minutes, e.g. "30m")
//   - "Nh" (hours, e.g. "24h")
//   - "Nd" (days, e.g. "7d")
func parseTTL(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid TTL format %q (use e.g. \"30m\", \"24h\", \"7d\")", s)
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var n int
	if _, err := fmt.Sscanf(numStr, "%d", &n); err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid TTL %q: number must be a positive integer", s)
	}

	switch unit {
	case 'm':
		return n * 60, nil
	case 'h':
		return n * 3600, nil
	case 'd':
		return n * 86400, nil
	default:
		return 0, fmt.Errorf("invalid TTL unit %q in %q (use 'm' for minutes, 'h' for hours, 'd' for days)", string(unit), s)
	}
}
