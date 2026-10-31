// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
//
// Files and directories stream: each file is read once, encoded, compressed
// and sealed chunk by chunk into a private temporary file holding only
// ciphertext, which is then uploaded. Memory stays flat whatever the size;
// the temporary file needs free disk space for the encrypted payload (see
// EncryptOptions.TempDir). Text, key-value data and in-memory bytes are
// small and are encoded in memory.

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
	return c.encryptAndSend(recipients, memPlaintext("message", data, nil), opt)
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
	return c.encryptAndSend(recipients, memPlaintext("data", data, nil), opt)
}

// EncryptFile encrypts a single file for one or more recipients and
// uploads it once. The file streams from disk.
//
//	result, _ := client.EncryptFile([]string{"bob@example.com"}, "./report.pdf", sdk.EncryptOptions{})
func (c *Client) EncryptFile(recipients []string, filePath string, opt EncryptOptions) (*EncryptResult, error) {

	if opt.Name == "" {
		opt.Name = filepath.Base(filePath)
	}
	return c.EncryptFiles(recipients, []string{filePath}, opt)
}

// EncryptFiles encrypts multiple files for one or more recipients and
// uploads them once. Each file is named by its base name and streams from
// disk.
//
//	result, _ := client.EncryptFiles([]string{"bob@example.com"}, []string{
//	    "./report.pdf",
//	    "./data.csv",
//	}, sdk.EncryptOptions{})
func (c *Client) EncryptFiles(recipients []string, filePaths []string, opt EncryptOptions) (*EncryptResult, error) {

	if _, err := preflightFileSize(filePaths, maxPayloadSize(opt)); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(filePaths))
	srcs := make([]payload.FileSource, len(filePaths))
	for i, fp := range filePaths {
		info, err := os.Stat(fp)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", fp, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", fp)
		}
		name := filepath.Base(fp)
		if seen[name] {
			return nil, fmt.Errorf("two files are named %q: a secret's files need distinct names", name)
		}
		seen[name] = true
		srcs[i] = fileSource(name, fp, info)
	}
	return c.encryptAndSend(recipients, filesPlaintext(srcs), opt)
}

// EncryptBytes encrypts raw binary data for one or more recipients as a
// single-file payload.
//
//	result, _ := client.EncryptBytes([]string{"bob@example.com"}, jsonBytes, sdk.EncryptOptions{})
func (c *Client) EncryptBytes(recipients []string, raw []byte, opt EncryptOptions) (*EncryptResult, error) {

	h := sha256.Sum256(raw)
	file := payload.FileEntry{
		Name:   "data.bin",
		Data:   raw,
		Size:   int64(len(raw)),
		SHA256: hex.EncodeToString(h[:]),
		Mode:   0644,
	}
	data, err := payload.Marshal(payload.Payload{Type: "files", Files: []payload.FileEntry{file}})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	meta := []secrets.FileMetaEntry{{Name: file.Name, Size: file.Size, SHA256: file.SHA256}}
	return c.encryptAndSend(recipients, memPlaintext("files", data, meta), opt)
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
	if _, err := preflightExpandedSize(expanded, maxPayloadSize(opt)); err != nil {
		return nil, err
	}

	var srcs []payload.FileSource
	seen := make(map[string]bool, len(expanded))
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
		info, err := os.Stat(ef.FullPath)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		if seen[ef.RelPath] {
			return nil, fmt.Errorf("two files would be named %q: a secret's files need distinct names", ef.RelPath)
		}
		seen[ef.RelPath] = true
		srcs = append(srcs, fileSource(ef.RelPath, ef.FullPath, info))
	}
	return c.encryptAndSend(recipients, filesPlaintext(srcs), opt)
}

// encryptArchive sends the files as one tar archive. The tar inside the
// payload is uncompressed, so its exact length is known before any file is
// read (archive.TarSize), and the whole payload is zstd-compressed as it
// streams.
func (c *Client) encryptArchive(recipients []string, expanded []archive.ExpandedFile, opt EncryptOptions) (*EncryptResult, error) {
	originalSize, err := preflightExpandedSize(expanded, maxPayloadSize(opt))
	if err != nil {
		return nil, err
	}
	tarSize, err := archive.TarSize(expanded)
	if err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}
	tarFile := payload.FileSource{Name: "archive.tar", Size: tarSize, Open: func() (io.ReadCloser, error) {
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(archive.WriteTar(pw, expanded, compress.None)) }()
		return pr, nil
	}}
	p := &plaintext{
		payloadType:    "files",
		size:           tarSize + 512,
		archived:       true,
		archiveEntries: len(expanded),
		originalSize:   originalSize,
	}
	p.write = func(w io.Writer) error {
		_, err := payload.EncodeFiles(w, []payload.FileSource{tarFile}, true, "")
		return err
	}
	return c.encryptAndSend(recipients, p, opt)
}

// plaintext is what a send seals: a payload written as a stream, and what
// the create call says about it.
type plaintext struct {
	payloadType string
	size        int64 // the bytes write produces before compression, or a close estimate
	write       func(w io.Writer) error

	// files are listed in files_meta. For streamed files they are set when
	// write completes, since their SHA-256 is computed as they stream. An
	// archive lists none.
	files []secrets.FileMetaEntry

	archived       bool
	archiveEntries int
	originalSize   int64 // an archive's files, before tar and compression

	// inMemory payloads are sealed in memory: they are already there,
	// and need no disk.
	inMemory bool
}

// memPlaintext is an encoded payload already in memory.
func memPlaintext(payloadType string, data []byte, files []secrets.FileMetaEntry) *plaintext {
	return &plaintext{payloadType: payloadType, size: int64(len(data)), files: files, inMemory: true,
		write: func(w io.Writer) error {
			_, err := w.Write(data)
			return err
		}}
}

// filesPlaintext streams files into a files payload.
func filesPlaintext(srcs []payload.FileSource) *plaintext {
	p := &plaintext{payloadType: "files", size: 64}
	for _, s := range srcs {
		p.size += s.Size + int64(len(s.Name)) + 128
	}
	p.write = func(w io.Writer) error {
		sums, err := payload.EncodeFiles(w, srcs, false, "")
		if err != nil {
			return err
		}
		p.files = make([]secrets.FileMetaEntry, len(srcs))
		for i, s := range srcs {
			p.files[i] = secrets.FileMetaEntry{Name: s.Name, Size: s.Size, SHA256: sums[i]}
		}
		return nil
	}
	return p
}

// fileSource reads the file at path, named name in the payload. info is
// the file's stat: the send fails if the file's size changes before it is
// read.
func fileSource(name, path string, info os.FileInfo) payload.FileSource {
	return payload.FileSource{Name: name, Size: info.Size(), Mode: info.Mode(),
		Open: func() (io.ReadCloser, error) { return os.Open(path) }} // #nosec G304 -- a file the caller chose to send.
}

func maxPayloadSize(opt EncryptOptions) int64 {
	if opt.MaxPayloadSize > 0 {
		return opt.MaxPayloadSize
	}
	return DefaultMaxPayloadSize
}

// compressionSample is how much of a plaintext decides whether compressing
// it is worth it: it is, when the sample shrinks by at least 5%.
const compressionSample = 8 << 20

var errSampleFull = errors.New("compression sample is full")

// worthCompressing compresses the first compressionSample bytes of p and
// reports whether they shrink by at least 5%. Payloads smaller than the
// sample are decided on all of their bytes.
func worthCompressing(p *plaintext, algo compress.Algorithm) (bool, error) {
	sample := &sampleWriter{max: compressionSample}
	if err := p.write(sample); err != nil && !errors.Is(err, errSampleFull) {
		return false, err
	}
	if len(sample.buf) == 0 {
		return false, nil
	}
	n, err := compress.CompressedSize(sample.buf, algo)
	if err != nil {
		return false, nil
	}
	return n <= int64(len(sample.buf))*95/100, nil
}

// sampleWriter keeps the first max bytes written to it, then refuses more.
type sampleWriter struct {
	buf []byte
	max int
}

func (s *sampleWriter) Write(p []byte) (int, error) {
	room := s.max - len(s.buf)
	if len(p) <= room {
		s.buf = append(s.buf, p...)
		return len(p), nil
	}
	s.buf = append(s.buf, p[:room]...)
	return room, errSampleFull
}

// countingWriter counts what passes through it.
type countingWriter struct {
	w  io.Writer
	n  int64
	on func(n int64) // optional: the count after each write
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if c.on != nil {
		c.on(c.n)
	}
	return n, err
}

// sealPlaintext writes p, compressed with algo unless it is None, through
// crypto.Seal into dst. It returns the sealed manifest and wraps, and how
// many bytes p wrote before compression. It stops when ctx is done.
func sealPlaintext(ctx context.Context, dst io.Writer, p *plaintext, algo compress.Algorithm, sender *crypto.KeyPair, pubs []*crypto.PublicKeys, params crypto.SealParams, onProgress func(done, total int64)) (*crypto.Sealed, int64, error) {
	pr, pw := io.Pipe()
	var written int64
	done := make(chan error, 1)
	go func() {
		err := func() error {
			var zw io.WriteCloser = nopCloser{pw}
			if algo != compress.None {
				w, err := compress.NewCompressWriterFor(pw, algo, p.size)
				if err != nil {
					return err
				}
				zw = w
			}
			cw := &countingWriter{w: zw}
			if onProgress != nil {
				cw.on = func(n int64) { onProgress(n, max(p.size, n)) }
			}
			if err := p.write(cw); err != nil {
				_ = zw.Close() // the write already failed and its error is returned; the sealed output is discarded.
				return err
			}
			written = cw.n
			if onProgress != nil {
				// p.size may be an estimate: the end is what was written.
				onProgress(written, written)
			}
			return zw.Close()
		}()
		pw.CloseWithError(err)
		done <- err
	}()

	bw := bufio.NewWriterSize(dst, 1<<20)
	sealed, sealErr := crypto.Seal(bw, ctxReader{ctx, pr}, sender, pubs, params)
	// Unblocks the writer when Seal stopped early.
	_ = pr.Close() // io.PipeReader.Close always returns nil.
	writeErr := <-done
	if writeErr != nil && !errors.Is(writeErr, io.ErrClosedPipe) {
		return nil, 0, writeErr
	}
	if sealErr != nil {
		return nil, 0, sealErr
	}
	if err := bw.Flush(); err != nil {
		return nil, 0, fmt.Errorf("write payload: %w", err)
	}
	return sealed, written, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

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
		// It goes into API paths and onto screens, so nothing that could
		// change a path or a terminal passes: see plausibleEmail.
		if !plausibleEmail(email) || !strings.Contains(email[strings.LastIndexByte(email, '@'):], ".") {
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
// v4) and sends it in one create call, one upload and one confirm. The
// ciphertext goes to a private temporary file, and the upload reads it from
// there.
func (c *Client) encryptAndSend(recipients []string, p *plaintext, opt EncryptOptions) (*EncryptResult, error) {
	if opt.LocalFile != "" {
		return c.encryptToFile(recipients, p, opt)
	}
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
	if p.size == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	debugf("encrypt", "payload type=%s", p.payloadType)
	debugf("encrypt", "plaintext size=%s", humanBytes(p.size))
	if p.archived {
		debugf("encrypt", "archived=true")
	}

	// Enforce payload size limit before expensive operations
	if maxSize := maxPayloadSize(opt); p.size > maxSize {
		return nil, fmt.Errorf("payload size %d exceeds limit %d bytes: reduce input size or increase MaxPayloadSize",
			p.size, maxSize)
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

	kp, senderFP, err := c.loadIdentity(opt.Identity, opt.Password)
	if err != nil {
		return nil, fmt.Errorf("load sender identity: %w", err)
	}
	debugf("identity", "sender fingerprint=%s", crypto.ShortFingerprint(senderFP))
	debugf("verify", "sender identity loaded (X25519+Ed25519, ML-KEM-768+ML-DSA-65)")

	// Resolve every recipient's actor id and primary keys. The sender is a
	// recipient only when the caller listed them: by one of their accounts
	// this device recorded, the caller's among them, or by an address the
	// server resolves to the caller's account.
	known, err := c.recordOwnAccount(actorInfo.Email, senderFP, false)
	if err != nil {
		return nil, err
	}
	pubs := make([]*crypto.PublicKeys, len(recipients))
	actorIDs := make([]string, len(recipients))
	var firstUse []Recipient
	for i, email := range recipients {
		actorID, err := identity.ResolveRecipientID(c.api, email)
		if err != nil {
			return nil, fmt.Errorf("resolve recipient %s: %w", email, err)
		}
		self := ownAccount(known[strings.ToLower(email)]) || (actorID != "" && actorID == actorInfo.ID)
		keys, first, err := c.recipientKeys(known, email, self, senderFP)
		if err != nil {
			return nil, err
		}
		pubs[i], actorIDs[i] = keys, actorID
		if first {
			firstUse = append(firstUse, Recipient{Email: email, Fingerprint: keys.Fingerprint})
		}
		debugf("recipient", "email=%s fingerprint=%s actor_id=%s",
			sanitizeForLog(email), crypto.ShortFingerprint(keys.Fingerprint), actorID)
		debugf("verify", "recipient %s: %s", sanitizeForLog(email), recipientKeyNote(keys.Fingerprint, self, first))
	}
	debugf("verify", "recipient key bundles from the server (%d): fingerprint and both self-signatures checked; not proof the keys are the recipient's (compare fingerprints with them)", len(recipients))

	algo, err := chooseCompression(p, opt.Compress, debugf)
	if err != nil {
		return nil, err
	}

	// Seal once: one payload, a fresh content key, a wrap per recipient and
	// the signed manifest. The revision id is bound into all of them, so it
	// is chosen here, before the create call.
	revisionID := uuid.New().String()
	sp := newMemSpool(0)
	if !p.inMemory {
		if sp, err = newSendSpool(opt, revisionID, spoolNeed(p.size)); err != nil {
			return nil, err
		}
	}
	defer sp.Close()
	debugf("plan", "encryption: %s", encryptionPlan(len(pubs)))
	debugf("plan", "ciphertext: %s", sp.plan(spoolNeed(p.size)))

	tEnc := time.Now()
	sealed, written, err := sealPlaintext(c.api.Context(), sp, p, algo, kp, pubs, crypto.SealParams{
		RevisionID:  revisionID,
		PayloadType: p.payloadType,
		Compressed:  algo != compress.None,
		Compression: string(algo),
	}, opt.OnEncryptProgress)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	encElapsed := time.Since(tEnc)
	m := sealed.Manifest
	digestHex := hex.EncodeToString(m.PayloadDigest)
	compressionLabel, compressionRatio, originalSize := compressionSummary(p, algo, m, written)
	if algo != compress.None && written > 0 {
		debugf("compress", "ratio=%.1f%%", float64(m.PlaintextSize)/float64(written)*100)
	}
	debugf("encrypt", "input=%s", humanBytes(written))
	debugf("encrypt", "payload=%s", humanBytes(m.CiphertextSize))
	debugf("encrypt", "manifest=%s", humanBytes(int64(len(sealed.ManifestData))))
	debugf("encrypt", "elapsed=%s", encElapsed.Round(time.Millisecond))
	debugf("encrypt", "rate=%s", formatRate(written, encElapsed))
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
		FilesCount:      len(p.files),
		Size:            m.CiphertextSize,
		Etag:            digestHex[:16],
		KDF:             crypto.KDF,
		ProtocolVersion: m.Version,
		CipherSuite:     m.CipherSuite,
		PayloadType:     p.payloadType,
		KeyFingerprint:  m.SenderFingerprint,
		Manifest:        sealed.ManifestData,
		Recipients:      inputs,
		RevokeMissing:   opt.RevokeMissing,
		FilesMeta:       p.files,
	}

	if compressionLabel != "" {
		req.Compressed = true
		req.Compression = compressionLabel
		req.CompressionRatio = compressionRatio
		req.OriginalSize = originalSize
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
	if p.archived {
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
	// the /multipart/* endpoints. Both read the ciphertext from the
	// temporary file.
	size := m.CiphertextSize
	if secret.IsMultipart {
		pending, err := c.startUpload(sp, secret, revisionID, size)
		if err != nil {
			return nil, err
		}
		tUp := time.Now()
		if err := c.api.MultipartUploadOpts(revisionID, sp, size, api.MultipartUploadOptions{
			Threads:    opt.UploadThreads,
			OnProgress: opt.OnUploadProgress,
			OnDebug:    opt.OnDebug,
			Status:     opt.UploadStatus,
		}); err != nil {
			return nil, uploadFailed(sp, pending, err)
		}
		upElapsed := time.Since(tUp)
		debugf("upload", "elapsed=%s", upElapsed.Round(time.Millisecond))
		debugf("upload", "rate=%s", formatRate(size, upElapsed))
		debugf("verify", "server completed multipart upload (HEAD-verified size)")
	} else {
		debugf("plan", "upload: %s", api.SinglePutPlan(size, opt.PresignExpiryMinutes))
		tUp := time.Now()
		if err := c.api.PresignUploadFrom(actorInfo.OrgID, revisionID, sp, size, opt.OnUploadProgress, opt.PresignExpiryMinutes, opt.UploadStatus); err != nil {
			return nil, fmt.Errorf("upload: %w", err)
		}
		upElapsed := time.Since(tUp)
		debugf("upload", "elapsed=%s", upElapsed.Round(time.Millisecond))
		debugf("upload", "rate=%s", formatRate(size, upElapsed))

		// Confirm the upload so the backend HEAD-verifies size/etag and marks
		// the revision downloadable. Without this, downloads fall back to
		// on-demand verification at extra latency.
		debugf("confirm", "POST /secrets/revisions/%s/confirm", revisionID)
		if err := c.api.ConfirmUpload(revisionID); err != nil {
			return nil, fmt.Errorf("confirm upload: %w", err)
		}
		debugf("verify", "server confirmed upload (HEAD-verified size and etag)")
	}

	// Sent: the keys new to this device that it went to are accepted now.
	if err := c.recordFirstUse(firstUse, false); err != nil {
		return nil, fmt.Errorf("secret %s was sent, but recording its recipients' keys on this device failed: %w", secret.ID, err)
	}

	result := &EncryptResult{
		Secret:            *secret,
		EncryptedSize:     size,
		SenderFingerprint: senderFP,
		Recipients:        sentTo,
		FirstUse:          firstUse,
		Revoked:           revoked,
		Compressed:        compressionLabel != "",
		Compression:       compressionLabel,
		CompressionRatio:  compressionRatio,
		OriginalSize:      originalSize,
		PayloadType:       p.payloadType,
		FilesCount:        len(p.files),
		Archived:          p.archived,
	}
	if p.archived {
		result.ArchiveEntryCount = p.archiveEntries
	}
	return result, nil
}

// loadIdentity loads the local key pair with the fingerprint (or prefix)
// fp, or the primary identity registered on the server when fp is empty,
// and returns it with its full fingerprint.
func (c *Client) loadIdentity(fp, password string) (*crypto.KeyPair, string, error) {
	if fp == "" {
		return identity.LoadPrimaryIdentity(c.api, password)
	}
	kp, err := crypto.LoadKeyPair(fp, password)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", crypto.ShortFingerprint(fp), err)
	}
	full, err := crypto.Fingerprint(kp)
	if err != nil {
		return nil, "", fmt.Errorf("compute fingerprint: %w", err)
	}
	return kp, full, nil
}

// recipientKeys fetches a recipient's primary public keys, verified against
// their fingerprint and both self-signatures. When the recipient is the
// sender (self), the keys must also be a key pair on this device, the
// sending identity senderFP or another: see identity.CheckOwnKeys.
// Anyone else's must pass checkKey against known, what this device knows
// on the server; a key new to it is reported as first, for recordFirstUse
// once the send succeeds.
func (c *Client) recipientKeys(known map[string][]knownKeyDisk, email string, self bool, senderFP string) (keys *crypto.PublicKeys, first bool, err error) {
	if keys, err = identity.GetRecipientKeys(c.api, email); err != nil {
		return nil, false, fmt.Errorf("resolve recipient %s: %w", email, err)
	}
	if self {
		err = identity.CheckOwnKeys(keys, senderFP)
		if err != nil && ownAccount(known[strings.ToLower(email)]) {
			err = fmt.Errorf("%w (%s is recorded as your own account on this device; if it is not yours, forget it)", err, email)
		}
	} else {
		first, err = checkKey(known, strings.ToLower(email), keys.Fingerprint, false)
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolve recipient %s: %w", email, err)
	}
	return keys, first, nil
}

// recipientKeyNote says, for the debug log, why a recipient's key fp was
// trusted.
func recipientKeyNote(fp string, self, first bool) string {
	switch {
	case self:
		return fmt.Sprintf("you: key %s is on this device", crypto.ShortFingerprint(fp))
	case first:
		return fmt.Sprintf("key %s is new to this device: accepted on first use once the send succeeds (compare fingerprints with them)", crypto.ShortFingerprint(fp))
	}
	return fmt.Sprintf("key %s is the one this device accepted for them", crypto.ShortFingerprint(fp))
}

// chooseCompression picks how p is compressed. An archive is always
// zstd-compressed: the tar inside it is not. Other payloads are compressed
// with want when it is set and a sample of them shrinks by at least 5%.
func chooseCompression(p *plaintext, want compress.Algorithm, debugf func(step, format string, args ...any)) (compress.Algorithm, error) {
	switch {
	case p.archived:
		debugf("plan", "compression: zstd (an archive is always compressed)")
		return compress.Zstd, nil
	case want == "" || want == compress.None:
		debugf("plan", "compression: none (not requested)")
		return compress.None, nil
	}
	worth, err := worthCompressing(p, want)
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}
	if !worth {
		debugf("plan", "compression: none (a sample of the payload did not shrink by 5%%)")
		return compress.None, nil
	}
	debugf("plan", "compression: %s (a sample of the payload shrank by at least 5%%)", want)
	return want, nil
}

// encryptionPlan describes how a payload is sealed for n recipients.
func encryptionPlan(n int) string {
	return fmt.Sprintf("AES-256-GCM in %s chunks under a fresh content key, wrapped for %d recipient%s with HPKE (X25519 + ML-KEM-768); manifest signed with Ed25519 + ML-DSA-65",
		humanBytes(crypto.ChunkSize), n, pluralSuffix(n))
}

// compressionSummary describes a sealed payload's compression: its label
// ("tar+zstd", "zstd" or ""), the compressed size as a percentage of the
// original, and the original size. written is what p wrote before
// compression.
func compressionSummary(p *plaintext, algo compress.Algorithm, m *crypto.Manifest, written int64) (string, float64, int64) {
	switch {
	case p.archived:
		ratio := 0.0
		if p.originalSize > 0 {
			ratio = float64(m.PlaintextSize) / float64(p.originalSize) * 100
		}
		return "tar+zstd", ratio, p.originalSize
	case algo != compress.None:
		ratio := 0.0
		if written > 0 {
			ratio = float64(m.PlaintextSize) / float64(written) * 100
		}
		return string(algo), ratio, written
	}
	return "", 0, written
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
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 || n > 1_000_000 || numStr[0] == '+' {
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
