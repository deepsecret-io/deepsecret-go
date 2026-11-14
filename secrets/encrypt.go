// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/identity"
	"github.com/deepsecret-io/deepsecret-go/internal/archive"
	"github.com/deepsecret-io/deepsecret-go/internal/compress"
	"github.com/deepsecret-io/deepsecret-go/internal/directory"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
	"github.com/deepsecret-io/deepsecret-go/internal/payload"
	"github.com/deepsecret-io/deepsecret-go/internal/protocol"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/transfer"
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
//	result, _ := client.Secrets.EncryptText(ctx, []string{"bob@example.com"}, "hello world", secrets.EncryptOptions{})
func (c *Client) EncryptText(ctx context.Context, recipients []string, text string, opt EncryptOptions) (*EncryptResult, error) {

	p := payload.Payload{Type: "message", Message: text}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(ctx, recipients, memPlaintext("message", data, nil), opt)
}

// EncryptData encrypts key-value pairs for one or more recipients and
// uploads them once.
//
//	result, _ := client.Secrets.EncryptData(ctx, []string{"bob@example.com"}, map[string]string{
//	    "DB_PASSWORD": "s3cret",
//	    "API_KEY":     "ak_123",
//	}, secrets.EncryptOptions{})
func (c *Client) EncryptData(ctx context.Context, recipients []string, kvPairs map[string]string, opt EncryptOptions) (*EncryptResult, error) {

	var entries []payload.KeyValuePair
	for k, v := range kvPairs {
		entries = append(entries, payload.KeyValuePair{Key: k, Value: v})
	}
	p := payload.Payload{Type: "data", Entries: entries}
	data, err := payload.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return c.encryptAndSend(ctx, recipients, memPlaintext("data", data, nil), opt)
}

// EncryptBytes encrypts raw binary data for one or more recipients as a
// single-file payload.
//
//	result, _ := client.Secrets.EncryptBytes(ctx, []string{"bob@example.com"}, jsonBytes, secrets.EncryptOptions{})
func (c *Client) EncryptBytes(ctx context.Context, recipients []string, raw []byte, opt EncryptOptions) (*EncryptResult, error) {

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
	meta := []fileMetaEntry{{Name: file.Name, Size: file.Size, SHA256: file.SHA256}}
	return c.encryptAndSend(ctx, recipients, memPlaintext("files", data, meta), opt)
}

// EncryptPaths encrypts a mix of files and directories for one or more
// recipients. Directories are expanded recursively. Supports archive mode
// and auto-archive.
//
//	result, _ := client.Secrets.EncryptPaths(ctx, []string{"bob@example.com"}, []string{
//	    "./src",
//	    "./README.md",
//	}, secrets.EncryptOptions{Archive: true})
func (c *Client) EncryptPaths(ctx context.Context, recipients []string, paths []string, opt EncryptOptions) (*EncryptResult, error) {
	if opt.Name == "" && len(paths) == 1 {
		// One file or folder names the secret, unless it has no name of
		// its own, as "." has not.
		if base := filepath.Base(paths[0]); base != "." && base != string(filepath.Separator) {
			opt.Name = base
		}
	}

	expanded, err := archive.ExpandPaths(paths, opt.SkipHidden)
	if err != nil {
		return nil, err
	}

	archiveOn, archiveReason := shouldArchive(expanded, opt)
	emitArchiveDecision(opt, archiveOn, archiveReason, expanded)
	if archiveOn {
		return c.encryptArchive(ctx, recipients, expanded, opt)
	}
	return c.encryptExpandedFiles(ctx, recipients, expanded, opt)
}

// emitArchiveDecision logs whether the files go into one archive, and
// why, also when they do not, so the decision shows in the log.
func emitArchiveDecision(opt EncryptOptions, archiveOn bool, reason string, expanded []archive.ExpandedFile) {
	log := logattr.Module(logattr.Logger(opt.Logger), "archive")
	regular := regularFiles(expanded)
	if archiveOn {
		log.Debug("archive enabled", "reason", reason, "entries", len(expanded), "regular_files", regular)
	} else {
		log.Debug("archive disabled", "reason", reason, "regular_files", regular)
	}
}

// regularFiles counts the regular files among expanded, without folders
// and links.
func regularFiles(expanded []archive.ExpandedFile) int {
	n := 0
	for _, ef := range expanded {
		if !ef.IsDir && !ef.IsSymlink {
			n++
		}
	}
	return n
}

// ── Internal helpers ─────────────────────────────────────────────────────────

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
//  3. opt.AutoArchive is on AND there are more than autoArchiveFiles
//     regular files: one archive keeps a large tree to one upload and one
//     download, at the cost of the per-file metadata the server would
//     otherwise see.
//
// Notes intentionally NOT triggering archive:
//   - Plain directory entries: the flat path preserves directory structure
//     implicitly via each file's RelPath (e.g. "subdir/file.txt"), so a
//     tree of regular files with subdirectories rides the flat path with
//     full per-file metadata visible to the server.
//   - Empty directories: lost in the flat path. Operators who need them
//     preserved can pass --archive.
//
// The server enforces the tier's file limit on its own: CheckFilesQuota
// rejects a CreateSecret whose files_count exceeds tier.MaxFilesPerSecret,
// whatever the client decided here.
//
// Returns (archive, reason).
func shouldArchive(expanded []archive.ExpandedFile, opt EncryptOptions) (bool, string) {
	if opt.Archive {
		return true, "requested"
	}
	for _, ef := range expanded {
		if ef.IsSymlink {
			return true, fmt.Sprintf("%s is a symbolic link, and only an archive carries link targets", ef.RelPath)
		}
	}
	if !opt.AutoArchive {
		return false, "not requested"
	}
	// Directory entries only place the files: count the regular files.
	n := regularFiles(expanded)
	if n > autoArchiveFiles {
		return true, fmt.Sprintf("%d files: more than %d are sent as one archive", n, autoArchiveFiles)
	}
	if n == 1 {
		return false, fmt.Sprintf("1 file: up to %d are sent without an archive", autoArchiveFiles)
	}
	return false, fmt.Sprintf("%d files: up to %d are sent without an archive", n, autoArchiveFiles)
}

// autoArchiveFiles is the most regular files a send with AutoArchive
// sends one by one; more go in one archive.
const autoArchiveFiles = 50

func (c *Client) encryptExpandedFiles(ctx context.Context, recipients []string, expanded []archive.ExpandedFile, opt EncryptOptions) (*EncryptResult, error) {
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
		info, err := archive.Capture(ef.FullPath)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		if !info.Mode().IsRegular() {
			// A FIFO would block the send, a device would go out empty,
			// and a link could point elsewhere by the time it is read.
			return nil, fmt.Errorf("%s is not a regular file", ef.FullPath)
		}
		if seen[ef.RelPath] {
			return nil, fmt.Errorf("two files would be named %q: a secret's files need distinct names", ef.RelPath)
		}
		seen[ef.RelPath] = true
		srcs = append(srcs, fileSource(ef.RelPath, ef.FullPath, info))
	}
	return c.encryptAndSend(ctx, recipients, filesPlaintext(srcs), opt)
}

// encryptArchive sends the files as one tar archive. The tar inside the
// payload is uncompressed and its headers are captured before any file is
// read (archive.NewTar), so its exact length is known up front, and the
// whole payload is zstd-compressed as it streams. A file that changes
// after the capture fails the send with ErrFileChanged, naming it.
func (c *Client) encryptArchive(ctx context.Context, recipients []string, expanded []archive.ExpandedFile, opt EncryptOptions) (*EncryptResult, error) {
	originalSize, err := preflightExpandedSize(expanded, maxPayloadSize(opt))
	if err != nil {
		return nil, err
	}
	tarball, err := archive.NewTar(expanded)
	if err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}
	tarFile := payload.FileSource{Name: "archive.tar", Size: tarball.Size, Open: func() (io.ReadCloser, error) {
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(tarball.Write(pw, compress.None)) }()
		return pr, nil
	}}
	p := &plaintext{
		payloadType:    "files",
		size:           tarball.Size + 512,
		archived:       true,
		archiveEntries: len(expanded),
		archiveFiles:   regularFiles(expanded),
		originalSize:   originalSize,
	}
	p.write = func(w io.Writer) error {
		_, err := payload.EncodeFiles(w, []payload.FileSource{tarFile}, true, "")
		return err
	}
	return c.encryptAndSend(ctx, recipients, p, opt)
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
	files []fileMetaEntry

	archived       bool
	archiveEntries int   // an archive's entries, folders and links included
	archiveFiles   int   // its regular files
	originalSize   int64 // an archive's files, before tar and compression

	// inMemory payloads are sealed in memory: they are already there,
	// and need no disk.
	inMemory bool
}

// memPlaintext is an encoded payload already in memory.
func memPlaintext(payloadType string, data []byte, files []fileMetaEntry) *plaintext {
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
		p.files = make([]fileMetaEntry, len(srcs))
		for i, s := range srcs {
			p.files[i] = fileMetaEntry{Name: s.Name, Size: s.Size, SHA256: sums[i]}
		}
		return nil
	}
	return p
}

// fileSource reads the file at path, named name in the payload. info is
// the file's capture (archive.Capture): the send fails with ErrFileChanged
// if the file is replaced or its size changes before it is read.
func fileSource(name, path string, info os.FileInfo) payload.FileSource {
	return payload.FileSource{Name: name, Size: info.Size(), Mode: info.Mode(),
		Open: func() (io.ReadCloser, error) { return archive.OpenCaptured(path, info) }}
}

func maxPayloadSize(opt EncryptOptions) int64 {
	if opt.MaxPayloadSize > 0 {
		return opt.MaxPayloadSize
	}
	return defaultMaxPayloadSize
}

// compressionSample is how much of a plaintext decides whether compressing
// it is worth it: it is, when the sample shrinks by at least 5%.
const compressionSample = 8 << 20

var errSampleFull = errors.New("compression sample is full")

// worthCompressing compresses the first compressionSample bytes of p and
// reports whether they shrink by at least 5%. Payloads smaller than the
// sample are decided on all of their bytes. An algorithm that cannot
// compress the sample is an error, not a payload that does not shrink.
func worthCompressing(p *plaintext, algo compress.Algorithm) (bool, error) {
	sample := &sampleWriter{max: compressionSample}
	if err := p.write(sample); err != nil && !errors.Is(err, errSampleFull) {
		return false, fmt.Errorf("read payload: %w", err)
	}
	if len(sample.buf) == 0 {
		return false, nil
	}
	n, err := compress.CompressedSize(sample.buf, algo)
	if err != nil {
		return false, fmt.Errorf("compress: %w", err)
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
// protocol.Seal into dst. It returns the sealed manifest and wraps, and how
// many bytes p wrote before compression. It stops when ctx is done.
func sealPlaintext(ctx context.Context, dst io.Writer, p *plaintext, algo compress.Algorithm, sender *keys.Pair, pubs []*keys.PublicKeys, params protocol.SealParams, onProgress func(done, total int64)) (*protocol.Sealed, int64, error) {
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
	sealed, sealErr := protocol.Seal(bw, ctxReader{ctx, pr}, sender, pubs, params)
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
		if !knownkeys.PlausibleEmail(email) || !strings.Contains(email[strings.LastIndexByte(email, '@'):], ".") {
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
func (c *Client) encryptAndSend(ctx context.Context, recipients []string, p *plaintext, opt EncryptOptions) (*EncryptResult, error) {
	if opt.LocalFile != "" {
		return c.encryptToFile(ctx, recipients, p, opt)
	}
	log := logattr.Logger(opt.Logger)

	// Input validation
	if err := ValidateRecipients(recipients); err != nil {
		return nil, err
	}
	if p.size == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	logPayload(log, p)

	// Enforce payload size limit before expensive operations
	if maxSize := maxPayloadSize(opt); p.size > maxSize {
		return nil, fmt.Errorf("payload size %d exceeds limit %d bytes: reduce input size or increase MaxPayloadSize",
			p.size, maxSize)
	}

	// Resolve actor info (always needed for org_id; also used for tier validation)
	// Single line per phase. "Loading X..." pre-events were noise.
	actorInfo, err := c.senderAccount(ctx, opt)
	if err != nil {
		return nil, err
	}
	if actorInfo.OrgID == "" {
		return nil, fmt.Errorf("no organization found: activate a plan first")
	}
	logattr.Module(log, "auth").Debug("account resolved", "actor_id", actorInfo.ID, "org_id", actorInfo.OrgID, "tier", actorInfo.TierName)

	kp, senderFP, err := c.loadIdentity(ctx, opt.Identity, opt.unlock())
	if err != nil {
		return nil, fmt.Errorf("load sender identity: %w", err)
	}
	logKeyPair(log, senderFP, opt.Identity)

	// Resolve every recipient's actor id and primary keys. The sender is a
	// recipient only when the caller listed them: by one of their accounts
	// this device recorded, the caller's among them, or by an address the
	// server resolves to the caller's account.
	known, err := c.store.RecordOwnAccount(actorInfo.Email, senderFP, false)
	if err != nil {
		return nil, err
	}
	pubs := make([]*keys.PublicKeys, len(recipients))
	actorIDs := make([]string, len(recipients))
	var firstUse []Recipient
	for i, email := range recipients {
		actorID, err := resolveRecipientID(ctx, c.api, email)
		if err != nil {
			return nil, fmt.Errorf("resolve recipient %s: %w", email, err)
		}
		self := knownkeys.OwnAccount(known[strings.ToLower(email)]) || (actorID != "" && actorID == actorInfo.ID)
		pubKeys, first, err := c.recipientKeys(ctx, known, email, self, senderFP)
		if err != nil {
			return nil, err
		}
		pubs[i], actorIDs[i] = pubKeys, actorID
		if first {
			firstUse = append(firstUse, Recipient{Email: email, Fingerprint: pubKeys.Fingerprint})
		}
		logRecipientKeys(log, email, actorID, pubKeys.Fingerprint, self, first)
	}

	algo, err := chooseCompression(p, compress.Algorithm(opt.Compress), log)
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
	defer func() { _ = sp.Close() }()
	logEncryptPlan(log, len(pubs))
	logattr.Module(log, "encrypt").Debug("ciphertext storage", sp.logArgs(spoolNeed(p.size))...)

	opt.phase(transfer.PhaseEncrypting)
	tEnc := time.Now()
	name := secretName(opt)
	sealed, written, err := sealPlaintext(ctx, sp, p, algo, kp, pubs, protocol.SealParams{
		RevisionID:  revisionID,
		SecretName:  name,
		PayloadType: p.payloadType,
		Compressed:  algo != compress.None,
		Compression: string(algo),
	}, opt.OnEncryptProgress)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	logSealed(log, algo, sealed, written, time.Since(tEnc))
	m := sealed.Manifest
	digestHex := hex.EncodeToString(m.PayloadDigest)
	compressionLabel, compressionRatio, originalSize := compressionSummary(p, algo, m, written)

	inputs := make([]recipientInput, len(recipients))
	sentTo := make([]Recipient, len(recipients))
	for i, pub := range pubs {
		w, ok := sealed.Wrap(pub.Fingerprint)
		if !ok {
			return nil, fmt.Errorf("encrypt: no wrap was made for %s", recipients[i]) // #nosec G602 -- pubs holds one key per recipient
		}
		in := recipientInput{
			RecipientID:    actorIDs[i],
			KeyFingerprint: pub.Fingerprint,
			Wrap:           secretWrap{Enc: w.Enc, Ct: w.Ciphertext},
		}
		if actorIDs[i] == actorInfo.ID {
			// The caller's own org is known. For anyone else the server
			// resolves it.
			in.RecipientOrgID = actorInfo.OrgID
		}
		inputs[i] = in
		sentTo[i] = Recipient{Email: recipients[i], Fingerprint: pub.Fingerprint} // #nosec G602 -- pubs holds one key per recipient
	}

	// The server checks the manifest against revision_id, name, size,
	// checksum_sha256 and key_fingerprint, so they are taken from it.
	req := &createRequest{
		OrgID:           actorInfo.OrgID,
		Name:            name,
		RevisionID:      m.RevisionID,
		ChecksumSHA256:  digestHex,
		FilesCount:      len(p.files),
		Size:            m.CiphertextSize,
		Etag:            digestHex[:16],
		KDF:             protocol.KDF,
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

	secretLog := logattr.Module(log, "secret")
	createArgs := []any{"name", req.Name, "revision_id", req.RevisionID, "recipients", len(req.Recipients), "size", logattr.Bytes(req.Size)}
	if p.archived {
		createArgs = append(createArgs, "archived", true)
	} else {
		createArgs = append(createArgs, "files", req.FilesCount)
	}
	createArgs = append(createArgs, "revoke_missing", req.RevokeMissing)
	if req.TTLSeconds > 0 {
		createArgs = append(createArgs, "ttl", time.Duration(req.TTLSeconds)*time.Second)
	}
	if len(req.AllowedIPs) > 0 {
		createArgs = append(createArgs, "allowed_ips", len(req.AllowedIPs))
	}
	// The upload begins with the create call. The server adds a revision
	// to a secret of this name the sender has, or creates the secret with
	// this as its first revision.
	opt.phase(transfer.PhaseUploading)
	secretLog.Debug("creating revision", createArgs...)
	secret, revoked, err := createSecret(ctx, c.api, req)
	if err != nil {
		// A send under an existing name that leaves out people who have
		// access now is refused unless RevokeMissing is set. The server's
		// message names them, so surface it as is.
		var apiErr *apierror.Error
		if errors.Is(err, apierror.ErrConflict) && errors.As(err, &apiErr) && apiErr.Message != "" {
			return nil, fmt.Errorf("send refused (%w): %s", apierror.ErrConflict, apiErr.Message)
		}
		return nil, err
	}
	if secret.RevisionNumber > 1 {
		secretLog.Info("revision added", "secret_id", secret.ID, "revision_id", revisionID, "revision", secret.RevisionNumber, "multipart", secret.IsMultipart)
	} else {
		secretLog.Info("secret created", "secret_id", secret.ID, "revision_id", revisionID, "multipart", secret.IsMultipart)
	}
	for _, r := range revoked {
		secretLog.Info("access revoked", "secret_id", secret.ID, "actor_id", r.ID, "email", r.Email)
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
		// The multipart upload logs its plan, and its completion once the
		// server has assembled the parts.
		if err := c.api.MultipartUploadOpts(ctx, revisionID, sp, size, transport.MultipartUploadOptions{
			Threads:    opt.UploadThreads,
			OnProgress: opt.OnUploadProgress,
			Logger:     opt.Logger,
			Status:     opt.UploadStatus.transport(),
		}); err != nil {
			return nil, uploadFailed(sp, pending, err)
		}
	} else {
		transport.LogSinglePutPlan(log, size, opt.PresignExpiryMinutes)
		tUp := time.Now()
		if err := c.api.PresignUploadFrom(ctx, actorInfo.OrgID, revisionID, sp, size, opt.OnUploadProgress, opt.PresignExpiryMinutes, opt.UploadStatus.transport()); err != nil {
			return nil, fmt.Errorf("upload: %w", err)
		}

		// Confirm the upload so the server checks the stored object's size
		// and marks the revision downloadable: until then a download of it
		// is refused.
		if err := c.api.ConfirmUpload(ctx, revisionID); err != nil {
			return nil, fmt.Errorf("confirm upload: %w", err)
		}
		upElapsed := time.Since(tUp)
		logattr.Module(log, "upload").Info("upload complete", "size", logattr.Bytes(size), "parts", 1, "sent", logattr.Bytes(size),
			"elapsed", upElapsed.Round(time.Millisecond), "rate", logattr.RateOf(size, upElapsed))
	}

	// Sent: the keys new to this device that it went to are accepted now.
	if err := c.store.RecordFirstUse(firstUsePeople(firstUse), false); err != nil {
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
		result.ArchiveEntryCount, result.ArchiveFileCount = p.archiveEntries, p.archiveFiles
	}
	return result, nil
}

// loadIdentity loads the local key pair with the fingerprint (or prefix)
// fp, or the primary identity registered on the server when fp is empty,
// unlocking it once with u, and returns it with its full fingerprint.
func (c *Client) loadIdentity(ctx context.Context, fp string, u keystore.Unlock) (*keys.Pair, string, error) {
	if fp == "" {
		return c.identity.LoadPrimary(ctx, u)
	}
	kp, err := keystore.Open(ctx, c.keys(), fp, u)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", keys.ShortFingerprint(fp), err)
	}
	full, err := keys.Fingerprint(kp)
	if err != nil {
		return nil, "", fmt.Errorf("compute fingerprint: %w", err)
	}
	return kp, full, nil
}

// recipientKeys fetches a recipient's primary public keys, verified against
// their fingerprint and both self-signatures. When the recipient is the
// sender (self), the keys must also be a key pair on this device, the
// sending identity senderFP or another: see checkOwnKeys.
// Anyone else's must pass checkKey against known, what this device knows
// on the server; a key new to it is reported as first, for recordFirstUse
// once the send succeeds.
func (c *Client) recipientKeys(ctx context.Context, known map[string][]knownkeys.Entry, email string, self bool, senderFP string) (pubKeys *keys.PublicKeys, first bool, err error) {
	if pubKeys, err = directory.GetRecipientKeys(ctx, c.api, email); err != nil {
		return nil, false, fmt.Errorf("resolve recipient %s: %w", email, err)
	}
	if self {
		err = checkOwnKeys(c.keys(), pubKeys, senderFP)
		if err != nil && knownkeys.OwnAccount(known[strings.ToLower(email)]) {
			err = fmt.Errorf("%w (%s is recorded as your own account on this device; if it is not yours, forget it)", err, email)
		}
	} else {
		first, err = knownkeys.CheckKey(known, strings.ToLower(email), pubKeys.Fingerprint, false)
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolve recipient %s: %w", email, err)
	}
	return pubKeys, first, nil
}

// senderAccount is the sender's account: the one the caller gave, or else
// the server's answer now.
func (c *Client) senderAccount(ctx context.Context, opt EncryptOptions) (*identity.Actor, error) {
	if opt.Account != nil {
		return opt.Account, nil
	}
	a, err := c.identity.WhoAmI(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch actor info: %w", err)
	}
	return a, nil
}

// secretName is the name a send goes under: opt.Name without surrounding
// white space, as the API stores it, or "sdk-" and the Unix time. The
// manifest signs it, so it is chosen before sealing.
func secretName(opt EncryptOptions) string {
	if name := strings.TrimSpace(opt.Name); name != "" {
		return name
	}
	return fmt.Sprintf("sdk-%d", time.Now().Unix())
}

// chooseCompression picks how p is compressed, and logs why. An archive is
// always zstd-compressed: the tar inside it is not. Other payloads are
// compressed with want when it is set and a sample of them shrinks by at
// least 5%.
func chooseCompression(p *plaintext, want compress.Algorithm, log *slog.Logger) (compress.Algorithm, error) {
	log = logattr.Module(log, "compress")
	switch {
	case p.archived:
		log.Debug("compression enabled", "algorithm", compress.Zstd, "reason", "an archive is always compressed")
		return compress.Zstd, nil
	case want == "" || want == compress.None:
		log.Debug("compression disabled", "reason", "not requested")
		return compress.None, nil
	}
	worth, err := worthCompressing(p, want)
	if err != nil {
		return "", err
	}
	if !worth {
		log.Debug("compression disabled", "requested", want, "reason", "a sample of the payload did not shrink by 5%")
		return compress.None, nil
	}
	log.Debug("compression enabled", "algorithm", want, "reason", "a sample of the payload shrank by at least 5%")
	return want, nil
}

// compressionSummary describes a sealed payload's compression: its label
// ("tar+zstd", "zstd" or ""), the compressed size as a percentage of the
// original, and the original size. written is what p wrote before
// compression.
func compressionSummary(p *plaintext, algo compress.Algorithm, m *protocol.Manifest, written int64) (string, float64, int64) {
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
