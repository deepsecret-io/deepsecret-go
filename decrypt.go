// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/internal/archive"
	"github.com/deepsecret-io/sdk/internal/compress"
	"github.com/deepsecret-io/sdk/internal/payload"
	"github.com/deepsecret-io/sdk/internal/protocol"
	"github.com/deepsecret-io/sdk/internal/transport"
)

// ── Decrypting ───────────────────────────────────────────────────────────────
//
// OpenSecret downloads a revision's ciphertext into a private temporary
// file and opens the caller's wrap. From there:
//
//   - WriteFiles writes a files payload to disk in constant memory, whatever
//     its size. It decrypts the verified ciphertext once to check every
//     file, then again to write them, so nothing is written unless the
//     whole payload checks out.
//   - Payload decodes a payload in memory, for messages, key-value data and
//     files up to DefaultMaxInMemorySize.
//
// Every decrypt checks the ciphertext against the signed manifest's digest
// before releasing any plaintext (protocol v4 §6).

// DecryptSecret downloads and decrypts a secret in memory, returning
// full metadata. It fetches revisions, checks that the revision was sealed
// for your key, and includes the verified manifest's metadata
// (fingerprints, recipients, protocol version, cipher suite, payload
// digest) in the result. A payload stored larger than
// DefaultMaxInMemorySize is refused: write it to disk with DecryptToDir.
func (c *Client) DecryptSecret(ctx context.Context, secretID string, opt DecryptOptions) (*DecryptResult, error) {
	c = c.with(ctx)
	o, err := c.openSecret(secretID, opt, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = o.Close() }()
	d, err := o.Payload()
	if err != nil {
		return nil, err
	}
	result := o.Result
	result.Decrypted = d
	return &result, nil
}

// DecryptToDir downloads a files secret and writes its files, or extracts
// its archive, into dir, in constant memory. See OpenedSecret.WriteFiles.
func (c *Client) DecryptToDir(ctx context.Context, secretID, dir string, opt DecryptOptions, w WriteOptions) (*DecryptResult, *WriteResult, error) {
	c = c.with(ctx)
	// Check the destination before downloading, as WriteFiles will again
	// with the payload's own names.
	before := opt.BeforeDownload
	opt.BeforeDownload = func(p UpcomingDownload) error {
		if p.PayloadType == "files" {
			if err := CheckDestination(dir, p.Files, w.Overwrite); err != nil {
				return err
			}
		}
		if before != nil {
			return before(p)
		}
		return nil
	}
	o, err := c.OpenSecret(c.api.Context(), secretID, opt)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = o.Close() }()
	written, err := o.WriteFiles(dir, w)
	if err != nil {
		return nil, nil, err
	}
	result := o.Result
	return &result, written, nil
}

// OpenedSecret is a revision whose ciphertext is downloaded and whose wrap
// is opened, ready to decrypt. Call Close when done: it removes the
// temporary ciphertext and clears the payload key.
type OpenedSecret struct {
	// Result is the verified manifest's metadata. Its Decrypted is nil.
	Result DecryptResult

	opened     *protocol.Opened
	spool      *spool
	journal    *downloadJournal // records a kept download's ranges; nil otherwise
	ctx        context.Context
	log        *slog.Logger
	onProgress func(stage DecryptStage, done, total int64) // optional

	// recordSender records the sender's key, new to this device, once a
	// decrypt succeeds (Result.SenderFirstUse); nil when there is nothing
	// to record or it is done.
	recordSender func() error
	// recordNewest records the revision's signing time as the newest of
	// its secret once a decrypt succeeds; nil for a local file or when it
	// is done.
	recordNewest func() error
}

// decrypted records, once a decrypt succeeded, the sender's key it relied
// on as new to this device and the revision's signing time.
func (o *OpenedSecret) decrypted() error {
	if o.recordSender != nil {
		if err := o.recordSender(); err != nil {
			return fmt.Errorf("recording the sender's key on this device failed: %w", err)
		}
		o.recordSender = nil
	}
	if o.recordNewest != nil {
		if err := o.recordNewest(); err != nil {
			return fmt.Errorf("recording the revision's signing time on this device failed: %w", err)
		}
		o.recordNewest = nil
	}
	return nil
}

// DecryptStage names a pass over the downloaded ciphertext. Payload makes
// one pass; WriteFiles checks the whole payload before it writes anything,
// so it makes two, and three for an archive.
type DecryptStage string

const (
	// DecryptDecrypting is Payload's pass, decrypting in memory.
	DecryptDecrypting DecryptStage = "decrypting"
	// DecryptChecking is WriteFiles' first pass: the payload's structure,
	// names, sizes and every file's SHA-256, writing nothing.
	DecryptChecking DecryptStage = "checking"
	// DecryptCheckingArchive checks an archive's entries.
	DecryptCheckingArchive DecryptStage = "checking the archive"
	// DecryptWriting writes the files.
	DecryptWriting DecryptStage = "writing"
)

// smallPayloadSize is the largest stored payload OpenSecret keeps in
// memory rather than in a temporary file.
const smallPayloadSize = 4 << 20

// OpenSecret opens one revision as protocol v4 §6 orders it: fetch the
// manifest and the caller's wrap, verify the manifest and open the wrap,
// and download the payload into a private temporary file, or into memory
// when it is at most 4 MiB. The payload's digest is checked against the
// manifest by every decrypt, before any plaintext is released.
func (c *Client) OpenSecret(ctx context.Context, secretID string, opt DecryptOptions) (*OpenedSecret, error) {
	c = c.with(ctx)
	return c.openSecret(secretID, opt, false)
}

// openSecret is OpenSecret; inMemory keeps the payload in memory whatever
// its size, refusing one over DefaultMaxInMemorySize before downloading.
func (c *Client) openSecret(secretID string, opt DecryptOptions, inMemory bool) (*OpenedSecret, error) {
	if secretID == "" {
		return nil, fmt.Errorf("secret ID is required")
	}

	log := api.Logger(opt.Logger)
	secretLog := api.Module(log, "secret")

	var secretInfo *SecretInfo
	var revisions []RevisionInfo // nil: resolveRevision fetches them
	if d := opt.Secret; d != nil {
		if !strings.EqualFold(d.Secret.ID, secretID) {
			return nil, fmt.Errorf("the secret given is %s, not the one to open, %s", d.Secret.ID, secretID)
		}
		secretInfo, revisions = &d.Secret, d.Revisions
	} else {
		var err error
		if secretInfo, err = c.DescribeSecret(c.api.Context(), secretID); err != nil {
			return nil, fmt.Errorf("fetch secret: %w", err)
		}
	}
	secretLog.Debug("secret fetched", "secret_id", secretInfo.ID, "name", secretInfo.Name, "latest_revision_id", secretInfo.LatestRevisionID, "sender_id", secretInfo.SenderID)

	// Load recipient identity (explicit fingerprint or server-registered primary)
	kp, localFP, err := c.loadIdentity(opt.Identity, opt.unlock())
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	logKeyPair(log, localFP, opt.Identity)

	// Resolve target revision and pre-validate fingerprint
	rev, err := c.resolveRevision(secretID, secretInfo.LatestRevisionID, localFP, opt.Revision, revisions)
	if err != nil {
		return nil, err
	}
	targetRevID := rev.ID
	source := "latest"
	if opt.Revision != "" {
		source = "requested"
	}
	secretLog.Debug("revision chosen", "revision_id", targetRevID, "source", source, "recipients", len(rev.Integrity.Recipients))

	// Fetch the signed manifest and the caller's own wrap.
	rm, err := getManifest(c.api, targetRevID)
	if err != nil {
		return nil, err
	}
	if !fingerprintMatch(rm.KeyFingerprint, localFP) {
		return nil, fmt.Errorf("your wrap for this revision was made for key %s, not the key in use (%s)",
			crypto.ShortFingerprint(rm.KeyFingerprint), crypto.ShortFingerprint(localFP))
	}
	wrap := &protocol.Wrap{RecipientFingerprint: localFP, Enc: rm.Wrap.Enc, Ciphertext: rm.Wrap.Ct}

	// Resolve the sender's Ed25519 key from the identity service by the
	// manifest's sender fingerprint, so Open cross-checks the embedded key
	// against it. The manifest is parsed here for that fingerprint only;
	// Open verifies it in full.
	peek, err := protocol.UnmarshalManifest(rm.Manifest)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	senderEmail, err := resolveActorEmail(c.api, secretInfo.SenderID)
	if err != nil {
		return nil, fmt.Errorf("resolve sender key: %w", err)
	}
	// The server names the sender: hold its email to the rule local files
	// follow, so a lookalike with spaces or controls cannot dodge the pins.
	if !plausibleEmail(senderEmail) {
		return nil, fmt.Errorf("the server gave an invalid sender email %q", senderEmail)
	}
	senderED25519, err := resolveED25519ByEmail(c.api, senderEmail, peek.SenderFingerprint)
	if err != nil {
		return nil, fmt.Errorf("resolve sender key: %w", err)
	}

	// The manifest must be signed for this secret's name, so a revision of
	// another secret from the same sender is refused. The server names the
	// secret too, so Result carries the signed name to show.
	opened, err := protocol.Open(rm.Manifest, wrap, kp, protocol.OpenParams{
		RevisionID:    targetRevID,
		SecretName:    secretInfo.Name,
		SenderED25519: senderED25519,
	})
	if err != nil {
		return nil, err
	}
	m := opened.Manifest
	logManifestVerified(log, m, len(rm.Manifest))
	senderFirst, err := c.checkSenderKey(senderEmail, m.SenderFingerprint, log)
	if err != nil {
		opened.Close()
		return nil, fmt.Errorf("check sender %s: %w", senderEmail, err)
	}
	// The server picks the latest revision: one signed before a revision
	// of this secret already opened here is refused as a rollback.
	if opt.Revision == "" {
		if err := c.checkNewest(senderEmail, m); err != nil {
			opened.Close()
			return nil, err
		}
	}

	maxSize := opt.MaxDownloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxDownloadSize
	}
	if m.CiphertextSize > maxSize {
		opened.Close()
		return nil, fmt.Errorf("the payload is %s, over the %s download limit (set MaxDownloadSize to allow it)",
			humanBytes(m.CiphertextSize), humanBytes(maxSize))
	}
	if inMemory && m.CiphertextSize > DefaultMaxInMemorySize {
		opened.Close()
		return nil, fmt.Errorf("the payload is %s, too large to decrypt in memory: write it to disk with DecryptToDir or WriteFiles",
			humanBytes(m.CiphertextSize))
	}
	if opt.BeforeDownload != nil {
		pending := UpcomingDownload{RevisionID: targetRevID, PayloadType: m.PayloadType, Size: m.CiphertextSize, Files: rev.FilesMeta}
		if err := opt.BeforeDownload(pending); err != nil {
			opened.Close()
			return nil, err
		}
	}
	var sp *spool
	var journal *downloadJournal // a download kept under ResumeDir
	switch {
	case inMemory || m.CiphertextSize <= smallPayloadSize:
		sp = newMemSpool(m.CiphertextSize)
	case opt.ResumeDir != "":
		var rec *PendingDownload
		if sp, rec, err = c.openDownloadSpool(opt.ResumeDir, secretInfo, m, log); err != nil {
			opened.Close()
			return nil, err
		}
		journal = newDownloadJournal(sp.file, rec)
	default:
		if sp, err = newSpool(opt.TempDir, spoolNeed(m.CiphertextSize)); err != nil {
			opened.Close()
			return nil, err
		}
	}
	o := &OpenedSecret{opened: opened, spool: sp, ctx: c.api.Context(), log: log, onProgress: opt.OnDecryptProgress,
		recordSender: c.senderRecorder(senderEmail, m.SenderFingerprint, senderFirst),
		recordNewest: c.newestRecorder(senderEmail, m)}

	// Download the ciphertext into the spool, or the ranges a kept
	// download lacks.
	dl := transport.MultipartDownloadOptions{
		Threads:              opt.DownloadThreads,
		OnProgress:           opt.OnDownloadProgress,
		Logger:               opt.Logger,
		Status:               opt.DownloadStatus.transport(),
		PresignExpiryMinutes: opt.PresignExpiryMinutes,
	}
	var resumed int64
	if journal != nil {
		dl.Have, dl.OnRange = journal.rec.Have, journal.add
		resumed = journal.rec.Downloaded()
		go journal.run()
	}
	api.Module(log, "decrypt").Debug("ciphertext storage", sp.logArgs(spoolNeed(m.CiphertextSize-resumed))...)
	// The download logs its plan and its completion.
	opt.phase(PhaseDownloading)
	err = c.api.DownloadToFile(targetRevID, sp, m.CiphertextSize, dl)
	if journal != nil {
		journal.halt()
		o.journal = journal
		if err != nil {
			if cerr := journal.checkpoint(); cerr != nil {
				logRecordFailed(log, cerr)
			}
			if journal.rec.Downloaded() > 0 {
				_ = o.Close() // the folder stays for the next decrypt (sp.keep); it holds ciphertext only, in a private (0700) directory.
				return nil, &DownloadInterruptedError{Download: *journal.rec, Err: err}
			}
		}
	}
	if err != nil {
		sp.keep = false // nothing downloaded is worth keeping
		_ = o.Close()   // the download error is returned; the spool holds ciphertext only, in a private (0700) directory.
		return nil, fmt.Errorf("download: %w", err)
	}

	o.Result = DecryptResult{
		RevisionID:           targetRevID,
		SecretName:           m.SecretName,
		SignedAt:             time.Unix(m.Timestamp, 0),
		SenderFingerprint:    m.SenderFingerprint,
		SenderEmail:          senderEmail,
		SenderFirstUse:       senderFirst,
		RecipientFingerprint: localFP,
		Recipients:           signedRecipients(m, rev),
		Compressed:           m.Compressed,
		Compression:          m.Compression,
		PayloadType:          m.PayloadType,
		ProtocolVersion:      m.Version,
		CipherSuite:          m.CipherSuite,
		PayloadDigest:        hex.EncodeToString(m.PayloadDigest),
		EncryptedSize:        m.CiphertextSize,
		PlaintextSize:        m.PlaintextSize,
		ResumedBytes:         resumed,
	}
	return o, nil
}

// Close removes the temporary ciphertext and clears the payload key. A
// download kept under DecryptOptions.ResumeDir stays unless its payload
// was decrypted or failed its check, so the next decrypt need not fetch
// it again.
func (o *OpenedSecret) Close() error {
	o.opened.Close()
	if o.spool.keep && o.journal != nil {
		if err := o.journal.checkpoint(); err != nil {
			logRecordFailed(o.log, err)
		}
	}
	return o.spool.Close()
}

// errPassDone stops a decrypt pass whose reader finished early.
var errPassDone = errors.New("decrypt pass stopped")

// pass decrypts the stored ciphertext once and hands the plaintext,
// decompressed, to read. The ciphertext's size and digest are checked
// against the signed manifest before the first plaintext byte, and every
// chunk is authenticated before it is released. stage names the pass for
// OnDecryptProgress.
func (o *OpenedSecret) pass(stage DecryptStage, read func(r io.Reader) error) error {
	if err := o.ctx.Err(); err != nil {
		return err
	}
	m := o.opened.Manifest
	var src io.ReadSeeker = o.spool.reader(m.CiphertextSize)
	if o.onProgress != nil {
		// DecryptTo reads the ciphertext twice, for the digest and then
		// to decrypt: each read is half the pass.
		size := m.CiphertextSize
		o.onProgress(stage, 0, size)
		src = &passReader{r: src, total: 2 * size, report: func(n int64) { o.onProgress(stage, n/2, size) }}
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := o.opened.DecryptTo(pw, src)
		pw.CloseWithError(err)
		done <- err
	}()

	// A cancel stops the pass at the next read.
	in := ctxReader{o.ctx, pr}
	readErr := func() error {
		if !m.Compressed {
			return read(in)
		}
		zr, err := compress.NewDecompressReader(in, compress.Algorithm(m.Compression))
		if err != nil {
			return fmt.Errorf("decompress (%s): %w", m.Compression, err)
		}
		defer func() { _ = zr.Close() }()
		return read(zr)
	}()
	_ = pr.CloseWithError(errPassDone) // io.PipeReader.CloseWithError always returns nil.
	decErr := <-done
	if decErr != nil && !errors.Is(decErr, errPassDone) && !errors.Is(decErr, io.ErrClosedPipe) {
		// The ciphertext failed its check or could not be read: a kept
		// download goes, so the next decrypt fetches it afresh.
		o.spool.keep = false
		if o.Result.ResumedBytes > 0 {
			return fmt.Errorf("%w (%s of it was kept from an earlier download; that copy is discarded, so decrypting again downloads it afresh)",
				decErr, humanBytes(o.Result.ResumedBytes))
		}
		return decErr
	}
	return readErr
}

// passReader counts what a pass reads of the ciphertext, rewinds
// included, up to total.
type passReader struct {
	r      io.ReadSeeker
	n      int64
	total  int64
	report func(n int64)
}

func (p *passReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n += int64(n)
		p.report(min(p.n, p.total))
	}
	return n, err
}

func (p *passReader) Seek(offset int64, whence int) (int64, error) {
	return p.r.Seek(offset, whence)
}

// maxSmallPlaintext bounds a decrypted message or key-value payload.
const maxSmallPlaintext = 16 << 20

// Payload decrypts the payload in memory: a message, key-value data, or
// files with their contents. The stored payload must be at most
// DefaultMaxInMemorySize, and decompresses to at most that for files and
// 16 MiB for messages and data; larger file payloads go to disk with
// WriteFiles.
func (o *OpenedSecret) Payload() (*DecryptedPayload, error) {
	m := o.opened.Manifest
	if m.CiphertextSize > DefaultMaxInMemorySize {
		return nil, fmt.Errorf("the payload is %s, too large to decrypt in memory: write it to disk with DecryptToDir or WriteFiles",
			humanBytes(m.CiphertextSize))
	}
	limit := int64(maxSmallPlaintext)
	if m.PayloadType == "files" {
		limit = DefaultMaxInMemorySize
	}
	var plaintext []byte
	tDec := time.Now()
	err := o.pass(DecryptDecrypting, func(r io.Reader) error {
		b, err := io.ReadAll(io.LimitReader(r, limit+1))
		if err != nil {
			return err
		}
		if int64(len(b)) > limit {
			return fmt.Errorf("the decrypted payload exceeds %s", humanBytes(limit))
		}
		plaintext = b
		return nil
	})
	if err != nil {
		return nil, err
	}
	o.spool.keep = false // decrypted: a kept download has done its job
	logPayloadVerified(o.log, m)
	decElapsed := time.Since(tDec)
	api.Module(o.log, "decrypt").Info("payload decrypted", "size", api.Bytes(int64(len(plaintext))), "elapsed", decElapsed.Round(time.Millisecond))
	if err := o.decrypted(); err != nil {
		return nil, err
	}

	var p payload.Payload
	if err := payload.Unmarshal(plaintext, &p); err != nil {
		return &DecryptedPayload{Type: "raw", Raw: plaintext}, nil
	}
	decrypted := &DecryptedPayload{Type: p.Type, Raw: plaintext}
	switch p.Type {
	case "message":
		decrypted.Message = p.Message
	case "files":
		decrypted.Archived = p.Archive && len(p.Files) == 1
		decrypted.ArchiveCompression = p.ArchiveCompression
		// The sender names the files: refuse any name that is not a safe
		// relative path, so a caller writing them out cannot be led out of
		// its directory. WriteFiles holds them to the same rule.
		for _, f := range p.Files {
			name, err := archive.ValidateArchivePath(f.Name)
			if err != nil {
				return nil, fmt.Errorf("the payload names an unsafe file: %w", err)
			}
			decrypted.Files = append(decrypted.Files, DecryptedFile{
				Name: name, Data: f.Data, Size: f.Size, SHA256: f.SHA256, Mode: f.Mode,
			})
		}
	case "data":
		for _, e := range p.Entries {
			decrypted.Entries = append(decrypted.Entries, KeyValue{Key: e.Key, Value: e.Value})
		}
	}
	return decrypted, nil
}

// WriteOptions configures WriteFiles.
type WriteOptions struct {
	// Overwrite lets files replace existing ones. Without it, WriteFiles
	// refuses before writing anything when a destination exists.
	Overwrite bool

	// MaxFiles, MaxFileSize and MaxTotalSize bound the payload, or an
	// archive's entries. Zero means 100,000 files, 100 GiB per file and
	// 500 GiB in all.
	MaxFiles     int
	MaxFileSize  int64
	MaxTotalSize int64
}

func (w WriteOptions) limits() (payload.DecodeLimits, *archive.Limits) {
	files, size, total := w.MaxFiles, w.MaxFileSize, w.MaxTotalSize
	if files <= 0 {
		files = 100_000
	}
	if size <= 0 {
		size = 100 << 30
	}
	if total <= 0 {
		total = 500 << 30
	}
	return payload.DecodeLimits{MaxFiles: files, MaxFileSize: size, MaxTotalSize: total},
		&archive.Limits{MaxEntries: files, MaxEntrySize: size, MaxTotalSize: total, AllowOverwrite: w.Overwrite}
}

// CheckDestination checks, before a download, that the files of a pending
// one (UpcomingDownload.Files) can be written into dir: dir, or the nearest
// directory above it that exists, accepts new files; none of the files
// exists there already unless overwrite; and the disk holds them. The list
// comes from the server and is only a prediction: a name that is not a
// safe relative path is skipped here, and WriteFiles checks the payload's
// own names again before writing anything.
func CheckDestination(dir string, files []FileMeta, overwrite bool) error {
	if err := checkWritable(dir); err != nil {
		return err
	}
	var total int64
	for _, f := range files {
		total += max(f.Size, 0)
		name, err := archive.ValidateArchivePath(f.Name)
		if err != nil {
			continue
		}
		if err := checkDestination(dir, name, overwrite); err != nil {
			return err
		}
	}
	return checkFreeSpace(dir, total+total/100, "the decrypted files", "")
}

// checkWritable checks that dir, or the nearest directory above it that
// exists, is a directory this process can create files in, by creating
// and removing one.
func checkWritable(dir string) error {
	probe := filepath.Clean(dir)
	for {
		info, err := os.Stat(probe) // #nosec G703 -- the directory the caller writes to, or its parent.
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("cannot write into %s: %s is not a directory", dir, probe)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check destination %s: %w", probe, err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return fmt.Errorf("check destination %s: no existing directory above it", dir)
		}
		probe = parent
	}
	f, err := os.CreateTemp(probe, ".deepsecret-write-check-*")
	if err != nil {
		return fmt.Errorf("cannot write into %s: %w", probe, err)
	}
	name := f.Name()
	_ = f.Close() // empty; removed next.
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove write check %s: %w", name, err)
	}
	return nil
}

// checkDestination refuses a payload entry that could not be written under
// dir: a parent that exists but is not a directory, a destination that
// exists unless overwrite, or any lookup that fails for another reason
// than not existing.
func checkDestination(dir, name string, overwrite bool) error {
	parts := strings.Split(name, "/")
	path := dir
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("check destination %s: %w", path, err)
		}
		if i < len(parts)-1 {
			if !info.IsDir() {
				return fmt.Errorf("cannot write %s: %s is not a directory", filepath.Join(dir, filepath.FromSlash(name)), path)
			}
			continue
		}
		if !overwrite {
			return fmt.Errorf("destination already exists: %s (allow overwriting to replace it)", path)
		}
	}
	return nil
}

// WrittenFile is one file WriteFiles wrote.
type WrittenFile struct {
	Path   string // where it was written
	Name   string // its name in the payload
	Size   int64
	SHA256 string // hex, checked against the payload
}

// WriteResult is what WriteFiles wrote.
type WriteResult struct {
	Files     []WrittenFile // the payload's files, when it is not an archive
	Archived  bool
	Extracted int   // entries extracted from an archive
	Size      int64 // the files' own bytes, written or extracted
}

// WriteFiles writes a files payload into dir, or extracts its archive
// there, in constant memory. It decrypts the verified ciphertext once to
// check the whole payload (structure, names, sizes, SHA-256 of every file,
// and an archive's entries), and only then again to write, so a payload
// that fails a check writes nothing. Names are portable relative paths and
// every write stays inside dir; existing files are not replaced unless
// w.Overwrite is set. When writing fails midway, or the second decryption differs
// from the first, everything it created is removed, files it overwrote
// among them; what was there before stays.
func (o *OpenedSecret) WriteFiles(dir string, w WriteOptions) (*WriteResult, error) {
	m := o.opened.Manifest
	if m.PayloadType != "files" {
		return nil, fmt.Errorf("the payload is %s, not files: decrypt it with Payload", m.PayloadType)
	}
	decLim, tarLim := w.limits()

	// Pass 1: check the payload, writing nothing.
	tCheck := time.Now()
	var info *payload.Files
	if err := o.pass(DecryptChecking, func(r io.Reader) error {
		var err error
		info, err = payload.DecodeFiles(r, decLim, nil)
		return err
	}); err != nil {
		return nil, fmt.Errorf("check payload: %w", err)
	}
	logPayloadVerified(o.log, m)

	var names []string
	var total int64
	archiveAlgo := compress.Algorithm(info.ArchiveCompression)
	if info.Archive {
		// The archive's entries are checked on a pass of their own: a
		// payload says it is an archive only after its data.
		if err := o.pass(DecryptCheckingArchive, func(r io.Reader) error {
			_, err := payload.DecodeFiles(r, decLim, func(_ int, _ int64, data io.Reader) error {
				var err error
				names, total, err = archive.ValidateTarReader(data, archiveAlgo, tarLim)
				return err
			})
			return err
		}); err != nil {
			return nil, fmt.Errorf("check archive: %w", err)
		}
	} else {
		seen := make(map[string]bool, len(info.Files))
		for _, f := range info.Files {
			name, err := archive.ValidateArchivePath(f.Name)
			if err != nil {
				return nil, fmt.Errorf("unsafe file name: %w", err)
			}
			if seen[name] {
				return nil, fmt.Errorf("the payload lists %q twice", name)
			}
			seen[name] = true
			names = append(names, name)
			total += f.Size
		}
	}
	// What the payload holds must fit, so a payload that decompresses to
	// far more than it was cannot fill the disk.
	if err := checkFreeSpace(dir, total+total/100, "the decrypted files", ""); err != nil {
		return nil, err
	}
	for _, name := range names {
		if err := checkDestination(dir, name, w.Overwrite); err != nil {
			return nil, err
		}
	}
	api.Module(o.log, "decrypt").Debug("payload checked", "archived", info.Archive, "files", len(names), "size", api.Bytes(total),
		"elapsed", time.Since(tCheck).Round(time.Millisecond))

	// Directories made to hold decrypted files are private. undo records
	// what the write creates, so a failure removes all of it.
	var undo archive.Undo
	if err := undo.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	// Pass 2: write.
	tWrite := time.Now()
	result := &WriteResult{Archived: info.Archive, Size: total}
	err := o.pass(DecryptWriting, func(r io.Reader) error {
		out, err := payload.DecodeFiles(r, decLim, func(idx int, size int64, data io.Reader) error {
			if info.Archive {
				n, err := archive.ExtractTarReaderInto(data, dir, archiveAlgo, tarLim, &undo)
				result.Extracted = n
				return err
			}
			f := info.Files[idx]
			mode := f.Mode & 0o777
			if mode == 0 {
				mode = 0o600
			}
			path, _, err := archive.WriteFile(dir, f.Name, mode, data, size, w.Overwrite, &undo)
			if err != nil {
				return err
			}
			result.Files = append(result.Files, WrittenFile{Path: path, Name: f.Name, Size: f.Size, SHA256: f.SHA256})
			return nil
		})
		if err != nil {
			return err
		}
		// The second decryption must read exactly what the first checked.
		if len(out.Files) != len(info.Files) {
			return fmt.Errorf("the payload changed between passes")
		}
		for i := range out.Files {
			if out.Files[i] != info.Files[i] {
				return fmt.Errorf("the payload changed between passes")
			}
		}
		return nil
	})
	if err != nil {
		return nil, undo.Remove(fmt.Errorf("write files: %w", err))
	}
	if err := o.decrypted(); err != nil {
		return nil, undo.Remove(err)
	}
	o.spool.keep = false // decrypted: a kept download has done its job
	written := []any{"archived", info.Archive}
	if info.Archive {
		written = append(written, "extracted", result.Extracted)
	} else {
		written = append(written, "files", len(result.Files))
	}
	api.Module(o.log, "decrypt").Info("files written", append(written, "dir", dir, "size", api.Bytes(total),
		"elapsed", time.Since(tWrite).Round(time.Millisecond))...)
	return result, nil
}

// senderRecorder returns what records email's key fp, which signed a secret
// from them, once it is decrypted, when the key was new to this device
// (first); nil otherwise.
func (c *Client) senderRecorder(email, fp string, first bool) func() error {
	if !first {
		return nil
	}
	return func() error { return c.recordFirstUse([]Recipient{{Email: email, Fingerprint: fp}}, true) }
}

// signedRecipients lists every recipient fingerprint the sender signed
// for, in manifest order. Emails are the server's labels for those
// fingerprints, from the revision listing, and are empty when the server
// does not name one.
func signedRecipients(m *protocol.Manifest, rev *RevisionInfo) []Recipient {
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
// the revision's recipients. It lists the revisions unless the caller gave
// them.
func (c *Client) resolveRevision(secretID, latestRevID, localFP, requestedRevID string, revisions []RevisionInfo) (*RevisionInfo, error) {
	if revisions == nil {
		var err error
		if revisions, err = c.ListRevisions(c.api.Context(), secretID); err != nil {
			return nil, err
		}
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
