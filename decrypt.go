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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/archive"
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
	"github.com/deepsecret-io/sdk/payload"
	"github.com/deepsecret-io/sdk/secrets"
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

// DecryptSecret downloads and decrypts a secret by its ID, in memory.
// Returns only the decrypted payload. For manifest metadata, use DecryptSecretFull.
func (c *Client) DecryptSecret(secretID string) (*payload.Decrypted, error) {
	result, err := c.DecryptSecretFull(secretID, DecryptOptions{})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptRevision downloads and decrypts a specific revision of a secret,
// in memory. Returns only the decrypted payload. For manifest metadata, use
// DecryptRevisionFull.
func (c *Client) DecryptRevision(secretID, revisionID string) (*payload.Decrypted, error) {
	result, err := c.DecryptRevisionFull(secretID, DecryptOptions{Revision: revisionID})
	if err != nil {
		return nil, err
	}
	return result.Decrypted, nil
}

// DecryptSecretFull downloads and decrypts a secret in memory, returning
// full metadata. It fetches revisions, checks that the revision was sealed
// for your key, and includes the verified manifest's metadata
// (fingerprints, recipients, protocol version, cipher suite, payload
// digest) in the result. A payload stored larger than
// DefaultMaxInMemorySize is refused: write it to disk with DecryptToDir.
func (c *Client) DecryptSecretFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {
	o, err := c.openSecret(secretID, opt, true)
	if err != nil {
		return nil, err
	}
	defer o.Close()
	d, err := o.Payload()
	if err != nil {
		return nil, err
	}
	result := o.Result
	result.Decrypted = d
	return &result, nil
}

// DecryptRevisionFull downloads and decrypts a specific revision in memory,
// returning full metadata. Set opts.Revision to target a specific revision;
// empty means latest.
func (c *Client) DecryptRevisionFull(secretID string, opt DecryptOptions) (*DecryptResult, error) {
	return c.DecryptSecretFull(secretID, opt)
}

// DecryptToDir downloads a files secret and writes its files, or extracts
// its archive, into dir, in constant memory. See OpenedSecret.WriteFiles.
func (c *Client) DecryptToDir(secretID, dir string, opt DecryptOptions, w WriteOptions) (*DecryptResult, *WriteResult, error) {
	o, err := c.OpenSecret(secretID, opt)
	if err != nil {
		return nil, nil, err
	}
	defer o.Close()
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

	opened *crypto.Opened
	spool  *spool
	ctx    context.Context
	debugf func(step, format string, args ...any)
}

// smallPayloadSize is the largest stored payload OpenSecret keeps in
// memory rather than in a temporary file.
const smallPayloadSize = 4 << 20

// OpenSecret opens one revision as protocol v4 §6 orders it: fetch the
// manifest and the caller's wrap, verify the manifest and open the wrap,
// and download the payload into a private temporary file, or into memory
// when it is at most 4 MiB. The payload's digest is checked against the
// manifest by every decrypt, before any plaintext is released.
func (c *Client) OpenSecret(secretID string, opt DecryptOptions) (*OpenedSecret, error) {
	return c.openSecret(secretID, opt, false)
}

// openSecret is OpenSecret; inMemory keeps the payload in memory whatever
// its size, refusing one over DefaultMaxInMemorySize before downloading.
func (c *Client) openSecret(secretID string, opt DecryptOptions, inMemory bool) (*OpenedSecret, error) {
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
	m := opened.Manifest
	debugf("verify", "sender bundle bound to fingerprint, Ed25519 + ML-DSA-65 signatures verified")
	debugf("verify", "manifest is for this revision and lists your key")
	debugf("verify", "wrap matches the signed digest and opened (HPKE X25519 + ML-KEM-768)")

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
	var sp *spool
	if inMemory || m.CiphertextSize <= smallPayloadSize {
		sp = newMemSpool(m.CiphertextSize)
	} else if sp, err = newSpool(opt.TempDir, spoolNeed(m.CiphertextSize)); err != nil {
		opened.Close()
		return nil, err
	}
	o := &OpenedSecret{opened: opened, spool: sp, ctx: c.api.Context(), debugf: debugf}

	// Download the ciphertext into the spool.
	debugf("download", "revision=%s", targetRevID)
	if sp.dir != "" {
		debugf("download", "temporary ciphertext=%s", sp.dir)
	}
	t0 := time.Now()
	if err := c.api.DownloadToFile(targetRevID, sp, m.CiphertextSize, api.MultipartDownloadOptions{
		Threads:              opt.DownloadThreads,
		OnProgress:           opt.OnDownloadProgress,
		OnDebug:              opt.OnDebug,
		PresignExpiryMinutes: opt.PresignExpiryMinutes,
	}); err != nil {
		o.Close()
		return nil, fmt.Errorf("download: %w", err)
	}
	dlElapsed := time.Since(t0)
	debugf("download", "payload=%s", humanBytes(m.CiphertextSize))
	debugf("download", "elapsed=%s", dlElapsed.Round(time.Millisecond))
	debugf("download", "rate=%s", formatRate(m.CiphertextSize, dlElapsed))

	o.Result = DecryptResult{
		RevisionID:           targetRevID,
		SenderFingerprint:    m.SenderFingerprint,
		RecipientFingerprint: localFP,
		Recipients:           signedRecipients(m, rev),
		Compressed:           m.Compressed,
		Compression:          m.Compression,
		PayloadType:          m.PayloadType,
		ProtocolVersion:      m.Version,
		CipherSuite:          m.CipherSuite,
		PayloadDigest:        hex.EncodeToString(m.PayloadDigest),
		EncryptedSize:        m.CiphertextSize,
	}
	return o, nil
}

// Close removes the temporary ciphertext and clears the payload key.
func (o *OpenedSecret) Close() error {
	o.opened.Close()
	return o.spool.Close()
}

// errPassDone stops a decrypt pass whose reader finished early.
var errPassDone = errors.New("decrypt pass stopped")

// pass decrypts the stored ciphertext once and hands the plaintext,
// decompressed, to read. The ciphertext's size and digest are checked
// against the signed manifest before the first plaintext byte, and every
// chunk is authenticated before it is released.
func (o *OpenedSecret) pass(read func(r io.Reader) error) error {
	if err := o.ctx.Err(); err != nil {
		return err
	}
	m := o.opened.Manifest
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := o.opened.DecryptTo(pw, o.spool.reader(m.CiphertextSize))
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
		defer zr.Close()
		return read(zr)
	}()
	pr.CloseWithError(errPassDone)
	decErr := <-done
	if decErr != nil && !errors.Is(decErr, errPassDone) && !errors.Is(decErr, io.ErrClosedPipe) {
		return decErr
	}
	return readErr
}

// maxSmallPlaintext bounds a decrypted message or key-value payload.
const maxSmallPlaintext = 16 << 20

// Payload decrypts the payload in memory: a message, key-value data, or
// files with their contents. The stored payload must be at most
// DefaultMaxInMemorySize, and decompresses to at most that for files and
// 16 MiB for messages and data; larger file payloads go to disk with
// WriteFiles.
func (o *OpenedSecret) Payload() (*payload.Decrypted, error) {
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
	err := o.pass(func(r io.Reader) error {
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
	o.debugf("verify", "payload sha256=%s… matches the signed manifest", hex.EncodeToString(m.PayloadDigest)[:12])
	o.debugf("verify", "every chunk authenticated, in order, ending on the last-chunk flag")
	o.debugf("decrypt", "plaintext=%s", humanBytes(int64(len(plaintext))))
	o.debugf("decrypt", "elapsed=%s", time.Since(tDec).Round(time.Millisecond))

	var p payload.Payload
	if err := payload.Unmarshal(plaintext, &p); err != nil {
		return &payload.Decrypted{Type: "raw", Raw: plaintext}, nil
	}
	decrypted := &payload.Decrypted{Type: p.Type, Raw: plaintext}
	switch p.Type {
	case "message":
		decrypted.Message = p.Message
	case "files":
		decrypted.Archived = p.Archive && len(p.Files) == 1
		decrypted.ArchiveCompression = p.ArchiveCompression
		for _, f := range p.Files {
			decrypted.Files = append(decrypted.Files, payload.DecryptedFile{
				Name: f.Name, Data: f.Data, Size: f.Size, SHA256: f.SHA256, Mode: f.Mode,
			})
		}
	case "data":
		for _, e := range p.Entries {
			decrypted.Entries = append(decrypted.Entries, payload.KeyValue{Key: e.Key, Value: e.Value})
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
	Extracted int // entries extracted from an archive
}

// WriteFiles writes a files payload into dir, or extracts its archive
// there, in constant memory. It decrypts the verified ciphertext once to
// check the whole payload (structure, names, sizes, SHA-256 of every file,
// and an archive's entries), and only then again to write, so a payload
// that fails a check writes nothing. Names are portable relative paths and
// every write stays inside dir; existing files are not replaced unless
// w.Overwrite is set.
func (o *OpenedSecret) WriteFiles(dir string, w WriteOptions) (*WriteResult, error) {
	m := o.opened.Manifest
	if m.PayloadType != "files" {
		return nil, fmt.Errorf("the payload is %s, not files: decrypt it with Payload", m.PayloadType)
	}
	decLim, tarLim := w.limits()

	// Pass 1: check the payload, writing nothing.
	tCheck := time.Now()
	var info *payload.Files
	if err := o.pass(func(r io.Reader) error {
		var err error
		info, err = payload.DecodeFiles(r, decLim, nil)
		return err
	}); err != nil {
		return nil, fmt.Errorf("check payload: %w", err)
	}
	o.debugf("verify", "payload sha256=%s… matches the signed manifest", hex.EncodeToString(m.PayloadDigest)[:12])
	o.debugf("verify", "every chunk authenticated, in order, ending on the last-chunk flag")

	var names []string
	var total int64
	archiveAlgo := compress.Algorithm(info.ArchiveCompression)
	if info.Archive {
		// The archive's entries are checked on a pass of their own: a
		// payload says it is an archive only after its data.
		if err := o.pass(func(r io.Reader) error {
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
	o.debugf("verify", "checked %d payload entries in %s", len(names), time.Since(tCheck).Round(time.Millisecond))

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	// Pass 2: write.
	result := &WriteResult{Archived: info.Archive}
	err := o.pass(func(r io.Reader) error {
		out, err := payload.DecodeFiles(r, decLim, func(idx int, size int64, data io.Reader) error {
			if info.Archive {
				n, err := archive.ExtractTarReader(data, dir, archiveAlgo, tarLim)
				result.Extracted = n
				return err
			}
			f := info.Files[idx]
			mode := f.Mode & 0o777
			if mode == 0 {
				mode = 0o600
			}
			path, _, err := archive.WriteFile(dir, f.Name, mode, data, size, w.Overwrite)
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
		for _, f := range result.Files {
			os.Remove(f.Path)
		}
		return nil, fmt.Errorf("write files: %w", err)
	}
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
