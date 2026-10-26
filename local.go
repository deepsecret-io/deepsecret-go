// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"

	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/identity"
)

// ── Local files ──────────────────────────────────────────────────────────────
//
// A local file is a sealed secret written to disk instead of being sent.
// It holds what a send stores on the server, the signed manifest, a wrap
// per recipient and the encrypted payload, sealed and opened by the same
// protocol v4 code. Only public keys come from the API: the sender's client
// looks up each recipient's registered key, and the recipient's client
// checks that the key which signed the manifest is one the named sender
// registered. Nothing is uploaded and no secret is created.
//
// The file is a CBOR sequence (RFC 8742) of three items:
//
//	"deepsecret-local-v1"                  text string
//	payload                                byte string, its length in 8 bytes
//	{sender_email, manifest, wraps}        map
//
// The map comes last because the manifest signs the payload's digest, so it
// exists only once the payload is sealed: a send seals straight into the
// file in one pass and fills in the payload's length afterwards.

// LocalFileExt is the extension the CLI gives local files.
const LocalFileExt = ".cbor"

const (
	localMagic = "deepsecret-local-v1"

	// maxLocalHeader bounds the map after the payload: a manifest of at
	// most 1 MiB and crypto.MaxRecipients wraps of about 1.2 KB each.
	maxLocalHeader = 4 << 20

	// maxEmailLen is the longest email address (RFC 5321).
	maxEmailLen = 254

	// maxCheckedLabels bounds the API lookups that check recipient labels
	// on open; recipients past it are shown by fingerprint only.
	maxCheckedLabels = 100
)

// localMagicItem is localMagic encoded as a CBOR text string (major type
// 3; the length fits in the initial byte).
var localMagicItem = append([]byte{0x60 | byte(len(localMagic))}, localMagic...)

// localPrefixLen is the magic item and the payload byte string's head: the
// major type 2 initial byte for an 8-byte length (0x5b) and the length.
var localPrefixLen = int64(len(localMagicItem) + 9)

// localHeader is the map after the payload. Emails are labels the
// signature does not cover: on open, the sender's is checked against the
// key that signed the manifest, and each recipient's against the key it
// labels, and a label that fails is not shown.
type localHeader struct {
	SenderEmail string      `cbor:"sender_email"`
	Manifest    []byte      `cbor:"manifest"`
	Wraps       []localWrap `cbor:"wraps"`
}

type localWrap struct {
	Fingerprint string `cbor:"recipient_fp"`
	Email       string `cbor:"email"`
	Enc         []byte `cbor:"enc"`
	Ct          []byte `cbor:"ct"`
}

// localDecMode decodes a header strictly: definite lengths only, no
// duplicate or unknown keys, and bounded sizes.
var localDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxNestedLevels:   4,
		MaxArrayElements:  crypto.MaxRecipients,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// encryptToFile is encryptAndSend for EncryptOptions.LocalFile: it seals p
// for recipients into the file instead of sending it.
func (c *Client) encryptToFile(recipients []string, p *plaintext, opt EncryptOptions) (*EncryptResult, error) {
	debugf := func(step, format string, args ...any) {
		if opt.OnDebug == nil {
			return
		}
		opt.OnDebug(step, fmt.Sprintf(format, args...))
	}
	if err := ValidateRecipients(recipients); err != nil {
		return nil, err
	}
	if p.size == 0 {
		return nil, fmt.Errorf("payload is empty")
	}
	if maxSize := maxPayloadSize(opt); p.size > maxSize {
		return nil, fmt.Errorf("payload size %d exceeds limit %d bytes: reduce input size or increase MaxPayloadSize", p.size, maxSize)
	}
	out := opt.LocalFile
	if _, err := os.Lstat(out); err == nil && !opt.LocalOverwrite {
		return nil, fmt.Errorf("%s already exists (allow overwriting to replace it)", out)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("check %s: %w", out, err)
	}
	dir := filepath.Dir(out)
	if err := checkFreeSpace(dir, spoolNeed(p.size), "the encrypted file", ""); err != nil {
		return nil, err
	}
	debugf("encrypt", "payload type=%s", p.payloadType)
	debugf("encrypt", "plaintext size=%s", humanBytes(p.size))
	need := spoolNeed(p.size)
	if free, ok := freeDiskBytes(dir); ok {
		debugf("plan", "local file: %s, sealed into a private file beside it and renamed when complete; needs %s, %s free", out, humanBytes(need), humanBytes(free))
	} else {
		debugf("plan", "local file: %s, sealed into a private file beside it and renamed when complete; needs %s", out, humanBytes(need))
	}

	// The sender's email goes in the file, so the recipient's client can
	// check the signing key against the keys that account registered.
	me, err := identity.WhoAmI(c.api)
	if err != nil {
		return nil, fmt.Errorf("fetch actor info: %w", err)
	}
	kp, senderFP, err := c.loadIdentity(opt.Identity, opt.Password)
	if err != nil {
		return nil, fmt.Errorf("load sender identity: %w", err)
	}
	debugf("identity", "sender fingerprint=%s", crypto.ShortFingerprint(senderFP))
	pubs := make([]*crypto.PublicKeys, len(recipients))
	for i, email := range recipients {
		if pubs[i], err = c.recipientKeys(email); err != nil {
			return nil, err
		}
		debugf("recipient", "email=%s fingerprint=%s", sanitizeForLog(email), crypto.ShortFingerprint(pubs[i].Fingerprint))
	}
	algo, err := chooseCompression(p, opt.Compress, debugf)
	if err != nil {
		return nil, err
	}
	debugf("plan", "encryption: %s", encryptionPlan(len(pubs)))

	// Seal into a private file beside the destination, renamed into place
	// once complete, so a failure never leaves a partial file under it.
	f, err := os.CreateTemp(dir, ".deepsecret-*.partial")
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", out, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	head := append(append([]byte{}, localMagicItem...), 0x5b, 0, 0, 0, 0, 0, 0, 0, 0)
	if _, err := f.Write(head); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	tEnc := time.Now()
	sealed, written, err := sealPlaintext(c.api.Context(), f, p, algo, kp, pubs, crypto.SealParams{
		RevisionID:  uuid.New().String(),
		PayloadType: p.payloadType,
		Compressed:  algo != compress.None,
		Compression: string(algo),
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	m := sealed.Manifest
	debugf("encrypt", "payload=%s", humanBytes(m.CiphertextSize))
	debugf("encrypt", "elapsed=%s", time.Since(tEnc).Round(time.Millisecond))

	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(m.CiphertextSize))
	if _, err := f.WriteAt(length[:], int64(len(localMagicItem))+1); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != localPrefixLen+m.CiphertextSize {
		return nil, fmt.Errorf("write %s: the payload is not the size the manifest signs", out)
	}
	hdr := localHeader{SenderEmail: me.Email, Manifest: sealed.ManifestData, Wraps: make([]localWrap, len(pubs))}
	sentTo := make([]Recipient, len(pubs))
	for i, pub := range pubs {
		w, ok := sealed.Wrap(pub.Fingerprint)
		if !ok {
			return nil, fmt.Errorf("encrypt: no wrap was made for %s", recipients[i])
		}
		hdr.Wraps[i] = localWrap{Fingerprint: pub.Fingerprint, Email: recipients[i], Enc: w.Enc, Ct: w.Ciphertext}
		sentTo[i] = Recipient{Email: recipients[i], Fingerprint: pub.Fingerprint}
	}
	data, err := cbor.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", out, err)
	}
	if _, err := f.Write(data); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	if err := os.Rename(f.Name(), out); err != nil {
		return nil, fmt.Errorf("write %s: %w", out, err)
	}
	renamed = true
	debugf("local", "wrote %s", humanBytes(localPrefixLen+m.CiphertextSize+int64(len(data))))

	label, ratio, original := compressionSummary(p, algo, m, written)
	result := &EncryptResult{
		LocalFile:         out,
		EncryptedSize:     m.CiphertextSize,
		SenderFingerprint: senderFP,
		Recipients:        sentTo,
		Compressed:        label != "",
		Compression:       label,
		CompressionRatio:  ratio,
		OriginalSize:      original,
		PayloadType:       p.payloadType,
		FilesCount:        len(p.files),
		Archived:          p.archived,
	}
	if p.archived {
		result.ArchiveEntryCount = p.archiveEntries
	}
	return result, nil
}

// OpenLocalFile opens a file written with EncryptOptions.LocalFile, as
// OpenSecret opens a secret: it verifies the manifest and that the key
// which signed it is one the sender named in the file registered, opens
// the caller's wrap, and copies the payload into a private temporary file
// (or memory, at most 4 MiB), so the file can change afterwards without
// affecting what is checked and decrypted. Decrypt it with Payload or
// WriteFiles, which check the payload's digest before any plaintext.
// OnDownloadProgress reports the copy. Revision and the download options
// do not apply.
func (c *Client) OpenLocalFile(path string, opt DecryptOptions) (*OpenedSecret, error) {
	debugf := func(step, format string, args ...any) {
		if opt.OnDebug == nil {
			return
		}
		opt.OnDebug(step, fmt.Sprintf(format, args...))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	hdr, payloadSize, err := readLocalHeader(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	debugf("local", "file=%s", path)
	debugf("local", "sender=%s", sanitizeForLog(hdr.SenderEmail))
	debugf("local", "recipients=%d", len(hdr.Wraps))

	kp, localFP, err := c.loadIdentity(opt.Identity, opt.Password)
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}
	debugf("identity", "recipient fingerprint=%s", crypto.ShortFingerprint(localFP))
	var wrap *crypto.Wrap
	emails := make(map[string]string, len(hdr.Wraps))
	for _, w := range hdr.Wraps {
		emails[w.Fingerprint] = w.Email
		if w.Fingerprint == localFP {
			wrap = &crypto.Wrap{RecipientFingerprint: localFP, Enc: w.Enc, Ciphertext: w.Ct}
		}
	}
	if wrap == nil {
		return nil, fmt.Errorf("%s was not encrypted for your key (%s)", path, crypto.ShortFingerprint(localFP))
	}

	// The manifest is parsed here for the sender's fingerprint only; Open
	// verifies it in full, with the Ed25519 key of the sender's registered
	// key of that fingerprint.
	peek, err := crypto.UnmarshalManifest(hdr.Manifest)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Callers name output after the revision, as for a secret, so it must
	// be what a send makes: a canonical UUID, never a path.
	if id, err := uuid.Parse(peek.RevisionID); err != nil || id.String() != peek.RevisionID {
		return nil, fmt.Errorf("%s: malformed local file: the revision ID is not a UUID", path)
	}
	senderED25519, err := identity.ResolveED25519ByEmail(c.api, hdr.SenderEmail, peek.SenderFingerprint)
	if err != nil {
		return nil, fmt.Errorf("check sender %s: %w", hdr.SenderEmail, err)
	}
	debugf("verify", "sender key %s is registered to %s", crypto.ShortFingerprint(peek.SenderFingerprint), sanitizeForLog(hdr.SenderEmail))
	opened, err := crypto.Open(hdr.Manifest, wrap, kp, crypto.OpenParams{
		RevisionID:    peek.RevisionID,
		SenderED25519: senderED25519,
	})
	if err != nil {
		return nil, err
	}
	m := opened.Manifest
	debugf("verify", "sender bundle bound to fingerprint, Ed25519 + ML-DSA-65 signatures verified")
	debugf("verify", "wrap matches the signed digest and opened (HPKE X25519 + ML-KEM-768)")
	if m.CiphertextSize != payloadSize {
		opened.Close()
		return nil, fmt.Errorf("%s: the payload is %d bytes, the signed manifest says %d", path, payloadSize, m.CiphertextSize)
	}
	maxSize := opt.MaxDownloadSize
	if maxSize <= 0 {
		maxSize = DefaultMaxDownloadSize
	}
	if m.CiphertextSize > maxSize {
		opened.Close()
		return nil, fmt.Errorf("the payload is %s, over the %s limit (set MaxDownloadSize to allow it)",
			humanBytes(m.CiphertextSize), humanBytes(maxSize))
	}

	var sp *spool
	if m.CiphertextSize <= smallPayloadSize {
		sp = newMemSpool(0)
	} else if sp, err = newSpool(opt.TempDir, m.CiphertextSize); err != nil {
		opened.Close()
		return nil, err
	}
	debugf("plan", "local file: the %s payload is copied before it is checked, so the file cannot change under the checks, to %s", humanBytes(payloadSize), sp.plan(m.CiphertextSize))
	o := &OpenedSecret{opened: opened, spool: sp, ctx: c.api.Context(), debugf: debugf}
	var src io.Reader = io.NewSectionReader(f, localPrefixLen, payloadSize)
	if opt.OnDownloadProgress != nil {
		src = &copyProgress{r: src, total: payloadSize, onProgress: opt.OnDownloadProgress}
	}
	if n, err := io.Copy(sp, ctxReader{o.ctx, src}); err != nil || n != payloadSize {
		o.Close()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// The signed list holds fingerprints only, so an email is shown for
	// one only when that account registered the key: anyone handling the
	// file could have changed the labels.
	recipients := make([]Recipient, len(m.Recipients))
	checked := 0
	for i, r := range m.Recipients {
		email := emails[r.Fingerprint]
		if email != "" {
			checked++
			if checked > maxCheckedLabels {
				email = ""
			} else if _, err := identity.ResolveED25519ByEmail(c.api, email, r.Fingerprint); err != nil {
				debugf("verify", "recipient label %s does not own key %s; not shown", sanitizeForLog(email), crypto.ShortFingerprint(r.Fingerprint))
				email = ""
			}
		}
		recipients[i] = Recipient{Email: email, Fingerprint: r.Fingerprint}
	}
	o.Result = DecryptResult{
		RevisionID:           m.RevisionID,
		SenderFingerprint:    m.SenderFingerprint,
		SenderEmail:          hdr.SenderEmail,
		RecipientFingerprint: localFP,
		Recipients:           recipients,
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

// LocalFileRecipients lists the keys a local file was sealed for, with the
// emails the sender gave them. Nothing is verified: it lets a caller pick
// which of its keys to open the file with, and OpenLocalFile checks the
// file.
func LocalFileRecipients(path string) ([]Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	hdr, _, err := readLocalHeader(f, info.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := make([]Recipient, len(hdr.Wraps))
	for i, w := range hdr.Wraps {
		out[i] = Recipient{Email: w.Email, Fingerprint: w.Fingerprint}
	}
	return out, nil
}

// readLocalHeader checks a local file's layout and returns its header and
// the payload's size; the payload starts at localPrefixLen.
func readLocalHeader(r io.ReaderAt, size int64) (*localHeader, int64, error) {
	notLocal := errors.New("not a DeepSecret local file")
	if size < localPrefixLen {
		return nil, 0, notLocal
	}
	prefix := make([]byte, localPrefixLen)
	if _, err := r.ReadAt(prefix, 0); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(prefix[:len(localMagicItem)], localMagicItem) || prefix[len(localMagicItem)] != 0x5b {
		return nil, 0, notLocal
	}
	n := binary.BigEndian.Uint64(prefix[len(localMagicItem)+1:])
	if n > uint64(size-localPrefixLen) {
		return nil, 0, errors.New("the file is truncated")
	}
	payloadSize := int64(n)
	headerSize := size - localPrefixLen - payloadSize
	if headerSize <= 0 || headerSize > maxLocalHeader {
		return nil, 0, errors.New("malformed local file: missing or oversized header")
	}
	data := make([]byte, headerSize)
	if _, err := r.ReadAt(data, localPrefixLen+payloadSize); err != nil {
		return nil, 0, err
	}
	var h localHeader
	if err := localDecMode.Unmarshal(data, &h); err != nil {
		return nil, 0, fmt.Errorf("malformed local file: %w", err)
	}
	if err := h.validate(); err != nil {
		return nil, 0, fmt.Errorf("malformed local file: %w", err)
	}
	return &h, payloadSize, nil
}

// validate checks what Open does not: the emails, and that the wraps name
// distinct, well-formed fingerprints.
func (h *localHeader) validate() error {
	if !plausibleEmail(h.SenderEmail) {
		return errors.New("invalid sender email")
	}
	if len(h.Manifest) == 0 {
		return errors.New("missing manifest")
	}
	if len(h.Wraps) == 0 {
		return errors.New("no recipients")
	}
	seen := make(map[string]bool, len(h.Wraps))
	for i, w := range h.Wraps {
		if len(w.Fingerprint) != 64 || strings.ToLower(w.Fingerprint) != w.Fingerprint {
			return fmt.Errorf("recipient %d has an invalid fingerprint", i)
		}
		if _, err := hex.DecodeString(w.Fingerprint); err != nil {
			return fmt.Errorf("recipient %d has an invalid fingerprint", i)
		}
		if seen[w.Fingerprint] {
			return fmt.Errorf("recipient %s is listed twice", crypto.ShortFingerprint(w.Fingerprint))
		}
		seen[w.Fingerprint] = true
		if w.Email != "" && !plausibleEmail(w.Email) {
			return fmt.Errorf("recipient %d has an invalid email", i)
		}
	}
	return nil
}

// plausibleEmail accepts what could be an email address and nothing that
// could change the path it is looked up under or the terminal it is
// printed to: only printable characters, no spaces, controls or
// formatting marks.
func plausibleEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if len(s) > maxEmailLen || at < 1 || at == len(s)-1 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == ' ' || !unicode.IsPrint(r) || strings.ContainsRune("/\\?#%", r) {
			return false
		}
	}
	return true
}

// copyProgress reports how much of total has been read.
type copyProgress struct {
	r          io.Reader
	n, total   int64
	onProgress func(transferred, total int64)
}

func (p *copyProgress) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n += int64(n)
		p.onProgress(p.n, p.total)
	}
	return n, err
}
