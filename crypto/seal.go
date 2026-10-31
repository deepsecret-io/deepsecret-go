// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"time"
)

// ── Sealing and opening a revision (protocol v4 §2 to §6) ───────────────────

// SealParams describes the revision being sealed.
type SealParams struct {
	RevisionID  string // the revision id the payload is bound to
	SecretName  string // the name of the secret the revision belongs to, as the API stores it
	PayloadType string // "message", "data" or "files"
	Compressed  bool   // whether the plaintext was compressed first
	Compression string // "zstd" or ""
}

// Sealed is the output of Seal besides the payload itself: the signed
// manifest and one wrap per recipient, in manifest order.
type Sealed struct {
	Manifest     *Manifest
	ManifestData []byte
	Wraps        []*Wrap
}

// Wrap returns the wrap made for fingerprint fp, if any.
func (s *Sealed) Wrap(fp string) (*Wrap, bool) {
	for _, w := range s.Wraps {
		if w.RecipientFingerprint == fp {
			return w, true
		}
	}
	return nil, false
}

// Seal encrypts the plaintext read from src once, writing the stored
// payload object to dst, and wraps a fresh content key for every recipient.
// The sender signs a manifest covering the payload and every wrap.
//
// A recipient's Fingerprint, when set, must match its keys. To keep a copy
// the sender lists themself as a recipient.
func Seal(dst io.Writer, src io.Reader, sender *KeyPair, recipients []*PublicKeys, p SealParams) (*Sealed, error) {
	if p.RevisionID == "" || len(p.RevisionID) > maxRevisionIDLen {
		return nil, fmt.Errorf("revision id must be 1 to %d bytes", maxRevisionIDLen)
	}
	if err := validateSecretName(p.SecretName); err != nil {
		return nil, err
	}
	if err := validatePayloadParams(p.PayloadType, p.Compressed, p.Compression); err != nil {
		return nil, err
	}
	signer, err := decodeSigner(sender)
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 || len(recipients) > MaxRecipients {
		return nil, fmt.Errorf("a revision needs 1 to %d recipients, got %d", MaxRecipients, len(recipients))
	}
	keys := make([]recipientKey, 0, len(recipients))
	seen := make(map[string]bool, len(recipients))
	for i, r := range recipients {
		k, err := decodeRecipient(r)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		if seen[k.fp] {
			return nil, fmt.Errorf("recipient %s is listed twice", ShortFingerprint(k.fp))
		}
		seen[k.fp] = true
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].fp < keys[j].fp })

	contentKey := make([]byte, ContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, fmt.Errorf("generate content key: %w", err)
	}
	defer clear(contentKey)
	payloadKey, err := derivePayloadKey(contentKey)
	if err != nil {
		return nil, err
	}
	defer clear(payloadKey)

	stream, err := encryptStream(dst, src, payloadKey, chunkAAD(p.RevisionID, p.PayloadType))
	if err != nil {
		return nil, err
	}

	m := &Manifest{
		Version:           ProtocolVersion,
		CipherSuite:       CipherSuite,
		RevisionID:        p.RevisionID,
		SecretName:        p.SecretName,
		SenderFingerprint: signer.fp,
		SenderED25519:     signer.edPub,
		SenderX25519:      signer.x25519Pub,
		SenderMLKEM768:    signer.mlkemPub,
		SenderMLDSA65:     signer.mldsaPub,
		PayloadType:       p.PayloadType,
		Compressed:        p.Compressed,
		Compression:       p.Compression,
		ChunkSize:         ChunkSize,
		PlaintextSize:     stream.PlaintextSize,
		CiphertextSize:    stream.CiphertextSize,
		PayloadDigest:     stream.Digest,
		Timestamp:         time.Now().Unix(),
	}
	wraps := make([]*Wrap, 0, len(keys))
	for _, k := range keys {
		w, err := sealContentKey(contentKey, k.pub, k.fp, wrapInfo(p.RevisionID, signer.fp, k.fp, stream.Digest))
		if err != nil {
			return nil, fmt.Errorf("wrap for %s: %w", ShortFingerprint(k.fp), err)
		}
		wraps = append(wraps, w)
		m.Recipients = append(m.Recipients, ManifestRecipient{Fingerprint: k.fp, WrapDigest: w.Digest()})
	}

	signable := m.SignableBytes()
	m.Signature = ed25519.Sign(signer.edPriv, signable)
	if m.SignatureMLDSA65, err = SignMLDSA65(signer.mldsaSeed, signable); err != nil {
		return nil, fmt.Errorf("mldsa65 sign: %w", err)
	}
	data, err := m.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return &Sealed{Manifest: m, ManifestData: data, Wraps: wraps}, nil
}

// SealBytes is Seal over an in-memory plaintext. It returns the stored
// payload object.
func SealBytes(plaintext []byte, sender *KeyPair, recipients []*PublicKeys, p SealParams) ([]byte, *Sealed, error) {
	var out bytes.Buffer
	out.Grow(int(ciphertextSizeFor(int64(len(plaintext)))))
	sealed, err := Seal(&out, bytes.NewReader(plaintext), sender, recipients, p)
	if err != nil {
		return nil, nil, err
	}
	return out.Bytes(), sealed, nil
}

// OpenParams says which revision of which secret the caller asked for and,
// optionally, which Ed25519 key the sender is expected to hold.
type OpenParams struct {
	RevisionID    string // required: the manifest must be for this revision
	SecretName    string // required: the manifest must be signed for this secret name
	SenderED25519 string // optional base64 key, cross-checked against the manifest
}

// Opened is a verified manifest together with the payload key recovered
// from the caller's wrap. Call Close when done.
type Opened struct {
	Manifest   *Manifest
	payloadKey []byte
}

// Open performs steps 2 to 4 of opening a revision: it verifies the
// manifest's sender binding and both signatures, checks that the manifest
// is for the requested revision of the requested secret and lists the
// caller with this exact wrap, and opens the wrap. The payload is checked and decrypted afterwards with
// Decrypt or DecryptTo.
func Open(manifestData []byte, w *Wrap, kp *KeyPair, p OpenParams) (*Opened, error) {
	if kp == nil {
		return nil, fmt.Errorf("recipient key pair must not be nil")
	}
	m, err := UnmarshalManifest(manifestData)
	if err != nil {
		return nil, err
	}
	if err := m.verifySignatures(); err != nil {
		return nil, err
	}
	if p.SenderED25519 != "" {
		external, err := base64.RawStdEncoding.DecodeString(p.SenderED25519)
		if err != nil || len(external) != ED25519PubKeySize {
			return nil, fmt.Errorf("external sender ed25519 key is malformed")
		}
		if !bytes.Equal(m.SenderED25519, external) {
			return nil, fmt.Errorf("sender ed25519 key in manifest does not match the expected key")
		}
	}
	if p.RevisionID == "" || m.RevisionID != p.RevisionID {
		return nil, fmt.Errorf("manifest is for revision %q, not the requested %q", m.RevisionID, p.RevisionID)
	}
	if p.SecretName == "" || m.SecretName != p.SecretName {
		return nil, fmt.Errorf("manifest is signed for secret %q, not the requested %q", m.SecretName, p.SecretName)
	}

	localFP, err := Fingerprint(kp)
	if err != nil {
		return nil, fmt.Errorf("compute local fingerprint: %w", err)
	}
	listed, ok := m.Recipient(localFP)
	if !ok {
		return nil, fmt.Errorf("revision was not encrypted for your key (%s)", ShortFingerprint(localFP))
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	if w.RecipientFingerprint != localFP || subtle.ConstantTimeCompare(w.Digest(), listed.WrapDigest) != 1 {
		return nil, fmt.Errorf("wrap does not match the one the sender signed for your key")
	}

	priv, err := decodeRecipientPrivate(kp)
	if err != nil {
		return nil, err
	}
	contentKey, err := openContentKey(w, priv, wrapInfo(m.RevisionID, m.SenderFingerprint, localFP, m.PayloadDigest))
	if err != nil {
		return nil, err
	}
	defer clear(contentKey)
	payloadKey, err := derivePayloadKey(contentKey)
	if err != nil {
		return nil, err
	}
	return &Opened{Manifest: m, payloadKey: payloadKey}, nil
}

// Close clears the payload key.
func (o *Opened) Close() {
	clear(o.payloadKey)
}

// DecryptTo checks src's size and digest against the signed manifest, and
// only then decrypts it into dst. src is read twice, so it must be memory or
// a private temporary file the caller controls.
func (o *Opened) DecryptTo(dst io.Writer, src io.ReadSeeker) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind payload: %w", err)
	}
	size, digest, err := hashStream(src)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if size != o.Manifest.CiphertextSize || subtle.ConstantTimeCompare(digest, o.Manifest.PayloadDigest) != 1 {
		return fmt.Errorf("payload does not match the signed manifest")
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind payload: %w", err)
	}
	n, err := decryptStream(dst, src, o.payloadKey, chunkAAD(o.Manifest.RevisionID, o.Manifest.PayloadType))
	if err != nil {
		return err
	}
	if n != o.Manifest.PlaintextSize {
		return fmt.Errorf("payload decrypted to %d bytes, manifest says %d", n, o.Manifest.PlaintextSize)
	}
	return nil
}

// Decrypt is DecryptTo over an in-memory payload object.
func (o *Opened) Decrypt(payload []byte) ([]byte, error) {
	if int64(len(payload)) != o.Manifest.CiphertextSize {
		return nil, fmt.Errorf("payload does not match the signed manifest")
	}
	var out bytes.Buffer
	out.Grow(int(o.Manifest.PlaintextSize))
	if err := o.DecryptTo(&out, bytes.NewReader(payload)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ── Key decoding ─────────────────────────────────────────────────────────────

// signer is a sender key pair decoded for sealing.
type signer struct {
	fp        string
	edPriv    ed25519.PrivateKey
	edPub     []byte
	x25519Pub []byte
	mlkemPub  []byte
	mldsaPub  []byte
	mldsaSeed []byte
}

func decodeSigner(kp *KeyPair) (*signer, error) {
	if kp == nil {
		return nil, fmt.Errorf("sender key pair must not be nil")
	}
	if kp.ED25519Private == "" || kp.ED25519Public == "" || kp.X25519Public == "" ||
		kp.MLKEM768PK == "" || kp.MLDSA65Seed == "" || kp.MLDSA65PK == "" {
		return nil, fmt.Errorf("sender key pair is missing required fields")
	}
	s := &signer{}
	fields := []struct {
		name string
		in   string
		out  *[]byte
		size int
	}{
		{"ed25519 private", kp.ED25519Private, (*[]byte)(&s.edPriv), ED25519PrivKeySize},
		{"ed25519 public", kp.ED25519Public, &s.edPub, ED25519PubKeySize},
		{"x25519 public", kp.X25519Public, &s.x25519Pub, X25519PubKeySize},
		{"mlkem768 public", kp.MLKEM768PK, &s.mlkemPub, MLKEM768PubKeySize},
		{"mldsa65 public", kp.MLDSA65PK, &s.mldsaPub, MLDSA65PubKeySize},
		{"mldsa65 seed", kp.MLDSA65Seed, &s.mldsaSeed, MLDSA65SeedSize},
	}
	for _, f := range fields {
		b, err := base64.RawStdEncoding.DecodeString(f.in)
		if err != nil {
			return nil, fmt.Errorf("decode sender %s: %w", f.name, err)
		}
		if len(b) != f.size {
			return nil, fmt.Errorf("sender %s key: expected %d bytes, got %d", f.name, f.size, len(b))
		}
		*f.out = b
	}
	fp, err := Fingerprint(kp)
	if err != nil {
		return nil, fmt.Errorf("compute sender fingerprint: %w", err)
	}
	s.fp = fp
	return s, nil
}

// recipientKey is a recipient's fingerprint and HPKE public key.
type recipientKey struct {
	fp  string
	pub hpke.PublicKey
}

func decodeRecipient(r *PublicKeys) (recipientKey, error) {
	if r == nil {
		return recipientKey{}, fmt.Errorf("public keys must not be nil")
	}
	if r.ED25519 == "" || r.X25519 == "" || r.MLKEM768 == "" || r.MLDSA65 == "" {
		return recipientKey{}, fmt.Errorf("public keys must include ED25519, X25519, MLKEM768, and MLDSA65")
	}
	sizes := []struct {
		name string
		in   string
		size int
	}{
		{"ed25519", r.ED25519, ED25519PubKeySize},
		{"x25519", r.X25519, X25519PubKeySize},
		{"mlkem768", r.MLKEM768, MLKEM768PubKeySize},
		{"mldsa65", r.MLDSA65, MLDSA65PubKeySize},
	}
	decoded := make([][]byte, len(sizes))
	for i, s := range sizes {
		b, err := base64.RawStdEncoding.DecodeString(s.in)
		if err != nil {
			return recipientKey{}, fmt.Errorf("decode %s: %w", s.name, err)
		}
		if len(b) != s.size {
			return recipientKey{}, fmt.Errorf("%s public key: expected %d bytes, got %d", s.name, s.size, len(b))
		}
		decoded[i] = b
	}
	fp, err := FingerprintFromPubs(r.ED25519, r.X25519, r.MLKEM768, r.MLDSA65)
	if err != nil {
		return recipientKey{}, err
	}
	if r.Fingerprint != "" && r.Fingerprint != fp {
		return recipientKey{}, fmt.Errorf("fingerprint mismatch: provided %s but keys compute to %s",
			ShortFingerprint(r.Fingerprint), ShortFingerprint(fp))
	}
	pub, err := buildHPKEPublicKey(decoded[2], decoded[1])
	if err != nil {
		return recipientKey{}, fmt.Errorf("build hpke public key: %w", err)
	}
	return recipientKey{fp: fp, pub: pub}, nil
}

func decodeRecipientPrivate(kp *KeyPair) (hpke.PrivateKey, error) {
	x25519Priv, err := base64.RawStdEncoding.DecodeString(kp.X25519Private)
	if err != nil {
		return nil, fmt.Errorf("decode x25519 private: %w", err)
	}
	if len(x25519Priv) != X25519PrivKeySize {
		return nil, fmt.Errorf("recipient x25519 private key: expected %d bytes, got %d", X25519PrivKeySize, len(x25519Priv))
	}
	mlkemSeed, err := base64.RawStdEncoding.DecodeString(kp.MLKEM768SK)
	if err != nil {
		return nil, fmt.Errorf("decode mlkem768 sk: %w", err)
	}
	if len(mlkemSeed) != MLKEM768SeedSize {
		return nil, fmt.Errorf("recipient mlkem768 seed: expected %d bytes, got %d", MLKEM768SeedSize, len(mlkemSeed))
	}
	priv, err := buildHPKEPrivateKey(mlkemSeed, x25519Priv)
	if err != nil {
		return nil, fmt.Errorf("build hpke private key: %w", err)
	}
	return priv, nil
}
