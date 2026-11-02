// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

type party struct {
	kp  *KeyPair
	fp  string
	pub *PublicKeys
}

func newParty(t *testing.T) party {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return party{kp: kp, fp: fp, pub: &PublicKeys{
		ED25519: kp.ED25519Public, X25519: kp.X25519Public,
		MLKEM768: kp.MLKEM768PK, MLDSA65: kp.MLDSA65PK, Fingerprint: fp,
	}}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

var msgParams = SealParams{RevisionID: "4f9c1e5a-8b2d-4c3e-9f1a-2b3c4d5e6f70", SecretName: "db-password", PayloadType: "message"}

func seal(t *testing.T, plaintext []byte, sender party, p SealParams, recipients ...party) ([]byte, *Sealed) {
	t.Helper()
	pubs := make([]*PublicKeys, len(recipients))
	for i, r := range recipients {
		pubs[i] = r.pub
	}
	ct, sealed, err := SealBytes(plaintext, sender.kp, pubs, p)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return ct, sealed
}

func wrapData(t *testing.T, s *Sealed, fp string) *Wrap {
	t.Helper()
	w, ok := s.Wrap(fp)
	if !ok {
		t.Fatalf("no wrap for %s", ShortFingerprint(fp))
	}
	return w
}

func open(t *testing.T, s *Sealed, r party, revisionID string) *Opened {
	t.Helper()
	o, err := Open(s.ManifestData, wrapData(t, s, r.fp), r.kp, OpenParams{RevisionID: revisionID, SecretName: msgParams.SecretName})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return o
}

// Every recipient decrypts the one payload, at sizes around the chunk
// boundaries, and the stored object has exactly the size the manifest
// signs.
func TestSealOpenRoundTrip(t *testing.T) {
	sender, alice, bob := newParty(t), newParty(t), newParty(t)
	for _, size := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2*ChunkSize + 5} {
		plaintext := randomBytes(t, size)
		ct, sealed := seal(t, plaintext, sender, msgParams, alice, bob, sender)
		if int64(len(ct)) != sealed.Manifest.CiphertextSize || sealed.Manifest.CiphertextSize != ciphertextSizeFor(int64(size)) {
			t.Fatalf("size %d: ciphertext %d, manifest %d", size, len(ct), sealed.Manifest.CiphertextSize)
		}
		if len(sealed.Wraps) != 3 || len(sealed.Manifest.Recipients) != 3 {
			t.Fatalf("size %d: want 3 wraps", size)
		}
		for _, r := range []party{alice, bob, sender} {
			o := open(t, sealed, r, msgParams.RevisionID)
			got, err := o.Decrypt(ct)
			o.Close()
			if err != nil {
				t.Fatalf("size %d: decrypt: %v", size, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("size %d: plaintext differs", size)
			}
		}
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	sender, alice := newParty(t), newParty(t)
	cases := map[string]struct {
		recipients []*PublicKeys
		params     SealParams
		want       string
	}{
		"no recipients":     {nil, msgParams, "recipients"},
		"duplicate":         {[]*PublicKeys{alice.pub, alice.pub}, msgParams, "listed twice"},
		"no revision":       {[]*PublicKeys{alice.pub}, SealParams{SecretName: "n", PayloadType: "message"}, "revision id"},
		"no secret name":    {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", PayloadType: "message"}, "secret name"},
		"padded name":       {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: "token ", PayloadType: "message"}, "white space"},
		"line break":        {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: "token\nRun: rm", PayloadType: "message"}, "control"},
		"bidi override":     {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: "invoice\u202etxt.exe", PayloadType: "message"}, "bidi"},
		"name not utf-8":    {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: "token\xff", PayloadType: "message"}, "UTF-8"},
		"name too long":     {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: strings.Repeat("a", maxSecretNameLen+1), PayloadType: "message"}, "secret name"},
		"bad payload type":  {[]*PublicKeys{alice.pub}, SealParams{RevisionID: "r", SecretName: "n", PayloadType: "exe"}, "payload type"},
		"wrong fingerprint": {[]*PublicKeys{{ED25519: alice.pub.ED25519, X25519: alice.pub.X25519, MLKEM768: alice.pub.MLKEM768, MLDSA65: alice.pub.MLDSA65, Fingerprint: strings.Repeat("a", 64)}}, msgParams, "fingerprint mismatch"},
	}
	for name, c := range cases {
		if _, _, err := SealBytes([]byte("x"), sender.kp, c.recipients, c.params); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// Open refuses anyone not listed, a wrap made for someone else, a wrap from
// another revision, a manifest for another revision, and one signed for
// another secret: a server cannot pass one secret's revision off as
// another's, even from the same sender.
func TestOpenRefusesWrongRecipientWrapOrRevision(t *testing.T) {
	sender, alice, bob, eve := newParty(t), newParty(t), newParty(t), newParty(t)
	_, sealed := seal(t, []byte("payload"), sender, msgParams, alice, bob)

	if _, err := Open(sealed.ManifestData, wrapData(t, sealed, alice.fp), eve.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName}); err == nil || !strings.Contains(err.Error(), "not encrypted for your key") {
		t.Errorf("non-recipient: %v", err)
	}
	if _, err := Open(sealed.ManifestData, wrapData(t, sealed, alice.fp), bob.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName}); err == nil || !strings.Contains(err.Error(), "wrap does not match") {
		t.Errorf("someone else's wrap: %v", err)
	}
	if _, err := Open(sealed.ManifestData, wrapData(t, sealed, alice.fp), alice.kp, OpenParams{RevisionID: "another-revision"}); err == nil || !strings.Contains(err.Error(), "not the requested") {
		t.Errorf("other revision: %v", err)
	}
	for _, name := range []string{"api-token", ""} {
		if _, err := Open(sealed.ManifestData, wrapData(t, sealed, alice.fp), alice.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: name}); err == nil || !strings.Contains(err.Error(), "signed for secret") {
			t.Errorf("other secret %q: %v", name, err)
		}
	}

	other := msgParams
	other.RevisionID = "5a0d2f6b-9c3e-4d4f-8a2b-3c4d5e6f7081"
	_, sealed2 := seal(t, []byte("payload"), sender, other, alice)
	if _, err := Open(sealed.ManifestData, wrapData(t, sealed2, alice.fp), alice.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName}); err == nil || !strings.Contains(err.Error(), "wrap does not match") {
		t.Errorf("wrap moved from another revision: %v", err)
	}
}

// A manifest with no secret name was sealed before the name was signed: it
// is refused as outdated, while a name that breaks the rule stays malformed.
func TestUnmarshalManifestRefusesUnnamedAsOutdated(t *testing.T) {
	sender, alice := newParty(t), newParty(t)
	_, sealed := seal(t, []byte("payload"), sender, msgParams, alice)
	m, err := UnmarshalManifest(sealed.ManifestData)
	if err != nil {
		t.Fatal(err)
	}
	m.SecretName = ""
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalManifest(data); !errors.Is(err, ErrOutdatedManifest) {
		t.Errorf("unnamed manifest: got %v, want ErrOutdatedManifest", err)
	}
	if _, err := Open(data, wrapData(t, sealed, alice.fp), alice.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName}); !errors.Is(err, ErrOutdatedManifest) {
		t.Errorf("open an unnamed manifest: got %v, want ErrOutdatedManifest", err)
	}
	m.SecretName = strings.Repeat("a", maxSecretNameLen+1)
	if data, err = m.Marshal(); err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalManifest(data); errors.Is(err, ErrOutdatedManifest) || err == nil || !strings.Contains(err.Error(), "secret name must be") {
		t.Errorf("overlong name: %v", err)
	}
}

// Any change to a signed field, the recipient list included, breaks both
// signatures.
func TestOpenRefusesTamperedManifest(t *testing.T) {
	sender, alice, bob := newParty(t), newParty(t), newParty(t)
	_, sealed := seal(t, []byte("payload"), sender, msgParams, alice, bob)

	tamper := map[string]func(m *Manifest){
		"recipient removed": func(m *Manifest) {
			if m.Recipients[0].Fingerprint == bob.fp {
				m.Recipients = m.Recipients[1:]
			} else {
				m.Recipients = m.Recipients[:1]
			}
		},
		"payload digest": func(m *Manifest) { m.PayloadDigest[0] ^= 1 },
		"payload type":   func(m *Manifest) { m.PayloadType = "data" },
		"timestamp":      func(m *Manifest) { m.Timestamp++ },
		"secret name":    func(m *Manifest) { m.SecretName = "api-token" },
	}
	for name, change := range tamper {
		m, err := UnmarshalManifest(sealed.ManifestData)
		if err != nil {
			t.Fatal(err)
		}
		change(m)
		data, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(data, wrapData(t, sealed, alice.fp), alice.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName}); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("%s: %v", name, err)
		}
	}

	m, _ := UnmarshalManifest(sealed.ManifestData)
	m.Recipients[0], m.Recipients[1] = m.Recipients[1], m.Recipients[0]
	data, _ := m.Marshal()
	if _, err := UnmarshalManifest(data); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Errorf("unsorted recipients: %v", err)
	}

	if _, err := Open(sealed.ManifestData, wrapData(t, sealed, alice.fp), alice.kp, OpenParams{RevisionID: msgParams.RevisionID, SecretName: msgParams.SecretName, SenderED25519: bob.kp.ED25519Public}); err == nil || !strings.Contains(err.Error(), "does not match the expected key") {
		t.Errorf("unexpected sender key: %v", err)
	}
}

// A changed payload is refused before any plaintext is released, and that
// includes a payload a co-recipient encrypted under the shared content key:
// only the sender's signed digest is accepted.
func TestDecryptRefusesPayloadNotSigned(t *testing.T) {
	sender, alice, bob := newParty(t), newParty(t), newParty(t)
	plaintext := randomBytes(t, ChunkSize+10)
	ct, sealed := seal(t, plaintext, sender, msgParams, alice, bob)

	flipped := bytes.Clone(ct)
	flipped[len(flipped)/2] ^= 1
	var out bytes.Buffer
	o := open(t, sealed, bob, msgParams.RevisionID)
	defer o.Close()
	if err := o.DecryptTo(&out, bytes.NewReader(flipped)); err == nil || out.Len() != 0 {
		t.Fatalf("flipped byte: err %v, released %d bytes", err, out.Len())
	}

	// Alice holds the content key and re-encrypts other content under it.
	a := open(t, sealed, alice, msgParams.RevisionID)
	var forged bytes.Buffer
	if _, err := encryptStream(&forged, bytes.NewReader(randomBytes(t, len(plaintext))), a.payloadKey, chunkAAD(msgParams.RevisionID, "message")); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if err := o.DecryptTo(&out, bytes.NewReader(forged.Bytes())); err == nil || out.Len() != 0 {
		t.Fatalf("co-recipient forgery: err %v, released %d bytes", err, out.Len())
	}
}

// The stream itself refuses reordered, dropped, truncated and appended
// chunks, independent of the digest check.
func TestStreamIntegrity(t *testing.T) {
	key := randomBytes(t, 32)
	aad := chunkAAD("rev", "files")
	var buf bytes.Buffer
	if _, err := encryptStream(&buf, bytes.NewReader(randomBytes(t, 3*ChunkSize)), key, aad); err != nil {
		t.Fatal(err)
	}
	ct := buf.Bytes()
	full := ChunkSize + chunkTagSize
	chunk := func(i int) []byte { return ct[i*full : (i+1)*full] }
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	// A payload of exactly 3 chunks ends on a full last chunk.
	if len(ct) != 3*full {
		t.Fatalf("want 3 full chunks, got %d bytes", len(ct))
	}
	cases := map[string][]byte{
		"reordered":             join(chunk(1), chunk(0), chunk(2)),
		"dropped":               join(chunk(0), chunk(2)),
		"cut at a boundary":     join(chunk(0), chunk(1)),
		"appended after last":   join(ct, chunk(0)),
		"cut inside a chunk":    ct[:2*full+100],
		"wrong associated data": nil,
	}
	for name, stream := range cases {
		a := aad
		if stream == nil {
			stream, a = ct, chunkAAD("rev", "data")
		}
		if _, err := decryptStream(&bytes.Buffer{}, bytes.NewReader(stream), key, a); err == nil {
			t.Errorf("%s: decrypted", name)
		}
	}
	if n, err := decryptStream(&bytes.Buffer{}, bytes.NewReader(ct), key, aad); err != nil || n != 3*ChunkSize {
		t.Fatalf("intact stream: %d, %v", n, err)
	}
}
