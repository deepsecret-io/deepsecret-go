// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/deepsecret-io/sdk/crypto"
)

// openLocal opens path as email and decrypts it in memory.
func (f *fakeAPI) openLocal(email, path string) (*DecryptResult, error) {
	f.t.Helper()
	o, err := f.client(email).OpenLocalFile(path, DecryptOptions{})
	if err != nil {
		return nil, err
	}
	defer o.Close()
	d, err := o.Payload()
	if err != nil {
		return nil, err
	}
	res := o.Result
	res.Decrypted = d
	return &res, nil
}

func TestLocalFileRoundTrip(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["carol@example.com"]
	path := filepath.Join(t.TempDir(), "note"+LocalFileExt)

	res, err := f.client(alice.email).EncryptText([]string{bob.email, carol.email}, "offline hello", EncryptOptions{LocalFile: path})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if f.creates != 0 || f.puts != 0 {
		t.Fatalf("a local send created %d secrets and uploaded %d objects", f.creates, f.puts)
	}
	if res.LocalFile != path || res.Secret.ID != "" || res.SenderFingerprint != alice.fp || len(res.Recipients) != 2 {
		t.Fatalf("result %+v", res)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(raw, localMagicItem) {
		t.Fatalf("file does not start with the magic: %v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, want 0600", info.Mode().Perm())
	}

	for _, r := range []*fakeActor{bob, carol} {
		out, err := f.openLocal(r.email, path)
		if err != nil {
			t.Fatalf("%s open: %v", r.email, err)
		}
		if out.Decrypted.Message != "offline hello" || out.SenderEmail != alice.email || out.SenderFingerprint != alice.fp || out.RecipientFingerprint != r.fp {
			t.Fatalf("%s: got %+v", r.email, out)
		}
		for _, sr := range out.Recipients {
			if (sr.Fingerprint == bob.fp) != (sr.Email == bob.email) || sr.Email == "" {
				t.Errorf("%s: recipient %+v is mislabeled", r.email, sr)
			}
		}
	}
	if _, err := f.openLocal(alice.email, path); err == nil || !strings.Contains(err.Error(), "not encrypted for your key") {
		t.Fatalf("sender who is not a recipient: %v", err)
	}

	// Recipient emails are unsigned labels: one moved to another key is
	// not shown, though the file still opens.
	rewriteHeader(t, path, func(h *localHeader) {
		for i := range h.Wraps {
			if h.Wraps[i].Fingerprint == carol.fp {
				h.Wraps[i].Email = bob.email
			}
		}
	})
	out, err := f.openLocal(bob.email, path)
	if err != nil {
		t.Fatalf("open relabeled: %v", err)
	}
	for _, sr := range out.Recipients {
		if sr.Fingerprint == carol.fp && sr.Email != "" {
			t.Fatalf("carol's key is shown as %s", sr.Email)
		}
		if sr.Fingerprint == bob.fp && sr.Email != bob.email {
			t.Fatalf("bob's own label was dropped: %+v", sr)
		}
	}
}

// Files over the in-memory size go through a private temporary file, and
// write out as a cloud send's do.
func TestLocalFileWithLargeFiles(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := t.TempDir()
	data := make([]byte, 6<<20)
	rand.Read(data)
	if err := os.WriteFile(filepath.Join(src, "disk.img"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "disk"+LocalFileExt)
	if _, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, filepath.Join(src, "disk.img"), EncryptOptions{LocalFile: path}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	o, err := f.client("bob@example.com").OpenLocalFile(path, DecryptOptions{TempDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer o.Close()
	if o.spool.file == nil {
		t.Fatal("a 6 MiB payload was copied into memory")
	}
	dst := t.TempDir()
	if _, err := o.WriteFiles(dst, WriteOptions{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "disk.img"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("written file differs: %v", err)
	}
}

func TestLocalFileOverwrite(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := t.TempDir()
	path := filepath.Join(dir, "a"+LocalFileExt)
	c := f.client("alice@example.com")
	if _, err := c.EncryptText([]string{"bob@example.com"}, "one", EncryptOptions{LocalFile: path}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EncryptText([]string{"bob@example.com"}, "two", EncryptOptions{LocalFile: path}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second write over the file: %v", err)
	}
	if _, err := c.EncryptText([]string{"bob@example.com"}, "two", EncryptOptions{LocalFile: path, LocalOverwrite: true}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if out, err := f.openLocal("bob@example.com", path); err != nil || out.Decrypted.Message != "two" {
		t.Fatalf("after overwrite: %+v, %v", out, err)
	}
	// A failed send leaves nothing behind.
	if _, err := c.EncryptText([]string{"nobody@example.com"}, "x", EncryptOptions{LocalFile: filepath.Join(dir, "b"+LocalFileExt)}); err == nil {
		t.Fatal("a send to an unknown recipient succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the first file", len(entries))
	}
}

// rewriteHeader replaces a local file's header with what edit makes of it.
func rewriteHeader(t *testing.T, path string, edit func(*localHeader)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h, size, err := readLocalHeader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	edit(h)
	data, err := cbor.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	out := append(raw[:localPrefixLen+size:localPrefixLen+size], data...)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalFileRefusesTampering(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "mallory@example.com")
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig"+LocalFileExt)
	if _, err := f.client("alice@example.com").EncryptText([]string{"bob@example.com"}, "the real one", EncryptOptions{LocalFile: orig}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(orig)
	variant := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	clone := func() []byte { return append([]byte(nil), raw...) }

	flipped := clone()
	flipped[localPrefixLen+10] ^= 1
	longer := clone()
	longer[len(localMagicItem)+8]++
	cases := map[string]struct {
		path, want string
	}{
		"payload byte flipped": {variant("flipped", flipped), "does not match the signed manifest"},
		"truncated":            {variant("truncated", raw[:len(raw)-40]), "malformed"},
		"trailing bytes":       {variant("trailing", append(clone(), 0)), "malformed"},
		"length changed":       {variant("longer", longer), "malformed"},
		"not a local file":     {variant("random", []byte("hello, this is not one")), "not a DeepSecret local file"},
	}
	// The sender named as someone else: their keys do not include the one
	// that signed.
	relabeled := variant("relabeled", clone())
	rewriteHeader(t, relabeled, func(h *localHeader) { h.SenderEmail = "mallory@example.com" })
	cases["sender relabeled"] = struct{ path, want string }{relabeled, "no key matching"}
	// A path-changing email is refused before any lookup.
	pathy := variant("pathy", clone())
	rewriteHeader(t, pathy, func(h *localHeader) { h.SenderEmail = "../../actors/me@x" })
	cases["sender email with a path"] = struct{ path, want string }{pathy, "invalid sender email"}
	// The revision ID names the output directory, so a sender cannot make
	// it a path; it is checked before the signature.
	pathID := variant("path-id", clone())
	rewriteHeader(t, pathID, func(h *localHeader) {
		m, err := crypto.UnmarshalManifest(h.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		m.RevisionID = "../../escape"
		if h.Manifest, err = m.Marshal(); err != nil {
			t.Fatal(err)
		}
	})
	cases["revision ID is a path"] = struct{ path, want string }{pathID, "not a UUID"}
	// A wrap moved to another fingerprint does not match the signed one.
	dup := variant("dup", clone())
	rewriteHeader(t, dup, func(h *localHeader) { h.Wraps = append(h.Wraps, h.Wraps[0]) })
	cases["wrap listed twice"] = struct{ path, want string }{dup, "listed twice"}

	for name, c := range cases {
		out, err := f.openLocal("bob@example.com", c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %+v, %v; want an error with %q", name, out, err, c.want)
		}
	}
	if out, err := f.openLocal("bob@example.com", orig); err != nil || out.Decrypted.Message != "the real one" {
		t.Fatalf("the original no longer opens: %v", err)
	}
}

// Emails from a file are looked up and printed, so they may not hold path
// characters, controls (C0 or C1, such as an ANSI escape) or formatting
// marks such as a right-to-left override.
func TestPlausibleEmail(t *testing.T) {
	for _, s := range []string{"alice@example.com", "o'brien+x@example.co.uk", "ünï@exämple.com"} {
		if !plausibleEmail(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{
		"", "alice", "@example.com", "alice@", "a b@example.com", "a/b@example.com", "../x@y",
		"a\x1b[31m@example.com", "a\u009b31m@example.com", "a\u202e@example.com", "a\x00@example.com",
		"bad\xff@example.com", strings.Repeat("a", 250) + "@example.com",
	} {
		if plausibleEmail(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
