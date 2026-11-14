// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/archive"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/deepsecret-io/deepsecret-go/keystore"
)

func newKeyPair(t *testing.T) (*keys.Pair, string) {
	t.Helper()
	kp, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		t.Fatal(err)
	}
	return kp, fp
}

// A sender's own keys, as the server lists them, are accepted only when
// they are the sending identity or another key pair on this device.
func TestCheckOwnKeys(t *testing.T) {
	dir := t.TempDir()
	sender, senderFP := newKeyPair(t)
	stored, storedFP := newKeyPair(t)
	// A password-protected key is checked without its password.
	if err := keystore.Save(dir, storedFP, stored, "correct horse"); err != nil {
		t.Fatal(err)
	}
	attacker, _ := newKeyPair(t)

	pubs := func(kp *keys.Pair) *keys.PublicKeys {
		fp, _ := keys.Fingerprint(kp)
		return &keys.PublicKeys{ED25519: kp.ED25519Public, X25519: kp.X25519Public,
			MLKEM768: kp.MLKEM768PK, MLDSA65: kp.MLDSA65PK, Fingerprint: fp}
	}

	if err := checkOwnKeys(dir, pubs(sender), senderFP); err != nil {
		t.Errorf("sending identity: %v", err)
	}
	if err := checkOwnKeys(dir, pubs(stored), senderFP); err != nil {
		t.Errorf("another key on this device: %v", err)
	}
	if err := checkOwnKeys(dir, pubs(attacker), senderFP); err == nil || !strings.Contains(err.Error(), "not a key on this device") {
		t.Errorf("substituted key: %v, want refused", err)
	}

	// The fingerprint is computed from the keys, never taken from the
	// Fingerprint field.
	forged := pubs(attacker)
	forged.Fingerprint = senderFP
	if err := checkOwnKeys(dir, forged, senderFP); err == nil {
		t.Error("substituted key labelled with the sender's fingerprint accepted")
	}
}

// A TTL is a whole positive number of minutes, hours or days; nothing
// else is read as one.
func TestParseTTL(t *testing.T) {
	for in, want := range map[string]int{"30m": 1800, "24h": 86400, "7d": 604800, " 2m ": 120} {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "h", "1.5h", "0m", "-5m", "+5m", "5s", "5", "1e3m", "9999999d"} {
		if _, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) accepted", in)
		}
	}
}

// Up to autoArchiveFiles regular files go without an archive and more in
// one; directory entries do not count, and the reason counts the files in
// the right number.
func TestShouldArchive(t *testing.T) {
	files := func(n int) []archive.ExpandedFile {
		out := []archive.ExpandedFile{{RelPath: "dir", IsDir: true}}
		for i := range n {
			out = append(out, archive.ExpandedFile{RelPath: fmt.Sprintf("dir/f%d", i)})
		}
		return out
	}
	for _, c := range []struct {
		n   int
		on  bool
		why string
	}{
		{1, false, "1 file: up to 50 are sent without an archive"},
		{50, false, "50 files: up to 50 are sent without an archive"},
		{51, true, "51 files: more than 50 are sent as one archive"},
	} {
		if on, why := shouldArchive(files(c.n), EncryptOptions{AutoArchive: true}); on != c.on || why != c.why {
			t.Errorf("%d files: %v %q, want %v %q", c.n, on, why, c.on, c.why)
		}
	}
	if on, why := shouldArchive(files(1), EncryptOptions{Archive: true}); !on || why != "requested" {
		t.Errorf("--archive: %v %q", on, why)
	}
	if on, why := shouldArchive(files(60), EncryptOptions{}); on || why != "not requested" {
		t.Errorf("without AutoArchive: %v %q", on, why)
	}
}

// A payload that does not fit on the disk is refused before anything is
// written, and so is one under a parent that is not a directory.
func TestWriteChecks(t *testing.T) {
	if err := checkFreeSpace(t.TempDir(), 1<<60, "the decrypted files", ""); err == nil || !strings.Contains(err.Error(), "not enough free space") {
		t.Fatalf("free space: %v", err)
	}
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "file"), []byte("x"), 0o600)
	if err := checkDestination(dir, "file/inner", false); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("under a file: %v", err)
	}
	if err := checkDestination(dir, "file", false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing: %v", err)
	}
	if err := checkDestination(dir, "file", true); err != nil {
		t.Fatalf("existing with overwrite: %v", err)
	}
	if err := checkDestination(dir, "new/dir/f", false); err != nil {
		t.Fatalf("new path: %v", err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// A file sent on its own that is replaced between the scan and the read is
// refused with ErrFileChanged, naming it, instead of sending the new file's
// bytes under the scanned name and size.
func TestFileSourceRefusesAReplacedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	writeTestFile(t, path, []byte("one\n"), 0o600)
	info, err := archive.Capture(path)
	if err != nil {
		t.Fatal(err)
	}
	src := fileSource("app.log", path, info)

	writeTestFile(t, path+".new", []byte("two\n"), 0o600)
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Open(); !errors.Is(err, ErrFileChanged) || !strings.Contains(err.Error(), path) {
		t.Fatalf("Open: %v, want ErrFileChanged naming %s", err, path)
	}
}
