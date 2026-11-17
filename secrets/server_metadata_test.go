// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// A file send tells the server each file's name and size, never a hash of
// its content: an unsalted SHA-256 would let the server recognise a file it
// has seen before, or confirm a guess at one. The hash goes in the encrypted
// payload only, where the recipient checks it. The create request is read as
// the client sent it, so the hash cannot pass under another field name.
func TestFileSendGivesTheServerNoContentHash(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.client("alice@example.com"), f.client("bob@example.com")
	content := []byte("quarterly figures, not for the server\n")
	sum := sha256.Sum256(content)
	path := filepath.Join(t.TempDir(), "report.txt")
	writeFile(t, path, content, 0o600)

	sends := []struct {
		what, file string
		send       func() (*secrets.EncryptResult, error)
	}{
		{"a streamed file", "report.txt", func() (*secrets.EncryptResult, error) {
			return alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{path}, secrets.EncryptOptions{Name: "streamed"})
		}},
		{"EncryptBytes", "data.bin", func() (*secrets.EncryptResult, error) {
			return alice.Secrets.EncryptBytes(context.Background(), []string{"bob@example.com"}, content, secrets.EncryptOptions{Name: "bytes"})
		}},
	}
	for _, c := range sends {
		res, err := c.send()
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}

		var body struct {
			FilesMeta []map[string]json.RawMessage `json:"files_meta"`
		}
		if err := json.Unmarshal(f.lastBody, &body); err != nil {
			t.Fatalf("%s: create request: %v", c.what, err)
		}
		if len(body.FilesMeta) != 1 {
			t.Fatalf("%s: files_meta lists %d files, want 1: %s", c.what, len(body.FilesMeta), f.lastBody)
		}
		entry := body.FilesMeta[0]
		if fields := slices.Sorted(maps.Keys(entry)); !slices.Equal(fields, []string{"name", "size"}) {
			t.Errorf("%s: files_meta carries %v, want the name and the size only", c.what, fields)
		}
		if name, size := string(entry["name"]), string(entry["size"]); name != `"`+c.file+`"` || size != strconv.Itoa(len(content)) {
			t.Errorf("%s: files_meta names %s of %s bytes, want %q of %d", c.what, name, size, c.file, len(content))
		}
		for form, hash := range map[string]string{
			"hex":             hex.EncodeToString(sum[:]),
			"base64":          base64.StdEncoding.EncodeToString(sum[:]),
			"unpadded base64": base64.RawStdEncoding.EncodeToString(sum[:]),
			"URL base64":      base64.RawURLEncoding.EncodeToString(sum[:]),
		} {
			if bytes.Contains(bytes.ToLower(f.lastBody), []byte(strings.ToLower(hash))) {
				t.Errorf("%s: the create request carries the file's SHA-256 (%s)", c.what, form)
			}
		}

		// The recipient still gets the hash, from the payload it decrypted.
		out, err := bob.Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{})
		if err != nil {
			t.Fatalf("%s: decrypt: %v", c.what, err)
		}
		if files := out.Decrypted.Files; len(files) != 1 || files[0].Name != c.file || files[0].SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: decrypted files %+v, want %s with its SHA-256", c.what, files, c.file)
		}
	}
}

// An IP lock the organization enforces reaches a client by its source alone:
// the API lists no addresses for it, since the organization's allowlist is
// for its admins. A read of the secret and a policy update both report the
// source, in the result and in its JSON form, so a client can show the lock
// in place of no lock.
func TestOrgEnforcedIPLockIsReported(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice := f.client("alice@example.com")
	res, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.ipLockSource = "org-enforced"
	f.mu.Unlock()

	reported := func(what string, result any) {
		t.Helper()
		shown, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(shown, []byte(`"ip_lock_source":"org-enforced"`)) || bytes.Contains(shown, []byte(`"allowed_ips"`)) {
			t.Errorf("%s: %s, want the lock's source and no addresses", what, shown)
		}
	}
	info, err := alice.Secrets.Describe(context.Background(), res.Secret.ID)
	if err != nil {
		t.Fatal(err)
	}
	reported("the secret", info)
	if info.IPLockSource != "org-enforced" || len(info.AllowedIPs) != 0 {
		t.Errorf("the secret: IP lock source %q with addresses %v", info.IPLockSource, info.AllowedIPs)
	}

	ttl := 3600
	policy, err := alice.Secrets.UpdatePolicy(context.Background(), res.Secret.ID, secrets.PolicyUpdate{TTLSeconds: &ttl})
	if err != nil {
		t.Fatal(err)
	}
	reported("the policy update", policy)
	if policy.IPLockSource != "org-enforced" || len(policy.AllowedIPs) != 0 {
		t.Errorf("the policy update: IP lock source %q with addresses %v", policy.IPLockSource, policy.AllowedIPs)
	}
}

// An archive hides its files from the server. The create request of a send
// that goes as an archive names the secret at random unless the caller
// named it, never after the path, and carries neither the files' size
// before compression nor the compression ratio. The sender still gets both
// in the result.
func TestArchiveSendTellsTheServerNothingAboutTheFiles(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice := f.client("alice@example.com")
	folder := filepath.Join(t.TempDir(), "payroll-2026")
	writeFile(t, filepath.Join(folder, "salaries.csv"), bytes.Repeat([]byte("name,amount\n"), 4096), 0o600)
	linked := filepath.Join(t.TempDir(), "linked-tree")
	writeFile(t, filepath.Join(linked, "target.txt"), []byte("target"), 0o600)
	if err := os.Symlink("target.txt", filepath.Join(linked, "link")); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}
	random := regexp.MustCompile(`^sdk-[0-9]+-[0-9a-f]{12}$`)

	for what, c := range map[string]struct {
		path string
		opt  secrets.EncryptOptions
	}{
		"Archive":                     {folder, secrets.EncryptOptions{Archive: true}},
		"an archive forced by a link": {linked, secrets.EncryptOptions{}},
	} {
		res, err := alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{c.path}, c.opt)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !res.Archived || !random.MatchString(res.Secret.Name) {
			t.Errorf("%s: archived %v under the name %q, want an archive under a random name", what, res.Archived, res.Secret.Name)
		}
		if res.OriginalSize == 0 || res.CompressionRatio == 0 {
			t.Errorf("%s: the result has original size %d and ratio %v, want both for the sender", what, res.OriginalSize, res.CompressionRatio)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(f.lastBody, &body); err != nil {
			t.Fatalf("%s: create request: %v", what, err)
		}
		for _, field := range []string{"original_size", "compression_ratio", "files_meta"} {
			if v, sent := body[field]; sent {
				t.Errorf("%s: the create request carries %s = %s", what, field, v)
			}
		}
		if string(body["compression"]) != `"tar+zstd"` || string(body["files_count"]) != "0" {
			t.Errorf("%s: compression %s, files_count %s", what, body["compression"], body["files_count"])
		}
		for _, leak := range []string{filepath.Base(c.path), "salaries", "target.txt"} {
			if bytes.Contains(f.lastBody, []byte(leak)) {
				t.Errorf("%s: the create request names %q", what, leak)
			}
		}
	}

	// A name the caller gives is the caller's to tell.
	res, err := alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{folder}, secrets.EncryptOptions{Archive: true, Name: "q4"})
	if err != nil || res.Secret.Name != "q4" {
		t.Fatalf("a named archive: %+v, %v", res, err)
	}
	// Without an archive the path still names the secret, and a compressed
	// send still says how well it compressed.
	res, err = alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{folder}, secrets.EncryptOptions{Compress: secrets.CompressZstd})
	if err != nil || res.Archived || res.Secret.Name != "payroll-2026" {
		t.Fatalf("a send without an archive: %+v, %v", res, err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(f.lastBody, &body); err != nil || body["original_size"] == nil || body["compression_ratio"] == nil {
		t.Fatalf("a compressed send without an archive carries no original size or ratio: %s, %v", f.lastBody, err)
	}
}
