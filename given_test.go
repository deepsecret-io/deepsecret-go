// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// An open given the secret and its revisions, as the caller just fetched
// them, reads neither again, and the signed manifest is still checked
// against them: a changed name is refused, and so is another secret's.
// The written files report their size, and the result the payload's size
// as sealed.
func TestOpenWithTheSecretGiven(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.client("alice@example.com"), f.client("bob@example.com")
	src := filepath.Join(t.TempDir(), "notes.txt")
	data := bytes.Repeat([]byte("compressible "), 1<<16)
	writeFile(t, src, data, 0o600)
	res, err := alice.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, EncryptOptions{Compress: CompressZstd})
	if err != nil {
		t.Fatal(err)
	}
	detail, err := bob.DescribeSecretFull(context.Background(), res.Secret.ID)
	if err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	gets, lists := f.secretGets, f.revisionLists
	f.mu.Unlock()
	o, err := bob.OpenSecret(context.Background(), res.Secret.ID, DecryptOptions{Secret: detail})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	f.mu.Lock()
	if f.secretGets != gets || f.revisionLists != lists {
		t.Errorf("the open read the secret %d and its revisions %d more times", f.secretGets-gets, f.revisionLists-lists)
	}
	f.mu.Unlock()
	w, err := o.WriteFiles(t.TempDir(), WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w.Size != int64(len(data)) {
		t.Errorf("written size %d, want %d", w.Size, len(data))
	}
	if p := o.Result.PlaintextSize; !o.Result.Compressed || p <= 0 || p >= int64(len(data)) {
		t.Errorf("sealed size %d of %d bytes (compressed %v)", p, len(data), o.Result.Compressed)
	}

	renamed := *detail
	renamed.Secret.Name = "another name"
	if _, err := bob.OpenSecret(context.Background(), res.Secret.ID, DecryptOptions{Secret: &renamed}); err == nil {
		t.Error("a secret given with another name than the signed one was opened")
	}
	other, err := alice.EncryptText(context.Background(), []string{"bob@example.com"}, "other", EncryptOptions{Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	otherDetail, err := bob.DescribeSecretFull(context.Background(), other.Secret.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.OpenSecret(context.Background(), res.Secret.ID, DecryptOptions{Secret: otherDetail}); err == nil {
		t.Error("another secret's details were taken")
	}
}

// A send given the sender's account, as the caller just fetched it, does
// not fetch it again, whether it uploads or writes a local file.
func TestSendWithTheAccountGiven(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice := f.client("alice@example.com")
	me, err := alice.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []string{"", filepath.Join(t.TempDir(), "note"+LocalFileExt)} {
		f.mu.Lock()
		before := f.accountGets
		f.mu.Unlock()
		if _, err := alice.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", EncryptOptions{Name: "note", Account: me, LocalFile: local}); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		if f.accountGets != before {
			t.Errorf("local file %q: the send read the account %d more times", local, f.accountGets-before)
		}
		f.mu.Unlock()
	}
}
