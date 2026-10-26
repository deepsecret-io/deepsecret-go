// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// interruptedSend starts a three-part send that storage stops at part 2,
// with one upload thread so part 1 is in storage and part 3 never went.
func interruptedSend(t *testing.T, f *fakeAPI, dir string) ([]byte, *UploadInterruptedError) {
	t.Helper()
	// The SDK keeps ciphertext only in a folder private to this user.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.multipartAt, f.partSize, f.refusePart = 5<<20, 5<<20, 2
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 12<<20)
	writeFile(t, src, data, 0o600)
	_, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{ResumeDir: dir, UploadThreads: 1})
	var interrupted *UploadInterruptedError
	if !errors.As(err, &interrupted) {
		t.Fatalf("send: %v, want an interrupted upload", err)
	}
	return data, interrupted
}

func TestInterruptedSendResumes(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := t.TempDir()
	data, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID

	pending, err := ListPendingUploads(dir)
	if err != nil || len(pending) != 1 || pending[0].RevisionID != rev || pending[0].Name != "backup.bin" {
		t.Fatalf("pending: %+v, %v", pending, err)
	}
	for path, mode := range map[string]os.FileMode{
		pending[0].Dir:                               0o700 | os.ModeDir,
		filepath.Join(pending[0].Dir, "payload"):     0o600,
		filepath.Join(pending[0].Dir, "upload.json"): 0o600,
	} {
		if info, err := os.Stat(path); err != nil || info.Mode() != mode {
			t.Fatalf("%s: %v, %v", path, info.Mode(), err)
		}
	}

	f.mu.Lock()
	f.refusePart = 0
	before := f.puts
	f.mu.Unlock()
	alice := f.client("alice@example.com")
	if _, err := alice.ResumeUpload(dir, rev, ResumeOptions{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	f.mu.Lock()
	sent := f.puts - before
	f.mu.Unlock()
	if sent != 2 {
		t.Fatalf("resume sent %d parts, want the 2 storage lacked", sent)
	}
	if left, _ := ListPendingUploads(dir); len(left) != 0 {
		t.Fatalf("still pending: %+v", left)
	}
	assertEmptyDir(t, dir)

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(interrupted.Upload.SecretID, out, DecryptOptions{}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// Ctrl+C in the CLI cancels the client's root context. A send cancelled
// mid-upload keeps its ciphertext and record, and resumes with a new
// client, sending only the parts storage lacks.
func TestCancelledSendResumes(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.multipartAt, f.partSize = 5<<20, 5<<20
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 12<<20)
	writeFile(t, src, data, 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.afterPart = func(n int) {
		if n == 1 {
			cancel()
		}
	}
	alice := f.client("alice@example.com")
	alice.SetRootContext(ctx)
	_, err := alice.EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{ResumeDir: dir, UploadThreads: 1})
	var interrupted *UploadInterruptedError
	if !errors.As(err, &interrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send: %v, want an interrupted upload caused by the cancel", err)
	}
	pending, err := ListPendingUploads(dir)
	if err != nil || len(pending) != 1 || pending[0].RevisionID != interrupted.Upload.RevisionID {
		t.Fatalf("pending after cancel: %+v, %v", pending, err)
	}
	if info, err := os.Stat(filepath.Join(pending[0].Dir, "payload")); err != nil || info.Size() != interrupted.Upload.Size {
		t.Fatalf("kept ciphertext: %v, %v", info, err)
	}

	f.mu.Lock()
	f.afterPart = nil
	before := f.puts
	f.mu.Unlock()
	if _, err := f.client("alice@example.com").ResumeUpload(dir, interrupted.Upload.RevisionID, ResumeOptions{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	f.mu.Lock()
	sent := f.puts - before
	f.mu.Unlock()
	if sent != 2 {
		t.Fatalf("resume sent %d parts, want the 2 the cancel stopped", sent)
	}
	assertEmptyDir(t, dir)
	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(interrupted.Upload.SecretID, out, DecryptOptions{}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

func TestDiscardPendingUpload(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := t.TempDir()
	_, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID
	alice := f.client("alice@example.com")
	if err := alice.DiscardPendingUpload(dir, rev); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	_, live := f.uploads[rev]
	f.mu.Unlock()
	if live {
		t.Fatal("the upload was not aborted on the server")
	}
	assertEmptyDir(t, dir)
	if _, err := alice.ResumeUpload(dir, rev, ResumeOptions{}); err == nil {
		t.Fatal("resumed a discarded upload")
	}
}

// Revision IDs name folders, so anything else is refused.
func TestPendingUploadsRefuseOddIDs(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.client("alice@example.com")
	for _, id := range []string{"../etc", "", "a/b"} {
		if _, err := alice.ResumeUpload(t.TempDir(), id, ResumeOptions{}); err == nil {
			t.Errorf("resume %q accepted", id)
		}
		if err := alice.DiscardPendingUpload(t.TempDir(), id); err == nil {
			t.Errorf("discard %q accepted", id)
		}
	}
}

// Without ResumeDir, a failed upload keeps nothing.
func TestFailedSendWithoutResumeDirKeepsNothing(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize, f.refusePart = 5<<20, 5<<20, 1
	tmp := t.TempDir()
	src := filepath.Join(t.TempDir(), "backup.bin")
	writeFile(t, src, randomBytes(t, 6<<20), 0o600)
	_, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{TempDir: tmp})
	var interrupted *UploadInterruptedError
	if err == nil || errors.As(err, &interrupted) {
		t.Fatalf("send: %v", err)
	}
	assertEmptyDir(t, tmp)
}

// A folder a killed send left without an upload record is removed by the
// next send once it is old; a recent one may still be sealing.
func TestAbandonedSendFoldersArePruned(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "10000000-0000-4000-8000-000000000001")
	recent := filepath.Join(dir, "10000000-0000-4000-8000-000000000002")
	for _, d := range []string{old, recent} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(d, "payload"), []byte("ciphertext"), 0o600)
	}
	past := time.Now().Add(-2 * abandonedAfter)
	os.Chtimes(filepath.Join(old, "payload"), past, past)
	pruneAbandoned(dir)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the abandoned folder is still there")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("a recent folder was removed")
	}
}
