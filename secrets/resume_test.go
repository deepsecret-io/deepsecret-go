// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/secrets"
	"github.com/deepsecret-io/deepsecret-go/trust"
)

// interruptedSend starts a three-part send that storage stops at part 2,
// with one upload thread so part 1 is in storage and part 3 never went.
func interruptedSend(t *testing.T, f *fakeAPI, dir string) ([]byte, *secrets.UploadInterruptedError) {
	t.Helper()
	// The SDK keeps ciphertext only in a folder private to this user.
	disktest.MakePrivate(t, dir)
	f.multipartAt, f.partSize, f.refusePart = 5<<20, 5<<20, 2
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 12<<20)
	writeFile(t, src, data, 0o600)
	_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{ResumeDir: dir, UploadThreads: 1})
	var interrupted *secrets.UploadInterruptedError
	if !errors.As(err, &interrupted) {
		t.Fatalf("send: %v, want an interrupted upload", err)
	}
	return data, interrupted
}

func TestInterruptedSendResumes(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	data, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID

	pending, err := secrets.ListPendingUploads(dir)
	if err != nil || len(pending) != 1 || pending[0].RevisionID != rev || pending[0].Name != "backup.bin" {
		t.Fatalf("pending: %+v, %v", pending, err)
	}
	// On Windows the folder is private, and what is in it inherits that.
	if runtime.GOOS == "windows" {
		disktest.AssertPrivate(t, pending[0].Dir)
	}
	for path, mode := range map[string]os.FileMode{
		pending[0].Dir:                               0o700 | os.ModeDir,
		filepath.Join(pending[0].Dir, "payload"):     0o600,
		filepath.Join(pending[0].Dir, "upload.json"): 0o600,
	} {
		if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode() != mode) {
			t.Fatalf("%s: %v, %v", path, info.Mode(), err)
		}
	}

	f.mu.Lock()
	f.refusePart = 0
	before := f.puts
	f.mu.Unlock()
	alice := f.client("alice@example.com")
	if _, err := alice.Secrets.ResumeUpload(context.Background(), dir, rev, secrets.ResumeOptions{}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	f.mu.Lock()
	sent := f.puts - before
	f.mu.Unlock()
	if sent != 2 {
		t.Fatalf("resume sent %d parts, want the 2 storage lacked", sent)
	}
	if left, _ := secrets.ListPendingUploads(dir); len(left) != 0 {
		t.Fatalf("still pending: %+v", left)
	}
	assertEmptyDir(t, dir)

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), interrupted.Upload.SecretID, out, secrets.DecryptOptions{}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// Ctrl+C in the CLI cancels the client's root context. A send cancelled
// mid-upload keeps its ciphertext and record, and resumes with a new
// client, sending only the parts storage lacks.
func TestCancelledSendResumes(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
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
	_, err := alice.Secrets.EncryptPaths(ctx, []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{ResumeDir: dir, UploadThreads: 1})
	var interrupted *secrets.UploadInterruptedError
	if !errors.As(err, &interrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled send: %v, want an interrupted upload caused by the cancel", err)
	}
	pending, err := secrets.ListPendingUploads(dir)
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
	if _, err := f.client("alice@example.com").Secrets.ResumeUpload(context.Background(), dir, interrupted.Upload.RevisionID, secrets.ResumeOptions{}); err != nil {
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
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), interrupted.Upload.SecretID, out, secrets.DecryptOptions{}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

func TestDiscardPendingUpload(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID
	alice := f.client("alice@example.com")
	if err := alice.Secrets.DiscardPendingUpload(context.Background(), dir, rev); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	_, live := f.uploads[rev]
	f.mu.Unlock()
	if live {
		t.Fatal("the upload was not aborted on the server")
	}
	assertEmptyDir(t, dir)
	if _, err := alice.Secrets.ResumeUpload(context.Background(), dir, rev, secrets.ResumeOptions{}); err == nil {
		t.Fatal("resumed a discarded upload")
	}
}

// Revision IDs name folders, so anything else is refused.
func TestPendingUploadsRefuseOddIDs(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.client("alice@example.com")
	for _, id := range []string{"../etc", "", "a/b"} {
		if _, err := alice.Secrets.ResumeUpload(context.Background(), t.TempDir(), id, secrets.ResumeOptions{}); err == nil {
			t.Errorf("resume %q accepted", id)
		}
		if err := alice.Secrets.DiscardPendingUpload(context.Background(), t.TempDir(), id); err == nil {
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
	_, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{TempDir: tmp})
	var interrupted *secrets.UploadInterruptedError
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
	past := time.Now().Add(-2 * secrets.AbandonedAfter)
	os.Chtimes(filepath.Join(old, "payload"), past, past)
	secrets.PruneAbandoned(dir, "")
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the abandoned folder is still there")
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal("a recent folder was removed")
	}
}

// An interrupted send recorded none of its recipients' keys: it stopped
// before a send does. The upload record lists the ones new to this device,
// and the resume that finishes the upload records them and returns them,
// so a first contact made through a resume is pinned and reported like any
// other.
func TestResumedSendRecordsFirstUseKeys(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, interrupted := interruptedSend(t, f, dir)
	bob := secrets.Recipient{Email: "bob@example.com", Fingerprint: f.members["bob@example.com"].fp}
	alice := f.client("alice@example.com")

	if got := interrupted.Upload.FirstUse; len(got) != 1 || got[0] != bob {
		t.Fatalf("the interrupted upload lists %+v as first use, want bob's key", got)
	}
	pending, err := secrets.ListPendingUploads(dir)
	if err != nil || len(pending) != 1 || len(pending[0].FirstUse) != 1 || pending[0].FirstUse[0] != bob {
		t.Fatalf("the upload record: %+v, %v, want bob's key listed", pending, err)
	}
	if known := knownKeys(t, alice, "bob@example.com"); len(known) != 0 {
		t.Fatalf("an interrupted send recorded %+v", known)
	}

	f.mu.Lock()
	f.refusePart = 0
	f.mu.Unlock()
	done, err := alice.Secrets.ResumeUpload(context.Background(), dir, interrupted.Upload.RevisionID, secrets.ResumeOptions{})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if len(done.FirstUse) != 1 || done.FirstUse[0] != bob {
		t.Fatalf("the resume reports %+v as first use, want bob's key", done.FirstUse)
	}
	known := knownKeys(t, alice, "bob@example.com")
	if k, ok := known[bob.Fingerprint]; !ok || len(known) != 1 || k.State != trust.FirstUse {
		t.Fatalf("known keys after the resume: %+v, want bob's key accepted on first use", known)
	}

	// The next send to bob is no first use, and a changed key is refused.
	res, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{Name: "n"})
	if err != nil || len(res.FirstUse) != 0 {
		t.Fatalf("a send after the resume: %+v, %v, want no first use", res, err)
	}
}

// A key this device recorded for the recipient after the send was sealed
// stops the resume before the upload is finished, with the error a send to
// them gets: the revision was sealed for a key no longer accepted for them,
// so it must not become downloadable.
func TestResumeRefusesAKeyRecordedMeanwhile(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID
	alice := f.client("alice@example.com")

	// Meanwhile bob's real key was accepted on this device, by another send.
	accepted := fmt.Sprintf("%064x", 7)
	store := knownkeys.New(f.knownFile("alice@example.com"), f.srv.URL, f.members["alice@example.com"].keys)
	if err := store.RecordFirstUse([]knownkeys.Person{{Email: "bob@example.com", Fingerprint: accepted}}, false); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.refusePart = 0
	before := f.puts
	f.mu.Unlock()
	_, err := alice.Secrets.ResumeUpload(context.Background(), dir, rev, secrets.ResumeOptions{})
	var changed *trust.KeyChangedError
	if !errors.As(err, &changed) || changed.Email != "bob@example.com" || changed.Got != f.members["bob@example.com"].fp || changed.Sender {
		t.Fatalf("resume: %v, want a trust.KeyChangedError for bob's key", err)
	}
	f.mu.Lock()
	sent := f.puts - before
	f.mu.Unlock()
	if sent != 0 || len(f.object(rev)) != 0 {
		t.Fatalf("the refused resume sent %d parts and stored %d bytes: the upload must not be finished", sent, len(f.object(rev)))
	}
	if known := knownKeys(t, alice, "bob@example.com"); len(known) != 1 || known[accepted].Email != "bob@example.com" {
		t.Fatalf("known keys after the refused resume: %+v, want the key recorded meanwhile only", known)
	}
	// The upload stays, to be discarded.
	if pending, err := secrets.ListPendingUploads(dir); err != nil || len(pending) != 1 {
		t.Fatalf("pending after the refused resume: %+v, %v", pending, err)
	}
	if err := alice.Secrets.DiscardPendingUpload(context.Background(), dir, rev); err != nil {
		t.Fatal(err)
	}
}

// What an upload record lists goes into the known keys file, so a record
// listing a malformed key is refused, not resumed.
func TestResumeRefusesADamagedFirstUseList(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, interrupted := interruptedSend(t, f, dir)
	rev := interrupted.Upload.RevisionID
	record := filepath.Join(interrupted.Upload.Dir, "upload.json")
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), f.members["bob@example.com"].fp, "not-a-fingerprint", 1)
	if edited == string(raw) {
		t.Fatalf("the record does not list bob's key:\n%s", raw)
	}
	writeFile(t, record, []byte(edited), 0o600)
	if _, err := f.client("alice@example.com").Secrets.ResumeUpload(context.Background(), dir, rev, secrets.ResumeOptions{}); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("resume of a record listing a malformed key: %v, want it refused", err)
	}
}
