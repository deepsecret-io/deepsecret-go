// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

const mib = 1 << 20

// privateDir is a ResumeDir: the SDK keeps ciphertext only in a folder
// private to this user.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// sendLarge sends bob a 20 MiB file, which downloads in three ranges: 8
// MiB, 8 MiB and the rest.
func sendLarge(t *testing.T, f *fakeAPI) (string, []byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 20*mib)
	writeFile(t, src, data, 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Secret.ID, data
}

// interruptedDownload sends bob a large file and starts his decrypt with
// one thread, cancelling it once the first 8 MiB range is in: the
// download is kept in dir, holding that range.
func interruptedDownload(t *testing.T, f *fakeAPI, dir string) (string, []byte, *DownloadInterruptedError) {
	t.Helper()
	secretID, data := sendLarge(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bob := f.client("bob@example.com")
	bob.SetRootContext(ctx)
	_, _, err := bob.DecryptToDir(secretID, t.TempDir(), DecryptOptions{
		ResumeDir: dir, DownloadThreads: 1,
		OnDownloadProgress: func(done, _ int64) {
			if done >= 8*mib {
				cancel()
			}
		},
	}, WriteOptions{})
	var interrupted *DownloadInterruptedError
	if !errors.As(err, &interrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled decrypt: %v, want an interrupted download caused by the cancel", err)
	}
	if got := interrupted.Download.Downloaded(); got != 8*mib {
		t.Fatalf("kept %d bytes, want the 8 MiB of the first range", got)
	}
	return secretID, data, interrupted
}

// rangesSince returns every range storage was asked for since the first
// n, as [from, to), and the bytes they add up to. A range in flight can be
// split, so the count of requests is not fixed; their bytes are.
func rangesSince(t *testing.T, f *fakeAPI, n int) ([][2]int64, int64) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var ranges [][2]int64
	var total int64
	for _, r := range f.ranges[n:] {
		var start, end int64
		if _, err := fmt.Sscanf(r, "bytes=%d-%d", &start, &end); err != nil {
			t.Fatalf("range %q: %v", r, err)
		}
		ranges = append(ranges, [2]int64{start, end + 1})
		total += end + 1 - start
	}
	return ranges, total
}

func rangeCount(f *fakeAPI) (ranges, presigns int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ranges), f.presigns
}

func TestInterruptedDownloadResumes(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, data, interrupted := interruptedDownload(t, f, dir)
	if kept := interrupted.Download; kept.SecretID != secretID || kept.Name != "backup.bin" {
		t.Fatalf("kept download %+v", kept)
	}

	pending, err := ListPendingDownloads(dir)
	if err != nil || len(pending) != 1 || pending[0].RevisionID != interrupted.Download.RevisionID || pending[0].Downloaded() != 8*mib {
		t.Fatalf("pending: %+v, %v", pending, err)
	}
	for path, mode := range map[string]os.FileMode{
		pending[0].Dir:                                 0o700 | os.ModeDir,
		filepath.Join(pending[0].Dir, "payload"):       0o600,
		filepath.Join(pending[0].Dir, "download.json"): 0o600,
	} {
		if info, err := os.Stat(path); err != nil || info.Mode() != mode {
			t.Fatalf("%s: %v, %v", path, info.Mode(), err)
		}
	}

	before, presigns := rangeCount(f)
	out := t.TempDir()
	res, _, err := f.client("bob@example.com").DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{})
	if err != nil {
		t.Fatalf("resumed decrypt: %v", err)
	}
	if res.ResumedBytes != 8*mib {
		t.Fatalf("ResumedBytes %d, want 8 MiB", res.ResumedBytes)
	}
	ranges, fetched := rangesSince(t, f, before)
	if fetched != res.EncryptedSize-8*mib {
		t.Fatalf("the resumed download fetched %d bytes in %v, want the %d it lacked", fetched, ranges, res.EncryptedSize-8*mib)
	}
	for _, r := range ranges {
		if r[0] < 8*mib {
			t.Fatalf("the resumed download fetched bytes from %d again", r[0])
		}
	}
	if _, now := rangeCount(f); now != presigns+1 {
		t.Fatalf("%d presigns for the resumed download, want 1", now-presigns)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
	assertEmptyDir(t, dir)
}

// A download that finished, but whose files could not be written, stays:
// the next decrypt fetches nothing, yet still presigns, which is where the
// server applies the secret's policies and records the download.
func TestFinishedDownloadIsKeptUntilDecrypted(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, data := sendLarge(t, f)
	out := t.TempDir()
	writeFile(t, filepath.Join(out, "backup.bin"), []byte("already here"), 0o600)

	bob := f.client("bob@example.com")
	if _, _, err := bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("decrypt onto an existing file: %v", err)
	}
	pending, err := ListPendingDownloads(dir)
	if err != nil || len(pending) != 1 || pending[0].Downloaded() != pending[0].Size {
		t.Fatalf("pending after the failed write: %+v, %v", pending, err)
	}

	before, presigns := rangeCount(f)
	res, _, err := bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{Overwrite: true})
	if err != nil {
		t.Fatal(err)
	}
	ranges, now := rangeCount(f)
	if ranges != before || now != presigns+1 {
		t.Fatalf("%d ranges and %d presigns, want none and 1", ranges-before, now-presigns)
	}
	if res.ResumedBytes != res.EncryptedSize {
		t.Fatalf("ResumedBytes %d of %d", res.ResumedBytes, res.EncryptedSize)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
	assertEmptyDir(t, dir)
}

// Kept bytes that no longer match fail the digest check like any download
// that does not match, are discarded, and the next decrypt starts afresh.
func TestKeptDownloadThatFailsItsCheckIsDiscarded(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, data, interrupted := interruptedDownload(t, f, dir)
	payload, err := os.OpenFile(filepath.Join(interrupted.Download.Dir, "payload"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := payload.ReadAt(b, 4096); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := payload.WriteAt(b, 4096); err != nil {
		t.Fatal(err)
	}
	payload.Close()

	bob := f.client("bob@example.com")
	out := t.TempDir()
	_, _, err = bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{})
	if err == nil || !strings.Contains(err.Error(), "does not match the signed manifest") || !strings.Contains(err.Error(), "kept from an earlier download") {
		t.Fatalf("decrypt of a changed kept download: %v", err)
	}
	assertEmptyDir(t, out)
	assertEmptyDir(t, dir)

	res, _, err := bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{})
	if err != nil || res.ResumedBytes != 0 {
		t.Fatalf("fresh decrypt: %v, resumed %d", err, res.ResumedBytes)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// A kept download whose record does not describe the payload the signed
// manifest does, or that its file cannot back, starts over.
func TestKeptDownloadThatDisagreesStartsOver(t *testing.T) {
	edits := map[string]func(t *testing.T, kept PendingDownload, record map[string]any){
		"another payload": func(_ *testing.T, _ PendingDownload, r map[string]any) { r["payload_digest"] = strings.Repeat("0", 64) },
		"another size":    func(_ *testing.T, _ PendingDownload, r map[string]any) { r["size"] = 21 * mib },
		"another server":  func(_ *testing.T, _ PendingDownload, r map[string]any) { r["api_url"] = "https://elsewhere.example" },
		"another folder":  func(_ *testing.T, _ PendingDownload, r map[string]any) { r["revision_id"] = uuid.NewString() },
		"ranges past the payload": func(_ *testing.T, kept PendingDownload, r map[string]any) {
			r["have"] = [][2]int64{{0, kept.Size + 1}}
		},
		"a file shorter than its ranges": func(t *testing.T, kept PendingDownload, _ map[string]any) {
			if err := os.Truncate(filepath.Join(kept.Dir, "payload"), mib); err != nil {
				t.Fatal(err)
			}
		},
		"garbage": nil,
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			f := newFakeAPI(t, "alice@example.com", "bob@example.com")
			dir := privateDir(t)
			secretID, data, interrupted := interruptedDownload(t, f, dir)
			path := filepath.Join(interrupted.Download.Dir, "download.json")
			out := []byte("{")
			if edit != nil {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				record := map[string]any{}
				if err := json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				edit(t, interrupted.Download, record)
				if out, err = json.Marshal(record); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}

			before, _ := rangeCount(f)
			dest := t.TempDir()
			res, _, err := f.client("bob@example.com").DecryptToDir(secretID, dest, DecryptOptions{ResumeDir: dir}, WriteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if ranges, fetched := rangesSince(t, f, before); res.ResumedBytes != 0 || fetched != res.EncryptedSize {
				t.Fatalf("resumed %d bytes, fetched %d in %v: want a fresh download of all %d", res.ResumedBytes, fetched, ranges, res.EncryptedSize)
			}
			assertFile(t, filepath.Join(dest, "backup.bin"), data, 0o600)
			assertEmptyDir(t, dir)
		})
	}
}

// While one decrypt holds a kept download, another of the same revision
// is refused, and so is discarding it.
func TestKeptDownloadIsLockedWhileInUse(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, data, interrupted := interruptedDownload(t, f, dir)
	held, err := os.Open(filepath.Join(interrupted.Download.Dir, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := lockFile(held); err != nil {
		t.Fatal(err)
	}

	bob := f.client("bob@example.com")
	out := t.TempDir()
	if _, _, err := bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{}); err == nil || !strings.Contains(err.Error(), "another decrypt is downloading") {
		t.Fatalf("second decrypt: %v", err)
	}
	if err := DiscardPendingDownload(dir, interrupted.Download.RevisionID); err == nil {
		t.Fatal("discarded a download in use")
	}
	old := time.Now().Add(-staleDownloadAfter - time.Hour)
	if err := os.Chtimes(filepath.Join(interrupted.Download.Dir, "download.json"), old, old); err != nil {
		t.Fatal(err)
	}
	pruneAbandoned(dir, "")
	if _, err := os.Stat(interrupted.Download.Dir); err != nil {
		t.Fatalf("pruned a download in use: %v", err)
	}
	held.Close()

	// Released, and over a week old, it still resumes: a decrypt never
	// prunes the download it continues.
	res, _, err := bob.DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{})
	if err != nil || res.ResumedBytes != 8*mib {
		t.Fatalf("decrypt once released: %v, resumed %d", err, res.ResumedBytes)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// A kept download unused for a week is removed by the next send or
// decrypt using its ResumeDir; a recent one stays.
func TestStaleKeptDownloadsArePruned(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, _, interrupted := interruptedDownload(t, f, dir)
	pruneAbandoned(dir, "")
	if _, err := os.Stat(interrupted.Download.Dir); err != nil {
		t.Fatalf("pruned a recent download: %v", err)
	}
	old := time.Now().Add(-staleDownloadAfter - time.Hour)
	if err := os.Chtimes(filepath.Join(interrupted.Download.Dir, "download.json"), old, old); err != nil {
		t.Fatal(err)
	}
	pruneAbandoned(dir, "")
	assertEmptyDir(t, dir)
}

// Uploads and downloads kept in one folder stay apart: each listing and
// discard sees only its own.
func TestDiscardPendingDownload(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	_, _, interrupted := interruptedDownload(t, f, dir)
	_, upload := interruptedSend(t, f, dir)

	if uploads, err := ListPendingUploads(dir); err != nil || len(uploads) != 1 {
		t.Fatalf("uploads: %+v, %v", uploads, err)
	}
	if downloads, err := ListPendingDownloads(dir); err != nil || len(downloads) != 1 {
		t.Fatalf("downloads: %+v, %v", downloads, err)
	}
	for _, id := range []string{"../escape", uuid.NewString(), upload.Upload.RevisionID} {
		if err := DiscardPendingDownload(dir, id); err == nil {
			t.Fatalf("discarded %q", id)
		}
	}
	if err := DiscardPendingDownload(dir, strings.ToUpper(interrupted.Download.RevisionID)); err != nil {
		t.Fatal(err)
	}
	if downloads, _ := ListPendingDownloads(dir); len(downloads) != 0 {
		t.Fatalf("still kept: %+v", downloads)
	}
	if uploads, _ := ListPendingUploads(dir); len(uploads) != 1 {
		t.Fatalf("the upload went with the download: %+v", uploads)
	}
}

// A download stopped before any range finished keeps nothing, and its
// error is the download's own.
func TestDownloadStoppedBeforeAnyRangeKeepsNothing(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, _ := sendLarge(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.mu.Lock()
	f.beforeRange = func(r *http.Request) {
		cancel()
		<-r.Context().Done()
	}
	f.mu.Unlock()
	bob := f.client("bob@example.com")
	bob.SetRootContext(ctx)
	_, _, err := bob.DecryptToDir(secretID, t.TempDir(), DecryptOptions{ResumeDir: dir}, WriteOptions{})
	var interrupted *DownloadInterruptedError
	if err == nil || errors.As(err, &interrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("decrypt stopped before any range: %v", err)
	}
	assertEmptyDir(t, dir)
}

// The record names finished ranges while the download still runs, so a
// process that dies mid-download keeps what it fetched.
func TestKeptDownloadRecordsRangesAsTheyFinish(t *testing.T) {
	saved := downloadCheckpoint
	downloadCheckpoint = 10 * time.Millisecond
	t.Cleanup(func() { downloadCheckpoint = saved })

	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	secretID, data := sendLarge(t, f)
	release := make(chan struct{})
	var recorded atomic.Bool
	f.mu.Lock()
	f.beforeRange = func(r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Range"), fmt.Sprintf("bytes=%d-", 16*mib)) {
			return
		}
		// The last range waits until the record lists the two before it.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if kept, _ := ListPendingDownloads(dir); len(kept) == 1 && kept[0].Downloaded() == 16*mib {
				recorded.Store(true)
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(release)
	}
	f.mu.Unlock()

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(secretID, out, DecryptOptions{ResumeDir: dir, DownloadThreads: 1}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	<-release
	if !recorded.Load() {
		t.Fatal("the record did not list the finished ranges while the download ran")
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
	assertEmptyDir(t, dir)
}

// Payloads that stay in memory never touch the ResumeDir.
func TestSmallDecryptsLeaveResumeDirAlone(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "small.bin")
	data := randomBytes(t, mib)
	writeFile(t, src, data, 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "kept")
	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{ResumeDir: dir}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "small.bin"), data, 0o600)
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ResumeDir was created for a small payload: %v", err)
	}
}

// The last range, held up, is split: the idle connection fetches its second
// half, the held one stops where that half starts, and the decrypt reads
// the whole payload from both.
func TestSplitTailDecrypts(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := privateDir(t)
	src := filepath.Join(t.TempDir(), "big.bin")
	data := randomBytes(t, 40*mib)
	writeFile(t, src, data, 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	last := fmt.Sprintf("bytes=%d-", 32*mib)
	split := make(chan struct{})
	var once sync.Once
	f.mu.Lock()
	f.beforeRange = func(r *http.Request) {
		rng := r.Header.Get("Range")
		var start, end int64
		if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err == nil && start > 32*mib {
			once.Do(func() { close(split) })
		}
		if strings.HasPrefix(rng, last) {
			select {
			case <-split:
			case <-time.After(5 * time.Second):
			}
		}
	}
	f.mu.Unlock()

	before, _ := rangeCount(f)
	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{ResumeDir: dir, DownloadThreads: 2}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-split:
	default:
		t.Fatal("the held last range was not split")
	}
	if ranges, fetched := rangesSince(t, f, before); fetched < res.EncryptedSize {
		t.Fatalf("fetched %d of %d bytes in %v", fetched, res.EncryptedSize, ranges)
	}
	assertFile(t, filepath.Join(out, "big.bin"), data, 0o600)
	assertEmptyDir(t, dir)
}
