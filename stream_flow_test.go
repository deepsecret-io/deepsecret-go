// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk/payload"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// assertEmptyDir fails when a send or decrypt left anything in its
// temporary directory.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%s holds %d leftover entries", dir, len(entries))
	}
}

func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: content differs (%d bytes, want %d)", path, len(got), len(want))
	}
	if mode != 0 {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != mode {
			t.Fatalf("%s: mode %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
}

// Files stream from the sender's disk to the recipient's: names, contents
// and permissions arrive, files_meta lists each file, and neither side
// leaves its temporary ciphertext behind.
func TestStreamFilesRoundTrip(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := t.TempDir()
	big := randomBytes(t, 3<<20)
	writeFile(t, filepath.Join(src, "a.txt"), []byte(strings.Repeat("compress me ", 1000)), 0o640)
	writeFile(t, filepath.Join(src, "sub", "b.bin"), big, 0o600)
	writeFile(t, filepath.Join(src, "empty"), nil, 0o644)

	sendTmp, recvTmp := t.TempDir(), t.TempDir()
	res, err := f.client("alice@example.com").EncryptPaths([]string{"bob@example.com"}, []string{src},
		EncryptOptions{Name: "tree", Compress: CompressZstd, TempDir: sendTmp})
	if err != nil {
		t.Fatal(err)
	}
	assertEmptyDir(t, sendTmp)
	if res.FilesCount != 3 || f.lastReq.FilesCount != 3 || len(f.lastReq.FilesMeta) != 3 {
		t.Fatalf("files %d, request %d with %d metadata entries", res.FilesCount, f.lastReq.FilesCount, len(f.lastReq.FilesMeta))
	}
	sum := sha256.Sum256(big)
	found := false
	root := filepath.Base(src)
	for _, m := range f.lastReq.FilesMeta {
		if m.Name == root+"/sub/b.bin" && m.Size == int64(len(big)) && m.SHA256 == hex.EncodeToString(sum[:]) {
			found = true
		}
	}
	if !found {
		t.Fatalf("files_meta %+v lacks sub/b.bin", f.lastReq.FilesMeta)
	}

	out := filepath.Join(t.TempDir(), "out")
	result, written, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{TempDir: recvTmp}, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEmptyDir(t, recvTmp)
	if result.PayloadType != "files" || written.Archived || len(written.Files) != 3 {
		t.Fatalf("result %+v, written %+v", result, written)
	}
	assertFile(t, filepath.Join(out, root, "a.txt"), []byte(strings.Repeat("compress me ", 1000)), 0o640)
	assertFile(t, filepath.Join(out, root, "sub", "b.bin"), big, 0o600)
	assertFile(t, filepath.Join(out, root, "empty"), nil, 0o644)

	// Decrypting again into the same directory replaces nothing.
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{}, WriteOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second decrypt: %v", err)
	}
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{}, WriteOptions{Overwrite: true}); err != nil {
		t.Fatalf("decrypt with overwrite: %v", err)
	}
}

// An archive carries directories and symlinks: the tar inside the payload
// is plain and the payload is zstd-compressed as it streams.
func TestStreamArchiveRoundTrip(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := t.TempDir()
	data := randomBytes(t, 1<<20)
	writeFile(t, filepath.Join(src, "dir", "data.bin"), data, 0o600)
	writeFile(t, filepath.Join(src, "notes.md"), []byte("# notes"), 0o644)
	if err := os.Symlink("notes.md", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	res, err := f.client("alice@example.com").EncryptPaths([]string{"bob@example.com"}, []string{src},
		EncryptOptions{Name: "bundle", Archive: true, Compress: CompressZstd})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Archived || res.FilesCount != 0 || !f.lastReq.Compressed || f.lastReq.Compression != "tar+zstd" || len(f.lastReq.FilesMeta) != 0 {
		t.Fatalf("result %+v, request compression %v %q, %d metadata entries", res, f.lastReq.Compressed, f.lastReq.Compression, len(f.lastReq.FilesMeta))
	}

	out := t.TempDir()
	_, written, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{}, WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !written.Archived || written.Extracted == 0 {
		t.Fatalf("written %+v", written)
	}
	root := filepath.Join(out, filepath.Base(src))
	assertFile(t, filepath.Join(root, "dir", "data.bin"), data, 0o600)
	if target, err := os.Readlink(filepath.Join(root, "link")); err != nil || target != "notes.md" {
		t.Fatalf("symlink: %q, %v", target, err)
	}
}

// A secret above the multipart threshold uploads in parts from the
// temporary file and downloads in ranges into another.
func TestStreamMultipartRoundTrip(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize, f.downloadPartSize = 5<<20, 5<<20, 1<<20
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 12<<20)
	writeFile(t, src, data, 0o600)

	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{Compress: CompressZstd, UploadThreads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secret.IsMultipart || len(f.uploads[res.Secret.RevisionID].registered) != 3 {
		t.Fatalf("multipart %v with %d parts", res.Secret.IsMultipart, len(f.uploads[res.Secret.RevisionID].registered))
	}
	if res.Compressed {
		t.Fatal("random data was compressed")
	}

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{DownloadThreads: 4}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// A download that outlives its presigned URL presigns again and finishes.
func TestDownloadRenewsRefusedURL(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.downloadPartSize, f.urlUses = 1<<20, 2
	src := filepath.Join(t.TempDir(), "six.bin")
	data := randomBytes(t, 6<<20)
	writeFile(t, src, data, 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, out, DecryptOptions{DownloadThreads: 2}, WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "six.bin"), data, 0)
	if f.presigns < 3 {
		t.Fatalf("7 ranges with 2 uses per URL took %d presigns", f.presigns)
	}
}

// A small file payload still decrypts in memory.
func TestFilesDecryptInMemory(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "key.pem")
	writeFile(t, src, []byte("-----BEGIN KEY-----"), 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{Compress: CompressZstd})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.client("bob@example.com").DecryptSecret(res.Secret.ID)
	if err != nil || len(out.Files) != 1 || string(out.Files[0].Data) != "-----BEGIN KEY-----" || out.Files[0].Name != "key.pem" {
		t.Fatalf("%+v, %v", out, err)
	}
}

// sendRaw sends an encoded payload as is, the way a hostile sender could.
func sendRaw(t *testing.T, f *fakeAPI, p payload.Payload) string {
	t.Helper()
	data, err := payload.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.client("alice@example.com").encryptAndSend([]string{"bob@example.com"}, memPlaintext("files", data, nil), EncryptOptions{Name: "hostile"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Secret.ID
}

func fileEntry(name, content string) payload.FileEntry {
	sum := sha256.Sum256([]byte(content))
	return payload.FileEntry{Name: name, Data: []byte(content), Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), Mode: 0o644}
}

// A payload that fails a check writes nothing: not its good files, and
// nothing outside the output directory.
func TestWriteFilesRefusesHostilePayloads(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	bob := f.client("bob@example.com")
	cases := map[string]struct {
		files []payload.FileEntry
		want  string
	}{
		"escape":       {[]payload.FileEntry{fileEntry("ok.txt", "fine"), fileEntry("../evil", "x")}, "'..' segment"},
		"absolute":     {[]payload.FileEntry{fileEntry("ok.txt", "fine"), fileEntry("/etc/evil", "x")}, "empty segment"},
		"duplicate":    {[]payload.FileEntry{fileEntry("a", "1"), fileEntry("a", "2")}, "twice"},
		"wrong sha256": {[]payload.FileEntry{fileEntry("ok.txt", "fine"), {Name: "b", Data: []byte("x"), Size: 1, SHA256: strings.Repeat("0", 64)}}, "SHA-256"},
	}
	for name, c := range cases {
		id := sendRaw(t, f, payload.Payload{Type: "files", Files: c.files})
		parent := t.TempDir()
		out := filepath.Join(parent, "out")
		if _, _, err := bob.DecryptToDir(id, out, DecryptOptions{}, WriteOptions{}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
			continue
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("%s: wrote %d entries", name, len(entries))
		}
	}

	// A destination that exists stops the write before any file is written.
	id := sendRaw(t, f, payload.Payload{Type: "files", Files: []payload.FileEntry{fileEntry("a.txt", "new"), fileEntry("b.txt", "new")}})
	out := t.TempDir()
	writeFile(t, filepath.Join(out, "b.txt"), []byte("mine"), 0o600)
	if _, _, err := bob.DecryptToDir(id, out, DecryptOptions{}, WriteOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing destination: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("a.txt was written although b.txt exists")
	}
	assertFile(t, filepath.Join(out, "b.txt"), []byte("mine"), 0)
}

// Memory stays flat whatever the payload's size: sending and receiving
// 192 MiB peaks about where 48 MiB does, and far below the payload, which
// the in-memory pipeline held three or four times over.
func TestStreamingKeepsMemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 240 MiB")
	}
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize, f.downloadPartSize = 8<<20, 8<<20, 8<<20

	roundTrip := func(mib int) uint64 {
		src := filepath.Join(t.TempDir(), "big.bin")
		out, err := os.Create(src)
		if err != nil {
			t.Fatal(err)
		}
		chunk := randomBytes(t, 1<<20)
		h := sha256.New()
		for i := 0; i < mib; i++ {
			out.Write(chunk)
			h.Write(chunk)
			chunk[0]++
		}
		out.Close()
		want := hex.EncodeToString(h.Sum(nil))
		return measurePeakHeap(t, func() {
			res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{Compress: CompressZstd})
			if err != nil {
				t.Fatal(err)
			}
			_, written, err := f.client("bob@example.com").DecryptToDir(res.Secret.ID, t.TempDir(), DecryptOptions{}, WriteOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if written.Files[0].SHA256 != want {
				t.Fatal("the received file differs")
			}
		})
	}
	small, large := roundTrip(48), roundTrip(192)
	t.Logf("peak heap: %d MiB for 48 MiB, %d MiB for 192 MiB", small>>20, large>>20)
	// The bounds leave room for garbage-collection timing; holding the
	// payload in memory would take over 576 MiB.
	if large > 128<<20 || large > small+32<<20 {
		t.Fatalf("memory grows with the payload: %d MiB for 48 MiB, %d MiB for 192 MiB", small>>20, large>>20)
	}
}

// measurePeakHeap runs fn and returns the largest heap in use seen while
// it ran.
func measurePeakHeap(t *testing.T, fn func()) uint64 {
	t.Helper()
	runtime.GC()
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak.Load() {
				peak.Store(ms.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	return peak.Load()
}

// A send refused after sealing leaves no temporary ciphertext behind.
func TestSendFailureRemovesTemporaryFile(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice := f.client("alice@example.com")
	if _, err := alice.EncryptText([]string{"bob@example.com", "carol@example.com"}, "v1", EncryptOptions{Name: "db"}); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if _, err := alice.EncryptText([]string{"bob@example.com"}, "v2", EncryptOptions{Name: "db", TempDir: tmp}); err == nil {
		t.Fatal("a send leaving out carol was accepted")
	}
	assertEmptyDir(t, tmp)
}

// Text, data and small payloads never touch the disk: they send and
// decrypt with no usable temporary directory.
func TestSmallPayloadsNeedNoTempDir(t *testing.T) {
	t.Setenv(TempDirEnv, filepath.Join(t.TempDir(), "missing", "dir"))
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	res, err := f.client("alice@example.com").EncryptText([]string{"bob@example.com"}, "hello", EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.client("bob@example.com").DecryptSecret(res.Secret.ID)
	if err != nil || out.Message != "hello" {
		t.Fatalf("%+v, %v", out, err)
	}
}

// Two files with one name cannot be sent: the recipient could not write
// both.
func TestSendRefusesDuplicateNames(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	a, b := filepath.Join(t.TempDir(), "same.txt"), filepath.Join(t.TempDir(), "same.txt")
	writeFile(t, a, []byte("a"), 0o600)
	writeFile(t, b, []byte("b"), 0o600)
	if _, err := f.client("alice@example.com").EncryptFiles([]string{"bob@example.com"}, []string{a, b}, EncryptOptions{}); err == nil || !strings.Contains(err.Error(), "two files are named") {
		t.Fatalf("got %v", err)
	}
}

// A cancel stops a decrypt before it writes anything.
func TestWriteFilesStopsOnCancel(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "f.bin")
	writeFile(t, src, randomBytes(t, 1<<20), 0o600)
	res, err := f.client("alice@example.com").EncryptFile([]string{"bob@example.com"}, src, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bob := f.client("bob@example.com")
	opened, err := bob.OpenSecret(res.Secret.ID, DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bob.api.SetRootContext(ctx)
	opened.ctx = ctx
	out := filepath.Join(t.TempDir(), "out")
	if _, err := opened.WriteFiles(out, WriteOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("the cancelled decrypt created its output")
	}
}

// A payload that does not fit on the disk is refused before anything is
// written, and so is one under a parent that is not a directory.
func TestWriteChecks(t *testing.T) {
	if err := checkFreeSpace(t.TempDir(), 1<<60, "the decrypted files", ""); err == nil || !strings.Contains(err.Error(), "not enough free space") {
		t.Fatalf("free space: %v", err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file"), []byte("x"), 0o600)
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
