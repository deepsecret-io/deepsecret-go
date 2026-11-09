// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

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

	"github.com/deepsecret-io/deepsecret-go/internal/payload"
	"github.com/deepsecret-io/deepsecret-go/secrets"
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
	// Windows has no such modes; what it writes is private to the user
	// instead (internal/disk).
	if mode != 0 && runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != mode {
			t.Fatalf("%s: mode %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
}

// Files stream from the sender's disk to the recipient's: names and
// contents arrive, each file private to the recipient with only its
// owner's execute bit kept, files_meta lists each file, and neither side
// leaves its temporary ciphertext behind.
func TestStreamFilesRoundTrip(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := t.TempDir()
	big := randomBytes(t, 3<<20)
	writeFile(t, filepath.Join(src, "a.txt"), []byte(strings.Repeat("compress me ", 1000)), 0o640)
	writeFile(t, filepath.Join(src, "sub", "b.bin"), big, 0o600)
	writeFile(t, filepath.Join(src, "empty"), nil, 0o755)

	sendTmp, recvTmp := t.TempDir(), t.TempDir()
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{Name: "tree", Compress: secrets.CompressZstd, TempDir: sendTmp})
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
	result, written, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{TempDir: recvTmp}, secrets.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertEmptyDir(t, recvTmp)
	if result.PayloadType != "files" || written.Archived || len(written.Files) != 3 {
		t.Fatalf("result %+v, written %+v", result, written)
	}
	assertFile(t, filepath.Join(out, root, "a.txt"), []byte(strings.Repeat("compress me ", 1000)), 0o600)
	assertFile(t, filepath.Join(out, root, "sub", "b.bin"), big, 0o600)
	assertFile(t, filepath.Join(out, root, "empty"), nil, 0o700)
	// The directories made to hold decrypted files are private.
	if runtime.GOOS != "windows" {
		for _, dir := range []string{out, filepath.Join(out, root), filepath.Join(out, root, "sub")} {
			if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("%s: %v, %v; want a private directory", dir, info, err)
			}
		}
	}

	// Decrypting again into the same directory replaces nothing.
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{}, secrets.WriteOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second decrypt: %v", err)
	}
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{}, secrets.WriteOptions{Overwrite: true}); err != nil {
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

	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{Name: "bundle", Archive: true, Compress: secrets.CompressZstd})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Archived || res.FilesCount != 0 || !f.lastReq.Compressed || f.lastReq.Compression != "tar+zstd" || len(f.lastReq.FilesMeta) != 0 {
		t.Fatalf("result %+v, request compression %v %q, %d metadata entries", res, f.lastReq.Compressed, f.lastReq.Compression, len(f.lastReq.FilesMeta))
	}

	out := t.TempDir()
	_, written, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{}, secrets.WriteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !written.Archived || written.Extracted == 0 {
		t.Fatalf("written %+v", written)
	}
	root := filepath.Join(out, filepath.Base(src))
	assertFile(t, filepath.Join(root, "dir", "data.bin"), data, 0o600)
	// The archive's 0644 file and 0755 directory arrive private.
	assertFile(t, filepath.Join(root, "notes.md"), []byte("# notes"), 0o600)
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(root, "dir")); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("dir: %v, %v; want a private directory", info, err)
		}
	}
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

	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{Compress: secrets.CompressZstd, UploadThreads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Secret.IsMultipart || len(f.uploads[res.Secret.RevisionID].parts) != 3 {
		t.Fatalf("multipart %v with %d parts", res.Secret.IsMultipart, len(f.uploads[res.Secret.RevisionID].parts))
	}
	if res.Compressed {
		t.Fatal("random data was compressed")
	}

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{DownloadThreads: 4}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// A send reports its encryption as the file is read, and its upload and
// the download part by part, each ending with every byte counted. A small
// send goes in one request, shown as one part.
func TestSendAndDownloadReportProgress(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.multipartAt, f.partSize, f.downloadPartSize = 5<<20, 5<<20, 1<<20
	src := filepath.Join(t.TempDir(), "backup.bin")
	data := randomBytes(t, 12<<20)
	writeFile(t, src, data, 0o600)

	var encDone, encTotal int64
	backwards := false
	var upload secrets.TransferStatus
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{
		UploadThreads: 3,
		UploadStatus:  &upload,
		OnEncryptProgress: func(done, total int64) {
			backwards = backwards || done < encDone || done > total
			encDone, encTotal = done, total
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The payload adds its file's header to the data.
	if backwards || encDone != encTotal || encDone < int64(len(data)) || encDone > int64(len(data))+1024 {
		t.Fatalf("encryption progress ended at %d of %d (backwards %v)", encDone, encTotal, backwards)
	}
	snap := upload.Snapshot()
	if snap.Total != res.EncryptedSize || snap.Done != snap.Total || snap.Parts != 3 || snap.PartsDone != 3 || len(snap.Connections) != 0 {
		t.Fatalf("upload %+v", snap)
	}

	var download secrets.TransferStatus
	passes := passRecorder{}
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, t.TempDir(), secrets.DecryptOptions{
		DownloadThreads: 4, DownloadStatus: &download, OnDecryptProgress: passes.record,
	}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	passes.check(t, res.EncryptedSize, secrets.DecryptChecking, secrets.DecryptWriting)
	// Ranges are 8 MiB below 1 GiB, whatever smaller size the server
	// suggests: two for 12 MiB.
	snap = download.Snapshot()
	if snap.Total != res.EncryptedSize || snap.Done != snap.Total || snap.Parts != 2 || snap.PartsDone != 2 || len(snap.Connections) != 0 {
		t.Fatalf("download %+v", snap)
	}

	var small secrets.TransferStatus
	res, err = f.client("alice@example.com").Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{UploadStatus: &small})
	if err != nil {
		t.Fatal(err)
	}
	if snap := small.Snapshot(); snap.Parts != 1 || snap.PartsDone != 1 || snap.Done != res.EncryptedSize || snap.Total != res.EncryptedSize {
		t.Fatalf("small send %+v", snap)
	}
}

// passRecorder follows OnDecryptProgress: the passes in order, and how
// far each went.
type passRecorder struct {
	stages    []secrets.DecryptStage
	ends      []int64
	backwards bool
}

func (p *passRecorder) record(stage secrets.DecryptStage, done, total int64) {
	if n := len(p.stages); n == 0 || p.stages[n-1] != stage {
		p.stages, p.ends = append(p.stages, stage), append(p.ends, 0)
	}
	n := len(p.ends) - 1
	p.backwards = p.backwards || done < p.ends[n] || done > total
	p.ends[n] = done
}

// check wants these passes, in order, each through all size bytes.
func (p *passRecorder) check(t *testing.T, size int64, want ...secrets.DecryptStage) {
	t.Helper()
	if p.backwards || len(p.stages) != len(want) {
		t.Fatalf("passes %v ending at %v (backwards %v), want %v", p.stages, p.ends, p.backwards, want)
	}
	for i := range want {
		if p.stages[i] != want[i] || p.ends[i] != size {
			t.Fatalf("passes %v ending at %v, want %v through %d bytes", p.stages, p.ends, want, size)
		}
	}
}

// Decrypting in memory is one pass, and an archive is checked on a pass
// of its own before it is written.
func TestDecryptReportsItsPasses(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	alice, bob := f.client("alice@example.com"), f.client("bob@example.com")

	res, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	passes := passRecorder{}
	if _, err := bob.Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{OnDecryptProgress: passes.record}); err != nil {
		t.Fatal(err)
	}
	passes.check(t, res.EncryptedSize, secrets.DecryptDecrypting)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), []byte("one"), 0o600)
	writeFile(t, filepath.Join(dir, "b.txt"), []byte("two"), 0o600)
	res, err = alice.Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{dir}, secrets.EncryptOptions{Archive: true})
	if err != nil {
		t.Fatal(err)
	}
	passes = passRecorder{}
	if _, _, err := bob.Secrets.DecryptToDir(context.Background(), res.Secret.ID, t.TempDir(), secrets.DecryptOptions{OnDecryptProgress: passes.record}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	passes.check(t, res.EncryptedSize, secrets.DecryptChecking, secrets.DecryptCheckingArchive, secrets.DecryptWriting)
}

// A download that outlives its presigned URL presigns again and finishes.
// The 20 MiB object downloads in three 8 MiB ranges.
func TestDownloadRenewsRefusedURL(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	f.downloadPartSize, f.urlUses = 1<<20, 1
	src := filepath.Join(t.TempDir(), "six.bin")
	data := randomBytes(t, 20<<20)
	writeFile(t, src, data, 0o600)
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()
	if _, _, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, out, secrets.DecryptOptions{DownloadThreads: 2}, secrets.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "six.bin"), data, 0)
	if f.presigns < 3 {
		t.Fatalf("3 ranges with 1 use per URL took %d presigns", f.presigns)
	}
}

// A small file payload still decrypts in memory.
func TestFilesDecryptInMemory(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "key.pem")
	writeFile(t, src, []byte("-----BEGIN KEY-----"), 0o600)
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{Compress: secrets.CompressZstd})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.client("bob@example.com").Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{})
	if err != nil || len(out.Decrypted.Files) != 1 || string(out.Decrypted.Files[0].Data) != "-----BEGIN KEY-----" || out.Decrypted.Files[0].Name != "key.pem" {
		t.Fatalf("%+v, %v", out, err)
	}
}

// A file name that is not a safe relative path is refused in memory too,
// so a caller writing the files out cannot be led out of its directory.
func TestPayloadRefusesUnsafeFileNames(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	bob := f.client("bob@example.com")
	for _, name := range []string{"../evil", "/etc/evil", "a/../../evil", "a\\b", "."} {
		id := sendRaw(t, f, payload.Payload{Type: "files", Files: []payload.FileEntry{fileEntry("ok.txt", "fine"), fileEntry(name, "x")}})
		if out, err := bob.Secrets.Decrypt(context.Background(), id, secrets.DecryptOptions{}); err == nil || !strings.Contains(err.Error(), "unsafe file") {
			t.Errorf("%q: %+v, %v, want it refused", name, out, err)
		}
	}
}

// sendRaw sends an encoded payload as is, the way a hostile sender could.
func sendRaw(t *testing.T, f *fakeAPI, p payload.Payload) string {
	t.Helper()
	data, err := payload.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.client("alice@example.com").Secrets.SendRaw([]string{"bob@example.com"}, "files", data, secrets.EncryptOptions{Name: "hostile"})
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
		if _, _, err := bob.Secrets.DecryptToDir(context.Background(), id, out, secrets.DecryptOptions{}, secrets.WriteOptions{}); err == nil || !strings.Contains(err.Error(), c.want) {
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
	if _, _, err := bob.Secrets.DecryptToDir(context.Background(), id, out, secrets.DecryptOptions{}, secrets.WriteOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
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
			res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{Compress: secrets.CompressZstd})
			if err != nil {
				t.Fatal(err)
			}
			_, written, err := f.client("bob@example.com").Secrets.DecryptToDir(context.Background(), res.Secret.ID, t.TempDir(), secrets.DecryptOptions{}, secrets.WriteOptions{})
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
	if _, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com", "carol@example.com"}, "v1", secrets.EncryptOptions{Name: "db"}); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if _, err := alice.Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "v2", secrets.EncryptOptions{Name: "db", TempDir: tmp}); err == nil {
		t.Fatal("a send leaving out carol was accepted")
	}
	assertEmptyDir(t, tmp)
}

// Text, data and small payloads never touch the disk: they send and
// decrypt with no usable temporary directory.
func TestSmallPayloadsNeedNoTempDir(t *testing.T) {
	t.Setenv(secrets.TempDirEnv, filepath.Join(t.TempDir(), "missing", "dir"))
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	res, err := f.client("alice@example.com").Secrets.EncryptText(context.Background(), []string{"bob@example.com"}, "hello", secrets.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.client("bob@example.com").Secrets.Decrypt(context.Background(), res.Secret.ID, secrets.DecryptOptions{})
	if err != nil || out.Decrypted.Message != "hello" {
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
	if _, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{a, b}, secrets.EncryptOptions{}); err == nil || !strings.Contains(err.Error(), "archive path collision") {
		t.Fatalf("got %v", err)
	}
}

// A cancel stops a decrypt before it writes anything.
func TestWriteFilesStopsOnCancel(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	src := filepath.Join(t.TempDir(), "f.bin")
	writeFile(t, src, randomBytes(t, 1<<20), 0o600)
	res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, []string{src}, secrets.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bob := f.client("bob@example.com")
	opened, err := bob.Secrets.Open(context.Background(), res.Secret.ID, secrets.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(t.TempDir(), "out")
	if _, err := opened.WriteFiles(ctx, out, secrets.WriteOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("the cancelled decrypt created its output")
	}
}

// One path names the secret, unless it has no name of its own.
func TestEncryptPathsNamesTheSecret(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	dir := t.TempDir()
	file := filepath.Join(dir, "report.txt")
	writeFile(t, file, []byte("a"), 0o600)
	other := filepath.Join(dir, "other.txt")
	writeFile(t, other, []byte("b"), 0o600)
	send := func(paths ...string) string {
		t.Helper()
		res, err := f.client("alice@example.com").Secrets.EncryptPaths(context.Background(), []string{"bob@example.com"}, paths, secrets.EncryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return res.Secret.Name
	}
	if got := send(file); got != "report.txt" {
		t.Errorf("one path: %q", got)
	}
	if got := send(file, other); !strings.HasPrefix(got, "sdk-") {
		t.Errorf("two paths: %q", got)
	}
}

// Each call ends with its own context, and only that call: AcceptKey and
// VerifyKey ask the server too.
func TestCallsEndWithTheirContext(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	c := f.client("alice@example.com")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Identity.WhoAmI(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("WhoAmI: %v", err)
	}
	fp := strings.Repeat("a", 64)
	if err := c.Trust.Accept(cancelled, "bob@example.com", fp); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept: %v", err)
	}
	if err := c.Trust.Verify(cancelled, "bob@example.com", fp); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := c.Trust.ServerListedKeys(cancelled, "bob@example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ServerListedKeys: %v", err)
	}
	if _, err := c.Identity.ListKeys(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListKeys: %v", err)
	}
	if _, _, err := c.Secrets.ListSent(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListSent: %v", err)
	}
	if _, err := c.Secrets.Open(cancelled, "10000000-0000-4000-8000-000000000001", secrets.DecryptOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open: %v", err)
	}
	if err := c.Secrets.Delete(cancelled, "10000000-0000-4000-8000-000000000001"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete: %v", err)
	}
	if err := c.Logout(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := c.Identity.WhoAmI(context.Background()); err != nil {
		t.Fatalf("a later call on the same client: %v", err)
	}
}
