// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
	"github.com/deepsecret-io/deepsecret-go/internal/protocol"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
)

// ── Resumable downloads ─────────────────────────────────────────────────────
//
// A large decrypt downloads its ciphertext in byte ranges. When
// DecryptOptions.ResumeDir is set, the ciphertext goes to
// <ResumeDir>/<revision id>/payload, with a record of the ranges written
// (download.json). If the download fails, is cancelled, or the process
// dies, both stay, and the next decrypt of that revision with the same
// ResumeDir fetches only the ranges the payload lacks.
//
// The record is a checkpoint: every few seconds, when a download fails,
// and when a finished one is kept, the payload is synced to disk before
// the record names the ranges written since, so it never lists bytes a
// crash could lose.
//
// Nothing kept is trusted. A decrypt fetches and verifies the signed
// manifest and opens the caller's wrap before it looks at the folder; a
// record that does not agree with that manifest starts over; and the whole
// ciphertext is checked against the manifest's digest before any plaintext
// is released, as after any download. The download URL is requested even
// when nothing is left to fetch: the server applies the secret's policies
// there and records the download.
//
// The folder stays until the payload is decrypted, so a decrypt that fails
// after the download (an existing destination, a full disk) does not fetch
// it again. It is removed once the payload is decrypted, when the
// ciphertext fails its check, and after a week unused. A lock on the
// payload keeps two decrypts from sharing it. The folder holds ciphertext
// only.

const (
	downloadFile = "download.json"

	// maxDownloadRecord bounds a record read from disk.
	maxDownloadRecord = 1 << 20

	// staleDownloadAfter is how long a kept download goes unused before
	// the next send or decrypt using its ResumeDir removes it.
	staleDownloadAfter = 7 * 24 * time.Hour
)

// downloadCheckpoint is how often a kept download records the ranges it
// wrote; tests shorten it.
var downloadCheckpoint = 5 * time.Second

// PendingDownload describes a download kept in a ResumeDir: one that
// stopped before it finished, or that finished but was not decrypted.
type PendingDownload struct {
	RevisionID string `json:"revision_id"`
	SecretID   string `json:"secret_id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"` // ciphertext bytes, from the signed manifest
	// PayloadDigest is the hex SHA-256 of the ciphertext, from the signed
	// manifest.
	PayloadDigest string `json:"payload_digest"`
	// Have lists the byte ranges the folder holds, as [from, to) offsets.
	Have      [][2]int64 `json:"have"`
	APIURL    string     `json:"api_url"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	// Dir is the folder holding the ciphertext and this record.
	Dir string `json:"-"`
}

// Downloaded is how many bytes of the ciphertext the folder holds.
func (p *PendingDownload) Downloaded() int64 {
	var n int64
	for _, r := range p.Have {
		n += r[1] - r[0]
	}
	return n
}

// DownloadInterruptedError is a download that stopped before it finished.
// What it wrote is kept, and the next decrypt of the revision with the
// same ResumeDir continues it.
type DownloadInterruptedError struct {
	Download PendingDownload
	Err      error
}

func (e *DownloadInterruptedError) Error() string {
	return fmt.Sprintf("download interrupted, it can be resumed: %v", e.Err)
}

func (e *DownloadInterruptedError) Unwrap() error { return e.Err }

// openDownloadSpool opens the download of m's revision kept in dir, or
// starts one there, locked for this decrypt. The record's Have is what the
// spool already holds. A kept download that does not agree with m, or that
// came from another server, starts over.
func (c *Client) openDownloadSpool(dir string, secret *Info, m *protocol.Manifest, log *slog.Logger) (*spool, *PendingDownload, error) {
	if id, err := uuid.Parse(m.RevisionID); err != nil || id.String() != m.RevisionID {
		return nil, nil, fmt.Errorf("revision ID %q is not a UUID", m.RevisionID)
	}
	if err := disk.MkdirPrivate(dir); err != nil {
		return nil, nil, fmt.Errorf("create download folder: %w", err)
	}
	if err := disk.CheckPrivateDir(dir); err != nil {
		return nil, nil, fmt.Errorf("download folder: %w", err)
	}
	pruneAbandoned(dir, m.RevisionID)

	pdir := filepath.Join(dir, m.RevisionID)
	want := &PendingDownload{
		RevisionID: m.RevisionID, SecretID: secret.ID, Name: secret.Name, Size: m.CiphertextSize,
		PayloadDigest: hex.EncodeToString(m.PayloadDigest), APIURL: c.api.BaseURL(), Dir: pdir,
	}
	f, rec, err := openKeptDownload(pdir, want, logattr.Module(log, "resume"))
	if err != nil {
		return nil, nil, err
	}
	if err := checkFreeSpace(pdir, spoolNeed(rec.Size-rec.Downloaded()), "the encrypted payload", "free some space or use another ResumeDir"); err != nil {
		_ = f.Close() // only opened and locked so far; the free space error is returned.
		if len(rec.Have) == 0 {
			_ = os.RemoveAll(pdir) // nothing was downloaded into it; the free space error is returned.
		}
		return nil, nil, err
	}
	return &spool{dir: pdir, file: f, resume: "download", keep: true}, rec, nil
}

// openKeptDownload opens pdir's payload, creating the folder and the
// payload when missing, and locks it. It returns the kept record when it
// describes want's payload, and otherwise empties the payload and records
// want, holding nothing. log is the "resume" module.
func openKeptDownload(pdir string, want *PendingDownload, log *slog.Logger) (*os.File, *PendingDownload, error) {
	if err := disk.Mkdir(pdir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("create download folder: %w", err)
	}
	if err := disk.CheckPrivateDir(pdir); err != nil {
		return nil, nil, fmt.Errorf("download folder: %w", err)
	}
	f, err := openPayloadFile(filepath.Join(pdir, payloadFile))
	if err != nil {
		return nil, nil, err
	}
	if err := disk.Lock(f); errors.Is(err, disk.ErrLocked) {
		_ = f.Close() // only opened so far; the lock error is returned.
		return nil, nil, fmt.Errorf("another decrypt is downloading revision %s: wait for it to finish", want.RevisionID)
	} else if err != nil {
		// Some network filesystems have no locks. The lock only keeps two
		// decrypts from sharing the folder; the digest check does not
		// depend on it.
		log.Warn("download file not locked", "dir", pdir, "error", err, "reason", "a second decrypt of this revision could share it")
	}

	kept, why := keptRecord(pdir, f, want)
	if kept != nil {
		log.Debug("resuming download", "revision_id", kept.RevisionID, "held", logattr.Bytes(kept.Downloaded()), "size", logattr.Bytes(kept.Size), "recorded_at", kept.UpdatedAt)
		return f, kept, nil
	}
	if why != "" {
		log.Warn("kept download discarded", "revision_id", want.RevisionID, "reason", why)
	}
	now := time.Now().UTC()
	rec := *want
	rec.Have, rec.CreatedAt, rec.UpdatedAt = nil, now, now
	if err := f.Truncate(0); err != nil {
		_ = f.Close() // the truncate error is returned; the next decrypt starts over again.
		return nil, nil, fmt.Errorf("empty download file: %w", err)
	}
	if err := writeDownloadRecord(&rec); err != nil {
		_ = f.Close() // the record error is returned; the next decrypt starts over again.
		return nil, nil, err
	}
	return f, &rec, nil
}

// openPayloadFile opens the payload at path for reading and writing,
// creating it (mode 0600) when missing. It refuses anything but a regular
// file, so a link in its place is never followed.
func openPayloadFile(path string) (*os.File, error) {
	// #nosec G304 -- path is <ResumeDir>/<revision UUID>/payload, in folders checkPrivateDir accepted.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create download file: %w", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("open download file: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	// #nosec G304 -- as above: Lstat found a regular file, and SameFile below refuses one swapped in since.
	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open download file: %w", err)
	}
	if after, err := f.Stat(); err != nil || !os.SameFile(before, after) {
		_ = f.Close() // refused before any use.
		return nil, fmt.Errorf("%s changed while it was opened", path)
	}
	return f, nil
}

// keptRecord returns pdir's record when it describes want's payload and f
// holds what it lists; otherwise the reason it cannot be used, or "" when
// there is no record.
func keptRecord(pdir string, f *os.File, want *PendingDownload) (*PendingDownload, string) {
	rec, err := readDownloadRecord(pdir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ""
	case err != nil:
		return nil, err.Error()
	case rec.Size != want.Size || rec.PayloadDigest != want.PayloadDigest:
		return nil, "it is not the payload the signed manifest describes"
	case rec.APIURL != want.APIURL:
		return nil, "it came from " + rec.APIURL
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err.Error()
	}
	if n := len(rec.Have); info.Size() > rec.Size || (n > 0 && info.Size() < rec.Have[n-1][1]) {
		return nil, fmt.Sprintf("the payload file is %d bytes, which does not fit what the record lists", info.Size())
	}
	// The secret's name may have changed since; the rest is the revision's.
	rec.SecretID, rec.Name = want.SecretID, want.Name
	return rec, ""
}

// readDownloadRecord reads and checks the record in pdir, a folder named
// after its revision.
func readDownloadRecord(pdir string) (*PendingDownload, error) {
	path := filepath.Join(pdir, downloadFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("download record %s is not a regular file", pdir)
	}
	f, err := os.Open(path) // #nosec G304 -- pdir is <ResumeDir>/<UUID>, from callers that checked both.
	if err != nil {
		return nil, err
	}
	// Opened to read only: once the record is read, a close error loses nothing.
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxDownloadRecord+1))
	if err != nil {
		return nil, fmt.Errorf("read download record %s: %w", pdir, err)
	}
	if len(data) > maxDownloadRecord {
		return nil, fmt.Errorf("download record %s is too large", pdir)
	}
	var p PendingDownload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("read download record %s: %w", pdir, err)
	}
	if _, err := uuid.Parse(p.RevisionID); err != nil || filepath.Base(pdir) != p.RevisionID {
		return nil, fmt.Errorf("download record %s does not match its folder", pdir)
	}
	if p.Size <= 0 {
		return nil, fmt.Errorf("download record %s has no size", pdir)
	}
	if p.Have, err = transport.MergeRanges(p.Have, p.Size); err != nil {
		return nil, fmt.Errorf("download record %s: %w", pdir, err)
	}
	p.Dir = pdir
	return &p, nil
}

// writeDownloadRecord replaces p's record in one rename, so a reader sees
// the old record or the new one, never a mix.
func writeDownloadRecord(p *PendingDownload) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := filepath.Join(p.Dir, downloadFile+".tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("record download: %w", err)
	}
	// #nosec G304 -- a fixed name in the folder openKeptDownload checked, created exclusively.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("record download: %w", err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(p.Dir, downloadFile))
	}
	if err != nil {
		_ = os.Remove(tmp) // the record error is returned; the old record stays.
		return fmt.Errorf("record download: %w", err)
	}
	return nil
}

// downloadJournal records a kept download's ranges as they finish. Each
// checkpoint syncs the payload to disk before the record names the ranges
// it covers, so the record never lists bytes a crash could lose.
type downloadJournal struct {
	rec   *PendingDownload // what the record on disk says; only checkpoints touch it
	file  *os.File
	size  int64
	every time.Duration

	mu    sync.Mutex
	have  [][2]int64
	dirty bool

	stop, done chan struct{}
}

func newDownloadJournal(f *os.File, rec *PendingDownload) *downloadJournal {
	return &downloadJournal{rec: rec, file: f, size: rec.Size, every: downloadCheckpoint, have: rec.Have,
		stop: make(chan struct{}), done: make(chan struct{})}
}

// add notes that [from, to) is written: MultipartDownloadOptions.OnRange.
func (j *downloadJournal) add(from, to int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if have, err := transport.MergeRanges(append(slices.Clip(j.have), [2]int64{from, to}), j.size); err == nil {
		j.have, j.dirty = have, true
	}
}

// run checkpoints every j.every until finish stops it.
func (j *downloadJournal) run() {
	defer close(j.done)
	tick := time.NewTicker(j.every)
	defer tick.Stop()
	for {
		select {
		case <-j.stop:
			return
		case <-tick.C:
			_ = j.checkpoint() // a failed checkpoint is tried again at the next tick, and by finish.
		}
	}
}

// halt stops run once the download ends. What finished since the last
// checkpoint is recorded only if the download is kept: a payload about to
// be decrypted and removed needs no fsync.
func (j *downloadJournal) halt() {
	close(j.stop)
	<-j.done
}

// checkpoint syncs the payload, then records the ranges finished before
// the sync. j.rec stays what the record on disk says.
func (j *downloadJournal) checkpoint() error {
	j.mu.Lock()
	have, dirty := j.have, j.dirty
	j.dirty = false
	j.mu.Unlock()
	if !dirty {
		return nil
	}
	err := j.file.Sync()
	if err == nil {
		rec := *j.rec
		rec.Have, rec.UpdatedAt = have, time.Now().UTC()
		if err = writeDownloadRecord(&rec); err == nil {
			*j.rec = rec
		}
	}
	if err != nil {
		j.mu.Lock()
		j.dirty = true
		j.mu.Unlock()
	}
	return err
}

// logRecordFailed logs a kept download whose ranges could not be
// recorded: the next decrypt fetches again what the record does not list.
func logRecordFailed(log *slog.Logger, err error) {
	logattr.Module(log, "resume").Warn("download record not written", "error", err)
}

// removeKeptDownload removes a kept download's folder unless a decrypt is
// using it.
func removeKeptDownload(pdir string) {
	if f, err := os.Open(filepath.Join(pdir, payloadFile)); err == nil { // #nosec G304 -- pdir is <ResumeDir>/<UUID>, which pruneAbandoned listed.
		locked := disk.Lock(f)
		_ = f.Close() // only opened to test the lock.
		if errors.Is(locked, disk.ErrLocked) {
			return
		}
	}
	_ = os.RemoveAll(pdir) // best-effort pruning of ciphertext nobody used for a week; the next send or decrypt retries it.
}

// ListPendingDownloads returns the downloads kept in dir, oldest first:
// interrupted ones, and finished ones not yet decrypted. A missing dir has
// none.
func ListPendingDownloads(dir string) ([]PendingDownload, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := disk.CheckPrivateDir(dir); err != nil {
		return nil, fmt.Errorf("download folder: %w", err)
	}
	var out []PendingDownload
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := uuid.Parse(e.Name()); err != nil {
			continue
		}
		p, err := readDownloadRecord(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // an upload's folder, or not ours
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// DiscardPendingDownload removes the download of revisionID kept in dir. A
// download a decrypt is using now is refused.
func DiscardPendingDownload(dir, revisionID string) error {
	pdir, err := pendingDir(dir, revisionID, "download folder")
	if err != nil {
		return err
	}
	if info, err := os.Lstat(filepath.Join(pdir, downloadFile)); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("no kept download %s", revisionID)
	}
	f, err := os.Open(filepath.Join(pdir, payloadFile)) // #nosec G304 -- pdir is <dir>/<UUID> from pendingDir, which checked both.
	if err == nil {
		locked := disk.Lock(f)
		if errors.Is(locked, disk.ErrLocked) {
			_ = f.Close() // only opened to test the lock.
			return fmt.Errorf("a decrypt is downloading revision %s now: wait for it to finish", revisionID)
		}
		_ = f.Close() // closed before RemoveAll so Windows can delete it.
	}
	return os.RemoveAll(pdir)
}
