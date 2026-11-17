// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/deepsecret-go/apierror"
	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/internal/knownkeys"
	"github.com/deepsecret-io/deepsecret-go/internal/transport"
)

// ── Resumable sends ─────────────────────────────────────────────────────────
//
// A large send uploads its ciphertext in parts. When EncryptOptions.ResumeDir
// is set, the sealed ciphertext is kept in <ResumeDir>/<revision id>/, with
// a record of the upload (upload.json) written before the upload starts.
// If the upload fails, is cancelled, or the process dies, both stay, and
// ResumeUpload finishes the upload later: the parts storage already holds
// are kept and the rest are sent. Nothing is sealed again, so resuming
// needs no keys, only the session. A finished upload removes the folder.
//
// The record also lists the recipients whose key was new to this device
// when the send was sealed (PendingUpload.FirstUse): the send stopped
// before it could record them, so ResumeUpload does, and returns them as
// EncryptResult.FirstUse would have.
//
// The folder holds ciphertext only. The server aborts an upload that sees
// no activity for a day, after which it cannot be resumed.

const (
	pendingFile = "upload.json"
	payloadFile = "payload"
)

// PendingUpload describes a send whose upload did not finish.
type PendingUpload struct {
	RevisionID string    `json:"revision_id"`
	SecretID   string    `json:"secret_id"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"` // ciphertext bytes
	APIURL     string    `json:"api_url"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	// FirstUse lists the recipients whose key was new to this device when
	// the send was sealed, as EncryptResult.FirstUse does: their address
	// and key fingerprint, nothing secret. The interrupted send recorded
	// none of them. ResumeUpload records them once the upload finishes, so
	// they are worth comparing with their owners then, and refuses to
	// finish it when this device has since recorded another key for one of
	// them.
	FirstUse []Recipient `json:"first_use"`
	// Dir is the folder holding the ciphertext and this record.
	Dir string `json:"-"`
}

// UploadInterruptedError is a send that was created but whose upload did
// not finish. Its ciphertext is kept for ResumeUpload.
type UploadInterruptedError struct {
	Upload PendingUpload
	Err    error
}

func (e *UploadInterruptedError) Error() string {
	return fmt.Sprintf("upload interrupted, it can be resumed: %v", e.Err)
}

func (e *UploadInterruptedError) Unwrap() error { return e.Err }

// ResumeOptions configures ResumeUpload.
type ResumeOptions struct {
	// UploadThreads fixes the number of parallel part uploads; 0 adapts.
	UploadThreads int
	// OnUploadProgress is called with bytes transferred and total bytes.
	OnUploadProgress func(transferred, total int64)
	// UploadStatus follows the upload, as for EncryptOptions.
	UploadStatus *TransferStatus
	// Logger receives the flow's logs, as for EncryptOptions.
	Logger *slog.Logger
}

// newSendSpool creates the spool a send seals into: a folder named after
// the revision under opt.ResumeDir when set, so an interrupted upload can
// resume, otherwise a private temporary directory.
func newSendSpool(opt EncryptOptions, revisionID string, need int64) (*spool, error) {
	if opt.ResumeDir == "" {
		return newSpool(opt.TempDir, need)
	}
	if err := disk.MkdirPrivate(opt.ResumeDir); err != nil {
		return nil, fmt.Errorf("create upload folder: %w", err)
	}
	if err := disk.CheckPrivateDir(opt.ResumeDir); err != nil {
		return nil, fmt.Errorf("upload folder: %w", err)
	}
	pruneAbandoned(opt.ResumeDir, revisionID)
	if err := checkFreeSpace(opt.ResumeDir, need, "the encrypted payload", "free some space or use another ResumeDir"); err != nil {
		return nil, err
	}
	dir := filepath.Join(opt.ResumeDir, revisionID)
	if err := disk.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create upload folder: %w", err)
	}
	// #nosec G304 -- revisionID is a UUID this client generated, in the caller's ResumeDir, which checkPrivateDir accepted.
	f, err := os.OpenFile(filepath.Join(dir, payloadFile), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir) // dir was just created and is empty; the open error is returned.
		return nil, fmt.Errorf("create upload file: %w", err)
	}
	return &spool{dir: dir, file: f, resume: "upload"}, nil
}

// abandonedAfter is how long a folder in ResumeDir without an upload
// record goes untouched before it counts as abandoned.
const abandonedAfter = time.Hour

// pruneAbandoned removes folders of sends that died before recording an
// upload (killed while sealing, or during a single PUT), and of downloads
// that died before recording theirs: nothing can resume them. A folder
// still being written is recent, so it stays. It also removes downloads
// kept for a week without use (download_resume.go), except the folder
// named except, which the caller is about to use.
func pruneAbandoned(dir, except string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if _, err := uuid.Parse(e.Name()); err != nil || !e.IsDir() || e.Name() == except {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		if _, err := os.Stat(filepath.Join(sub, pendingFile)); err == nil {
			continue
		}
		if record, err := os.Stat(filepath.Join(sub, downloadFile)); err == nil {
			if time.Since(record.ModTime()) > staleDownloadAfter {
				removeKeptDownload(sub)
			}
			continue
		}
		info, err := os.Stat(filepath.Join(sub, payloadFile))
		if err != nil {
			info, err = os.Stat(sub)
		}
		if err == nil && time.Since(info.ModTime()) > abandonedAfter {
			_ = os.RemoveAll(sub) // best-effort pruning of ciphertext no upload can resume; the next send retries it.
		}
	}
}

// startUpload records a multipart upload about to start, when its spool
// can resume. The record is what ResumeUpload and ListPendingUploads read.
// firstUse is the send's recipients whose key is new to this device: the
// record keeps them, since a send that stops here records none of them.
func (c *Client) startUpload(sp *spool, secret *Secret, revisionID string, size int64, firstUse []Recipient) (*PendingUpload, error) {
	if sp.resume != "upload" {
		return nil, nil
	}
	now := time.Now().UTC()
	p := &PendingUpload{
		RevisionID: revisionID, SecretID: secret.ID, Name: secret.Name, Size: size,
		APIURL: c.api.BaseURL(), CreatedAt: now, UpdatedAt: now, Dir: sp.dir,
		FirstUse: append([]Recipient{}, firstUse...),
	}
	if err := writePending(p); err != nil {
		return nil, err
	}
	return p, nil
}

// uploadFailed turns a failed multipart upload into an
// UploadInterruptedError and keeps the spool, unless it cannot resume: no
// record, or the server no longer has the upload.
func uploadFailed(sp *spool, p *PendingUpload, err error) error {
	if p == nil || !resumable(err) {
		return fmt.Errorf("multipart upload: %w", err)
	}
	sp.keep = true
	p.UpdatedAt = time.Now().UTC()
	_ = writePending(p)
	return &UploadInterruptedError{Upload: *p, Err: err}
}

// resumable reports whether an upload that failed with err can resume:
// not when the server refuses access or has dropped the upload.
func resumable(err error) bool {
	var apiErr *apierror.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
			return false
		}
	}
	return true
}

func writePending(p *PendingUpload) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(p.Dir, pendingFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("record upload: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(p.Dir, pendingFile)); err != nil {
		return fmt.Errorf("record upload: %w", err)
	}
	return nil
}

func readPending(dir string) (*PendingUpload, error) {
	// #nosec G304 -- dir is <ResumeDir>/<UUID>: pendingDir and ListPendingUploads accept only UUID names.
	data, err := os.ReadFile(filepath.Join(dir, pendingFile))
	if err != nil {
		return nil, err
	}
	var p PendingUpload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("read upload record %s: %w", dir, err)
	}
	if _, err := uuid.Parse(p.RevisionID); err != nil || filepath.Base(dir) != p.RevisionID {
		return nil, fmt.Errorf("upload record %s does not match its folder", dir)
	}
	// What is listed here goes into the known keys file, so it is held to
	// that file's rules: a plausible address and a full fingerprint.
	for _, r := range p.FirstUse {
		if _, fp, err := knownkeys.NormalizeKeyRef(r.Email, r.Fingerprint); err != nil || fp != r.Fingerprint {
			return nil, fmt.Errorf("upload record %s is damaged: it lists a recipient's key that is malformed", dir)
		}
	}
	p.Dir = dir
	return &p, nil
}

// pendingDir returns the folder of revisionID's pending upload or kept
// download in dir, named by the ID's canonical form; what names dir in
// errors.
func pendingDir(dir, revisionID, what string) (string, error) {
	id, err := uuid.Parse(revisionID)
	if err != nil {
		return "", fmt.Errorf("invalid revision ID %q", revisionID)
	}
	if err := disk.CheckPrivateDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return filepath.Join(dir, id.String()), nil
}

// ListPendingUploads returns the unfinished uploads kept in dir, oldest
// first. A missing dir has none.
func ListPendingUploads(dir string) ([]PendingUpload, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := disk.CheckPrivateDir(dir); err != nil {
		return nil, fmt.Errorf("upload folder: %w", err)
	}
	var out []PendingUpload
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := uuid.Parse(e.Name()); err != nil {
			continue
		}
		p, err := readPending(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // sealing never finished, or not ours
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// ResumeUpload finishes the pending upload of revisionID kept in dir. The
// parts storage holds stay and the rest are sent; on success the folder is
// removed. A failure that can resume again returns an
// UploadInterruptedError.
//
// The send that was interrupted recorded none of its recipients' keys.
// The upload returned lists in FirstUse those whose key was new to this
// device, and a finished resume records them, as a send that finishes
// does. When this device has since recorded another key for one of them,
// the resume fails before the upload is finished, with the error a send to
// them would get (trust.KeyChangedError or trust.KeyRelabelledError): the
// revision was sealed for a key this device no longer accepts for them.
// Discard it and send again.
func (c *Client) ResumeUpload(ctx context.Context, dir, revisionID string, opt ResumeOptions) (*PendingUpload, error) {
	pdir, err := pendingDir(dir, revisionID, "upload folder")
	if err != nil {
		return nil, err
	}
	p, err := readPending(pdir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no pending upload %s", revisionID)
		}
		return nil, err
	}
	if p.APIURL != c.api.BaseURL() {
		return nil, fmt.Errorf("upload %s was made against %s, not %s", revisionID, p.APIURL, c.api.BaseURL())
	}
	// Completing the upload is what gives the recipients access, so the
	// keys it was sealed for are checked against what this device knows
	// now, before anything more is sent.
	firstUse := firstUsePeople(p.FirstUse)
	if err := c.store.CheckFirstUse(firstUse, false); err != nil {
		return nil, fmt.Errorf("upload %s was sealed for a key this device no longer accepts; discard it and send again: %w", revisionID, err)
	}
	f, err := os.Open(filepath.Join(pdir, payloadFile)) // #nosec G304 -- pdir is <dir>/<UUID> from pendingDir, which checked both.
	if err != nil {
		return nil, fmt.Errorf("open upload file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || info.Size() != p.Size {
		return nil, fmt.Errorf("upload file of %s is not %d bytes; discard it and send again", revisionID, p.Size)
	}
	err = c.api.MultipartUploadOpts(ctx, revisionID, f, p.Size, transport.MultipartUploadOptions{
		Threads:    opt.UploadThreads,
		OnProgress: opt.OnUploadProgress,
		Logger:     opt.Logger,
		Status:     opt.UploadStatus.transport(),
	})
	if err != nil {
		if !resumable(err) {
			return nil, fmt.Errorf("upload %s can no longer resume (%w); discard it and send again", revisionID, err)
		}
		p.UpdatedAt = time.Now().UTC()
		_ = writePending(p)
		return nil, &UploadInterruptedError{Upload: *p, Err: err}
	}
	// Sent: the keys new to this device that it went to are accepted now,
	// as at the end of a send. The folder goes either way: the upload is
	// finished, and nothing is left to resume.
	recordErr := c.store.RecordFirstUse(firstUse, false)
	_ = f.Close() // f was only read; it is closed before RemoveAll so Windows can delete it.
	removeErr := os.RemoveAll(pdir)
	if recordErr != nil {
		return p, fmt.Errorf("secret %s was sent, but recording its recipients' keys on this device failed: %w", p.SecretID, recordErr)
	}
	if removeErr != nil {
		return p, fmt.Errorf("upload finished, but removing %s failed: %w", pdir, removeErr)
	}
	return p, nil
}

// DiscardPendingUpload aborts the pending upload of revisionID on the
// server, which frees what it stored, and removes its folder from dir. An
// upload the server already dropped or finished is removed all the same.
func (c *Client) DiscardPendingUpload(ctx context.Context, dir, revisionID string) error {
	pdir, err := pendingDir(dir, revisionID, "upload folder")
	if err != nil {
		return err
	}
	if _, err := os.Stat(pdir); err != nil {
		return fmt.Errorf("no pending upload %s", revisionID)
	}
	if err := c.api.MultipartAbort(ctx, revisionID); err != nil {
		var apiErr *apierror.Error
		if !errors.As(err, &apiErr) || (apiErr.StatusCode != http.StatusNotFound && apiErr.StatusCode != http.StatusConflict && apiErr.StatusCode != http.StatusGone) {
			return err
		}
	}
	return os.RemoveAll(pdir)
}
