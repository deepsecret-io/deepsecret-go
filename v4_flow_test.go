// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepsecret-io/sdk/api"
	"github.com/deepsecret-io/sdk/crypto"
	"github.com/deepsecret-io/sdk/internal/protocol"
)

// ── A fake of the protocol v4 secrets API ───────────────────────────────────
//
// It stores what the real API stores (PROTOCOL_V4.md §7) and makes the same
// agreement checks at create, so these tests pin the JSON contract the SDK
// speaks. Callers authenticate with their email as the API key.

type fakeActor struct {
	id, email string
	kp        *crypto.KeyPair
	fp        string
	old       []*crypto.KeyPair // keys that were primary before, still listed
	keys      string            // the key pair directory of their device
}

type fakeWrap struct {
	fp      string
	enc, ct []byte
}

type fakeRevision struct {
	id, secretID string
	manifest     []byte
	wraps        map[string]fakeWrap // by actor id
	filesMeta    any                 // the files_meta of the create request, served back as the API does
}

type fakeSecret struct {
	id, name, senderID string
	recipients         []string // actor ids
	revisions          []*fakeRevision
}

type fakeAPI struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	actors  map[string]*fakeActor // by email
	secrets map[string]*fakeSecret
	revs    map[string]*fakeRevision
	objects string // directory holding stored objects, one file each
	creates int
	puts    int
	lastReq createBody
	// secretGets, revisionLists and accountGets count the reads of a
	// secret, of its revisions and of the caller's account.
	secretGets, revisionLists, accountGets int

	// editBundle, when set, edits the primary key bundle listed for an
	// email before it is served, as a hostile server would.
	editBundle func(email string, bundle map[string]any)
	// whoAmI, when set, is the email /actors/me answers with, whoever
	// calls: a server lying about who the caller is.
	whoAmI string
	// known holds each client's known keys file, as each person's own
	// device would.
	known string

	// Multipart: a create at or above multipartAt bytes answers
	// is_multipart with partSize parts.
	multipartAt int64
	partSize    int64
	uploads     map[string]*fakeUpload // by revision id
	refusePart  int                    // storage refuses this part's PUTs
	afterPart   func(n int)            // called once storage holds part n

	// Downloads: the part size the presign suggests, and how many range
	// GETs a presigned URL serves before it is refused with 403 (0: no
	// limit). presigns counts download presigns.
	downloadPartSize int64
	urlUses          int
	presigns         int
	tokens           map[string]int        // uses left, by token
	ranges           []string              // the Range of every object GET, in order
	beforeRange      func(r *http.Request) // when set, runs before a range is served, and may hold it
}

// fakeUpload is a multipart upload: the parts storage holds.
type fakeUpload struct {
	parts map[int]fakePart
}

type fakePart struct {
	etag string
	size int64
}

type createBody struct {
	Name            string `json:"name"`
	RevisionID      string `json:"revision_id"`
	ChecksumSHA256  string `json:"checksum_sha256"`
	Size            int64  `json:"size"`
	KDF             string `json:"kdf"`
	ProtocolVersion string `json:"protocol_version"`
	CipherSuite     string `json:"cipher_suite"`
	KeyFingerprint  string `json:"key_fingerprint"`
	Manifest        []byte `json:"manifest"`
	PayloadType     string `json:"payload_type"`
	FilesCount      int    `json:"files_count"`
	Compressed      bool   `json:"compressed"`
	Compression     string `json:"compression"`
	FilesMeta       []struct {
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"files_meta"`
	Recipients []struct {
		RecipientID    string `json:"recipient_id"`
		RecipientOrgID string `json:"recipient_org_id"`
		KeyFingerprint string `json:"key_fingerprint"`
		Wrap           struct {
			Enc []byte `json:"enc"`
			Ct  []byte `json:"ct"`
		} `json:"wrap"`
	} `json:"recipients"`
	RevokeMissing bool `json:"revoke_missing"`
}

func newFakeAPI(t *testing.T, emails ...string) *fakeAPI {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := &fakeAPI{t: t, actors: map[string]*fakeActor{}, secrets: map[string]*fakeSecret{},
		revs: map[string]*fakeRevision{}, objects: t.TempDir(), multipartAt: 1 << 62,
		uploads: map[string]*fakeUpload{}, tokens: map[string]int{}, known: t.TempDir()}
	for i, email := range emails {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		// Each actor is on a device of their own: only their key pairs are
		// on it.
		fp, _ := crypto.Fingerprint(kp)
		keys := filepath.Join(home, email, ".deepsecret", "keys")
		if err := crypto.SaveKeyPairTo(keys, fp, kp, ""); err != nil {
			t.Fatal(err)
		}
		f.actors[email] = &fakeActor{id: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), email: email, kp: kp, fp: fp, keys: keys}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/actors/me", f.me)
	mux.HandleFunc("GET /api/v1/orgs", func(w http.ResponseWriter, _ *http.Request) { ok(w, []any{}) })
	mux.HandleFunc("GET /api/v1/actors/email/{email}", f.actorByEmail)
	mux.HandleFunc("GET /api/v1/actors/{id}", f.actorByID)
	mux.HandleFunc("GET /api/v1/identities", f.ownKeys)
	mux.HandleFunc("POST /api/v1/identities", func(w http.ResponseWriter, _ *http.Request) { ok(w, map[string]string{}) })
	mux.HandleFunc("GET /api/v1/identities/actor/{email}", f.publicKeys)
	mux.HandleFunc("POST /api/v1/orgs/{org}/secrets", f.create)
	mux.HandleFunc("POST /api/v1/orgs/{org}/storage/presign", f.presignUpload)
	mux.HandleFunc("PUT /s3/{key}", f.putObject)
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/multipart/init", f.multipartInit)
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/multipart/part-urls", f.multipartPartURLs)
	mux.HandleFunc("PUT /s3part/{id}/{n}", f.putPart)
	mux.HandleFunc("GET /api/v1/secrets/revisions/{id}/multipart/status", f.multipartStatus)
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/multipart/complete", f.multipartComplete)
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/multipart/abort", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		delete(f.uploads, r.PathValue("id"))
		f.mu.Unlock()
		ok(w, map[string]string{"status": "aborted"})
	})
	mux.HandleFunc("GET /s3/{key}", f.getObject)
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/confirm", func(w http.ResponseWriter, _ *http.Request) { ok(w, map[string]string{"status": "uploaded"}) })
	mux.HandleFunc("POST /api/v1/secrets/revisions/{id}/presign", f.presignDownload)
	mux.HandleFunc("GET /api/v1/secrets/revisions/{id}/manifest", f.manifest)
	mux.HandleFunc("GET /api/v1/secrets/{id}", f.secret)
	mux.HandleFunc("GET /api/v1/secrets/{id}/revisions", f.revisions)
	mux.HandleFunc("DELETE /api/v1/secrets/{id}/recipients/{actor}", f.revoke)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client(email string) *Client {
	f.t.Helper()
	c, err := NewClient(f.srv.URL, email)
	if err != nil {
		f.t.Fatal(err)
	}
	c.keysDir = f.actors[email].keys
	c.knownKeysFile = f.knownFile(email)
	return c
}

// sameDevice puts the key pairs of every actor in as on the first one's
// device, as for a user with several accounts.
func (f *fakeAPI) sameDevice(as ...*fakeActor) {
	f.t.Helper()
	for _, a := range as[1:] {
		if err := crypto.SaveKeyPairTo(as[0].keys, a.fp, a.kp, ""); err != nil {
			f.t.Fatal(err)
		}
		if err := os.RemoveAll(a.keys); err != nil {
			f.t.Fatal(err)
		}
		a.keys = as[0].keys
	}
}

// knownFile is the known keys file of email's client.
func (f *fakeAPI) knownFile(email string) string { return filepath.Join(f.known, email+".json") }

func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
}

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": false, "error": msg})
}

func (f *fakeAPI) caller(r *http.Request) *fakeActor { return f.actors[r.Header.Get("DS-API-KEY")] }

func (f *fakeAPI) byID(id string) *fakeActor {
	for _, a := range f.actors {
		if a.id == id {
			return a
		}
	}
	return nil
}

func (f *fakeAPI) me(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.accountGets++
	f.mu.Unlock()
	a := f.caller(r)
	if f.whoAmI != "" {
		a = f.actors[f.whoAmI]
	}
	ok(w, map[string]any{"actor": map[string]string{"id": a.id, "email": a.email},
		"membership": map[string]string{"org_id": "org-1", "role": "owner"}})
}

func (f *fakeAPI) actorByEmail(w http.ResponseWriter, r *http.Request) {
	a := f.actors[r.PathValue("email")]
	if a == nil {
		fail(w, http.StatusNotFound, "Actor not found")
		return
	}
	ok(w, map[string]string{"id": a.id})
}

func (f *fakeAPI) actorByID(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]string{"email": f.byID(r.PathValue("id")).email})
}

func (f *fakeAPI) ownKeys(w http.ResponseWriter, r *http.Request) {
	a := f.caller(r)
	ok(w, map[string]any{"keys": []map[string]any{{"id": "k-" + a.id, "fingerprint": a.fp, "is_primary": true}}})
}

func (f *fakeAPI) publicKeys(w http.ResponseWriter, r *http.Request) {
	a := f.actors[r.PathValue("email")]
	if a == nil {
		fail(w, http.StatusNotFound, "Actor not found")
		return
	}
	var keys []map[string]any
	for i, kp := range append([]*crypto.KeyPair{a.kp}, a.old...) {
		edSig, mldsaSig, err := crypto.SignKeyBundle(kp)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		fp, _ := crypto.Fingerprint(kp)
		bundle := map[string]any{
			"ed25519": kp.ED25519Public, "x25519": kp.X25519Public, "mlkem768": kp.MLKEM768PK,
			"mldsa65": kp.MLDSA65PK, "fingerprint": fp, "signature": edSig, "signature_mldsa65": mldsaSig,
			"is_primary": i == 0,
		}
		if i == 0 && f.editBundle != nil {
			f.editBundle(r.PathValue("email"), bundle)
		}
		keys = append(keys, bundle)
	}
	ok(w, map[string]any{"keys": keys})
}

// create makes the checks of the API contract §3 before storing anything.
func (f *fakeAPI) create(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sender := f.caller(r)
	var req createBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, 400, err.Error())
		return
	}
	f.creates++
	f.lastReq = req
	m, err := protocol.UnmarshalManifest(req.Manifest)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name) // the name the API stores the secret under
	if m.Version != req.ProtocolVersion || m.CipherSuite != req.CipherSuite || req.KDF != protocol.KDF ||
		m.RevisionID != req.RevisionID || m.SecretName != name || m.CiphertextSize != req.Size ||
		hex.EncodeToString(m.PayloadDigest) != req.ChecksumSHA256 || m.SenderFingerprint != req.KeyFingerprint {
		fail(w, 400, "manifest does not agree with the request")
		return
	}
	if len(req.Recipients) != len(m.Recipients) {
		fail(w, 400, "manifest lists a different set of recipients")
		return
	}
	rev := &fakeRevision{id: req.RevisionID, manifest: req.Manifest, wraps: map[string]fakeWrap{}, filesMeta: req.FilesMeta}
	var ids []string
	for _, in := range req.Recipients {
		a := f.byID(in.RecipientID)
		if a == nil || a.fp != in.KeyFingerprint {
			fail(w, 400, "key_fingerprint is not the recipient's primary key")
			return
		}
		listed, found := m.Recipient(in.KeyFingerprint)
		digest := (&protocol.Wrap{RecipientFingerprint: in.KeyFingerprint, Enc: in.Wrap.Enc, Ciphertext: in.Wrap.Ct}).Digest()
		if !found || hex.EncodeToString(listed.WrapDigest) != hex.EncodeToString(digest) {
			fail(w, 400, "wrap does not match the manifest")
			return
		}
		rev.wraps[a.id] = fakeWrap{fp: in.KeyFingerprint, enc: in.Wrap.Enc, ct: in.Wrap.Ct}
		ids = append(ids, a.id)
	}

	var revoked []map[string]string
	s := f.secretByName(sender.id, name)
	if s == nil {
		s = &fakeSecret{id: fmt.Sprintf("10000000-0000-4000-8000-%012d", len(f.secrets)+1), name: name, senderID: sender.id}
		f.secrets[s.id] = s
	} else {
		var missing []string
		for _, id := range s.recipients {
			if !slices.Contains(ids, id) {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 && !req.RevokeMissing {
			var emails []string
			for _, id := range missing {
				emails = append(emails, f.byID(id).email)
			}
			fail(w, http.StatusConflict, "This send leaves out people who have access now: "+strings.Join(emails, ", "))
			return
		}
		for _, id := range missing {
			revoked = append(revoked, map[string]string{"id": id, "email": f.byID(id).email})
			for _, old := range s.revisions {
				delete(old.wraps, id)
			}
		}
	}
	s.recipients = ids
	rev.secretID = s.id
	s.revisions = append(s.revisions, rev)
	f.revs[rev.id] = rev
	revision := map[string]any{"id": rev.id, "revision_number": len(s.revisions), "is_multipart": false}
	if req.Size >= f.multipartAt {
		revision["is_multipart"], revision["multipart_part_size"] = true, f.partSize
	}
	ok(w, map[string]any{
		"secret":   map[string]string{"id": s.id, "name": s.name},
		"revision": revision,
		"revoked":  revoked,
	})
}

func (f *fakeAPI) secretByName(senderID, name string) *fakeSecret {
	for _, s := range f.secrets {
		if s.senderID == senderID && s.name == name {
			return s
		}
	}
	return nil
}

func (f *fakeAPI) presignUpload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	ok(w, map[string]string{"url": f.srv.URL + "/s3/" + body.Key})
}

// object returns a stored object's bytes.
func (f *fakeAPI) object(key string) []byte {
	data, _ := os.ReadFile(filepath.Join(f.objects, key))
	return data
}

func (f *fakeAPI) objectSize(key string) int64 {
	info, err := os.Stat(filepath.Join(f.objects, key))
	if err != nil {
		return 0
	}
	return info.Size()
}

func (f *fakeAPI) putObject(w http.ResponseWriter, r *http.Request) {
	if !md5Matches(r) {
		fail(w, http.StatusBadRequest, "BadDigest")
		return
	}
	out, err := os.Create(filepath.Join(f.objects, r.PathValue("key")))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer out.Close()
	io.Copy(out, r.Body)
	f.mu.Lock()
	f.puts++
	f.mu.Unlock()
}

// md5Matches checks the Content-MD5 the client sent against the body, as
// S3 does, and leaves the body readable.
func md5Matches(r *http.Request) bool {
	data, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(data))
	sum := md5.Sum(data)
	return r.Header.Get("Content-MD5") == base64.StdEncoding.EncodeToString(sum[:])
}

// getObject serves an object with Range support, as S3 does. A presigned
// URL whose token has served its uses is refused with 403.
func (f *fakeAPI) getObject(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if tok := r.URL.Query().Get("t"); f.urlUses > 0 {
		if f.tokens[tok] <= 0 {
			f.mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.tokens[tok]--
	}
	f.ranges = append(f.ranges, r.Header.Get("Range"))
	hold := f.beforeRange
	f.mu.Unlock()
	if hold != nil {
		hold(r)
	}
	obj, err := os.Open(filepath.Join(f.objects, r.PathValue("key")))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer obj.Close()
	http.ServeContent(w, r, "", time.Time{}, obj)
}

func (f *fakeAPI) multipartInit(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.PathValue("id")
	if f.uploads[id] == nil {
		f.uploads[id] = &fakeUpload{parts: map[int]fakePart{}}
	}
	ok(w, map[string]any{"upload_id": "up-" + id, "part_size": f.partSize,
		"max_part_number": int((f.lastReq.Size + f.partSize - 1) / f.partSize), "expires_at": time.Now().Add(time.Hour)})
}

func (f *fakeAPI) multipartPartURLs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PartNumbers []int `json:"part_numbers"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if len(body.PartNumbers) == 0 || len(body.PartNumbers) > 100 {
		fail(w, 400, "part_numbers must list 1 to 100 parts")
		return
	}
	parts := make([]map[string]any, len(body.PartNumbers))
	for i, n := range body.PartNumbers {
		parts[i] = map[string]any{"part_number": n, "url": fmt.Sprintf("%s/s3part/%s/%d", f.srv.URL, r.PathValue("id"), n)}
	}
	ok(w, map[string]any{"parts": parts, "expires_in": 1800})
}

// putPart streams a part to disk, checking its Content-MD5 as S3 does.
func (f *fakeAPI) putPart(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.PathValue("n"))
	f.mu.Lock()
	up := f.uploads[r.PathValue("id")]
	refused := f.refusePart == n
	f.mu.Unlock()
	if refused {
		fail(w, http.StatusBadRequest, "InvalidPart")
		return
	}
	path := filepath.Join(f.objects, r.PathValue("id")+".part"+r.PathValue("n"))
	out, err := os.Create(path)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	h := md5.New()
	_, err = io.Copy(io.MultiWriter(out, h), r.Body)
	out.Close()
	sum := h.Sum(nil)
	if err != nil || r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(sum) {
		os.Remove(path)
		fail(w, http.StatusBadRequest, "BadDigest")
		return
	}
	info, _ := os.Stat(path)
	f.mu.Lock()
	f.puts++
	up.parts[n] = fakePart{etag: hex.EncodeToString(sum), size: info.Size()}
	after := f.afterPart
	f.mu.Unlock()
	if after != nil {
		after(n)
	}
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum)+`"`)
}

// multipartStatus lists the parts storage holds, as the API does.
func (f *fakeAPI) multipartStatus(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := []map[string]any{}
	if up := f.uploads[r.PathValue("id")]; up != nil {
		for n, p := range up.parts {
			parts = append(parts, map[string]any{"part_number": n, "etag": p.etag, "size": p.size})
		}
	}
	ok(w, map[string]any{"state": "in_progress", "parts": parts})
}

// multipartComplete assembles the parts, which must all be in storage with
// the ETags the client sends.
func (f *fakeAPI) multipartComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Parts []struct {
			PartNumber int    `json:"part_number"`
			Etag       string `json:"etag"`
		} `json:"parts"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.PathValue("id")
	up := f.uploads[id]
	out, err := os.Create(filepath.Join(f.objects, id))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer out.Close()
	for i, p := range body.Parts {
		if stored, held := up.parts[p.PartNumber]; p.PartNumber != i+1 || !held || stored.etag != p.Etag {
			fail(w, 400, "parts must be in storage and contiguous")
			return
		}
		part, err := os.Open(filepath.Join(f.objects, fmt.Sprintf("%s.part%d", id, p.PartNumber)))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		io.Copy(out, part)
		part.Close()
	}
	ok(w, map[string]string{"status": "completed"})
}

func (f *fakeAPI) presignDownload(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rev := f.revs[r.PathValue("id")]
	if _, held := rev.wraps[f.caller(r).id]; !held {
		fail(w, http.StatusForbidden, "no access to this revision")
		return
	}
	f.presigns++
	tok := fmt.Sprintf("tok%d", f.presigns)
	f.tokens[tok] = f.urlUses
	ok(w, map[string]any{"url": f.srv.URL + "/s3/" + rev.id + "?t=" + tok, "size": f.objectSize(rev.id), "part_size": f.downloadPartSize})
}

func (f *fakeAPI) manifest(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rev := f.revs[r.PathValue("id")]
	wr, held := rev.wraps[f.caller(r).id]
	if !held {
		fail(w, http.StatusNotFound, "Revision not found")
		return
	}
	ok(w, map[string]any{"revision_id": rev.id, "manifest": rev.manifest, "key_fingerprint": wr.fp,
		"wrap": map[string][]byte{"enc": wr.enc, "ct": wr.ct}})
}

func (f *fakeAPI) secret(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secretGets++
	s := f.secrets[r.PathValue("id")]
	var recipients []map[string]string
	for _, id := range s.recipients {
		recipients = append(recipients, map[string]string{"id": id, "email": f.byID(id).email})
	}
	ok(w, map[string]any{"id": s.id, "name": s.name, "sender_id": s.senderID, "sender_email": f.byID(s.senderID).email,
		"recipients": recipients, "latest_revision_id": s.revisions[len(s.revisions)-1].id, "revision_count": len(s.revisions)})
}

func (f *fakeAPI) revisions(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revisionLists++
	s := f.secrets[r.PathValue("id")]
	var out []map[string]any
	for i, rev := range s.revisions {
		var recipients []map[string]string
		for id, wr := range rev.wraps {
			recipients = append(recipients, map[string]string{"id": id, "email": f.byID(id).email, "key_fingerprint": wr.fp})
		}
		out = append(out, map[string]any{"id": rev.id, "revision_number": i + 1, "files_meta": rev.filesMeta,
			"integrity": map[string]any{"protocol_version": protocol.ProtocolVersion, "recipients": recipients}})
	}
	ok(w, map[string]any{"revisions": out, "total": len(out)})
}

func (f *fakeAPI) revoke(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.secrets[r.PathValue("id")]
	actor := r.PathValue("actor")
	if s.senderID != f.caller(r).id || !slices.Contains(s.recipients, actor) {
		fail(w, http.StatusNotFound, "Recipient not found")
		return
	}
	s.recipients = slices.DeleteFunc(s.recipients, func(id string) bool { return id == actor })
	for _, rev := range s.revisions {
		delete(rev.wraps, actor)
	}
	ok(w, map[string]bool{"secret_deleted": len(s.recipients) == 0})
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestValidateRecipients(t *testing.T) {
	many := make([]string, MaxRecipientsPerSend+1)
	for i := range many {
		many[i] = fmt.Sprintf("u%d@example.com", i)
	}
	cases := map[string]struct {
		emails []string
		want   string
	}{
		"none":      {nil, "at least one recipient"},
		"too many":  {many, "at most 100"},
		"invalid":   {[]string{"bob"}, "invalid recipient email"},
		"duplicate": {[]string{"bob@example.com", "Bob@Example.com"}, "listed twice"},
	}
	for name, c := range cases {
		if err := ValidateRecipients(c.emails); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	if err := ValidateRecipients(many[:MaxRecipientsPerSend]); err != nil {
		t.Errorf("100 recipients: %v", err)
	}
}

// One send seals once and uploads once for every recipient, and each
// recipient decrypts the same payload. The sender is not a recipient
// unless listed.
func TestSendOnceToManyRecipients(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["carol@example.com"]

	res, err := f.client(alice.email).EncryptText(context.Background(), []string{bob.email, carol.email}, "hello, both", EncryptOptions{Name: "greeting"})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if f.creates != 1 || f.puts != 1 {
		t.Fatalf("want one create and one upload, got %d and %d", f.creates, f.puts)
	}
	want := []Recipient{{Email: bob.email, Fingerprint: bob.fp}, {Email: carol.email, Fingerprint: carol.fp}}
	if !slices.Equal(res.Recipients, want) || res.SenderFingerprint != alice.fp {
		t.Fatalf("result recipients %+v, sender %s", res.Recipients, res.SenderFingerprint)
	}
	stored := f.object(res.Secret.RevisionID)
	if res.EncryptedSize != int64(len(stored)) || len(res.Revoked) != 0 {
		t.Fatalf("size %d, stored %d, revoked %v", res.EncryptedSize, len(stored), res.Revoked)
	}
	for _, in := range f.lastReq.Recipients {
		if in.RecipientOrgID != "" {
			t.Errorf("recipient_org_id set for %s, which only the server knows", in.RecipientID)
		}
	}

	digest := sha256.Sum256(stored)
	for _, r := range []*fakeActor{bob, carol} {
		out, err := f.client(r.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{})
		if err != nil {
			t.Fatalf("%s decrypt: %v", r.email, err)
		}
		if out.Decrypted.Message != "hello, both" || out.RecipientFingerprint != r.fp || out.SenderFingerprint != alice.fp {
			t.Fatalf("%s: got %+v", r.email, out)
		}
		if out.ProtocolVersion != protocol.ProtocolVersion || out.CipherSuite != protocol.CipherSuite ||
			out.PayloadDigest != hex.EncodeToString(digest[:]) || len(out.Recipients) != 2 {
			t.Fatalf("%s: metadata %+v", r.email, out)
		}
		for _, sr := range out.Recipients {
			if sr.Email == "" {
				t.Errorf("%s: no email for signed recipient %s", r.email, sr.Fingerprint)
			}
		}
	}

	if _, err := f.client(alice.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{}); err == nil || !strings.Contains(err.Error(), "not encrypted for your key") {
		t.Fatalf("sender who is not a recipient: %v", err)
	}
}

// nextSecond waits for the clock's next second, so a revision sealed after
// it is signed later than one sealed before.
func nextSecond() {
	for now := time.Now().Unix(); time.Now().Unix() == now; {
		time.Sleep(10 * time.Millisecond)
	}
}

// A server controls which revision it names as a secret's latest, and what
// it calls the secret. It cannot pass off another secret's revision from
// the same sender, because the manifest signs the secret's name. It cannot
// roll a secret back past a revision this device opened, because the
// device keeps the newest signing time per secret. A revision requested by
// id still opens.
func TestServerCannotSwapOrRollBackRevisions(t *testing.T) {
	f := newFakeAPI(t, "carol@example.com", "dave@example.com")
	carol, dave := f.actors["carol@example.com"], f.actors["dave@example.com"]
	send := func(name, text string) *EncryptResult {
		t.Helper()
		res, err := f.client(carol.email).EncryptText(context.Background(), []string{dave.email}, text, EncryptOptions{Name: name})
		if err != nil {
			t.Fatalf("send %s: %v", name, err)
		}
		return res
	}
	v1 := send("api-token", "TOKEN=v1-revoked")
	nextSecond()
	v2 := send(" api-token ", "TOKEN=v2-active") // the same secret: the name is signed and stored trimmed
	other := send("other-app", "TOKEN=other-app")
	if v2.Secret.ID != v1.Secret.ID || other.Secret.ID == v1.Secret.ID {
		t.Fatalf("secrets %s, %s, %s", v1.Secret.ID, v2.Secret.ID, other.Secret.ID)
	}
	secret := f.secrets[v1.Secret.ID]
	honest := slices.Clone(secret.revisions)
	serve := func(revs ...*fakeRevision) {
		f.mu.Lock()
		secret.revisions = revs
		f.mu.Unlock()
	}
	open := func(opt DecryptOptions) (*DecryptResult, error) {
		return f.client(dave.email).DecryptSecret(context.Background(), v1.Secret.ID, opt)
	}

	got, err := open(DecryptOptions{})
	if err != nil || got.Decrypted.Message != "TOKEN=v2-active" || got.RevisionID != v2.Secret.RevisionID ||
		got.SecretName != "api-token" || got.SignedAt.IsZero() {
		t.Fatalf("honest: %+v, %v", got, err)
	}

	// Rollback: the server names the first revision as the latest.
	serve(honest[1], honest[0])
	var stale *StaleRevisionError
	if _, err := open(DecryptOptions{}); !errors.As(err, &stale) ||
		stale.RevisionID != v1.Secret.RevisionID || stale.SecretName != "api-token" || stale.SenderEmail != carol.email {
		t.Fatalf("rollback: %v", err)
	}
	// Requested by id, the older revision opens, and opening it does not
	// make it the newest.
	if got, err := open(DecryptOptions{Revision: v1.Secret.RevisionID}); err != nil || got.Decrypted.Message != "TOKEN=v1-revoked" {
		t.Fatalf("older revision by id: %+v, %v", got, err)
	}
	if _, err := open(DecryptOptions{}); !errors.As(err, &stale) {
		t.Fatalf("rollback after opening the older revision by id: %v", err)
	}

	// Swap: the server names other-app's revision as api-token's latest.
	serve(honest[0], honest[1], f.revs[other.Secret.RevisionID])
	if _, err := open(DecryptOptions{}); err == nil || !strings.Contains(err.Error(), `signed for secret "other-app"`) {
		t.Fatalf("swap: %v", err)
	}
	// A server that also renames the secret gets the revision opened, but
	// the result names the secret its sender signed.
	f.mu.Lock()
	secret.name = "other-app"
	f.mu.Unlock()
	if got, err := open(DecryptOptions{}); err != nil || got.SecretName != "other-app" {
		t.Fatalf("swap with the name changed too: %+v, %v", got, err)
	}

	f.mu.Lock()
	secret.name = "api-token"
	f.mu.Unlock()
	serve(honest...)
	if got, err := open(DecryptOptions{}); err != nil || got.Decrypted.Message != "TOKEN=v2-active" {
		t.Fatalf("honest again: %+v, %v", got, err)
	}
}

// A self-send lists only the sender, whose org is the one known recipient
// org.
func TestSelfSend(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com")
	alice := f.actors["alice@example.com"]
	c := f.client(alice.email)
	res, err := c.EncryptData(context.Background(), []string{alice.email}, map[string]string{"K": "V"}, EncryptOptions{Name: "vault"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.lastReq.Recipients) != 1 || f.lastReq.Recipients[0].RecipientOrgID != "org-1" {
		t.Fatalf("self-send recipients %+v", f.lastReq.Recipients)
	}
	out, err := c.DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{})
	if err != nil || len(out.Decrypted.Entries) != 1 || out.Decrypted.Entries[0].Value != "V" {
		t.Fatalf("decrypt: %+v, %v", out, err)
	}
}

// A send under an existing name that leaves out a current recipient is
// refused with the server's message unless RevokeMissing is set.
func TestResendLeavingOutRecipient(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["carol@example.com"]
	c := f.client(alice.email)
	if _, err := c.EncryptText(context.Background(), []string{bob.email, carol.email}, "v1", EncryptOptions{Name: "db"}); err != nil {
		t.Fatal(err)
	}

	_, err := c.EncryptText(context.Background(), []string{bob.email}, "v2", EncryptOptions{Name: "db"})
	if !errors.Is(err, api.ErrConflict) || !strings.Contains(err.Error(), "leaves out people who have access now: carol@example.com") {
		t.Fatalf("leaving out carol: %v", err)
	}

	res, err := c.EncryptText(context.Background(), []string{bob.email}, "v2", EncryptOptions{Name: "db", RevokeMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Revoked) != 1 || res.Revoked[0].Email != carol.email {
		t.Fatalf("revoked %+v", res.Revoked)
	}
	if out, err := f.client(bob.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{}); err != nil || out.Decrypted.Message != "v2" {
		t.Fatalf("bob reads v2: %+v, %v", out, err)
	}
	if _, err := f.client(carol.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{}); err == nil {
		t.Fatal("carol still decrypts after being revoked")
	}
}

func TestRevokeRecipient(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := f.actors["alice@example.com"], f.actors["bob@example.com"], f.actors["carol@example.com"]
	c := f.client(alice.email)
	res, err := c.EncryptText(context.Background(), []string{bob.email, carol.email}, "x", EncryptOptions{Name: "token"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.RevokeRecipient(context.Background(), res.Secret.ID, "dave@example.com"); err == nil || !strings.Contains(err.Error(), "not a recipient") {
		t.Fatalf("unknown recipient: %v", err)
	}
	r, err := c.RevokeRecipient(context.Background(), res.Secret.ID, "Bob@Example.com")
	if err != nil || r.RecipientID != bob.id || r.Email != bob.email || r.SecretDeleted {
		t.Fatalf("revoke bob: %+v, %v", r, err)
	}
	if _, err := f.client(bob.email).DecryptSecret(context.Background(), res.Secret.ID, DecryptOptions{}); err == nil {
		t.Fatal("bob still decrypts after being revoked")
	}
	r, err = c.RevokeRecipient(context.Background(), res.Secret.ID, carol.email)
	if err != nil || !r.SecretDeleted {
		t.Fatalf("revoke the last recipient: %+v, %v", r, err)
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

// A recipient email goes into API paths and onto screens: anything that
// could change a path, a header or a terminal, or pass for another address
// with letters from another script, is refused.
func TestValidateRecipientsRefusesHostileEmails(t *testing.T) {
	for _, ok := range []string{"alice@example.com", "o'brien+tag@example.co.uk"} {
		if err := ValidateRecipients([]string{ok}); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"a b@example.com", "alice@example.com\r\nX-Injected: 1", "../../actors/me@x.io",
		"a/b@example.com", "a?b@example.com", "a#b@example.com", "a%2f@example.com",
		"a\x1b[31m@example.com", "a\u202e@example.com", "a\u009b@example.com",
		"alice@localhost", "alice@", "@example.com", strings.Repeat("a", 250) + "@example.com",
		"ünï@exämple.com", "\u0430lice@example.com", "alice@ex\u0430mple.com", "a\xffb@example.com",
	} {
		if err := ValidateRecipients([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
