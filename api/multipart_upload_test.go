// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// patternSource is a large source that costs no memory: each byte is a
// function of its offset.
type patternSource struct{ size int64 }

func (p patternSource) ReadAt(b []byte, off int64) (int, error) {
	if off >= p.size {
		return 0, io.EOF
	}
	n := min(int64(len(b)), p.size-off)
	for i := range n {
		x := off + i
		b[i] = byte(x*31 + x>>11)
	}
	if n < int64(len(b)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func storedETag(src io.ReaderAt, off, size int64) string {
	h := md5.New()
	io.Copy(h, io.NewSectionReader(src, off, size))
	return hex.EncodeToString(h.Sum(nil))
}

// uploadServer is the API's multipart endpoints and the storage they sign
// URLs for, in one test server.
type uploadServer struct {
	t        *testing.T
	srv      *httptest.Server
	size     int64
	partSize int64

	mu         sync.Mutex
	stored     map[int]MultipartPartStatus
	urlCalls   int
	batch      []int // sizes of each part-urls request
	puts       map[int]int
	apiCalls   map[string]int
	generation int // URLs carry it; storage refuses older ones
	completed  []completePart

	expireFirst bool        // storage refuses the first batch's URLs
	fail        map[int]int // part -> PUTs to fail with 503
	stall       map[int]int // part -> PUTs that hang without reading
}

// locked runs f holding the server's lock, for reading what it recorded.
func (u *uploadServer) locked(f func()) {
	u.mu.Lock()
	defer u.mu.Unlock()
	f()
}

func newUploadServer(t *testing.T, size, partSize int64) *uploadServer {
	u := &uploadServer{t: t, size: size, partSize: partSize, stored: map[int]MultipartPartStatus{},
		puts: map[int]int{}, apiCalls: map[string]int{}, fail: map[int]int{}, stall: map[int]int{}}
	u.srv = httptest.NewServer(u)
	t.Cleanup(u.srv.Close)
	return u
}

func (u *uploadServer) client(t *testing.T) *Client {
	c, err := NewClient(u.srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (u *uploadServer) parts() int { return int((u.size + u.partSize - 1) / u.partSize) }

func (u *uploadServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/storage/") {
		u.servePart(w, r)
		return
	}
	op := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	u.mu.Lock()
	u.apiCalls[op]++
	u.mu.Unlock()
	ok := func(v any) {
		data, _ := json.Marshal(v)
		fmt.Fprintf(w, `{"success":true,"data":%s}`, data)
	}
	switch op {
	case "init":
		ok(MultipartInitResponse{UploadID: "up-1", PartSize: u.partSize, MaxPartNumber: u.parts()})
	case "status":
		u.mu.Lock()
		st := MultipartStatus{State: "in_progress", PartSize: u.partSize, MaxPartNumber: u.parts()}
		for n := 1; n <= u.parts(); n++ {
			if p, ok := u.stored[n]; ok {
				st.Parts = append(st.Parts, p)
			}
		}
		u.mu.Unlock()
		ok(st)
	case "part-urls":
		var req struct {
			PartNumbers []int `json:"part_numbers"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		u.mu.Lock()
		u.urlCalls++
		u.batch = append(u.batch, len(req.PartNumbers))
		gen := u.generation
		if u.expireFirst && u.urlCalls == 1 {
			u.generation++
		}
		u.mu.Unlock()
		if len(req.PartNumbers) == 0 || len(req.PartNumbers) > 100 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"error":"bad batch"}`)
			return
		}
		resp := MultipartPartURLsResponse{ExpiresIn: 1800}
		for _, n := range req.PartNumbers {
			resp.Parts = append(resp.Parts, MultipartPartURL{PartNumber: n, URL: fmt.Sprintf("%s/storage/%d?gen=%d", u.srv.URL, n, gen)})
		}
		ok(resp)
	case "complete":
		var req struct {
			Parts []completePart `json:"parts"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		u.mu.Lock()
		defer u.mu.Unlock()
		for i, p := range req.Parts {
			if s, ok := u.stored[p.PartNumber]; p.PartNumber != i+1 || !ok || s.Etag != p.Etag {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"success":false,"error":"part %d does not match storage"}`, p.PartNumber)
				return
			}
		}
		if len(req.Parts) != u.parts() {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"error":"missing parts"}`)
			return
		}
		u.completed = req.Parts
		ok(map[string]string{"status": "completed"})
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"error":"no such endpoint"}`)
	}
}

func (u *uploadServer) servePart(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/storage/"))
	gen, _ := strconv.Atoi(r.URL.Query().Get("gen"))
	u.mu.Lock()
	u.puts[n]++
	refuse := gen < u.generation
	fail := !refuse && u.fail[n] > 0
	if fail {
		u.fail[n]--
	}
	stall := !refuse && u.stall[n] > 0
	if stall {
		u.stall[n]--
	}
	u.mu.Unlock()
	if stall {
		// Read nothing until the client gives up and closes.
		select {
		case <-r.Context().Done():
		case <-time.After(3 * stallTimeout):
		}
		return
	}
	data, _ := io.ReadAll(r.Body)
	if refuse {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<Error><Code>AccessDenied</Code><Message>Request has expired</Message></Error>")
		return
	}
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "<Error><Code>SlowDown</Code></Error>")
		return
	}
	sum := md5.Sum(data)
	etag := hex.EncodeToString(sum[:])
	u.mu.Lock()
	u.stored[n] = MultipartPartStatus{PartNumber: n, Etag: etag, Size: int64(len(data))}
	u.mu.Unlock()
	w.Header().Set("ETag", `"`+etag+`"`)
}

func fastRetries(t *testing.T) {
	unit, stall := backoffUnit, stallTimeout
	backoffUnit, stallTimeout = time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { backoffUnit, stallTimeout = unit, stall })
}

// An upload asks for part URLs in batches, never registers a part, and
// completes with the ETags storage holds.
func TestUpload_BatchesURLsAndRegistersNothing(t *testing.T) {
	const part = S3MinPartSize
	u := newUploadServer(t, 12*part+1234, part)
	src := patternSource{u.size}
	var last int64
	err := u.client(t).MultipartUploadOpts("rev-1", src, u.size, MultipartUploadOptions{OnProgress: func(n, total int64) {
		if total != u.size || n > total {
			t.Errorf("progress %d of %d", n, total)
		}
		last = n
	}})
	if err != nil {
		t.Fatal(err)
	}
	u.locked(func() {
		if u.urlCalls != 1 || u.apiCalls["init"] != 1 || u.apiCalls["status"] != 1 || u.apiCalls["complete"] != 1 || len(u.apiCalls) != 4 {
			t.Fatalf("API calls %v (%d part-urls)", u.apiCalls, u.urlCalls)
		}
		if len(u.completed) != 13 || last != u.size {
			t.Fatalf("completed %d parts, progress ended at %d", len(u.completed), last)
		}
		if got, want := u.stored[13].Etag, storedETag(src, 12*part, 1234); got != want {
			t.Fatalf("last part etag %s, want %s", got, want)
		}
	})
}

// URLs come a hundred at a time for the parts about to go.
func TestUpload_URLBatchesFollowTheQueue(t *testing.T) {
	u := newUploadServer(t, 250*S3MinPartSize, S3MinPartSize)
	parts := make([]uploadPart, 250)
	items := make([]int, 250)
	for i := range parts {
		parts[i] = uploadPart{Number: i + 1}
		items[i] = i
	}
	q := &partQueue{parts: parts, items: items}
	cache := &partURLCache{c: u.client(t), revisionID: "rev-1", queue: q, urls: map[int]cachedURL{}}
	for {
		idx, ok := q.pop()
		if !ok {
			break
		}
		url, err := cache.get(t.Context(), parts[idx].Number)
		if err != nil || !strings.Contains(url, fmt.Sprintf("/storage/%d?", idx+1)) {
			t.Fatalf("part %d: %q, %v", idx+1, url, err)
		}
	}
	u.locked(func() {
		if fmt.Sprint(u.batch) != "[100 100 50]" {
			t.Fatalf("batches %v, want 100, 100, 50", u.batch)
		}
	})
}

// A second run keeps what storage holds with matching bytes and sends the
// rest, including a stored part whose bytes differ.
func TestUpload_ResumesFromStorage(t *testing.T) {
	const part = S3MinPartSize
	u := newUploadServer(t, 8*part, part)
	src := patternSource{u.size}
	for n := 1; n <= 5; n++ {
		u.stored[n] = MultipartPartStatus{PartNumber: n, Etag: storedETag(src, int64(n-1)*part, part), Size: part}
	}
	u.stored[3] = MultipartPartStatus{PartNumber: 3, Etag: strings.Repeat("0", 32), Size: part}
	var first int64 = -1
	err := u.client(t).MultipartUploadOpts("rev-1", src, u.size, MultipartUploadOptions{OnProgress: func(n, _ int64) {
		if first < 0 {
			first = n
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	u.locked(func() {
		for n := 1; n <= 8; n++ {
			want := 1
			if n == 1 || n == 2 || n == 4 || n == 5 {
				want = 0
			}
			if u.puts[n] != want {
				t.Errorf("part %d sent %d times, want %d", n, u.puts[n], want)
			}
		}
	})
	if first != 4*part {
		t.Fatalf("progress started at %d, want the kept %d bytes", first, 4*part)
	}
}

// Storage refusing a URL (expired) gets the part presigned again; a
// throttled part is retried; a stalled part is cancelled and retried.
func TestUpload_RecoversFromRefusalsFailuresAndStalls(t *testing.T) {
	fastRetries(t)
	const part = S3MinPartSize
	u := newUploadServer(t, 6*part, part)
	u.expireFirst = true
	u.fail[2] = 2
	u.stall[4] = 1
	if err := u.client(t).MultipartUploadOpts("rev-1", patternSource{u.size}, u.size, MultipartUploadOptions{}); err != nil {
		t.Fatal(err)
	}
	u.locked(func() {
		// Every part was refused once, then part 2 failed twice and part 4
		// stalled once.
		if len(u.completed) != 6 || u.urlCalls < 2 || u.puts[2] != 4 || u.puts[4] != 3 || u.puts[1] != 2 {
			t.Fatalf("completed %d parts with %d URL batches; parts 1, 2, 4 sent %d, %d, %d times", len(u.completed), u.urlCalls, u.puts[1], u.puts[2], u.puts[4])
		}
	})
}

// A part that keeps failing fails the upload after its attempts run out.
func TestUpload_GivesUpAfterTheAttempts(t *testing.T) {
	fastRetries(t)
	const part = S3MinPartSize
	u := newUploadServer(t, 2*part, part)
	u.fail[2] = 100
	err := u.client(t).MultipartUploadOpts("rev-1", patternSource{u.size}, u.size, MultipartUploadOptions{})
	u.locked(func() {
		if err == nil || !strings.Contains(err.Error(), "part 2") || u.puts[2] != multipartAttempts {
			t.Fatalf("err %v after %d attempts", err, u.puts[2])
		}
		if u.apiCalls["complete"] != 0 {
			t.Fatal("completed an upload with a missing part")
		}
	})
}

// The upload refuses data whose size does not match the revision.
func TestUpload_RefusesASizeMismatch(t *testing.T) {
	u := newUploadServer(t, 4*S3MinPartSize, S3MinPartSize)
	err := u.client(t).MultipartUploadOpts("rev-1", patternSource{9 * S3MinPartSize}, 9*S3MinPartSize, MultipartUploadOptions{})
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("err %v", err)
	}
}
