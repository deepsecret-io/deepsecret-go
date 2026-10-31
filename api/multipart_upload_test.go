// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
	link        *sharedLink // when set, every PUT body is read through it
	connRate    float64     // when set, each PUT body is read at this rate on its own, as on a path that limits every connection
}

// sharedLink paces reads so that all requests together move rate bytes a
// second, like one uplink shared by every part in flight.
type sharedLink struct {
	mu   sync.Mutex
	rate float64
	next time.Time
}

func (l *sharedLink) Read(r io.Reader, b []byte) (int, error) {
	n, err := r.Read(b[:min(len(b), 32<<10)])
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	wait := time.Until(l.next)
	l.mu.Unlock()
	time.Sleep(wait)
	return n, err
}

type linkReader struct {
	r    io.Reader
	link *sharedLink
}

func (r linkReader) Read(b []byte) (int, error) { return r.link.Read(r.r, b) }

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
	var body io.Reader = r.Body
	if u.link != nil {
		body = linkReader{r.Body, u.link}
	}
	if u.connRate > 0 {
		body = linkReader{body, &sharedLink{rate: u.connRate}}
	}
	data, err := io.ReadAll(body)
	if err != nil || int64(len(data)) != r.ContentLength {
		return // the client gave up mid-part: storage keeps nothing of it
	}
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

// Before moving data an upload reports its plan: the parts, the threads,
// how part URLs are fetched, and how it retries.
func TestUpload_ReportsItsPlan(t *testing.T) {
	const part = S3MinPartSize
	u := newUploadServer(t, 3*part, part)
	plans := map[string]string{}
	opts := MultipartUploadOptions{OnDebug: func(step, msg string) {
		if step == "plan" {
			key, rest, _ := strings.Cut(msg, ": ")
			plans[key] = rest
		}
	}}
	if err := u.client(t).MultipartUploadOpts("rev-1", patternSource{u.size}, u.size, opts); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"upload":    "multipart, 15.00 MiB in 3 part(s) of 5.00 MiB",
		"part URLs": "100 per request",
		"retries":   "8 attempts per request, waits doubling from 2s up to 1m; a request that moves no bytes for 1m30s restarts",
	} {
		if !strings.HasPrefix(plans[key], want) {
			t.Errorf("plan %q: got %q, want it to start with %q", key, plans[key], want)
		}
	}
	// The threads plan gives the settings only: each decision is a
	// "threads" event with its own reason.
	if want := "adaptive: start 1, up to 3 (limit 32, at most one per part); measured every 5s (2s from 3.81 MiB/s); an increase stays only if throughput rises over 10%; parts in flight must each finish within 1m at the measured rate"; plans["threads"] != want {
		t.Errorf("threads plan:\n got %q\nwant %q", plans["threads"], want)
	}

	plans = map[string]string{}
	opts.Threads = 2
	u2 := newUploadServer(t, 3*part, part)
	if err := u2.client(t).MultipartUploadOpts("rev-1", patternSource{u2.size}, u2.size, opts); err != nil {
		t.Fatal(err)
	}
	if plans["threads"] != "fixed at 2 (requested)" {
		t.Errorf("fixed threads plan: %q", plans["threads"])
	}
}

// On a slow link, parts finish one after another rather than all sharing
// the link and none finishing, so an upload interrupted after moving five
// parts' worth of data keeps most of it, and resuming sends only the rest.
func TestUpload_SlowLinkKeepsFinishedPartsForResume(t *testing.T) {
	const part = S3MinPartSize
	win, fast, start, limit := adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit
	// A part alone takes 500ms on this link; a minute is to the real
	// link's 32 seconds a part what 800ms is here.
	adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit = 100*time.Millisecond, 40*time.Millisecond, 100*time.Millisecond, 800*time.Millisecond
	t.Cleanup(func() {
		adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit = win, fast, start, limit
	})

	u := newUploadServer(t, 8*part, part)
	u.link = &sharedLink{rate: 10 << 20}
	src := patternSource{u.size}
	c := u.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	c.SetRootContext(ctx)
	if err := c.MultipartUploadOpts("rev-1", src, u.size, MultipartUploadOptions{}); err == nil {
		t.Fatal("the upload finished before the interrupt; slow the link")
	}
	var kept []int
	u.locked(func() {
		for n := 1; n <= 8; n++ {
			if _, ok := u.stored[n]; ok {
				kept = append(kept, n)
			}
		}
	})
	if len(kept) < 3 {
		t.Fatalf("after moving 5 parts' worth of data, storage kept parts %v, want at least 3", kept)
	}

	c.SetRootContext(context.Background())
	if err := c.MultipartUploadOpts("rev-1", src, u.size, MultipartUploadOptions{}); err != nil {
		t.Fatal(err)
	}
	u.locked(func() {
		for _, n := range kept {
			if u.puts[n] != 1 {
				t.Errorf("kept part %d was sent %d times", n, u.puts[n])
			}
		}
		if len(u.completed) != 8 {
			t.Fatalf("completed %d parts, want 8", len(u.completed))
		}
	})
}

// Where every connection is limited on its own (16 MiB/s each here), one
// part measures slow, and the time bound, judged on that one connection,
// would hold the upload at one part to the end. The second part it tries
// doubles throughput, so it keeps it and climbs past two.
func TestUpload_LeavesOnePartWhenEachConnectionIsLimited(t *testing.T) {
	win, fast, start, limit := adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit
	adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond, 590*time.Millisecond
	t.Cleanup(func() {
		adaptiveWindow, adaptiveFastWindow, adaptiveStartWindow, partTimeLimit = win, fast, start, limit
	})

	const part = S3MinPartSize
	u := newUploadServer(t, 16*part, part)
	u.connRate = 16 << 20 // a part alone takes 0.31s, so the bound at one part allows 1.9 of them
	var mu sync.Mutex
	var said []string
	var status TransferStatus
	most := 0
	done, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
				most = max(most, len(status.Snapshot().Connections))
			}
		}
	}()
	err := u.client(t).MultipartUploadOpts("rev-1", patternSource{u.size}, u.size, MultipartUploadOptions{
		Status: &status,
		OnDebug: func(step, msg string) {
			if step == "threads" {
				mu.Lock()
				said = append(said, msg)
				mu.Unlock()
			}
		},
	})
	close(done)
	<-sampled
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Whether the bound held it at one when it tried depends on how fast
	// the window measured; the tuner's tests pin what each case says.
	if !slices.ContainsFunc(said, func(s string) bool { return strings.HasPrefix(s, "1 -> 2 ") }) {
		t.Fatalf("the upload never tried a second part: %q", said)
	}
	if most < 3 {
		t.Fatalf("at most %d parts in flight: %q", most, said)
	}
}
