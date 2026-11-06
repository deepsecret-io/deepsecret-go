// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
)

func TestMergeRanges(t *testing.T) {
	for _, c := range []struct{ in, want [][2]int64 }{
		{nil, nil},
		{[][2]int64{{10, 20}, {0, 5}}, [][2]int64{{0, 5}, {10, 20}}},
		{[][2]int64{{0, 5}, {5, 10}}, [][2]int64{{0, 10}}},
		{[][2]int64{{0, 8}, {4, 6}, {6, 12}, {30, 40}}, [][2]int64{{0, 12}, {30, 40}}},
	} {
		got, err := MergeRanges(c.in, 100)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("MergeRanges(%v) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, bad := range [][2]int64{{-1, 4}, {4, 4}, {6, 4}, {90, 101}} {
		if _, err := MergeRanges([][2]int64{bad}, 100); err == nil {
			t.Errorf("MergeRanges accepted %v of 100 bytes", bad)
		}
	}
	in := [][2]int64{{10, 20}, {0, 5}}
	if _, err := MergeRanges(in, 100); err != nil || in[0] != [2]int64{10, 20} {
		t.Fatalf("MergeRanges changed its input to %v (%v)", in, err)
	}
}

// resumeServer serves one object by range and records the presigns and
// the ranges it was asked for. send, when set, writes each range's body,
// given the offset it starts at.
type resumeServer struct {
	srv  *httptest.Server
	data []byte
	send func(w http.ResponseWriter, body []byte, start int64)

	mu       sync.Mutex
	presigns int
	asked    [][2]int64 // [from, to)
}

func newResumeServer(t *testing.T, data []byte) *resumeServer {
	s := &resumeServer{data: data}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/presign") {
			s.mu.Lock()
			s.presigns++
			s.mu.Unlock()
			fmt.Fprintf(w, `{"success":true,"data":{"url":%q,"size":%d}}`, s.srv.URL+"/object", len(data))
			return
		}
		var start, end int64
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || end >= int64(len(data)) || start > end {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		s.mu.Lock()
		s.asked = append(s.asked, [2]int64{start, end + 1})
		s.mu.Unlock()
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		if s.send != nil {
			s.send(w, data[start:end+1], start)
			return
		}
		_, _ = w.Write(data[start : end+1])
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *resumeServer) client(t *testing.T) *Client {
	c, err := NewClient(s.srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sortedRanges(r [][2]int64) [][2]int64 {
	out := slices.Clone(r)
	slices.SortFunc(out, func(a, b [2]int64) int { return int(a[0] - b[0]) })
	return out
}

// A download that holds some ranges already fetches only the rest, in
// ranges of the part size within each gap, reports each, and counts the
// held bytes in its progress from the start. Its plan and its completion
// say what it held and fetched.
func TestDownload_FetchesOnlyWhatItLacks(t *testing.T) {
	const mib = 1 << 20
	data := make([]byte, 5*mib+123)
	_, _ = rand.Read(data)
	s := newResumeServer(t, data)
	size := int64(len(data))

	dst := &sliceWriter{b: make([]byte, size)}
	copy(dst.b[:mib], data[:mib])
	copy(dst.b[3*mib:4*mib], data[3*mib:4*mib])
	var got [][2]int64
	var progress []int64
	var status TransferStatus
	var book logBook
	err := s.client(t).DownloadToFile(context.Background(), "rev-1", dst, size, MultipartDownloadOptions{
		Threads: 2, PartSize: mib, Status: &status, Logger: book.logger(),
		Have:       [][2]int64{{3 * mib, 4 * mib}, {0, mib}},
		OnRange:    func(from, to int64) { got = append(got, [2]int64{from, to}) },
		OnProgress: func(done, _ int64) { progress = append(progress, done) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]int64{{mib, 2 * mib}, {2 * mib, 3 * mib}, {4 * mib, 5 * mib}, {5 * mib, size}}
	if asked := sortedRanges(s.asked); !slices.Equal(asked, want) {
		t.Fatalf("storage was asked for %v, want %v", asked, want)
	}
	if !slices.Equal(sortedRanges(got), want) {
		t.Fatalf("OnRange reported %v, want %v", got, want)
	}
	if !bytes.Equal(dst.b, data) {
		t.Fatal("the download differs")
	}
	if len(progress) == 0 || progress[0] != 2*mib || progress[len(progress)-1] != size {
		t.Fatalf("progress %v: want it to start at the 2 MiB held and end at %d", progress, size)
	}
	if snap := status.Snapshot(); snap.Parts != 4 || snap.PartsDone != 4 || snap.Done != size {
		t.Fatalf("status %+v", snap)
	}
	book.has(t, "download", "plan", map[string]any{
		"size": logattr.Bytes(size), "held": logattr.Bytes(2 * mib), "ranges": 4, "range_size": logattr.Bytes(mib), "sizing": "requested",
		"url_expiry": 30 * time.Minute, "url_renew_before": 2 * time.Minute,
	})
	book.has(t, "download.threads", "plan", map[string]any{"mode": "fixed", "threads": 2, "requested": 2})
	book.has(t, "download", "retry plan", map[string]any{"attempts": 8})
	if n := len(book.all("download", "range complete")); n != 4 {
		t.Errorf("%d ranges logged complete, want 4", n)
	}
	book.has(t, "download", "download complete", map[string]any{"size": logattr.Bytes(size), "fetched": logattr.Bytes(size - 2*mib)})
}

// A download sized by the rule says so, and one the server suggests
// larger ranges for says that.
func TestDownload_PlanSaysWhatSizedTheRanges(t *testing.T) {
	data := make([]byte, 3<<20)
	s := newResumeServer(t, data)
	size := int64(len(data))
	var book logBook
	if err := s.client(t).DownloadToFile(context.Background(), "rev-1", &sliceWriter{b: make([]byte, size)}, size, MultipartDownloadOptions{Logger: book.logger()}); err != nil {
		t.Fatal(err)
	}
	// 3 MiB is under the rule's 8 MiB ranges: one range of all of it.
	r := book.has(t, "download", "plan", map[string]any{"ranges": 1, "range_size": logattr.Bytes(size), "sizing": PieceSizeRule})
	if _, ok := r.fields["held"]; ok {
		t.Fatalf("a fresh download's plan says it held something: %v", r)
	}
	book.has(t, "download.threads", "plan", map[string]any{"mode": "fixed", "threads": 1, "reason": "too few ranges to adapt: one per range"})
}

// A download that holds everything fetches nothing, but still presigns:
// the server applies the secret's policies there and records the download.
func TestDownload_PresignsWhenNothingIsLeft(t *testing.T) {
	data := bytes.Repeat([]byte("k"), 3<<20)
	s := newResumeServer(t, data)
	size := int64(len(data))
	var status TransferStatus
	var progress []int64
	var book logBook
	err := s.client(t).DownloadToFile(context.Background(), "rev-1", &sliceWriter{b: make([]byte, size)}, size, MultipartDownloadOptions{
		Have: [][2]int64{{0, size}}, Status: &status, Logger: book.logger(),
		OnProgress: func(done, _ int64) { progress = append(progress, done) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.presigns != 1 || len(s.asked) != 0 {
		t.Fatalf("%d presigns and %d ranges, want 1 and none", s.presigns, len(s.asked))
	}
	if snap := status.Snapshot(); !snap.Started || snap.Done != size || snap.Parts != 0 {
		t.Fatalf("status %+v", snap)
	}
	if !slices.Equal(progress, []int64{size}) {
		t.Fatalf("progress %v", progress)
	}
	book.has(t, "download", "download complete", map[string]any{"size": logattr.Bytes(size), "fetched": logattr.Bytes(0)})
	if plans := book.all("download", "plan"); len(plans) != 0 {
		t.Fatalf("a download with nothing to fetch logged a plan: %v", plans)
	}
}

// Held ranges outside the object are refused before anything is asked of
// the server.
func TestDownload_RefusesHeldRangesOutsideTheObject(t *testing.T) {
	s := newResumeServer(t, make([]byte, 2<<20))
	err := s.client(t).DownloadToFile(context.Background(), "rev-1", &sliceWriter{b: make([]byte, 2<<20)}, 2<<20, MultipartDownloadOptions{
		Have: [][2]int64{{1 << 20, 2<<20 + 1}},
	})
	if err == nil || s.presigns != 0 {
		t.Fatalf("err %v after %d presigns, want a refusal before any", err, s.presigns)
	}
}

func (s *resumeServer) requests() [][2]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

// crawl writes body at about rate bytes a second, until the client stops
// reading.
func crawl(w http.ResponseWriter, body []byte, rate int) {
	const chunk = 4 << 10
	for len(body) > 0 {
		n := min(len(body), chunk)
		if _, err := w.Write(body[:n]); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		body = body[n:]
		time.Sleep(time.Duration(chunk) * time.Second / time.Duration(rate))
	}
}

func shortSplits(t *testing.T, size int64) {
	saved := minSplit
	minSplit = size
	t.Cleanup(func() { minSplit = saved })
}

// coversOnce checks that ranges cover [0, size) with no byte twice.
func coversOnce(t *testing.T, ranges [][2]int64, size int64) {
	t.Helper()
	var sum int64
	for _, r := range ranges {
		sum += r[1] - r[0]
	}
	merged, err := MergeRanges(ranges, size)
	if err != nil || len(merged) != 1 || merged[0] != [2]int64{0, size} || sum != size {
		t.Fatalf("ranges %v (%d bytes) do not cover %d bytes once: %v, %v", sortedRanges(ranges), sum, size, merged, err)
	}
}

// When one range crawls, the connections that finished take halves of what
// it has left, so the download no longer waits on it: here half a minute
// on its own. The ranges written still cover the object once.
func TestDownload_SplitsASlowTail(t *testing.T) {
	shortSplits(t, 16<<10)
	const mib = 1 << 20
	data := make([]byte, 4*mib)
	_, _ = rand.Read(data)
	s := newResumeServer(t, data)
	s.send = func(w http.ResponseWriter, body []byte, start int64) {
		if start == 3*mib {
			crawl(w, body, 32<<10)
			return
		}
		_, _ = w.Write(body)
	}
	size := int64(len(data))
	dst := &sliceWriter{b: make([]byte, size)}
	var mu sync.Mutex
	var written [][2]int64
	var status TransferStatus
	t0 := time.Now()
	err := s.client(t).DownloadToFile(context.Background(), "rev-1", dst, size, MultipartDownloadOptions{
		Threads: 4, PartSize: mib, Status: &status,
		OnRange: func(from, to int64) {
			mu.Lock()
			written = append(written, [2]int64{from, to})
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(t0); took > 8*time.Second {
		t.Fatalf("the crawling range held the download for %s", took)
	}
	if !bytes.Equal(dst.b, data) {
		t.Fatal("the download differs")
	}
	coversOnce(t, written, size)
	snap := status.Snapshot()
	if snap.Parts <= 4 || snap.PartsDone != snap.Parts || snap.Done != size || len(snap.Connections) != 0 {
		t.Fatalf("status %+v: want more parts than the 4 ranges, all done", snap)
	}
}

// Many ranges crawling at once, on more connections, split and split
// again, and every byte is still written once.
func TestDownload_SplitsManyRangesAtOnce(t *testing.T) {
	shortSplits(t, 8<<10)
	const mib = 1 << 20
	data := make([]byte, 9*mib+777)
	_, _ = rand.Read(data)
	s := newResumeServer(t, data)
	s.send = func(w http.ResponseWriter, body []byte, start int64) {
		if start%mib == 0 && (start/mib)%3 == 0 {
			crawl(w, body, 128<<10)
			return
		}
		_, _ = w.Write(body)
	}
	size := int64(len(data))
	dst := &sliceWriter{b: make([]byte, size)}
	var mu sync.Mutex
	var written [][2]int64
	var book logBook
	err := s.client(t).DownloadToFile(context.Background(), "rev-1", dst, size, MultipartDownloadOptions{
		Threads: 8, PartSize: mib,
		OnRange: func(from, to int64) {
			mu.Lock()
			written = append(written, [2]int64{from, to})
			mu.Unlock()
		},
		Logger: book.logger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.b, data) {
		t.Fatal("the download differs")
	}
	coversOnce(t, written, size)
	if asked, n := s.requests(), len(book.all("download", "range split")); n == 0 || len(asked) != 10+n {
		t.Fatalf("%d requests for 10 ranges and %d splits", len(asked), n)
	}
}

// A range whose connection drops is asked again only for what did not
// arrive.
func TestDownload_RetryFetchesOnlyWhatIsMissing(t *testing.T) {
	fastRetries(t)
	const mib = 1 << 20
	data := make([]byte, 2*mib)
	_, _ = rand.Read(data)
	s := newResumeServer(t, data)
	var dropped bool
	s.send = func(w http.ResponseWriter, body []byte, _ int64) {
		s.mu.Lock()
		drop := !dropped
		dropped = true
		s.mu.Unlock()
		if drop {
			_, _ = w.Write(body[:mib])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write(body)
	}
	size := int64(len(data))
	dst := &sliceWriter{b: make([]byte, size)}
	var book logBook
	if err := s.client(t).DownloadToFile(context.Background(), "rev-1", dst, size, MultipartDownloadOptions{Threads: 1, PartSize: size, Logger: book.logger()}); err != nil {
		t.Fatal(err)
	}
	if asked := s.requests(); len(asked) != 2 || asked[0] != [2]int64{0, size} || asked[1] != [2]int64{mib, size} {
		t.Fatalf("requests %v: want the range, then only its second half", asked)
	}
	// The retry is the second attempt, for what did not arrive.
	book.has(t, "download", "retrying request", map[string]any{"part": 1, "attempt": 2, "attempts": 8, "offset": mib, "size": logattr.Bytes(mib)})
	if !bytes.Equal(dst.b, data) {
		t.Fatal("the download differs")
	}
}

// A split leaves each half at least the minimum, never an empty one, and a
// minimum too large to double does not wrap around into splitting.
func TestPieceSplitBounds(t *testing.T) {
	for _, c := range []struct {
		left, min int64
		ok        bool
	}{
		{8 << 20, 4 << 20, true},
		{8<<20 - 1, 4 << 20, false},
		{1 << 30, 1 << 62, false},
		{1 << 30, math.MaxInt64, false},
		{1, 0, false},
		{0, 0, false},
		{2, 0, true},
	} {
		p := &piece{start: 100, next: 100, end: 100 + c.left}
		from, to, ok := p.split(c.min)
		if ok != c.ok {
			t.Fatalf("split of %d left with minimum %d: %v, want %v", c.left, c.min, ok, c.ok)
		}
		if ok && (from != p.end || to != 100+c.left || p.end-p.next < max(c.min, 1) || to-from < max(c.min, 1)) {
			t.Fatalf("split of %d left with minimum %d: kept [%d, %d), gave [%d, %d)", c.left, c.min, p.next, p.end, from, to)
		}
	}
}
