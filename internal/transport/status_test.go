// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deepsecret-io/deepsecret-go/transfer"
)

// A nil status records nothing, so a transfer without one calls it freely.
func TestTransferStatus_NilRecordsNothing(_ *testing.T) {
	var s *TransferStatus
	s.start(10, 1, 0, 0, nil)
	c := s.begin(1, 10)
	c.add(5)
	c.set(5)
	c.retry(2, 0)
	c.shrink(4)
	c.resume()
	s.addPart()
	s.end(c, true)
}

// A part takes the lowest free connection, so connections keep their place
// as parts change, and Done counts finished parts and what the parts in
// flight moved.
func TestTransferStatus_ConnectionsAndBytes(t *testing.T) {
	var s TransferStatus
	if s.Snapshot().Started {
		t.Fatal("a status no transfer used says started")
	}
	s.start(100, 4, 10, 1, nil) // part 1, 10 bytes, kept from before
	a, b := s.begin(2, 30), s.begin(3, 30)
	a.add(12)
	b.add(5)
	snap := s.Snapshot()
	if !snap.Started || snap.Done != 27 || snap.PartsDone != 1 || snap.Parts != 4 || snap.Threads != 1 {
		t.Fatalf("snapshot %+v", snap)
	}
	if len(snap.Connections) != 2 || snap.Connections[0].Part != 2 || snap.Connections[1].Part != 3 || snap.Connections[0].Attempt != 1 {
		t.Fatalf("connections %+v", snap.Connections)
	}

	s.end(a, true)
	c := s.begin(4, 30)
	snap = s.Snapshot()
	if snap.Connections[0].Part != 4 || snap.Done != 45 || snap.PartsDone != 2 {
		t.Fatalf("after part 2: %+v", snap)
	}

	b.retry(2, 3)
	if got := s.Snapshot().Connections[1]; !got.Waiting || got.Attempt != 2 || got.Moved != 3 {
		t.Fatalf("a failed attempt that keeps 3 bytes: %+v", got)
	}
	b.resume()
	if got := s.Snapshot().Connections[1]; got.Waiting || got.Since.IsZero() {
		t.Fatalf("the next attempt: %+v", got)
	}
	s.end(b, false)
	if snap := s.Snapshot(); len(snap.Connections) != 1 || snap.PartsDone != 2 {
		t.Fatalf("a failed part is not done, and its free connection at the end is dropped: %+v", snap)
	}
	s.end(c, true)
	if snap := s.Snapshot(); len(snap.Connections) != 0 || snap.Done != 70 || snap.PartsDone != 3 {
		t.Fatalf("all free: %+v", snap)
	}
}

// A split moves part of a range in flight to a new part: the range's
// connection shows its smaller size, the parts count grows, and Done counts
// each byte once.
func TestTransferStatus_SplitParts(t *testing.T) {
	var s TransferStatus
	s.start(64, 1, 0, 0, nil)
	a := s.begin(1, 64)
	a.add(10)
	a.shrink(32)
	s.addPart()
	b := s.begin(2, 32)
	b.add(4)
	snap := s.Snapshot()
	if snap.Parts != 2 || snap.Done != 14 || snap.Connections[0].Size != 32 || snap.Connections[1].Size != 32 {
		t.Fatalf("after the split: %+v", snap)
	}
	a.add(22)
	b.add(28)
	s.end(a, true)
	s.end(b, true)
	if snap := s.Snapshot(); snap.Done != 64 || snap.PartsDone != 2 || len(snap.Connections) != 0 {
		t.Fatalf("both halves done: %+v", snap)
	}
}

// Bytes a connection reports past its part, or below zero, never show:
// Moved stays within the part and Done within the total.
func TestTransferStatus_BoundsWhatItShows(t *testing.T) {
	var s TransferStatus
	s.start(50, 2, 0, 0, nil)
	c := s.begin(1, 40)
	c.add(1 << 20)
	snap := s.Snapshot()
	if snap.Connections[0].Moved != 40 || snap.Done != 40 {
		t.Fatalf("over: %+v", snap)
	}
	d := s.begin(2, 10)
	d.add(1 << 20)
	if snap := s.Snapshot(); snap.Done != 50 {
		t.Fatalf("Done past the total: %+v", snap)
	}
	c.set(-5)
	if got := s.Snapshot().Connections[0].Moved; got != 0 {
		t.Fatalf("negative: %d", got)
	}
}

// watch polls a status until done closes and returns every snapshot seen.
func watch(s *TransferStatus, done <-chan struct{}) []transfer.Snapshot {
	var seen []transfer.Snapshot
	for {
		select {
		case <-done:
			return seen
		default:
			seen = append(seen, s.Snapshot())
			time.Sleep(time.Millisecond)
		}
	}
}

// An upload's status shows each part on a connection while it goes, and
// a retried part's attempt, and ends with every part done and every
// connection free.
func TestUpload_StatusFollowsTheParts(t *testing.T) {
	fastRetries(t)
	const part = S3MinPartSize
	u := newUploadServer(t, 6*part+100, part)
	u.link = &sharedLink{rate: 40 << 20}
	u.fail[2] = 1
	c := u.client(t)

	var status TransferStatus
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = c.MultipartUploadOpts(context.Background(), "rev-1", patternSource{u.size}, u.size, MultipartUploadOptions{Threads: 3, Status: &status})
	}()
	seen := watch(&status, done)
	if err != nil {
		t.Fatal(err)
	}

	moving, retried := false, false
	for _, snap := range seen {
		if !snap.Started {
			continue
		}
		if snap.Total != u.size || snap.Done > snap.Total || snap.Parts != 7 || snap.Threads != 3 || len(snap.Connections) > 3 {
			t.Fatalf("snapshot %+v", snap)
		}
		for _, conn := range snap.Connections {
			if conn.Part < 0 || conn.Part > 7 || conn.Moved > conn.Size {
				t.Fatalf("connection %+v", conn)
			}
			moving = moving || (conn.Part > 0 && conn.Moved > 0)
			retried = retried || (conn.Part == 2 && conn.Attempt == 2)
		}
	}
	if !moving || !retried {
		t.Fatalf("over %d snapshots: a part moving %v, part 2's retry %v", len(seen), moving, retried)
	}
	if final := status.Snapshot(); final.Done != u.size || final.PartsDone != 7 || len(final.Connections) != 0 {
		t.Fatalf("final %+v", final)
	}
}

// An upload resumed with every part in storage starts done, and its
// status says so without a connection.
func TestUpload_StatusCountsKeptParts(t *testing.T) {
	const part = S3MinPartSize
	u := newUploadServer(t, 2*part, part)
	src := patternSource{u.size}
	for n := 1; n <= 2; n++ {
		off := int64(n-1) * part
		u.stored[n] = MultipartPartStatus{PartNumber: n, Etag: storedETag(src, off, part), Size: part}
	}
	var status TransferStatus
	if err := u.client(t).MultipartUploadOpts(context.Background(), "rev-1", src, u.size, MultipartUploadOptions{Status: &status}); err != nil {
		t.Fatal(err)
	}
	if snap := status.Snapshot(); !snap.Started || snap.Done != u.size || snap.PartsDone != 2 || len(snap.Connections) != 0 {
		t.Fatalf("snapshot %+v", snap)
	}
}

// rangeServer is the presign call of a download and the object it signs,
// each range sent at rate bytes a second.
func rangeServer(t *testing.T, data []byte, rate float64) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/presign") {
			fmt.Fprintf(w, `{"success":true,"data":{"url":%q,"size":%d}}`, srv.URL+"/object", len(data))
			return
		}
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || end >= len(data) || start > end {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		body := data[start : end+1]
		for len(body) > 0 {
			n := min(len(body), 32<<10)
			time.Sleep(time.Duration(float64(n) / rate * float64(time.Second)))
			if _, err := w.Write(body[:n]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			body = body[n:]
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// sliceWriter is an io.WriterAt over a byte slice.
type sliceWriter struct {
	mu sync.Mutex
	b  []byte
}

func (s *sliceWriter) WriteAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copy(s.b[off:], p), nil
}

// A download's status shows its ranges on connections as they arrive and
// ends with every range done.
func TestDownload_StatusFollowsTheRanges(t *testing.T) {
	data := []byte(strings.Repeat("deepsecret", (5<<20)/10+10))
	srv := rangeServer(t, data, 10<<20)
	c, err := NewClient(srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	dst := &sliceWriter{b: make([]byte, len(data))}

	var status TransferStatus
	done := make(chan struct{})
	go func() {
		defer close(done)
		err = c.DownloadToFile(context.Background(), "rev-1", dst, int64(len(data)), MultipartDownloadOptions{Threads: 2, PartSize: 1 << 20, Status: &status})
	}()
	seen := watch(&status, done)
	if err != nil {
		t.Fatal(err)
	}
	moving := false
	for _, snap := range seen {
		for _, conn := range snap.Connections {
			if conn.Moved > conn.Size || conn.Part > snap.Parts {
				t.Fatalf("connection %+v of %d parts", conn, snap.Parts)
			}
			moving = moving || (conn.Part > 0 && conn.Moved > 0 && conn.Moved < conn.Size)
		}
	}
	final := status.Snapshot()
	if !moving || final.Parts != 6 || final.PartsDone != 6 || final.Done != int64(len(data)) || len(final.Connections) != 0 || final.Threads != 2 {
		t.Fatalf("moving %v, final %+v", moving, final)
	}
	if string(dst.b) != string(data) {
		t.Fatal("the download differs")
	}
}
