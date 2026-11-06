// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Storage requests run on HTTP/1.1, one connection each, even against a
// server that offers HTTP/2, so parallel parts are parallel TCP streams;
// and a finished part's connection carries the next part, rather than a
// new TLS handshake and TCP slow start for every other part.
func TestStorageTransportKeepsParallelWarmConnections(t *testing.T) {
	const part = S3MinPartSize
	u := &uploadServer{t: t, size: 48 * part, partSize: part, stored: map[int]MultipartPartStatus{},
		puts: map[int]int{}, apiCalls: map[string]int{}, fail: map[int]int{}, stall: map[int]int{}}
	var mu sync.Mutex
	protos := map[string]int{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/storage/") {
			mu.Lock()
			protos[r.Proto]++
			mu.Unlock()
		}
		u.ServeHTTP(w, r)
	}))
	var conns atomic.Int64
	u.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	u.srv.EnableHTTP2 = true
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)

	c, err := NewClient(u.srv.URL, "dsk_test")
	if err != nil {
		t.Fatal(err)
	}
	// Trust the test server; the storage transport keeps its own ALPN,
	// which offers HTTP/1.1 only.
	tlsCfg := u.srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	c.httpClient.Transport.(*http.Transport).TLSClientConfig = tlsCfg
	storage := tlsCfg.Clone()
	storage.NextProtos = nil
	c.presignClient.Transport.(*http.Transport).TLSClientConfig = storage

	const threads = 8
	if err := c.MultipartUploadOpts(context.Background(), "rev-1", patternSource{u.size}, u.size, MultipartUploadOptions{Threads: threads}); err != nil {
		t.Fatal(err)
	}
	if protos["HTTP/1.1"] != 48 || len(protos) != 1 {
		t.Fatalf("storage requests by protocol: %v, want 48 on HTTP/1.1", protos)
	}
	// The API's calls share one HTTP/2 connection; storage has one per
	// thread.
	if n := conns.Load(); n > threads+2 {
		t.Fatalf("%d connections for %d parts on %d threads: finished parts' connections were not reused", n, 48, threads)
	}
}

// An upload's first decision comes from its first part as soon as that
// finishes: on a fast link it takes 4 parts at once, well before the start
// window ends; a part that took long keeps it at one. A download has no
// such decision, and its limiter ignores finished parts.
func TestLimiter_FirstPartDecidesTheStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fast := newLimiter(ctx, 0, 32, 8<<20)
	go fast.tune(ctx, nil)
	fast.partDone(8<<20, 100*time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for fast.current() != adaptiveStartThreads {
		if time.Now().After(deadline) {
			t.Fatalf("a part at 84 MB/s left %d parts in flight after a second", fast.current())
		}
		time.Sleep(5 * time.Millisecond)
	}

	slow := newLimiter(ctx, 0, 32, 8<<20)
	go slow.tune(ctx, nil)
	slow.partDone(8<<20, 32*time.Second)
	time.Sleep(100 * time.Millisecond)
	if slow.current() != 1 {
		t.Fatalf("a part at 262 KB/s left %d parts in flight", slow.current())
	}

	download := newLimiter(ctx, 0, 32, 0)
	download.partDone(8<<20, time.Millisecond)
	if download.current() != adaptiveStartThreads {
		t.Fatalf("a download's limit moved to %d", download.current())
	}
}
