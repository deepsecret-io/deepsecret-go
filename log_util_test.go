// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/deepsecret-io/sdk/api"
)

// flowLog keeps every record a flow logs, at every level: its module
// (nested ones joined with a dot), its message, and its fields as one line.
type flowLog struct {
	mu      sync.Mutex
	records []flowRecord
}

type flowRecord struct {
	level       slog.Level
	module, msg string
	fields      string
}

func (l *flowLog) logger() *slog.Logger { return slog.New(&flowHandler{log: l}) }

// has checks that a record of module with message msg was logged at level,
// with each of fields ("key=value") in its fields.
func (l *flowLog) has(t *testing.T, level slog.Level, module, msg string, fields ...string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.records {
		if r.module != module || r.msg != msg {
			continue
		}
		if r.level != level {
			t.Errorf("%s: %s: logged at %v, want %v", module, msg, r.level, level)
		}
		for _, f := range fields {
			if !strings.Contains(" "+r.fields+" ", " "+f+" ") {
				t.Errorf("%s: %s: fields %q lack %q", module, msg, r.fields, f)
			}
		}
		return
	}
	t.Errorf("no %q record in %q", msg, module)
}

type flowHandler struct {
	log   *flowLog
	attrs []slog.Attr
}

func (h *flowHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *flowHandler) Handle(_ context.Context, r slog.Record) error {
	var modules, fields []string
	add := func(a slog.Attr) bool {
		if a.Key == api.ModuleKey {
			modules = append(modules, a.Value.String())
		} else {
			fields = append(fields, fmt.Sprintf("%s=%v", a.Key, a.Value.Resolve()))
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	h.log.records = append(h.log.records, flowRecord{r.Level, strings.Join(modules, "."), r.Message, strings.Join(fields, " ")})
	return nil
}

func (h *flowHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &flowHandler{log: h.log, attrs: append(slices.Clip(h.attrs), as...)}
}

func (h *flowHandler) WithGroup(string) slog.Handler { return h }

// A send and a decrypt log their milestones at info level and their
// checks and decisions at debug level, and never the plaintext or a
// presigned URL's query.
func TestFlowLogs(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	const text = "the vault code is 7319-alpha"
	var sent, opened flowLog
	res, err := f.client("alice@example.com").EncryptText([]string{"bob@example.com"}, text, EncryptOptions{Logger: sent.logger()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client("bob@example.com").DecryptSecretFull(res.Secret.ID, DecryptOptions{Logger: opened.logger()}); err != nil {
		t.Fatal(err)
	}

	sent.has(t, slog.LevelDebug, "encrypt", "payload", "type=message", "archived=false")
	sent.has(t, slog.LevelDebug, "identity", "key pair loaded", "source=primary")
	sent.has(t, slog.LevelDebug, "recipient", "recipient keys verified", "email=bob@example.com", "trust=first_use")
	sent.has(t, slog.LevelDebug, "compress", "compression disabled", "reason=not requested")
	sent.has(t, slog.LevelDebug, "encrypt", "ciphertext storage", "where=memory")
	sent.has(t, slog.LevelInfo, "encrypt", "payload encrypted")
	sent.has(t, slog.LevelDebug, "manifest", "manifest signed", "revision_id="+res.Secret.RevisionID, "recipients=1")
	sent.has(t, slog.LevelInfo, "secret", "secret created", "secret_id="+res.Secret.ID, "multipart=false")
	sent.has(t, slog.LevelDebug, "upload", "plan", "transfer=single", "url_expiry=30m0s")
	sent.has(t, slog.LevelInfo, "upload", "upload complete", "parts=1")

	opened.has(t, slog.LevelDebug, "secret", "revision chosen", "revision_id="+res.Secret.RevisionID, "source=latest")
	opened.has(t, slog.LevelDebug, "manifest", "manifest verified", "payload_type=message")
	// Every account's key pair is on this test's one device.
	opened.has(t, slog.LevelDebug, "verify", "sender key verified", "email=alice@example.com", "trust=own")
	opened.has(t, slog.LevelInfo, "download", "download complete")
	opened.has(t, slog.LevelDebug, "verify", "payload verified")
	opened.has(t, slog.LevelInfo, "decrypt", "payload decrypted")

	for _, l := range []*flowLog{&sent, &opened} {
		for _, r := range l.records {
			line := r.module + ": " + r.msg + ": " + r.fields
			if strings.Contains(line, "7319") || strings.Contains(line, "?t=") {
				t.Fatalf("logged a secret: %s", line)
			}
		}
	}
}
