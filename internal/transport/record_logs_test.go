// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package transport

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/internal/logattr"
)

// recordLogs is a logger that passes each record's module (nested ones
// joined with a dot), message and fields to on.
func recordLogs(on func(module, msg string, fields map[string]slog.Value)) *slog.Logger {
	return slog.New(&recorder{on: on})
}

type recorder struct {
	on    func(module, msg string, fields map[string]slog.Value)
	attrs []slog.Attr
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	fields := map[string]slog.Value{}
	var modules []string
	add := func(a slog.Attr) bool {
		if a.Key == logattr.ModuleKey {
			modules = append(modules, a.Value.String())
		} else {
			fields[a.Key] = a.Value.Resolve()
		}
		return true
	}
	for _, a := range r.attrs {
		add(a)
	}
	rec.Attrs(add)
	r.on(strings.Join(modules, "."), rec.Message, fields)
	return nil
}

func (r *recorder) WithAttrs(as []slog.Attr) slog.Handler {
	return &recorder{on: r.on, attrs: append(slices.Clip(r.attrs), as...)}
}

func (r *recorder) WithGroup(string) slog.Handler { return r }
