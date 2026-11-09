// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package archive

import (
	"archive/tar"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
)

// Windows has no umask and ignores modes, so everything extraction
// creates, folders it makes on its own included, is private to this user
// whatever modes the archive asks for, even in an output folder others may
// open.
func TestExtractTarCreatesPrivateEntries(t *testing.T) {
	out := t.TempDir()
	data := buildTar(t,
		tarTestEntry{typ: tar.TypeDir, name: "shared/", mode: 0o777},
		tarTestEntry{typ: tar.TypeReg, name: "shared/secret.txt", mode: 0o666, data: []byte("s")},
		tarTestEntry{typ: tar.TypeReg, name: "sub/file.txt", mode: 0o644, data: []byte("f")},
	)
	if _, err := ExtractTar(data, out, compress.None, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteFile(out, "other/file.txt", 0o644, strings.NewReader("o"), 1, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(out, "shared"),
		filepath.Join(out, "shared", "secret.txt"),
		filepath.Join(out, "sub"),
		filepath.Join(out, "sub", "file.txt"),
		filepath.Join(out, "other"),
		filepath.Join(out, "other", "file.txt"),
	} {
		disktest.AssertPrivate(t, path)
	}
}
