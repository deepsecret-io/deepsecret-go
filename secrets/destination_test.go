// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// A decrypt into a directory that already holds the files stops before
// anything is downloaded: it never asks for a download URL. With overwrite
// allowed it goes ahead.
func TestDecryptToDirChecksTheDestinationBeforeDownloading(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	secretID, data := sendLarge(t, f)
	out := t.TempDir()
	writeFile(t, filepath.Join(out, "backup.bin"), []byte("already here"), 0o600)

	bob := f.client("bob@example.com")
	_, presigns := rangeCount(f)
	_, _, err := bob.Secrets.DecryptToDir(context.Background(), secretID, out, secrets.DecryptOptions{}, secrets.WriteOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("decrypt onto an existing file: %v", err)
	}
	if _, now := rangeCount(f); now != presigns {
		t.Fatalf("the refused decrypt asked for %d download URLs", now-presigns)
	}

	if _, _, err := bob.Secrets.DecryptToDir(context.Background(), secretID, out, secrets.DecryptOptions{}, secrets.WriteOptions{Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(out, "backup.bin"), data, 0o600)
}

// BeforeDownload sees the verified revision before the download, and its
// error stops the decrypt with nothing fetched.
func TestBeforeDownloadStopsTheDecrypt(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	secretID, _ := sendLarge(t, f)
	_, presigns := rangeCount(f)
	var seen secrets.UpcomingDownload
	_, err := f.client("bob@example.com").Secrets.Open(context.Background(), secretID, secrets.DecryptOptions{
		BeforeDownload: func(p secrets.UpcomingDownload) error {
			seen = p
			return os.ErrPermission
		},
	})
	if err != os.ErrPermission {
		t.Fatalf("OpenSecret: %v, want the hook's error", err)
	}
	if seen.PayloadType != "files" || seen.RevisionID == "" || seen.Size <= 0 || len(seen.Files) != 1 || seen.Files[0].Name != "backup.bin" {
		t.Fatalf("the hook saw %+v", seen)
	}
	if _, now := rangeCount(f); now != presigns {
		t.Fatalf("the stopped decrypt asked for %d download URLs", now-presigns)
	}
}

// CheckDestination refuses what WriteFiles could not write: an existing
// file unless overwrite, a file where a directory must go, or a directory
// that refuses new files. A destination that does not exist yet is checked
// at its nearest existing parent and is not created.
func TestCheckDestination(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), []byte("x"), 0o600)
	writeFile(t, filepath.Join(root, "plain"), []byte("x"), 0o600)
	files := func(names ...string) []secrets.FileMeta {
		var out []secrets.FileMeta
		for _, n := range names {
			out = append(out, secrets.FileMeta{Name: n, Size: 1})
		}
		return out
	}

	for _, tc := range []struct {
		name      string
		dir       string
		files     []secrets.FileMeta
		overwrite bool
		want      string // part of the error, empty for none
	}{
		{"new files", root, files("b.txt", "sub/c.txt"), false, ""},
		{"an existing file", root, files("b.txt", "a.txt"), false, "already exists"},
		{"an existing file, overwrite", root, files("a.txt"), true, ""},
		{"a file where a directory goes", root, files("plain/c.txt"), false, "not a directory"},
		{"a destination that is a file", filepath.Join(root, "plain"), files("c.txt"), false, "not a directory"},
		{"a destination not made yet", filepath.Join(root, "new", "deeper"), files("c.txt"), false, ""},
		{"an unsafe name is left to WriteFiles", root, files("../escape.txt"), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := secrets.CheckDestination(tc.dir, tc.files, tc.overwrite)
			if tc.want == "" && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("%v, want an error saying %q", err, tc.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, "new")); !os.IsNotExist(err) {
		t.Fatalf("CheckDestination created the destination: %v", err)
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".deepsecret-write-check") {
			t.Fatalf("left %s behind", e.Name())
		}
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return // directory modes do not stop root, nor apply on Windows
	}
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if err := secrets.CheckDestination(locked, files("c.txt"), false); err == nil || !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("a read-only destination: %v", err)
	}
	if err := secrets.CheckDestination(filepath.Join(locked, "new"), files("c.txt"), false); err == nil || !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("a destination under a read-only directory: %v", err)
	}
}

// CheckDestination refuses a link at the destination itself, as WriteFiles
// does, so a decrypt into one stops before anything is downloaded. A link
// above the destination is followed, as it is when writing (/tmp is one on
// macOS).
func TestCheckDestinationRefusesALinkAtTheDestination(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
	}
	dangling := filepath.Join(base, "dangling")
	if err := os.Symlink(filepath.Join(base, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	files := []secrets.FileMeta{{Name: "c.txt", Size: 1}}
	for _, dir := range []string{link, dangling} {
		if err := secrets.CheckDestination(dir, files, false); err == nil || !strings.Contains(err.Error(), "a link to one is refused") {
			t.Errorf("CheckDestination(%s): %v, want the link refused", dir, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(base, "missing")); !os.IsNotExist(err) {
		t.Errorf("the dangling link's target: %v, want it not created", err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Errorf("the link's target holds %v, %v", entries, err)
	}
	if err := secrets.CheckDestination(filepath.Join(link, "new"), files, false); err != nil {
		t.Errorf("a destination under a link: %v", err)
	}
}
