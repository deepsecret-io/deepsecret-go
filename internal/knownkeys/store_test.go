// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package knownkeys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewPutsTheFileBesideTheKeysDir(t *testing.T) {
	base := t.TempDir()
	s := New("", "https://api.example.com", filepath.Join(base, "keys"))
	if err := s.RecordFirstUse([]Person{{Email: "bob@example.com", Fingerprint: strings.Repeat("a", 64)}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "known_keys.json")); err != nil {
		t.Error(err)
	}
}

// oldFile and oldServer come from a build before this package existed: its
// format and how it names a server must not change.
const oldServer = "https://api.example.com"

const oldFile = `{
  "version": 1,
  "servers": {
    "https://api.example.com": {
      "accepted@example.com": [
        {
          "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "state": "accepted",
          "first_seen": "2026-11-01T12:00:00Z"
        }
      ],
      "first@example.com": [
        {
          "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "state": "tofu",
          "first_seen": "2026-11-01T12:00:00Z",
          "replaced": true
        }
      ],
      "me@example.com": [
        {
          "fingerprint": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "state": "own",
          "first_seen": "2026-11-01T12:00:00Z"
        }
      ],
      "verified@example.com": [
        {
          "fingerprint": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "state": "verified",
          "first_seen": "2026-11-01T12:00:00Z"
        }
      ]
    }
  },
  "newest": {
    "https://api.example.com": {
      "accepted@example.com": {
        "note": 1793534400
      }
    }
  }
}`

func TestStoreReadsAFileFromTheOldBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_keys.json")
	if err := os.WriteFile(path, []byte(oldFile), 0o600); err != nil {
		t.Fatal(err)
	}
	// Upper case on purpose: the server name must lower-case to match the file.
	got, err := New(path, strings.ToUpper(oldServer), t.TempDir()).List("")
	if err != nil || len(got) != 4 {
		t.Fatalf("List = %v, %v; want the 4 fixture keys", got, err)
	}
	states := map[string]State{}
	for _, k := range got {
		states[k.Email] = k.State
	}
	want := map[string]State{
		"first@example.com":    FirstUse,
		"accepted@example.com": Accepted,
		"verified@example.com": Verified,
		"me@example.com":       Own,
	}
	for email, state := range want {
		if states[email] != state {
			t.Errorf("%s: state %q, want %q", email, states[email], state)
		}
	}
}

// The known keys file decides which keys this device accepts, so one that
// other users may open is refused, as a key file is, and what this package
// writes is private.
func TestStoreRefusesAFileOpenToOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes; the Windows rule is tested in internal/disk")
	}
	dir := filepath.Join(t.TempDir(), "new", "folder")
	path := filepath.Join(dir, "known_keys.json")
	s := New(path, oldServer, t.TempDir())
	bob := []Person{{Email: "bob@example.com", Fingerprint: strings.Repeat("a", 64)}}
	if err := s.RecordFirstUse(bob, false); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: %v, %v; want mode %o", p, info.Mode().Perm(), err, want)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(""); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("List of a file open to others: %v, want it refused", err)
	}
	if err := s.RecordFirstUse(bob, false); err == nil {
		t.Fatal("a change to a file open to others was accepted")
	}
}
