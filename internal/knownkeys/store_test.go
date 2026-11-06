// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package knownkeys

import (
	"os"
	"path/filepath"
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
