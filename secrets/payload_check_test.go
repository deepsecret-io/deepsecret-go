// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package secrets_test

import (
	"context"
	"strings"
	"testing"

	"github.com/deepsecret-io/deepsecret-go/internal/payload"
	"github.com/deepsecret-io/deepsecret-go/secrets"
)

// The in-memory decrypt holds every file to the size and SHA-256 its sender
// declared, as WriteFiles does: a payload that is signed and encrypted
// correctly, but declares a hash or a size its data does not have, is
// refused, so a result never carries either unchecked.
func TestPayloadRefusesFilesThatDoNotMatchTheirDeclaration(t *testing.T) {
	f := newFakeAPI(t, "alice@example.com", "bob@example.com")
	bob := f.client("bob@example.com")
	wrongHash := fileEntry("b.txt", "x")
	wrongHash.SHA256 = strings.Repeat("0", 64)
	wrongSize := fileEntry("c.txt", "xy")
	wrongSize.Size = 1
	cases := []struct {
		name  string
		files []payload.FileEntry
		want  string
	}{
		{"wrong sha256", []payload.FileEntry{fileEntry("ok.txt", "fine"), wrongHash}, "b.txt does not match its SHA-256"},
		{"wrong size", []payload.FileEntry{fileEntry("ok.txt", "fine"), wrongSize}, "c.txt declares 1 bytes but holds 2"},
	}
	for _, c := range cases {
		id := sendRaw(t, f, payload.Payload{Type: "files", Files: c.files})
		out, err := bob.Secrets.Decrypt(context.Background(), id, secrets.DecryptOptions{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %+v, %v, want %q", c.name, out, err, c.want)
		}
	}

	id := sendRaw(t, f, payload.Payload{Type: "files", Files: []payload.FileEntry{fileEntry("ok.txt", "fine")}})
	out, err := bob.Secrets.Decrypt(context.Background(), id, secrets.DecryptOptions{})
	if err != nil || len(out.Decrypted.Files) != 1 || string(out.Decrypted.Files[0].Data) != "fine" {
		t.Fatalf("an honest payload: %+v, %v", out, err)
	}
}
