// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package payload

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Every kind of payload the SDK writes decodes to what was written.
func TestUnmarshalRoundTrip(t *testing.T) {
	entries := make([]KeyValuePair, 20_000)
	for i := range entries {
		entries[i] = KeyValuePair{Key: fmt.Sprintf("KEY_%d", i), Value: "value"}
	}
	files := make([]FileEntry, 2_000)
	for i := range files {
		files[i] = FileEntry{Name: fmt.Sprintf("dir/%d.txt", i), Data: []byte("data"), Size: 4, SHA256: strings.Repeat("ab", 32), Mode: 0o644}
	}
	payloads := map[string]Payload{
		"message":       {Type: "message", Message: "hello"},
		"empty message": {Type: "message"},
		"data":          {Type: "data", Entries: []KeyValuePair{{Key: "DB_USER", Value: "app"}, {Key: "DB_PASSWORD", Value: "s3cret"}}},
		"many entries":  {Type: "data", Entries: entries},
		"files": {Type: "files", Files: []FileEntry{
			{Name: "a.txt", Data: []byte("alpha"), Size: 5, SHA256: strings.Repeat("0f", 32), Mode: 0o600},
			{Name: "dir/empty", Mode: 0o755},
		}},
		"many files": {Type: "files", Files: files},
		"archive": {Type: "files", Archive: true, ArchiveCompression: "zstd", Files: []FileEntry{
			{Name: "archive.tar.zst", Data: bytes.Repeat([]byte{0x28, 0xb5}, 600), Size: 1200, SHA256: strings.Repeat("c1", 32), Mode: 0o600},
		}},
	}
	for name, want := range payloads {
		data, err := Marshal(want)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var got Payload
		if err := Unmarshal(data, &got); err != nil {
			t.Errorf("%s: unmarshal: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: decoded to a different payload", name)
		}
	}
}

// text is the CBOR text string s, which must be shorter than 24 bytes.
func text(s string) []byte {
	return append([]byte{0x60 | byte(len(s))}, s...)
}

func errorAs[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// A payload is read strictly: bytes that say the same thing another way, or
// that another parser could read differently, are refused.
func TestUnmarshalRefusesLooseCBOR(t *testing.T) {
	data, err := Marshal(Payload{Type: "message", Message: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	// The payload is a map of two pairs: type, then message.
	if data[0] != 0xa2 || bytes.Count(data, text("type")) != 1 {
		t.Fatalf("the payload is %x", data)
	}
	more := func(pair ...[]byte) []byte {
		return bytes.Join(append([][]byte{{0xa3}, data[1:]}, pair...), nil)
	}
	file := bytes.Join([][]byte{
		{0xa2}, text("type"), text("files"), text("files"), {0x81},
		{0xa6}, text("data"), {0x41, 'x'}, text("mode"), {0x00}, text("name"), text("a"), text("size"), {0x01}, text("sha256"), {0x60},
		text("owner"), text("root"),
	}, nil)

	cases := map[string]struct {
		data    []byte
		refused func(error) bool
	}{
		"type twice":                 {more(text("type"), text("data")), errorAs[*cbor.DupMapKeyError]},
		"message twice, same value":  {more(text("message"), text("hello")), errorAs[*cbor.DupMapKeyError]},
		"unknown field":              {more(text("extra"), []byte{0x01}), errorAs[*cbor.UnknownFieldError]},
		"unknown field in a file":    {file, errorAs[*cbor.UnknownFieldError]},
		"key in another case":        {bytes.Replace(data, text("type"), text("Type"), 1), errorAs[*cbor.UnknownFieldError]},
		"map of indefinite length":   {append(append([]byte{0xbf}, data[1:]...), 0xff), errorAs[*cbor.IndefiniteLengthError]},
		"text of indefinite length":  {more(text("archive_compression"), []byte{0x7f}, text("zstd"), []byte{0xff}), errorAs[*cbor.IndefiniteLengthError]},
		"data after the payload":     {append(bytes.Clone(data), 0x00), errorAs[*cbor.ExtraneousDataError]},
		"nested past a file's field": {more(text("deep"), []byte{0x81, 0x81, 0x81, 0x81, 0x01}), errorAs[*cbor.MaxNestedLevelError]},
	}
	for name, c := range cases {
		var p Payload
		if err := Unmarshal(c.data, &p); err == nil || !c.refused(err) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
