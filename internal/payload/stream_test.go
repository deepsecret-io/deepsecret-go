// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

type memFile struct {
	name string
	data []byte
	mode os.FileMode
}

func sources(files []memFile) []FileSource {
	out := make([]FileSource, len(files))
	for i, f := range files {
		data := f.data
		out[i] = FileSource{Name: f.name, Size: int64(len(data)), Mode: f.mode,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
	}
	return out
}

func marshalled(t *testing.T, files []memFile, archived bool, compression string) []byte {
	t.Helper()
	p := Payload{Type: "files", Archive: archived, ArchiveCompression: compression}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		p.Files = append(p.Files, FileEntry{Name: f.name, Data: f.data, Size: int64(len(f.data)),
			SHA256: hex.EncodeToString(sum[:]), Mode: f.mode})
	}
	b, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randomFiles(r *rand.Rand) []memFile {
	names := []string{"a", "b.txt", "dir/c.bin", "ünïcode/файл.txt", strings.Repeat("long", 40)}
	sizes := []int{0, 1, 23, 24, 255, 256, 65535, 65536, 70000}
	files := make([]memFile, r.IntN(5)+1)
	for i := range files {
		data := make([]byte, sizes[r.IntN(len(sizes))])
		for j := range data {
			data[j] = byte(r.Uint32())
		}
		files[i] = memFile{name: fmt.Sprintf("%d-%s", i, names[r.IntN(len(names))]), data: data,
			mode: []os.FileMode{0, 0o644, 0o755, 0o4777}[r.IntN(4)]}
	}
	return files
}

// EncodeFiles writes byte for byte what Marshal writes, so receivers read a
// streamed payload exactly like an in-memory one.
func TestEncodeFilesMatchesMarshal(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 200; i++ {
		files := randomFiles(r)
		archived := false
		compression := ""
		if r.IntN(3) == 0 {
			files, archived = files[:1], true
			if r.IntN(2) == 0 {
				compression = "zstd"
			}
		}
		var got bytes.Buffer
		sums, err := EncodeFiles(&got, sources(files), archived, compression)
		if err != nil {
			t.Fatal(err)
		}
		if want := marshalled(t, files, archived, compression); !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("case %d: streamed payload differs from Marshal\n got %x\nwant %x", i, got.Bytes(), want)
		}
		for j, f := range files {
			if s := sha256.Sum256(f.data); sums[j] != hex.EncodeToString(s[:]) {
				t.Fatalf("case %d: sha256 of file %d", i, j)
			}
		}
	}

	var empty bytes.Buffer
	if _, err := EncodeFiles(&empty, nil, false, ""); err != nil {
		t.Fatal(err)
	}
	if want, _ := Marshal(Payload{Type: "files"}); !bytes.Equal(empty.Bytes(), want) {
		t.Fatalf("empty payload %x, want %x", empty.Bytes(), want)
	}
}

// A file that grows or shrinks while it is read fails the encoding.
func TestEncodeFilesRefusesChangedFiles(t *testing.T) {
	for name, actual := range map[string][]byte{"shorter": []byte("abc"), "longer": []byte("abcdef")} {
		src := []FileSource{{Name: "f", Size: 4, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(actual)), nil
		}}}
		if _, err := EncodeFiles(io.Discard, src, false, ""); err == nil || !strings.Contains(err.Error(), "changed while it was read") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// DecodeFiles reads back what Marshal writes, streaming each file's data.
func TestDecodeFilesRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 100; i++ {
		files := randomFiles(r)
		archived := len(files) == 1 && r.IntN(2) == 0
		data := marshalled(t, files, archived, "")
		got := map[int][]byte{}
		out, err := DecodeFiles(bytes.NewReader(data), DecodeLimits{}, func(idx int, _ int64, rd io.Reader) error {
			b, err := io.ReadAll(rd)
			got[idx] = b
			return err
		})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if out.Archive != archived || len(out.Files) != len(files) {
			t.Fatalf("case %d: %+v", i, out)
		}
		for j, f := range files {
			info := out.Files[j]
			if info.Name != f.name || info.Mode != f.mode || info.Size != int64(len(f.data)) || !bytes.Equal(got[j], f.data) {
				t.Fatalf("case %d file %d: %+v", i, j, info)
			}
		}
	}
}

// Whatever onData leaves unread is still read and checked.
func TestDecodeFilesChecksUnreadData(t *testing.T) {
	data := marshalled(t, []memFile{{name: "a", data: []byte("hello")}}, false, "")
	out, err := DecodeFiles(bytes.NewReader(data), DecodeLimits{}, func(int, int64, io.Reader) error { return nil })
	if err != nil || out.Files[0].Size != 5 {
		t.Fatalf("%+v, %v", out, err)
	}
}

// Payloads that are not canonical, carry unknown keys, lie about a file or
// exceed a limit are refused.
func TestDecodeFilesRefusesHostilePayloads(t *testing.T) {
	good := marshalled(t, []memFile{{name: "a", data: []byte("hi"), mode: 0o644}}, false, "")
	sum := sha256.Sum256([]byte("hi"))
	hexSum := hex.EncodeToString(sum[:])

	mutate := func(from, to string) []byte {
		b := bytes.Replace(good, []byte(from), []byte(to), 1)
		if bytes.Equal(b, good) {
			t.Fatalf("mutation %q not applied", from)
		}
		return b
	}
	cases := map[string]struct {
		data []byte
		lim  DecodeLimits
		want string
	}{
		"wrong type":        {mutate("files\x65files", "fileZ\x65files"), DecodeLimits{}, "payload type"},
		"unknown key":       {mutate("\x64name", "\x64nome"), DecodeLimits{}, "where \"name\" belongs"},
		"size mismatch":     {mutate("\x64size\x02", "\x64size\x03"), DecodeLimits{}, "declares 3 bytes"},
		"sha256 mismatch":   {mutate(hexSum, strings.Repeat("0", 64)), DecodeLimits{}, "does not match its SHA-256"},
		"trailing data":     {append(append([]byte{}, good...), 0x00), DecodeLimits{}, "data follows"},
		"truncated":         {good[:len(good)-3], DecodeLimits{}, "unexpected EOF"},
		"indefinite data":   {mutate("\x64data\x42hi", "\x64data\x5f\x42hi\xff"), DecodeLimits{}, "indefinite"},
		"long-form length":  {mutate("\x64data\x42", "\x64data\x58\x02"), DecodeLimits{}, "shortest form"},
		"file too large":    {good, DecodeLimits{MaxFileSize: 1}, "the limit is 1"},
		"total too large":   {good, DecodeLimits{MaxTotalSize: 1}, "total size limit"},
		"name too long":     {good, DecodeLimits{MaxNameLen: 0x7fffffff}, ""},
		"too many files":    {good, DecodeLimits{MaxFiles: 1}, ""},
		"not a payload map": {[]byte{0x80}, DecodeLimits{}, "major type 4"},
	}
	for name, c := range cases {
		_, err := DecodeFiles(bytes.NewReader(c.data), c.lim, nil)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: unexpected %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}

	two := marshalled(t, []memFile{{name: "a", data: []byte{}}, {name: "b", data: []byte{}}}, false, "")
	if _, err := DecodeFiles(bytes.NewReader(two), DecodeLimits{MaxFiles: 1}, nil); err == nil || !strings.Contains(err.Error(), "the limit is 1") {
		t.Errorf("too many files: %v", err)
	}
	twoArchived := bytes.Replace(two, []byte{0xa2}, []byte{0xa3}, 1)
	twoArchived = append(twoArchived, append([]byte("\x67archive"), cborTrue)...)
	if _, err := DecodeFiles(bytes.NewReader(twoArchived), DecodeLimits{}, nil); err == nil || !strings.Contains(err.Error(), "exactly one file") {
		t.Errorf("archive with two files: %v", err)
	}
	longName := marshalled(t, []memFile{{name: strings.Repeat("n", 300), data: []byte{}}}, false, "")
	nullData := marshalled(t, []memFile{{name: "empty"}}, false, "")
	if out, err := DecodeFiles(bytes.NewReader(nullData), DecodeLimits{}, nil); err != nil || out.Files[0].Size != 0 {
		t.Errorf("null data is an empty file: %+v, %v", out, err)
	}
	if _, err := DecodeFiles(bytes.NewReader(longName), DecodeLimits{MaxNameLen: 255}, nil); err == nil || !strings.Contains(err.Error(), "the limit is 255") {
		t.Errorf("long name: %v", err)
	}
	message, _ := Marshal(Payload{Type: "message", Message: "hi"})
	if _, err := DecodeFiles(bytes.NewReader(message), DecodeLimits{}, nil); err == nil {
		t.Error("a message payload decodes as files")
	}
}

// All names together are bounded too.
func TestDecodeFilesBoundsNameBytes(t *testing.T) {
	data := marshalled(t, []memFile{{name: "aaaa", data: []byte{}}, {name: "bbbb", data: []byte{}}}, false, "")
	if _, err := DecodeFiles(bytes.NewReader(data), DecodeLimits{MaxNameBytes: 6}, nil); err == nil || !strings.Contains(err.Error(), "6 bytes in all") {
		t.Fatalf("got %v", err)
	}
}
