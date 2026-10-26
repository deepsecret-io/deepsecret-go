// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package payload

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"unicode/utf8"
)

// ── Streaming files payload ─────────────────────────────────────────────────
//
// A files payload is the canonical CBOR of Payload{Type: "files", ...},
// byte for byte what Marshal produces, written and read as a stream so no
// file's data has to be in memory. Canonical CBOR orders map keys by length,
// then bytewise:
//
//	payload: type, files, archive, archive_compression
//	file:    data, mode, name, size, sha256
//
// Every key but a file's sha256 is known before its data, and the SHA-256
// computed while the data streams fills sha256 after it. A reader, in turn,
// meets a file's data before its name, and the files before the archive
// flag.

// FileSource is one file a streaming files payload reads.
type FileSource struct {
	Name string // the payload name, a portable relative path
	Size int64  // the exact byte count; encoding fails if the file has more or fewer
	Mode os.FileMode
	Open func() (io.ReadCloser, error)
}

// FileInfo is one file of a files payload, without its data.
type FileInfo struct {
	Name   string
	Size   int64
	Mode   os.FileMode
	SHA256 string // hex
}

// Files is the structure of a decoded files payload.
type Files struct {
	Files              []FileInfo
	Archive            bool
	ArchiveCompression string
}

// CBOR major types used by the payload.
const (
	majorUint  = 0
	majorBytes = 2
	majorText  = 3
	majorArray = 4
	majorMap   = 5

	cborTrue = 0xf5
	cborNull = 0xf6
)

// payloadKeys and fileKeys are the keys of each map in canonical order.
var (
	payloadKeys = []string{"type", "files", "archive", "archive_compression"}
	fileKeys    = []string{"data", "mode", "name", "size", "sha256"}
)

// EncodeFiles writes the canonical CBOR of a files payload to w, streaming
// each file's data from its source, and returns each file's SHA-256 (hex) in
// order. archived marks a payload that holds one tar archive compressed with
// archiveCompression ("" for none).
func EncodeFiles(w io.Writer, files []FileSource, archived bool, archiveCompression string) ([]string, error) {
	if archived && len(files) != 1 {
		return nil, fmt.Errorf("an archive payload holds exactly one file, got %d", len(files))
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	e := &streamEncoder{w: bw}

	keys := 1
	if len(files) > 0 {
		keys++
	}
	if archived {
		keys++
		if archiveCompression != "" {
			keys++
		}
	}
	e.head(majorMap, uint64(keys))
	e.text("type")
	e.text("files")
	sums := make([]string, len(files))
	if len(files) > 0 {
		e.text("files")
		e.head(majorArray, uint64(len(files)))
		for i, f := range files {
			sum, err := e.file(f)
			if err != nil {
				return nil, err
			}
			sums[i] = sum
		}
	}
	if archived {
		e.text("archive")
		e.raw([]byte{cborTrue})
		if archiveCompression != "" {
			e.text("archive_compression")
			e.text(archiveCompression)
		}
	}
	if e.err != nil {
		return nil, e.err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	return sums, nil
}

type streamEncoder struct {
	w   *bufio.Writer
	err error
}

func (e *streamEncoder) raw(b []byte) {
	if e.err == nil {
		_, e.err = e.w.Write(b)
	}
}

// head writes a major type and its argument in the shortest form.
func (e *streamEncoder) head(major byte, n uint64) {
	var b [9]byte
	switch {
	case n < 24:
		b[0] = major<<5 | byte(n)
		e.raw(b[:1])
	case n <= 0xff:
		b[0], b[1] = major<<5|24, byte(n)
		e.raw(b[:2])
	case n <= 0xffff:
		b[0] = major<<5 | 25
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		e.raw(b[:3])
	case n <= 0xffffffff:
		b[0] = major<<5 | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		e.raw(b[:5])
	default:
		b[0] = major<<5 | 27
		binary.BigEndian.PutUint64(b[1:], n)
		e.raw(b[:9])
	}
}

func (e *streamEncoder) text(s string) {
	if e.err == nil && !utf8.ValidString(s) {
		e.err = fmt.Errorf("%q is not valid UTF-8", s)
		return
	}
	e.head(majorText, uint64(len(s)))
	if e.err == nil {
		_, e.err = e.w.WriteString(s)
	}
}

// file writes one file entry, streaming its data, and returns its SHA-256.
func (e *streamEncoder) file(f FileSource) (string, error) {
	if f.Size < 0 {
		return "", fmt.Errorf("%s: negative size", f.Name)
	}
	if !utf8.ValidString(f.Name) {
		return "", fmt.Errorf("file name %q is not valid UTF-8", f.Name)
	}
	e.head(majorMap, uint64(len(fileKeys)))
	e.text("data")
	e.head(majorBytes, uint64(f.Size))
	if e.err != nil {
		return "", e.err
	}

	src, err := f.Open()
	if err != nil {
		return "", fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer src.Close()
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(e.w, h), src, f.Size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%s changed while it was read: %d of %d bytes", f.Name, n, f.Size)
		}
		return "", fmt.Errorf("read %s: %w", f.Name, err)
	}
	var probe [1]byte
	if m, _ := src.Read(probe[:]); m > 0 {
		return "", fmt.Errorf("%s changed while it was read: it is longer than %d bytes", f.Name, f.Size)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	e.text("mode")
	e.head(majorUint, uint64(f.Mode))
	e.text("name")
	e.text(f.Name)
	e.text("size")
	e.head(majorUint, uint64(f.Size))
	e.text("sha256")
	e.text(sum)
	return sum, e.err
}

// DecodeLimits bounds what DecodeFiles accepts. Zero fields take the
// defaults.
type DecodeLimits struct {
	MaxFiles     int   // default 100,000
	MaxFileSize  int64 // default 100 GiB
	MaxTotalSize int64 // default 500 GiB
	MaxNameLen   int   // default 4096 bytes
	MaxNameBytes int64 // all names together, default 64 MiB
}

func (l DecodeLimits) resolve() DecodeLimits {
	if l.MaxFiles <= 0 {
		l.MaxFiles = 100_000
	}
	if l.MaxFileSize <= 0 {
		l.MaxFileSize = 100 << 30
	}
	if l.MaxTotalSize <= 0 {
		l.MaxTotalSize = 500 << 30
	}
	if l.MaxNameLen <= 0 {
		l.MaxNameLen = 4096
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = 64 << 20
	}
	return l
}

// DecodeFiles reads a files payload from r and hands each file's data to
// onData as it streams, before the file's name is known: index is the file's
// position, and data yields exactly size bytes. Whatever onData leaves
// unread is read and hashed after it returns.
//
// The payload must be canonical CBOR, as EncodeFiles and Marshal write it,
// with known keys only, definite lengths and nothing after it. Each file's
// size and SHA-256 must match its data. File names are returned as the
// payload has them; checking them as paths is the caller's job.
func DecodeFiles(r io.Reader, lim DecodeLimits, onData func(index int, size int64, data io.Reader) error) (*Files, error) {
	lim = lim.resolve()
	d := &streamDecoder{r: bufio.NewReaderSize(r, 64<<10)}

	n, err := d.expect(majorMap, "payload")
	if err != nil {
		return nil, err
	}
	if n < 1 || n > uint64(len(payloadKeys)) {
		return nil, fmt.Errorf("payload map has %d keys", n)
	}
	out := &Files{}
	next := 0
	typed := false
	var total, nameBytes int64
	for i := uint64(0); i < n; i++ {
		key, err := d.text(32, "payload key")
		if err != nil {
			return nil, err
		}
		pos := indexAfter(payloadKeys, next, key)
		if pos < 0 {
			return nil, fmt.Errorf("payload key %q is unknown, repeated or out of order", key)
		}
		next = pos + 1
		switch key {
		case "type":
			t, err := d.text(32, "payload type")
			if err != nil {
				return nil, err
			}
			if t != "files" {
				return nil, fmt.Errorf("payload type is %q, not files", t)
			}
			typed = true
		case "files":
			count, err := d.expect(majorArray, "files")
			if err != nil {
				return nil, err
			}
			if count == 0 || count > uint64(lim.MaxFiles) {
				return nil, fmt.Errorf("payload lists %d files, the limit is %d", count, lim.MaxFiles)
			}
			out.Files = make([]FileInfo, 0, count)
			for idx := 0; idx < int(count); idx++ {
				f, err := d.file(idx, lim, &total, onData)
				if err != nil {
					return nil, err
				}
				if nameBytes += int64(len(f.Name)); nameBytes > lim.MaxNameBytes {
					return nil, fmt.Errorf("file names exceed %d bytes in all", lim.MaxNameBytes)
				}
				out.Files = append(out.Files, f)
			}
		case "archive":
			b, err := d.r.ReadByte()
			if err != nil {
				return nil, fmt.Errorf("read archive flag: %w", err)
			}
			if b != cborTrue {
				return nil, fmt.Errorf("archive flag is not true")
			}
			out.Archive = true
		case "archive_compression":
			c, err := d.text(32, "archive compression")
			if err != nil {
				return nil, err
			}
			if c != "zstd" {
				return nil, fmt.Errorf("archive compression %q is not supported", c)
			}
			out.ArchiveCompression = c
		}
	}
	if !typed {
		return nil, fmt.Errorf("payload has no type")
	}
	if out.ArchiveCompression != "" && !out.Archive {
		return nil, fmt.Errorf("archive compression is set on a payload that is not an archive")
	}
	if out.Archive && len(out.Files) != 1 {
		return nil, fmt.Errorf("an archive payload holds exactly one file, got %d", len(out.Files))
	}
	if _, err := d.r.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("data follows the payload")
		}
		return nil, err
	}
	return out, nil
}

type streamDecoder struct {
	r *bufio.Reader
}

// head reads a major type and its argument, refusing indefinite lengths
// and any argument not in its shortest form.
func (d *streamDecoder) head() (byte, uint64, error) {
	b, err := d.r.ReadByte()
	if err != nil {
		return 0, 0, unexpectedEOF(err)
	}
	major, info := b>>5, b&0x1f
	var size int
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24:
		size = 1
	case info == 25:
		size = 2
	case info == 26:
		size = 4
	case info == 27:
		size = 8
	default:
		return 0, 0, fmt.Errorf("indefinite or reserved CBOR length (0x%02x)", b)
	}
	var buf [8]byte
	if _, err := io.ReadFull(d.r, buf[:size]); err != nil {
		return 0, 0, unexpectedEOF(err)
	}
	var v uint64
	for _, c := range buf[:size] {
		v = v<<8 | uint64(c)
	}
	var minimum uint64
	switch size {
	case 1:
		minimum = 24
	case 2:
		minimum = 0x100
	case 4:
		minimum = 0x10000
	case 8:
		minimum = 0x100000000
	}
	if v < minimum {
		return 0, 0, fmt.Errorf("CBOR argument %d is not in its shortest form", v)
	}
	return major, v, nil
}

func (d *streamDecoder) expect(major byte, what string) (uint64, error) {
	m, v, err := d.head()
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", what, err)
	}
	if m != major {
		return 0, fmt.Errorf("%s has CBOR major type %d, want %d", what, m, major)
	}
	return v, nil
}

func (d *streamDecoder) text(max int, what string) (string, error) {
	n, err := d.expect(majorText, what)
	if err != nil {
		return "", err
	}
	if n > uint64(max) {
		return "", fmt.Errorf("%s is %d bytes, the limit is %d", what, n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(d.r, buf); err != nil {
		return "", fmt.Errorf("read %s: %w", what, unexpectedEOF(err))
	}
	if !utf8.Valid(buf) {
		return "", fmt.Errorf("%s is not valid UTF-8", what)
	}
	return string(buf), nil
}

func (d *streamDecoder) uint(max uint64, what string) (uint64, error) {
	v, err := d.expect(majorUint, what)
	if err != nil {
		return 0, err
	}
	if v > max {
		return 0, fmt.Errorf("%s %d is out of range", what, v)
	}
	return v, nil
}

// file reads one file entry, streaming its data to onData.
func (d *streamDecoder) file(idx int, lim DecodeLimits, total *int64, onData func(int, int64, io.Reader) error) (FileInfo, error) {
	n, err := d.expect(majorMap, "file entry")
	if err != nil {
		return FileInfo{}, err
	}
	if n != uint64(len(fileKeys)) {
		return FileInfo{}, fmt.Errorf("file %d has %d keys, want %d", idx, n, len(fileKeys))
	}
	key := func(want string) error {
		k, err := d.text(16, "file key")
		if err != nil {
			return err
		}
		if k != want {
			return fmt.Errorf("file %d has key %q where %q belongs", idx, k, want)
		}
		return nil
	}

	if err := key("data"); err != nil {
		return FileInfo{}, err
	}
	// Marshal writes a nil Data as null; it is an empty file.
	var size uint64
	if b, err := d.r.Peek(1); err == nil && b[0] == cborNull {
		d.r.ReadByte()
	} else if size, err = d.expect(majorBytes, "file data"); err != nil {
		return FileInfo{}, err
	}
	if size > uint64(lim.MaxFileSize) {
		return FileInfo{}, fmt.Errorf("file %d is %d bytes, the limit is %d", idx, size, lim.MaxFileSize)
	}
	if *total+int64(size) > lim.MaxTotalSize {
		return FileInfo{}, fmt.Errorf("files exceed the total size limit %d", lim.MaxTotalSize)
	}
	*total += int64(size)
	h := sha256.New()
	data := &hashingReader{r: io.LimitReader(d.r, int64(size)), h: h}
	if onData != nil {
		if err := onData(idx, int64(size), data); err != nil {
			return FileInfo{}, err
		}
	}
	if _, err := io.Copy(io.Discard, data); err != nil {
		return FileInfo{}, fmt.Errorf("read file %d: %w", idx, err)
	}
	if data.n != int64(size) {
		return FileInfo{}, fmt.Errorf("file %d: %w", idx, io.ErrUnexpectedEOF)
	}

	var f FileInfo
	if err := key("mode"); err != nil {
		return FileInfo{}, err
	}
	mode, err := d.uint(0xffffffff, "file mode")
	if err != nil {
		return FileInfo{}, err
	}
	f.Mode = os.FileMode(mode)
	if err := key("name"); err != nil {
		return FileInfo{}, err
	}
	if f.Name, err = d.text(lim.MaxNameLen, "file name"); err != nil {
		return FileInfo{}, err
	}
	if err := key("size"); err != nil {
		return FileInfo{}, err
	}
	declared, err := d.uint(uint64(lim.MaxFileSize), "file size")
	if err != nil {
		return FileInfo{}, err
	}
	if declared != size {
		return FileInfo{}, fmt.Errorf("%s declares %d bytes but holds %d", f.Name, declared, size)
	}
	f.Size = int64(size)
	if err := key("sha256"); err != nil {
		return FileInfo{}, err
	}
	if f.SHA256, err = d.text(64, "file sha256"); err != nil {
		return FileInfo{}, err
	}
	if sum := hex.EncodeToString(h.Sum(nil)); f.SHA256 != sum {
		return FileInfo{}, fmt.Errorf("%s does not match its SHA-256", f.Name)
	}
	return f, nil
}

// hashingReader hashes and counts what is read through it.
type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (hr *hashingReader) Read(p []byte) (int, error) {
	n, err := hr.r.Read(p)
	hr.h.Write(p[:n])
	hr.n += int64(n)
	return n, err
}

// indexAfter returns the position of key in keys at or after from, or -1.
func indexAfter(keys []string, from int, key string) int {
	for i := from; i < len(keys); i++ {
		if keys[i] == key {
			return i
		}
	}
	return -1
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
