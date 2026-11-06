// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package protocol

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ── Payload stream (protocol v4 §2 and §3) ──────────────────────────────────

const (
	// ChunkSize is the plaintext size of every payload chunk except the last.
	ChunkSize = 1 << 20

	// ContentKeySize is the size of a revision's random content key.
	ContentKeySize = 32

	// chunkTagSize is the AES-256-GCM tag appended to every chunk.
	chunkTagSize = 16

	// payloadKeyInfo is the HKDF info that derives the payload key from the
	// content key.
	payloadKeyInfo = "deepsecret/v4/payload"
)

// derivePayloadKey returns PK = HKDF-SHA256(ikm = K, salt = empty,
// info = "deepsecret/v4/payload", L = 32). K itself never touches the payload.
func derivePayloadKey(contentKey []byte) ([]byte, error) {
	if len(contentKey) != ContentKeySize {
		return nil, fmt.Errorf("content key must be %d bytes, got %d", ContentKeySize, len(contentKey))
	}
	return hkdf.Key(sha256.New, contentKey, nil, payloadKeyInfo, 32)
}

// chunkAAD binds every chunk to the protocol version, the revision and the
// payload type:
//
//	SHA-256(fields("deepsecret/v4/chunk", version, revision_id, payload_type, uint32_be(C)))
func chunkAAD(revisionID, payloadType string) []byte {
	h := sha256.New()
	writeField(h, []byte("deepsecret/v4/chunk"))
	writeField(h, []byte(ProtocolVersion))
	writeField(h, []byte(revisionID))
	writeField(h, []byte(payloadType))
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], ChunkSize)
	writeField(h, c[:])
	return h.Sum(nil)
}

// chunkNonce is uint88_be(i) || flag, where flag is 0x01 for the last chunk
// and 0x00 otherwise. The counter stops chunks being reordered or dropped;
// the flag stops truncation and appended data.
func chunkNonce(i uint64, last bool) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[3:11], i)
	if last {
		nonce[11] = 0x01
	}
	return nonce
}

// ciphertextSizeFor returns the stored size of a payload of plaintextSize
// bytes: every chunk carries a tag, and an empty payload is one empty chunk.
func ciphertextSizeFor(plaintextSize int64) int64 {
	chunks := plaintextSize / ChunkSize
	if plaintextSize%ChunkSize != 0 || plaintextSize == 0 {
		chunks++
	}
	return plaintextSize + chunks*chunkTagSize
}

func newPayloadAEAD(payloadKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(payloadKey)
	if err != nil {
		return nil, fmt.Errorf("payload cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// readChunk fills buf from r and reports whether this is the last chunk:
// either r ran out while filling buf, or nothing follows a full buf.
func readChunk(r *bufio.Reader, buf []byte) (n int, last bool, err error) {
	n, err = io.ReadFull(r, buf)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return n, true, nil
	case err != nil:
		return n, false, err
	}
	if _, err := r.Peek(1); errors.Is(err, io.EOF) {
		return n, true, nil
	} else if err != nil {
		return n, false, err
	}
	return n, false, nil
}

// streamResult describes an encrypted payload stream.
type streamResult struct {
	PlaintextSize  int64
	CiphertextSize int64
	Digest         []byte // SHA-256 of the stored payload object
}

// encryptStream seals src into dst chunk by chunk and hashes the
// ciphertext as it goes.
func encryptStream(dst io.Writer, src io.Reader, payloadKey, aad []byte) (*streamResult, error) {
	aead, err := newPayloadAEAD(payloadKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	out := io.MultiWriter(dst, digest)
	in := bufio.NewReaderSize(src, ChunkSize)
	buf := make([]byte, ChunkSize)
	sealed := make([]byte, 0, ChunkSize+chunkTagSize)

	res := &streamResult{}
	for i := uint64(0); ; i++ {
		n, last, err := readChunk(in, buf)
		if err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
		sealed = aead.Seal(sealed[:0], chunkNonce(i, last), buf[:n], aad)
		if _, err := out.Write(sealed); err != nil {
			return nil, fmt.Errorf("write payload: %w", err)
		}
		res.PlaintextSize += int64(n)
		res.CiphertextSize += int64(len(sealed))
		if last {
			break
		}
	}
	clear(buf)
	res.Digest = digest.Sum(nil)
	return res, nil
}

// decryptStream opens src chunk by chunk into dst. Each chunk is
// authenticated before its plaintext is written. The last-chunk flag is
// required on the final chunk only, so a stream cut at a chunk boundary, or
// with data after its last chunk, fails.
func decryptStream(dst io.Writer, src io.Reader, payloadKey, aad []byte) (int64, error) {
	aead, err := newPayloadAEAD(payloadKey)
	if err != nil {
		return 0, err
	}
	in := bufio.NewReaderSize(src, ChunkSize+chunkTagSize)
	buf := make([]byte, ChunkSize+chunkTagSize)
	plain := make([]byte, 0, ChunkSize)
	defer clear(plain[:cap(plain)])

	var written int64
	for i := uint64(0); ; i++ {
		n, last, err := readChunk(in, buf)
		if err != nil {
			return written, fmt.Errorf("read payload: %w", err)
		}
		if n < chunkTagSize {
			return written, fmt.Errorf("payload chunk %d is truncated", i)
		}
		plain, err = aead.Open(plain[:0], chunkNonce(i, last), buf[:n], aad)
		if err != nil {
			return written, fmt.Errorf("payload chunk %d failed authentication", i)
		}
		if _, err := dst.Write(plain); err != nil {
			return written, fmt.Errorf("write plaintext: %w", err)
		}
		written += int64(len(plain))
		if last {
			return written, nil
		}
	}
}

// hashStream returns the size and SHA-256 of everything in r.
func hashStream(r io.Reader) (int64, []byte, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return n, nil, err
	}
	return n, h.Sum(nil), nil
}
