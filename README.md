# DeepSecret Go SDK

End-to-end encrypted secrets management with hybrid post-quantum cryptography.

**Version:** 0.3.0
**Protocol:** v2 — HPKE (MLKEM768-X25519 + HKDF-SHA256 + AES-256-GCM) + Ed25519
**Payload:** CBOR (RFC 8949, canonical encoding)
**Compression:** Zstandard only
**Go:** 1.26+

## Architecture

```
sdk/                 ← orchestration (encrypt, decrypt)
├── api/             ← HTTP client, presigned upload/download
├── identity/        ← actor info, key management, resolution
├── secrets/         ← secret CRUD, creation request types
├── payload/         ← CBOR payload types (wire format)
├── crypto/          ← HPKE encrypt/decrypt, Ed25519, keystore
├── compress/        ← streaming zstd compression/decompression
├── archive/         ← tar creation/extraction, path validation
└── examples/
```

**Standalone packages** (no API dependency, portable to other languages):
- `crypto/` — encryption, signing, key management
- `compress/` — streaming zstd
- `archive/` — tar, path validation, file expansion
- `payload/` — CBOR payload types

## Quick Start

```go
import "deepsecret/sdk"

client := sdk.NewClient("https://api.deepsecret.io", "ds_your_api_key")

// Encrypt a message
secret, _ := client.EncryptText("bob@example.com", "sensitive data")

// Decrypt (auto-unarchives if needed)
result, _ := client.DecryptSecret(secret.ID)
fmt.Println(result.Message)
```

## Encrypt Options

```go
sdk.EncryptOptions{
    Name:       "report-q4",
    Compress:   sdk.CompressZstd,  // zstd or none
    Archive:    true,              // bundle as tar.zst (hides file metadata)
    SkipHidden: true,
    TTL:        "7d",              // "30m", "24h", "7d"
    IPs:        []string{"10.0.0.0/8"},
}
```

## Memory Model

The current protocol uses single-shot HPKE encryption, which requires the full
plaintext in memory. All `Encrypt*` functions load file contents into RAM.
For very large payloads, consider file-size limits. Future protocol versions
may add chunked encryption for true streaming.

## Packages

### `sdk/crypto` — Cryptographic Primitives

| Function | Description |
|---|---|
| `GenerateKeyPair()` | Generate Ed25519 + X25519 + ML-KEM-768 key pair |
| `Fingerprint(kp)` | Full SHA-256 hex fingerprint (64 chars) |
| `HybridEncrypt(pt, sender, recipient, params)` | HPKE encrypt + Ed25519 sign |
| `HybridDecrypt(envelope, recipient, senderPub)` | Verify + HPKE decrypt |
| `UnmarshalEnvelope(data)` | Inspect envelope without decrypting |
| `SaveKeyPair` / `LoadKeyPair` | Password-protected key storage |

### `sdk/compress` — Streaming Compression

| Function | Description |
|---|---|
| `NewCompressWriter(w, algo)` | Streaming compressor (primary) |
| `NewDecompressReader(r, algo)` | Streaming decompressor (primary) |
| `Compress(data, algo)` | Convenience []byte compression |
| `Decompress(data, algo, limits)` | Bounded decompression |

Algorithms: `compress.Zstd`, `compress.None`

### `sdk/archive` — Tar & File Operations

| Function | Description |
|---|---|
| `WriteTar(w, files, algo)` | Stream files → tar → writer (primary) |
| `WriteTarStream(w, entries, algo)` | Stream reader-backed entries → tar |
| `ExtractTarReader(r, dir, algo, limits)` | Stream tar → disk (primary) |
| `ValidateArchivePath(name)` | Portable archive path validation |
| `ExpandPaths(paths, skipHidden)` | Recursive file expansion |

### `sdk/payload` — Wire Format

CBOR-encoded payload types with canonical deterministic encoding.

### `sdk/identity` — Identity Management

Actor info, key resolution, sync, fingerprint lookup.

### `sdk/secrets` — Secret CRUD

List, describe, delete, create secrets via the API.

## Encryption Protocol (v2)

```
Sender                                           Recipient
  │                                                  │
  │  1. HPKE Encapsulate (MLKEM768-X25519) ─────►   │
  │  2. HPKE derives keys (HKDF-SHA256) internally  │
  │  3. HPKE encrypts plaintext (AES-256-GCM + AAD) │
  │  4. Ed25519 Sign(envelope)                       │
  │                                                  │
  │  ──── encrypted envelope (CBOR) ────────────►    │
  │                                                  │
  │                          5. Verify Ed25519 sig   │
  │                          6. Verify sender bundle │
  │                          7. HPKE Decapsulate     │
  │                          8. HPKE decrypt         │
```

## Running Tests

```bash
go test ./sdk/... -v
```

## Cross-Language Porting

The SDK is designed for portability:

- **Standalone packages**: `crypto/`, `compress/`, `archive/`, `payload/` have no HTTP dependency
- **Wire format**: CBOR (RFC 8949) with canonical encoding — deterministic across languages
- **Compression**: Zstandard (RFC 8878) — implementations in every language
- **Encryption**: HPKE (RFC 9180) with MLKEM768-X25519 — Go stdlib `crypto/hpke`
- **Signing**: Ed25519 (RFC 8032) — universal
- **Archive paths**: strict portable format (forward-slash, no traversal, validated)

Key porting targets: TypeScript/Node.js, Python, Rust, Swift, Kotlin
