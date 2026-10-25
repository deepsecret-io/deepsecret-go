# DeepSecret Go SDK

End-to-end encrypted secrets management with hybrid post-quantum cryptography.

**Version:** 0.3.0
**Protocol:** v4: one payload per revision (AES-256-GCM, 1 MiB chunks), a content-key wrap per recipient (HPKE X25519-ML-KEM-768 + HKDF-SHA256 + AES-256-GCM), and a manifest signed with Ed25519 + ML-DSA-65. See [PROTOCOL_V4.md](PROTOCOL_V4.md).
**Payload:** CBOR (RFC 8949, canonical encoding)
**Compression:** Zstandard only
**Go:** 1.26+

## Architecture

```
sdk/                 ← orchestration (encrypt, decrypt, revoke)
├── api/             ← HTTP client, presigned upload/download
├── identity/        ← actor info, key management, resolution
├── secrets/         ← secret CRUD, creation request types
├── payload/         ← CBOR payload types (wire format)
├── crypto/          ← payload stream, HPKE wraps, signed manifest, keystore
├── compress/        ← streaming zstd compression/decompression
├── archive/         ← tar creation/extraction, path validation
└── examples/
```

**Standalone packages** (no API dependency, portable to other languages):
- `crypto/`: encryption, signing, key management
- `compress/`: streaming zstd
- `archive/`: tar, path validation, file expansion
- `payload/`: CBOR payload types

## Quick Start

```go
import "github.com/deepsecret-io/sdk"

client, err := sdk.NewClient("https://api.deepsecret.io", "ds_your_api_key")
if err != nil {
    log.Fatal(err)
}

// Encrypt a message once for two recipients (you are a recipient only if listed)
res, _ := client.EncryptText([]string{"alice@example.com", "bob@example.com"}, "sensitive data", sdk.EncryptOptions{})

// Decrypt, as one of the recipients
result, _ := client.DecryptSecret(res.Secret.ID)
fmt.Println(result.Message)

// Revoke one recipient
client.RevokeRecipient(res.Secret.ID, "bob@example.com")
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
    // Resending under an existing name must list everyone with access now;
    // this revokes anyone the send leaves out.
    RevokeMissing: true,
}
```

## Memory Model

Protocol v4 encrypts in 1 MiB chunks, and `crypto.Seal` / `Opened.DecryptTo`
stream. The high-level `Encrypt*` functions still build the payload in memory,
and decrypt buffers the downloaded object so its digest is checked against the
signed manifest before any plaintext is released. For very large payloads,
consider file-size limits.

## Packages

### `sdk/crypto`: Cryptographic Primitives

| Function | Description |
|---|---|
| `GenerateKeyPair()` | Generate Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768 key pair |
| `Fingerprint(kp)` | Full SHA-256 hex fingerprint (64 chars) |
| `Seal` / `SealBytes(pt, sender, recipients, params)` | Encrypt once, wrap the content key per recipient, sign the manifest |
| `Open(manifest, wrap, recipient, params)` | Verify the manifest, open the caller's wrap |
| `Opened.Decrypt` / `DecryptTo` | Check the payload digest, then decrypt the chunks |
| `UnmarshalManifest(data)` | Inspect a manifest without opening it |
| `SaveKeyPair` / `LoadKeyPair` | Password-protected key storage |

### `sdk/compress`: Streaming Compression

| Function | Description |
|---|---|
| `NewCompressWriter(w, algo)` | Streaming compressor (primary) |
| `NewDecompressReader(r, algo)` | Streaming decompressor (primary) |
| `Compress(data, algo)` | Convenience []byte compression |
| `Decompress(data, algo, limits)` | Bounded decompression |

Algorithms: `compress.Zstd`, `compress.None`

### `sdk/archive`: Tar & File Operations

| Function | Description |
|---|---|
| `WriteTar(w, files, algo)` | Stream files → tar → writer (primary) |
| `WriteTarStream(w, entries, algo)` | Stream reader-backed entries → tar |
| `ExtractTarReader(r, dir, algo, limits)` | Stream tar → disk (primary) |
| `ValidateArchivePath(name)` | Portable archive path validation |
| `ExpandPaths(paths, skipHidden)` | Recursive file expansion |

### `sdk/payload`: Wire Format

CBOR-encoded payload types with canonical deterministic encoding.

### `sdk/identity`: Identity Management

Actor info, key resolution, sync, fingerprint lookup.

### `sdk/secrets`: Secret CRUD

List, describe, delete, create secrets, fetch a revision's manifest and wrap, and revoke recipients via the API.

## Encryption Protocol (v4)

```
Sender                                           Recipients
  │                                                  │
  │  1. Fresh content key K per revision             │
  │  2. AES-256-GCM, 1 MiB chunks, key HKDF(K)       │
  │  3. HPKE-wrap K for each recipient               │
  │     (X25519-ML-KEM-768, fresh context per wrap)  │
  │  4. Sign manifest (Ed25519 + ML-DSA-65):         │
  │     payload digest + every recipient's wrap      │
  │                                                  │
  │  ──── one payload, manifest, one wrap each ──►   │
  │                                                  │
  │                   5. Verify sender bundle + sigs │
  │                   6. Check listed + wrap digest  │
  │                   7. HPKE-open own wrap → K      │
  │                   8. Verify payload digest       │
  │                   9. Decrypt chunks in order     │
```

## Running Tests

```bash
go test ./... -v
```

## Cross-Language Porting

The SDK is designed for portability:

- **Standalone packages**: `crypto/`, `compress/`, `archive/`, `payload/` have no HTTP dependency
- **Wire format**: CBOR (RFC 8949) with canonical encoding, deterministic across languages
- **Compression**: Zstandard (RFC 8878), implementations in every language
- **Encryption**: HPKE (RFC 9180) with X25519-ML-KEM-768 (Go stdlib `crypto/hpke`) for wraps, AES-256-GCM in 1 MiB chunks for payloads
- **Signing**: Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204), both required
- **Test vectors**: `crypto/v4_vector_test.go` pins every deterministic v4 value
- **Archive paths**: strict portable format (forward-slash, no traversal, validated)

Key porting targets: TypeScript/Node.js, Python, Rust, Swift, Kotlin
