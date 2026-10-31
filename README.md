# DeepSecret Go SDK

End-to-end encrypted secrets management with hybrid post-quantum cryptography.

**Versions:** [semantic](#versions), one git tag per release
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
    Archive:    true,              // bundle as one tar archive, zstd-compressed (hides file metadata)
    SkipHidden: true,
    TTL:        "7d",              // "30m", "24h", "7d"
    IPs:        []string{"10.0.0.0/8"},
    // Resending under an existing name must list everyone with access now;
    // this revokes anyone the send leaves out.
    RevokeMissing: true,
}
```

## Memory Model

Files stream, so memory stays flat at any size, up to 100 GiB a secret.

- **Send.** `EncryptFile`, `EncryptFiles`, `EncryptDir` and `EncryptPaths` read
  each file once, encode, compress and seal it chunk by chunk into a private
  temporary file holding only ciphertext, then upload from that file.
- **Receive.** `OpenSecret` downloads the ciphertext into a temporary file.
  `WriteFiles` (or `DecryptToDir`) checks it against the signed manifest,
  decrypts it once to check every file name, size and SHA-256 and an archive's
  entries, then decrypts it again to write. A payload that fails a check
  writes nothing.
- **Disk.** Both sides need free space for the encrypted payload: set
  `TempDir` in the options or `DEEPSECRET_TMPDIR`, else the system temp
  directory is used. A send checks before it reads anything.
- **In memory.** `EncryptText`, `EncryptData` and `EncryptBytes`, and
  `DecryptSecretFull` for payloads up to `DefaultMaxInMemorySize` (256 MiB).

```go
// Write a files secret of any size to disk
result, written, err := client.DecryptToDir(secretID, "./out", sdk.DecryptOptions{}, sdk.WriteOptions{})

// Or open first, then choose where it goes
opened, err := client.OpenSecret(secretID, sdk.DecryptOptions{})
defer opened.Close()
if opened.Result.PayloadType == "files" {
    written, err = opened.WriteFiles("./out", sdk.WriteOptions{Overwrite: false})
} else {
    decrypted, err := opened.Payload() // a message or key-value data
}
```

## Large Transfers

Uploads above the server's multipart threshold go in parts (8 MiB, 32 MiB
from 1 GiB, 64 MiB from 16 GiB). Parts stream between the file and the
network, so memory does not grow with part size or threads.

- **Threads adapt.** A transfer doubles its connections while throughput
  rises by more than 10%, steps back when it does not, and halves them when
  requests fail or are throttled. It measures every 2 seconds from 4 MB/s
  and every 5 seconds below, where a short window measures noise. A download
  starts with 4. An upload starts with one part and never runs more parts
  than finish within a minute at the measured rate: storage keeps only
  finished parts, so on a slow link they go one after another and an
  interrupted upload keeps nearly all it sent. On a fast link it takes 4 as
  soon as its first part finishes and climbs as a download does. Where one
  connection cannot fill the link (high latency to storage, some VPNs,
  per-connection shaping), one part measures slow and that bound would
  hold the upload at one, so from one part an upload tries a second: it
  keeps it when throughput rises by more than 10%, and otherwise goes back
  to one and tries again five minutes later. `OnDebug` events with step
  `threads` say each change and why a count holds. `UploadThreads` and
  `DownloadThreads` fix the number instead.
- **Connections.** Each part runs on its own HTTP/1.1 connection, so
  parallel parts are parallel TCP streams, and a finished part's connection
  carries the next part instead of a new TLS handshake.
- **Tail.** Once every range of a download has started, a connection with
  nothing left to fetch takes the second half of what the range in flight
  with the most left has not fetched yet, while each half is at least 4
  MiB. The end of a download is shared by every connection instead of
  waiting on the last few, however slow they are.
- **Retries.** Each part is tried 8 times with backoff up to a minute; a
  part that moves no bytes for 90 seconds is cancelled and retried. A
  download range is retried from the first byte it lacks, an upload part
  whole. Part URLs come 100 per API call and are presigned again when
  storage refuses them.
- **Resume.** With `EncryptOptions.ResumeDir` set, a large send keeps its
  ciphertext in `<ResumeDir>/<revision id>/` until the upload finishes. A
  failed or cancelled upload returns an `*UploadInterruptedError`;
  `ResumeUpload` finishes it later, keeping the parts storage holds.
  `ListPendingUploads` and `DiscardPendingUpload` manage them.
- **Download resume.** With `DecryptOptions.ResumeDir` set, a large
  download keeps its ciphertext in `<ResumeDir>/<revision id>/`, with a
  record of the byte ranges it holds that is written only after they are
  synced to disk. A failed or cancelled download returns a
  `*DownloadInterruptedError`, and the next decrypt of that revision
  fetches only the missing ranges. Kept bytes get no more trust than fresh
  ones: the decrypt verifies the signed manifest first, still asks the
  server for the download URL (where the secret's policies apply and the
  download is recorded), and checks the whole ciphertext against the
  signed digest before releasing any plaintext. The folder stays until the
  payload is decrypted, and goes after a week unused.
  `ListPendingDownloads` and `DiscardPendingDownload` manage them.
- **Sessions.** A client authenticated with a `bearer:` session token
  renews it while in use: once an eighth of its lifetime has passed, and
  shortly before it expires whatever its age. A session in use lasts until
  the server's limit, seven days from login, and one left unused ends with
  its token, after an hour.
  The server revokes the old token, so set a `SessionStore` to save each
  new one.

```go
client.SetSessionStore(sdk.SessionStore{Load: loadToken, Save: saveToken})

_, err := client.EncryptFile(to, "backup.tar", sdk.EncryptOptions{ResumeDir: dir})
var interrupted *sdk.UploadInterruptedError
if errors.As(err, &interrupted) {
    _, err = client.ResumeUpload(dir, interrupted.Upload.RevisionID, sdk.ResumeOptions{})
}

_, _, err = client.DecryptToDir(secretID, "./out", sdk.DecryptOptions{ResumeDir: downloads}, sdk.WriteOptions{})
var stopped *sdk.DownloadInterruptedError
if errors.As(err, &stopped) {
    // The same call later fetches only what stopped.Download lacks.
}
```

## Recipient Keys

The server lists everyone's public keys. A key bundle is used only when it
carries its fingerprint and both self-signatures (Ed25519 and ML-DSA-65),
the fingerprint is the hash of its keys, and both signatures verify. That
proves the bundle is whole, not whose it is, so the SDK also checks who it
belongs to:

- **Your own keys.** Any account this device registers a key for
  (`SyncIdentity`), and the one it first sends from on a server, is
  recorded as yours, so what the server later says about who you are cannot
  change it. For one of your accounts only key pairs on this device pass: a
  send to it must use one, and a secret from it must be signed by one. If
  the server says you are someone this device knows as another person, the
  send or registration is refused. A secret signed by a key on this device
  is yours.
- **Everyone else's: trust on first use.** The first send to someone, or
  the first secret from them, accepts their key and reports it
  (`EncryptResult.FirstUse`, `DecryptResult.SenderFirstUse`) so you can
  compare fingerprints with them. The key is recorded once that send or
  decrypt succeeds. After that, a send to them or a secret from them under
  any other key is refused with a `*KeyChangedError`, before anything is
  sealed or downloaded.
- **A changed key.** Once the new key is confirmed with its owner,
  `AcceptKey(email, fingerprint)` accepts it, and `VerifyKey` records a key
  you compared. Both take the full fingerprint of a key the server lists
  for them, and both replace their other keys: sends go to the accepted key
  alone, while a replaced key still checks the secrets it signed until
  `ForgetKey` drops it. A send to a replaced key is refused
  (`KeyChangedError.Replaced`) until it is accepted again. `KnownKeys`
  lists what this device knows, your own accounts included.

Known keys are kept per API server in `~/.deepsecret/known_keys.json`
(mode 0600; `SetKnownKeysFile` moves it). A damaged file refuses sends
rather than accepting any key again.

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

## Versions

Releases follow [semantic versioning](https://semver.org). A release is an
annotated `vMAJOR.MINOR.PATCH` git tag, which is how Go finds module
versions:

```bash
go get github.com/deepsecret-io/sdk@v0.3.0
```

While the major version is 0 the API can still change: a breaking change
bumps the minor version, anything else the patch version. From v1.0.0 a
breaking change bumps the major version, and from v2 the module path ends
in it (`github.com/deepsecret-io/sdk/v2`).

To release, from a clean, pushed `main`:

```bash
task release VERSION=v0.3.1
```

It refuses a version that is not vMAJOR.MINOR.PATCH or not newer than the
last release, a tree with uncommitted or untracked files, a commit that is
not on `origin/main`, and a version already published. Then it runs vet,
the tests and `task security`, tags the commit and pushes the tag. A pushed
tag is permanent: the Go module mirror keeps it even if it is deleted.

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
