# DeepSecret Go SDK

End-to-end encrypted secrets management with hybrid post-quantum cryptography.

**Versions:** [semantic](#versions), one git tag per release
**Protocol:** v4: one payload per revision (AES-256-GCM, 1 MiB chunks), a content-key wrap per recipient (HPKE X25519-ML-KEM-768 + HKDF-SHA256 + AES-256-GCM), and a manifest signed with Ed25519 + ML-DSA-65. See [PROTOCOL_V4.md](PROTOCOL_V4.md).
**Payload:** CBOR (RFC 8949, canonical encoding)
**Compression:** Zstandard only
**Go:** 1.26+

## Architecture

```
deepsecret-go/       ← package deepsecret: the client and its setup
├── identity/        ← account, org, groups, keys registered on the server (client.Identity)
├── secrets/         ← send, receive, local files, list, revoke, policy, resume, storage (client.Secrets)
├── trust/           ← the keys this device knows: list, accept, verify, forget (client.Trust)
├── keys/            ← key pairs, fingerprints, safety numbers; no file access
├── keystore/        ← key files, protection, security key slots, recovery codes
├── fido2/           ← security keys, through libfido2
├── apierror/        ← API errors
├── transfer/        ← a transfer's state, phases and limits
├── internal/        ← protocol, transport, known keys, payload, archive and compression
└── examples/
```

Build on the `deepsecret` client. A send and a decrypt through it check every key against the ones this device knows and refuse a rollback, which the protocol underneath cannot do on its own, so the protocol is internal. To port the SDK to another language, follow [PROTOCOL_V4.md](PROTOCOL_V4.md).

Every call that can block takes a `context.Context` first and ends when it does.

## Quick Start

```go
import (
    deepsecret "github.com/deepsecret-io/deepsecret-go"
    "github.com/deepsecret-io/deepsecret-go/secrets"
)

client, err := deepsecret.NewClient("https://api.deepsecret.io", "ds_your_api_key")
if err != nil {
    log.Fatal(err)
}

// Encrypt a message once for two recipients (you are a recipient only if listed)
res, _ := client.Secrets.EncryptText(ctx, []string{"alice@example.com", "bob@example.com"}, "sensitive data", secrets.EncryptOptions{})

// Decrypt, as one of the recipients
result, _ := client.Secrets.Decrypt(ctx, res.Secret.ID, secrets.DecryptOptions{})
fmt.Println(result.Decrypted.Message)

// Revoke one recipient
client.Secrets.RevokeRecipient(ctx, res.Secret.ID, "bob@example.com")
```

## Encrypt Options

```go
secrets.EncryptOptions{
    Name:       "report-q4",
    Compress:   secrets.CompressZstd,  // zstd or none
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

- **Send.** `EncryptPaths` reads
  each file once, encode, compress and seal it chunk by chunk into a private
  temporary file holding only ciphertext, then upload from that file.
- **Receive.** `Secrets.Open` downloads the ciphertext into a temporary file.
  `WriteFiles` (or `DecryptToDir`) checks it against the signed manifest,
  decrypts it once to check every file name, size and SHA-256 and an archive's
  entries, then decrypts it again to write. A payload that fails a check
  writes nothing.
- **Disk.** Both sides need free space for the encrypted payload: set
  `TempDir` in the options or `DEEPSECRET_TMPDIR`, else the system temp
  directory is used. A send checks before it reads anything.
- **In memory.** `EncryptText`, `EncryptData` and `EncryptBytes`, and
  `Decrypt` for payloads up to 256 MiB.

```go
// Write a files secret of any size to disk
result, written, err := client.Secrets.DecryptToDir(ctx, secretID, "./out", secrets.DecryptOptions{}, secrets.WriteOptions{})

// Or open first, then choose where it goes
opened, err := client.Secrets.Open(ctx, secretID, secrets.DecryptOptions{})
defer opened.Close()
if opened.Result.PayloadType == "files" {
    written, err = opened.WriteFiles(ctx, "./out", secrets.WriteOptions{Overwrite: false})
} else {
    decrypted, err := opened.Payload(ctx) // a message or key-value data
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
  to one and tries again five minutes later. The `upload.threads` and
  `download.threads` logs say each change and why a count holds (see
  [Logging](#logging)). `UploadThreads` and `DownloadThreads` fix the
  number instead.
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
client, err := deepsecret.NewClient(url, "bearer:"+token,
    deepsecret.WithSessionStore(deepsecret.SessionStore{Load: loadToken, Save: saveToken}))

_, err = client.Secrets.EncryptPaths(ctx, to, []string{"backup.tar"}, secrets.EncryptOptions{ResumeDir: dir})
var interrupted *secrets.UploadInterruptedError
if errors.As(err, &interrupted) {
    _, err = client.Secrets.ResumeUpload(ctx, dir, interrupted.Upload.RevisionID, secrets.ResumeOptions{})
}

_, _, err = client.Secrets.DecryptToDir(ctx, secretID, "./out", secrets.DecryptOptions{ResumeDir: downloads}, secrets.WriteOptions{})
var stopped *secrets.DownloadInterruptedError
if errors.As(err, &stopped) {
    // The same call later fetches only what stopped.Download lacks.
}
```

## Logging

`EncryptOptions`, `DecryptOptions` and `ResumeOptions` take a `Logger
*slog.Logger`; nil logs nothing. Every record names its subsystem in the
`module` field (`deepsecret.LogModuleKey`): `encrypt`, `recipient`, `secret`,
`upload`, `download`, `verify` and others. A nested module carries the
field once per level, which a handler joins with a dot, as hclog's named
loggers do (`upload.threads`). The message names the event in a few words
and holds no values; the values are fields, with sizes and rates in binary
units in text and exact numbers in JSON, and durations as `time.Duration`.

- `deepsecret.LevelTrace`, below debug: each part, range and request.
- Debug: plans and decisions, such as `upload: plan`,
  `upload.threads: increasing` with its reason, and what each check
  verified.
- Info: milestones, such as `secret created`, `upload complete` and
  `payload decrypted`.
- Warn: what a flow recovers from, such as `retrying request`.

Logs never hold plaintext, keys, passwords, tokens or presigned URLs.

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: deepsecret.LevelTrace}))
_, err := client.Secrets.EncryptPaths(ctx, to, []string{"backup.tar"}, secrets.EncryptOptions{Logger: logger})
```

## Recipient Keys

The server lists everyone's public keys. A key bundle is used only when it
carries its fingerprint and both self-signatures (Ed25519 and ML-DSA-65),
the fingerprint is the hash of its keys, and both signatures verify. That
proves the bundle is whole, not whose it is, so the SDK also checks who it
belongs to:

- **Your own keys.** Any account this device registers a key for
  (`Identity.Sync`), and the one it first sends from on a server, is
  recorded as yours, so what the server later says about who you are cannot
  change it. For one of your accounts only key pairs on this device pass: a
  send to it must use one, and a secret from it must be signed by one. If
  the server says you are someone this device knows as another person (by a
  key that is not on this device, or one recorded for another of your
  accounts), the send or registration is refused, as is one that would
  record a key of one of your accounts for another: a key belongs to one
  account. An account this device knows only by other key pairs on it, as
  when one of your accounts sent to another before this device knew both
  were yours, is recorded as yours when the server says you are it, on a
  send or a key registration. That trusts how this device first learned those keys: a
  server that listed one of them for a contact then could get that contact
  recorded as yours, after which sends to them are refused until you forget
  it.
- **Secrets signed by your own keys.** The server names a secret's sender,
  so your key must not make your own secret pass as someone else's. A key
  recorded for one of your accounts passes for no other, even once it has
  left this device: a key belongs to one account. Any other key on this
  device passes for one of your accounts, or for someone this device knows by
  that very key. For someone this device knows by another key it is refused
  with a `*KeyChangedError`, and for someone it does not know it is refused
  as a possible relabelling. One limit remains: a key pair here that is
  recorded for none of your accounts, and that this device knows for someone
  else, passes as theirs. This device cannot tell a server that listed such a
  key for a contact on first contact from another of your accounts it does
  not know is yours yet, and refusing it would refuse that account's secrets
  too. A key is recorded once it is registered, or signs a send, from an
  account recorded here, so this takes a key that only signed elsewhere or
  for an account not recorded. What can go wrong is who your own secret
  appears to come from: the server gains no plaintext and chooses no content.
- **Everyone else's: trust on first use.** The first send to someone, or
  the first secret from them, accepts their key and reports it
  (`EncryptResult.FirstUse`, `DecryptResult.SenderFirstUse`) so you can
  compare fingerprints with them. The key is recorded once that send or
  decrypt succeeds. After that, a send to them or a secret from them under
  any other key is refused with a `*KeyChangedError`, before anything is
  sealed or downloaded.
- **A changed key.** Once the new key is confirmed with its owner,
  `Trust.Accept(ctx, email, fingerprint)` accepts it, and `Trust.Verify` records a key
  you compared. Both take the full fingerprint of a key the server lists
  for them, and both replace their other keys: sends go to the accepted key
  alone, while a replaced key still checks the secrets it signed until
  `Trust.Forget` drops it. A send to a replaced key is refused
  (`KeyChangedError.Replaced`) until it is accepted again. `Trust.List`
  lists what this device knows, your own accounts included.

- **Which secret, which version.** Every revision's manifest signs the
  name of the secret it belongs to, and a decrypt refuses a revision
  signed for another secret than the one opened. The server names the
  secret too, so `DecryptResult.SecretName` and `SignedAt` carry what the
  sender signed: show them, or compare the name with the secret you meant
  to open. Opening a secret's latest revision also refuses one signed
  before a revision of that secret this device already opened, with a
  `*StaleRevisionError` (a possible rollback by the server). Setting
  `DecryptOptions.Revision` opens an older revision on purpose.

Known keys, and the newest signing time opened per secret, are kept per
API server in `~/.deepsecret/known_keys.json` (mode 0600;
`WithKnownKeysFile` moves it). A damaged file refuses sends rather than
accepting any key again.

## Packages

### `identity`: `client.Identity`

| Name | Description |
|---|---|
| `WhoAmI`, `ResolveActorID` | The caller's account |
| `ListKeys`, `Sync`, `SetPrimaryKey`, `DeleteKey`, `SetKeySecurityKey` | Keys registered on the server |
| `LoadPrimary(ctx, unlock)`, `PrimaryFingerprint` | The primary key pair on this device |
| `ListGroups` | An org's groups and their members |

### `secrets`: `client.Secrets`

| Name | Description |
|---|---|
| `EncryptText`, `EncryptData`, `EncryptBytes`, `EncryptPaths` | Send |
| `Decrypt`, `DecryptToDir`, `Open`, `OpenLocalFile` | Receive |
| `ListSent`, `ListReceived`, `Describe`, `DescribeFull`, `ListRevisions` | Read what exists |
| `Delete`, `RevokeRecipient`, `UpdatePolicy` | Change it |
| `ResumeUpload`, `DiscardPendingUpload`, `ListPendingUploads`, `ListPendingDownloads`, `DiscardPendingDownload` | Interrupted transfers |
| `ListStorages` | An org's storages |

### `trust`: `client.Trust`

| Name | Description |
|---|---|
| `List`, `Accept`, `Verify`, `Forget` | The keys this device knows |
| `ServerListedKeys` | What the server lists for someone: only its claim, to compare and never to decide whom to trust |
| `KeyChangedError`, `StaleRevisionError` | What a send or a decrypt refuses with |

### `keys` and `keystore`: Keys

| Function | Description |
|---|---|
| `keys.Generate()` | Generate Ed25519 + ML-DSA-65 + X25519 + ML-KEM-768 key pair |
| `keys.Fingerprint(kp)` | Full SHA-256 hex fingerprint (64 chars) |
| `keys.SafetyNumber`, `keys.PairSafetyNumber` | A fingerprint as digits to compare aloud |
| `keystore.Save` / `keystore.Load` | Password-protected key storage |
| `keystore.ReadInfo` | How a key file is protected, and its slots, without unlocking it |
| `keystore.Open` | Unlock any key file: password, security key or recovery code |
| `keystore.Edit` / `keystore.NewSecurityKeyFile` | Protect a key pair with security keys, add or remove them, set a recovery code |

### `fido2`: Security Keys

| Function | Description |
|---|---|
| `New(prompter)` | A `keystore.Authenticator` for YubiKeys and other FIDO2 keys, through libfido2 loaded at run time |
| `Check()` | Whether libfido2 is installed, and which security keys are connected |

Builds with `-tags nofido2`, and builds for Windows, have no security key support.

### `apierror` and `transfer`

| Name | Description |
|---|---|
| `apierror.Error`, `apierror.ErrNotFound`, `apierror.ErrForbidden`, ... | What the server answered; branch with `errors.Is` |
| `apierror.IsMaintenanceError`, `apierror.MaintenanceMessage` | The API is under maintenance |
| `transfer.Snapshot`, `transfer.ConnectionStatus` | A transfer's state, from `secrets.TransferStatus.Snapshot` |
| `transfer.Phase` | The phases `OnPhase` reports |

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
go get github.com/deepsecret-io/deepsecret-go@v0.4.0
```

While the major version is 0 the API can still change: a breaking change
bumps the minor version, anything else the patch version. From v1.0.0 a
breaking change bumps the major version, and from v2 the module path ends
in it (`github.com/deepsecret-io/deepsecret-go/v2`).

To release, from a clean, pushed `main`:

```bash
task release VERSION=v0.4.0
```

It refuses a version that is not vMAJOR.MINOR.PATCH or not newer than the
last release, a tree with uncommitted or untracked files, a commit that is
not on `origin/main`, and a version already published. Then it runs vet,
the tests and `task security`, tags the commit and pushes the tag. A pushed
tag is permanent: the Go module mirror keeps it even if it is deleted.

## Cross-Language Porting

The SDK is designed for portability:

- **Specification**: [PROTOCOL_V4.md](PROTOCOL_V4.md)
- **Wire format**: CBOR (RFC 8949) with canonical encoding, deterministic across languages
- **Compression**: Zstandard (RFC 8878), implementations in every language
- **Encryption**: HPKE (RFC 9180) with X25519-ML-KEM-768 (Go stdlib `crypto/hpke`) for wraps, AES-256-GCM in 1 MiB chunks for payloads
- **Signing**: Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204), both required
- **Test vectors**: `internal/protocol/v4_vector_test.go` pins every deterministic v4 value
- **Archive paths**: strict portable format (forward-slash, no traversal, validated)

Key porting targets: TypeScript/Node.js, Python, Rust, Swift, Kotlin
