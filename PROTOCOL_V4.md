# DeepSecret protocol v4: one payload, many recipients

**Status: implemented.** This is how DeepSecret encrypts a secret for its recipients. v4 replaces v3 completely: no v3 envelope is read or written.

- **Cryptography:** §2 to §6 in `internal/protocol/` (`stream.go`, `wrap.go`, `manifest.go`, `seal.go`, `protocol.go`), with the test vectors in §10.
- **SDK and CLI:** one send path for any number of recipients, decrypt through the manifest and the caller's wrap, and revocation.
- **Server:** what it stores and checks is in §7.

## 1. Overview

v4 encrypts one payload once and wraps its content key for each recipient. v3, the format before it, sealed a separate copy for each recipient:

| | v3 (before) | v4 |
|---|---|---|
| Payload per send | One HPKE-sealed copy per recipient | One copy, encrypted once |
| Content key | HPKE's own key, one per recipient | A random content key per revision, wrapped for each recipient |
| Payload encryption | One AES-256-GCM operation over the whole plaintext, in memory | AES-256-GCM in 1 MiB chunks, streamed |
| Sender signature | Over each recipient's envelope | Over one manifest covering the payload and every recipient |

**Building blocks:**
- **Primitives:** RFC 9180 HPKE in base mode (KEM X25519-ML-KEM-768, KDF HKDF-SHA256, AEAD AES-256-GCM), Ed25519 plus ML-DSA-65 signatures (both required), and SHA-256.
- **Encodings:** canonical CBOR, and length-prefixed field hashing. `writeField` hashes a field as its length in 4 bytes big-endian, then its bytes, and `fields(a, b, ...)` means `writeField` of each argument in order.
- **Identity:** an identity key is a bundle of four public keys: Ed25519, X25519, ML-KEM-768 and ML-DSA-65. Its fingerprint is the lower-case hex SHA-256 of the four raw keys concatenated in that order. A manifest embeds the sender's bundle and binds it by fingerprint.
- **Payload contents:** the archive and compression pipeline (zstd, tar).

## 2. Keys

1. **Content key `K`:** 32 random bytes from the OS CSPRNG, generated for one revision and never reused.
2. **Payload key:** `PK = HKDF-SHA256(ikm = K, salt = empty, info = "deepsecret/v4/payload", L = 32)`. `K` itself never touches the payload; only `PK` does. This keeps the wrapped secret separate from the AEAD key.

## 3. Payload stream

The plaintext (the payload after archiving and compression, §1) is split into chunks of `C = 1 MiB`. The last chunk may be shorter, and an empty payload is a single empty last chunk. Chunk `i`, counting from 0, is sealed as:

- `nonce_i = uint88_be(i) || flag`: 11 bytes of chunk counter, then 1 byte that is `0x01` for the last chunk and `0x00` otherwise.
- `aad = SHA-256(fields("deepsecret/v4/chunk", version, revision_id, payload_type, uint32_be(C)))`.
- `ct_i = AES-256-GCM-Seal(PK, nonce_i, plaintext_i, aad)`.

The stored payload object is `ct_0 || ct_1 || ... || ct_n`. Every chunk except the last is exactly `C + 16` bytes.

A counter-only nonce is safe because `PK` encrypts exactly one stream. The counter stops chunks being reordered or dropped, and the last-chunk flag stops truncation and appended data.

`payload_digest = SHA-256(stored payload object)`, computed while encrypting.

## 4. Per-recipient wraps

Each wrap is made after the payload is encrypted, once for each recipient `R`, and once for the sender when they keep a copy. A vault secret, where sender and recipient are the same, has a single wrap.

- `info = SHA-256(fields("deepsecret/v4/wrap", version, revision_id, sender_fp, R.fp, payload_digest))`
- `(enc, sender_ctx) = HPKE-SetupBaseS(R.public_key, info)`. This is a fresh ephemeral key for every wrap.
- `wrap_ct = sender_ctx.Seal(aad = empty, plaintext = K)`, which is 48 bytes.
- `wrap = { recipient_fp: R.fp, enc, ct: wrap_ct }`, about 1.2 KB. The API carries it as JSON `{enc, ct}` in base64, next to the recipient's fingerprint.
- `wrap_digest = SHA-256(fields(R.fp, enc, wrap_ct))`.

A wrap only opens to the key it was made for. `info` binds it to this sender, this recipient, this revision and these payload bytes, so it cannot be moved onto another revision or payload.

## 5. Manifest

The manifest is a canonical-CBOR map, signed by the sender:

| Field | Value |
|---|---|
| `version` | `"4"` |
| `cipher_suite` | `"DS4_HPKE_X25519MLKEM768_HKDFSHA256_AES256GCM_STREAM1M_ED25519_MLDSA65"` |
| `revision_id` | The revision UUID the API assigned before upload |
| `secret_name` | The name of the secret the revision belongs to, exactly as the API stores it. Every revision of a secret carries the same name |
| `sender_fp`, `sender_ed25519`, `sender_x25519`, `sender_mlkem`, `sender_mldsa65` | The sender's fingerprint and full public key bundle (§1) |
| `payload_type`, `compressed`, `compression` | `payload_type` is `"message"`, `"data"` or `"files"`. `compression` is `"zstd"` when `compressed` is true and empty when it is false |
| `chunk_size` | `C` |
| `plaintext_size`, `ciphertext_size` | Sizes in bytes |
| `payload_digest` | §3 |
| `timestamp` | Unix seconds, by the sender's clock when sealing |
| `recipients` | Every wrap's `(recipient_fp, wrap_digest)`, sorted by `recipient_fp` |
| `sig`, `sig_mldsa65` | Ed25519 and ML-DSA-65 signatures over `SignableBytes` |

- **`SignableBytes`** is SHA-256 over every field above except the two signatures, in table order, each written with `writeField`. Strings are UTF-8 and booleans one byte. The integers `chunk_size`, `plaintext_size`, `ciphertext_size` and `timestamp` are 8 bytes big-endian. `recipients` is a 4-byte big-endian count, then each pair's `recipient_fp` and `wrap_digest` as two fields.
- **Limits.** 1 to 1000 recipients, sorted by fingerprint with no duplicates. A serialized manifest is at most 1 MiB; readers refuse anything larger before parsing. A wrap's `enc` is exactly 1120 bytes and its `ct` 48. `ciphertext_size` must equal `plaintext_size` plus 16 bytes per chunk, counting an empty payload as one chunk. `secret_name` is 1 to 1024 bytes of UTF-8 with no leading or trailing white space (Unicode `White_Space`) and no control character (`Cc`), line or paragraph separator (`Zl`, `Zp`) or bidi formatting character (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069).
- **Manifests from before the signed name.** Version 4 manifests sealed before `secret_name` was added (2026-11-01) have no name. A sealer refuses an empty name, so a reader takes a manifest without one as outdated and refuses it with that reason (`secrets.ErrOutdatedManifest`), not as malformed: it cannot be opened, and its sender has to send the secret again.
- **What the signature proves.** Every recipient holds `K` and could encrypt different content under it, so the AEAD alone cannot show who wrote the payload. The signature binds the payload digest to the sender's identity key. Covering the recipient list stops anyone adding, removing or swapping a recipient unnoticed. Covering `secret_name` stops a revision passing as part of another secret.
- **Who sees the recipient list.** Every recipient sees the full list of recipient fingerprints. This is an accepted trade-off: verifying the signature needs the list.

## 6. Opening a revision

A recipient MUST perform these steps in order and stop at the first failure:

1. Fetch the manifest and their own wrap.
2. Recompute `sender_fp` from the embedded bundle, then verify both signatures with the embedded keys. Trust decisions about the sender (primary key, fingerprint status) are separate: the manifest shows which key signed, and the client decides whether it trusts that key.
3. Check that `revision_id` is the revision requested, that `secret_name` is the name of the secret requested, that their own fingerprint appears in `recipients`, and that their wrap's digest matches the listed one. The structural checks of §5 (limits, sorting, sizes, the name rule) come before the signatures.
4. Open the wrap with HPKE using the `info` from §4, which yields `K`. Derive `PK`.
5. Download the payload. Check `ciphertext_size`, and check SHA-256 against `payload_digest`, **before releasing any plaintext**. Clients buffer to memory or to a private temporary file for this.
6. Decrypt the chunks in order. Require the last-chunk flag on the final chunk only, and accept no bytes after it.
7. Decompress and extract the payload (§1).

**Which revision is the latest.** The server says which revision is a secret's latest and what the secret is called, so neither answer is trusted on its own:

- A client shows the signed `secret_name` and `timestamp` with what it opened, so a server that also lies about the name is visible.
- A client that opens a secret's latest revision keeps, per server, sender and `secret_name`, the newest `timestamp` it has opened, and refuses a latest revision signed earlier than that: the server may be rolling the secret back. It records the time only after step 5 passed, and never lowers it. Opening a revision requested by id is not refused, so an older revision stays reachable on purpose.

The sender is the authority for their own content, so ordering by the sender's signed clock adds no trust in anyone else.

## 7. What the server stores and checks

This section is informative. Confidentiality and authenticity do not depend on it: they come from §2 to §6, and each recipient checks them. The server never sees a content key, and it keeps the manifest and the wraps as opaque bytes.

- **A secret** is identified by its sender and name, and has a list of recipients. **A revision** is one payload with the sender's signed manifest.
- **One payload object per revision** in storage, counted once against quotas.
- **The manifest** is kept exactly as uploaded, and **each wrap** is kept for its recipient. The API returns a recipient only their own wrap.
- **When a revision is sent, the API checks** that the manifest parses and is version 4, that its `revision_id`, `secret_name`, `ciphertext_size`, `payload_digest`, `sender_fp` and `payload_type` match the request (`secret_name` against the request's name with surrounding white space removed, the name the secret is stored under), and that it lists exactly the request's recipients, each at their current primary key and with the digest of the wrap sent for them. It verifies no signature: recipients do.
- **At upload confirmation** it checks the stored object's size, and access becomes the revision's wrap holders. Anyone left out loses access, so a send that never finishes uploading grants and revokes nothing. Only the secret's latest revision decides.
- **Sending again under the same name** adds a revision to the secret. A send that leaves out current recipients is refused (409) unless it says `revoke_missing`.
- **Downloading a revision** needs access to the secret and a wrap for that revision. A recipient lists only the revisions they hold a wrap for. A sender who did not list themself as a recipient holds no wrap, so they cannot open what they sent.
- **Revoking a recipient** deletes their access and wraps. A revision nobody with access can open, and a secret with no recipients left, are deleted under the organization's deletion policy.
- **Recipients per send:** the server may allow fewer than the 1000 the protocol does.

On the wire, with `manifest`, `enc` and `ct` in base64:

- `POST /api/v1/orgs/:id/secrets` sends, with the send's other fields, `manifest` and `recipients`, each one `{recipient_id, recipient_org_id, key_fingerprint, wrap: {enc, ct}}`. `recipient_org_id` is optional.
- `GET /api/v1/secrets/revisions/:id/manifest` returns `{revision_id, manifest, wrap: {enc, ct}, key_fingerprint}`: the manifest and only the caller's own wrap.

## 8. Security properties

- **Confidentiality** against everyone except the listed recipients, with hybrid post-quantum protection.
- **Sender authenticity and payload integrity** for every recipient, through both signatures over the manifest.
- **Secret binding:** a revision opens only as the secret its sender named, so the server cannot present one secret's revision as another's. A client that keeps the newest signing time per secret (§6) also refuses a rollback to a revision older than one it has opened. A rollback before the client has seen the newer revision is not detectable, because only the server knows a revision exists.
- **Integrity of the stream:** no reordering, dropping, truncation or appending of chunks.
- **Not covered:**
  - A recipient can re-share plaintext they decrypted.
  - Compromising a recipient's long-term private key exposes the content keys of the wraps made for it.
  - Revocation is enforced by the server, not by cryptography.

## 9. Implementation rules

`Rules.md` holds the rules the SDK keeps to. Rule 8 lists these primitives, rules 9 and 10 require the checks and the fresh keys above, and rules 13 and 14 cover streaming and when plaintext is released. `internal/protocol/doc.go` summarizes v4 for the code.

## 10. Test vectors

`internal/protocol/v4_vector_test.go` pins the deterministic values of v4: the payload key, the chunk associated data, two nonces, one sealed chunk, the payload digest, the wrap info, a wrap digest and a manifest's `SignableBytes`, all from fixed inputs. They were reproduced independently in Python (`hashlib`, and `cryptography` for HKDF and AES-GCM) from this text. Another SDK must reproduce every one of them. HPKE and the signatures are randomized, so the round-trip and tamper tests in `seal_test.go` cover them.

## 11. Safety numbers

A safety number shows a key fingerprint as decimal digits, for two people to read to each other and compare, as Signal and WhatsApp do (numbers only). It is a display of the fingerprint: nothing in the protocol signs or sends it. `crypto/safety_number.go` is the Go implementation (`SafetyNumber`, `PairSafetyNumber`, `GroupDigits`); a client that cannot use the Go SDK, such as the web app, repeats it and must give the same digits for the vectors below.

- **Input:** a full identity key fingerprint (`keys.Fingerprint`): exactly 64 lower-case hex characters, the SHA-256 of the key bundle. Anything else is refused, upper-case hex included, since fingerprints are lower case everywhere. `fp32` is its 32 bytes.
- **One key:** `h = SHA-512("DeepSecret safety number v1" || 0x00 || fp32)`, then 5199 more times `h = SHA-512(h || fp32)`: 5200 hashes in all, so finding a key with a matching number costs that much per try. `h[0:30]` is read as six 5-byte big-endian unsigned integers, each taken mod 100000 and written as 5 digits with leading zeros. The 30 digits are the key's number.
- **Two keys** (you and a contact): both keys' numbers, the lexicographically smaller first, concatenated: 60 digits. Both people see the same number, whichever key is theirs. The same key twice is allowed.
- **Display:** groups of 5 digits. A pair's 12 groups are shown in 3 rows of 4; a key's own 6 groups (on key pages) in one or two rows. Clients keep the hex fingerprint available as a secondary value, so older clients and scripts can still compare.
- **Which keys:** with another person, a client pairs your primary key with the key it has for them. It takes your half from a key pair on the device whose fingerprint it computes from the key file, never from the server's listing alone: a server that lists a key of its own for you and for them would otherwise get matching numbers. The web app holds no key pair, so its number pairs the keys the server lists and cannot catch a dishonest server; compare on the CLI or the desktop app for that.

**Test vectors** (`keys/safety_number_test.go`, reproduced independently in Python with `hashlib`):

| Fingerprint | Safety number |
|---|---|
| `0000000000000000000000000000000000000000000000000000000000000000` | `22498 68061 77197 31533 19831 84070` |
| `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `16409 37532 34229 26549 62996 69170` |
| `f282d3c8021155ac8b7f96fa35d1b84959855c84aa64690049664a206c8837fa` | `13132 50275 56127 30861 31849 97296` |

The pair of the first two is `16409 37532 34229 26549 62996 69170 22498 68061 77197 31533 19831 84070`.
