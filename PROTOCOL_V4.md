# DeepSecret protocol v4: one payload, many recipients

**Status: approved and implemented, 2026-10-25.** This implements §5 of the approved design (`api/docs/design/2026-10-25-tiers-trial-multi-recipient.md`). v4 replaces v3 completely: no v3 envelope is read or written, and the API deletes v3 secrets when it migrates.

- **Cryptography:** §2 to §6 in `sdk/crypto` (`stream.go`, `wrap.go`, `manifest.go`, `seal.go`, `protocol.go`), with the test vectors in §10.
- **SDK and CLI:** one send path for any number of recipients, decrypt through the manifest and the caller's wrap, and revocation.
- **API:** the contract in `api/docs/design/2026-10-25-protocol-v4-secrets-api.md` (§7).

## 1. What changes and what does not

| | v3 (before) | v4 |
|---|---|---|
| Payload per send | One HPKE-sealed copy per recipient | One copy, encrypted once |
| Content key | HPKE's own key, one per recipient | A random content key per revision, wrapped for each recipient |
| Payload encryption | One AES-256-GCM operation over the whole plaintext, in memory | AES-256-GCM in 1 MiB chunks, streamed |
| Sender signature | Over each recipient's envelope | Over one manifest covering the payload and every recipient |

**Unchanged:**
- **Primitives:** RFC 9180 HPKE in base mode (KEM X25519-ML-KEM-768, KDF HKDF-SHA256, AEAD AES-256-GCM), Ed25519 plus ML-DSA-65 signatures (both required), and SHA-256.
- **Encodings:** canonical CBOR, and length-prefixed field hashing (`writeField`).
- **Identity:** the sender's key bundle embedded and bound by fingerprint, and identity keys and fingerprints as today.
- **Payload contents:** the archive and compression pipeline (zstd, tar).

No new library is needed.

## 2. Keys

1. **Content key `K`:** 32 random bytes from the OS CSPRNG, generated for one revision and never reused.
2. **Payload key:** `PK = HKDF-SHA256(ikm = K, salt = empty, info = "deepsecret/v4/payload", L = 32)`. `K` itself never touches the payload; only `PK` does. This keeps the wrapped secret separate from the AEAD key.

## 3. Payload stream

The plaintext (compressed and archived exactly as in v3) is split into chunks of `C = 1 MiB`. The last chunk may be shorter, and an empty payload is a single empty last chunk. Chunk `i`, counting from 0, is sealed as:

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
| `sender_fp`, `sender_ed25519`, `sender_x25519`, `sender_mlkem`, `sender_mldsa65` | The sender's fingerprint and full public key bundle, as in v3 |
| `payload_type`, `compressed`, `compression` | As in v3 |
| `chunk_size` | `C` |
| `plaintext_size`, `ciphertext_size` | Sizes in bytes |
| `payload_digest` | §3 |
| `timestamp` | Unix seconds |
| `recipients` | Every wrap's `(recipient_fp, wrap_digest)`, sorted by `recipient_fp` |
| `sig`, `sig_mldsa65` | Ed25519 and ML-DSA-65 signatures over `SignableBytes` |

- **`SignableBytes`** is SHA-256 over every field above except the two signatures, in table order, each written with `writeField`. Strings are UTF-8 and booleans one byte. The integers `chunk_size`, `plaintext_size`, `ciphertext_size` and `timestamp` are 8 bytes big-endian. `recipients` is a 4-byte big-endian count, then each pair's `recipient_fp` and `wrap_digest` as two fields.
- **Limits.** 1 to 1000 recipients, sorted by fingerprint with no duplicates. A serialized manifest is at most 1 MiB; readers refuse anything larger before parsing. A wrap's `enc` is exactly 1120 bytes and its `ct` 48. `ciphertext_size` must equal `plaintext_size` plus 16 bytes per chunk, counting an empty payload as one chunk.
- **What the signature proves.** Every recipient holds `K` and could encrypt different content under it, so the AEAD alone cannot show who wrote the payload. The signature binds the payload digest to the sender's identity key. Covering the recipient list stops anyone adding, removing or swapping a recipient unnoticed.
- **Who sees the recipient list.** Every recipient sees the full list of recipient fingerprints. This was approved as an accepted trade-off on 2026-10-25.

## 6. Opening a revision

A recipient MUST perform these steps in order and stop at the first failure:

1. Fetch the manifest and their own wrap.
2. Recompute `sender_fp` from the embedded bundle, then verify both signatures with the embedded keys, as in v3. Trust decisions about the sender (primary key, fingerprint status) are unchanged.
3. Check that `revision_id` is the revision requested, that their own fingerprint appears in `recipients`, and that their wrap's digest matches the listed one. The structural checks of §5 (limits, sorting, sizes) come before the signatures.
4. Open the wrap with HPKE using the `info` from §4, which yields `K`. Derive `PK`.
5. Download the payload. Check `ciphertext_size`, and check SHA-256 against `payload_digest`, **before releasing any plaintext**. Clients buffer to memory or to a private temporary file for this.
6. Decrypt the chunks in order. Require the last-chunk flag on the final chunk only, and accept no bytes after it.
7. Decompress and extract as in v3.

## 7. What the server stores and checks

This section is informative; the API contract is `api/docs/design/2026-10-25-protocol-v4-secrets-api.md`.

- **One payload object per revision** in storage, counted once against quotas.
- **The manifest** on the revision row, and **each wrap** in its own row (`revision_wraps`). The API returns a recipient only their own wrap.
- **When a revision is sent, the API checks** that the manifest parses and is version 4, that its `revision_id`, `ciphertext_size`, `payload_digest`, `sender_fp` and `payload_type` match the request, and that it lists exactly the request's recipients, each at their current primary key and with the digest of the wrap sent for them. It verifies no signature: recipients do.
- **At upload confirmation** it checks the stored object's size, and access becomes the revision's wrap holders.
- **Revoking a recipient** deletes their access row and wraps. A revision nobody with access can open, and a secret with no recipients left, are deleted under the hard-delete policy.

## 8. Security properties

- **Confidentiality** against everyone except the listed recipients, with hybrid post-quantum protection, as in v3.
- **Sender authenticity and payload integrity** for every recipient, through both signatures over the manifest.
- **Integrity of the stream:** no reordering, dropping, truncation or appending of chunks.
- **Unchanged from v3:**
  - A recipient can re-share plaintext they decrypted.
  - Compromising a recipient's long-term private key exposes the content keys of the wraps made for it.
  - Revocation is enforced by the server, not by cryptography.

## 9. Changes to `sdk/Rules.md` (made)

- **Rule 8:** add "Signatures: Ed25519 and ML-DSA-65" and "Payload: AES-256-GCM STREAM, 1 MiB chunks, key derived with HKDF".
- **Rule 9:** add "payload digest verified against the signed manifest before plaintext is released".
- **Rule 10:** add "a fresh content key per revision, and a fresh HPKE context per wrap".
- **Rules 13 and 14:** replace them with "Encryption and decryption stream in 1 MiB chunks (protocol v4). Plaintext is released only after the payload digest is verified."
- **`crypto/doc.go`:** describes v4.

## 10. Test vectors

`sdk/crypto/v4_vector_test.go` pins the deterministic values of v4: the payload key, the chunk associated data, two nonces, one sealed chunk, the payload digest, the wrap info, a wrap digest and a manifest's `SignableBytes`, all from fixed inputs. They were reproduced independently in Python (`hashlib`, and `cryptography` for HKDF and AES-GCM) from this text. Another SDK must reproduce every one of them. HPKE and the signatures are randomized, so the round-trip and tamper tests in `seal_test.go` cover them.
