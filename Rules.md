# DeepSecret SDK Rules

## Purpose
The SDK is the single source of truth for all core functionality:
- Encryption / decryption
- Payload encoding (CBOR)
- Archive + compression pipelines
- Identity + key handling
- API communication
- Protocol correctness (HPKE, signatures, integrity)

The SDK must be usable standalone without the CLI.

---

## Architecture Rules

1. SDK owns ALL core logic
- No business logic should exist outside SDK
- CLI, UI, or other clients must not reimplement SDK logic

2. Layering inside SDK
- sdk/client.go → public entrypoint only
- sdk/api → HTTP transport layer
- sdk/crypto → cryptographic primitives
- sdk/payload → CBOR encoding/decoding
- sdk/archive → file expansion + tar
- sdk/compress → compression primitives
- sdk/secrets → secret workflows
- sdk/identity → identity/key workflows

3. No cross-layer leakage
- crypto must not depend on api
- payload must not depend on api
- archive/compress must not depend on api
- only top-level SDK layers orchestrate across packages

---

## API Boundary

4. Do NOT expose raw API unless necessary
- Avoid exposing low-level transport (e.g. Client.API())
- All operations must go through typed SDK methods

5. SDK methods must be high-level
Examples:
- EncryptText
- EncryptFiles
- DecryptSecret
- DescribeSecretFull
- UpdatePolicy

Never expose raw endpoint logic to callers.

---

## Payload & Encoding

6. SDK exclusively owns serialization
- CBOR is the only wire format
- Canonical CBOR must be enforced
- No JSON for encrypted payloads

7. Payload structure must be stable
- Versioned (v2)
- Backward compatible
- Explicit typing (message, files, data)

---

## Crypto Rules

8. Crypto is fully encapsulated
- Use HPKE (RFC 9180)
- Hybrid KEM: ML-KEM-768 + X25519
- AEAD: AES-256-GCM
- KDF: HKDF-SHA256
- Signatures: Ed25519

9. No partial implementations
- Encryption must always include:
  - authenticated encryption
  - signature verification
  - AAD binding

10. Forward secrecy
- Always use ephemeral sender keys
- Never reuse encryption context

---

## File & Archive Handling

11. SDK owns archive pipeline
- Directory expansion
- Tar creation
- Compression (zstd)

12. Metadata handling
- Default: metadata visible (names, sizes)
- Archive mode: hides metadata completely

---

## Memory & Streaming

13. Current constraint (v2)
- Encryption requires full plaintext in memory
- Streaming only applies to:
  - archive creation
  - upload/download

14. Do NOT fake streaming encryption
- No partial AEAD hacks
- No chunking unless protocol v3 is introduced

---

## Errors & Validation

15. Fail early and explicitly
- Invalid TTL → reject
- Invalid keys → reject
- Fingerprint mismatch → reject

16. No silent fallbacks
- No "best effort" crypto
- No skipping verification

---

## SDK Output Types

17. Always return structured results
- EncryptResult
- DecryptResult
- SecretInfo / DescribeSecretFull

18. Never return raw blobs unless explicitly requested

---

## Stability

19. SDK is a contract
- Changes must be backward compatible
- Version bump required for breaking changes

20. CLI must never compensate for SDK limitations
- Fix belongs in SDK, not CLI
