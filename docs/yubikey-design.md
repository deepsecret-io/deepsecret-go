# Security key (YubiKey) protection for key files

Status: implemented 2026-11-02 in the SDK (`sdk/crypto`, `sdk/fido2`) and
the CLI. Graphical clients use the same SDK API. The hardware
test passes on a real YubiKey on macOS: see section 12.

## 1. Summary

A user can protect a DeepSecret key pair with a YubiKey or another FIDO2
security key. It is optional: password-protected and unprotected key files
work exactly as before, and nothing about security keys is loaded unless a
key pair uses one.

- **The private keys stay in the key file.** All four (Ed25519, ML-DSA-65,
  X25519, ML-KEM-768) stay in the file, encrypted. None moves onto the
  security key: no YubiKey can hold ML-KEM-768 or ML-DSA-65, so moving keys
  would drop the post-quantum half of every identity.
- **The security key unlocks the file.** It uses the FIDO2 `hmac-secret`
  extension, the primitive behind WebAuthn PRF. The device computes
  HMAC-SHA-256 with a per-credential secret that never leaves it, and only
  after its PIN and a touch. The output derives the key that unwraps the file
  key.
  - A copy of the file is useless without an enrolled security key and its
    PIN, or the recovery code.
  - There is nothing to guess offline.
  - The stored file stays post-quantum: everything stored is protected by
    symmetric primitives (HMAC-SHA-256, HKDF-SHA256, AES-256-GCM). One caveat
    about live unlocks is in section 3.
- **Only security-key files change format.** They are storage version 5,
  with envelope encryption: one random file key seals the private keys, and
  each slot wraps that file key under one way in (a security key or a
  recovery code). Password and unprotected files stay version 4,
  byte-for-byte.
- **libfido2 is loaded at run time, only when a security key is used.** It
  comes from the system (Homebrew or MacPorts on macOS, the distribution's
  package on Linux), through `github.com/ebitengine/purego`, with no cgo.
  The CLI keeps building with `CGO_ENABLED=0`.

## 2. What existed before

- **Location.** A key pair is `~/.deepsecret/keys/<fingerprint>.json`,
  storage version 4, shared by every DeepSecret client on the machine.
- **Private keys** were stored in one of two ways:
  - In clear. This is the CLI default: `secret identity generate` without
    `-p`.
  - Encrypted. Argon2id (128 MiB, 3 passes, 4 lanes) derives an AES-256-GCM
    key from the password, with an AAD that binds the storage version and
    the fingerprint.
- **Unlocking.** Each command unlocks the key and drops it when it ends.
  There is no agent, cache or keychain.
- **No change here.** All of this is unchanged. The version 4 loader is the
  same code with the same error texts, which callers match on. Argon2id was
  already in use before the SDK rules named HKDF-SHA256 as the KDF, and it
  stays in use for passwords.

## 3. Threat model

Assets:

- The four private keys.
- The file key, which gives the private keys.

| Attacker | Has | Password (version 4) | Security key (version 5) |
|---|---|---|---|
| Lost or stolen laptop, powered off | Copy of the key file | Offline Argon2id guessing against the password. No barrier at all for an unprotected key | Nothing to guess. The key-encryption key comes from a 256-bit secret inside the security key |
| Backup, cloud sync or Time Machine copy | Copy of the key file | Same as above | Same as above |
| Lost bag holding the laptop and the security key | File and device | Same as above | The device PIN is required: 8 wrong PINs and it blocks, and 3 in a row need a re-plug. This is why user verification is mandatory |
| Stolen security key alone | Device | Not relevant | Useless without the key file, which holds the credential ID and PRF input, and without the PIN |
| Malware running as the user | File, keystrokes, process memory, the ability to talk to the device | Reads the file and logs the password: full compromise | Can log the PIN. Can ask the device for an assertion and hope the user touches, or ride on a real unlock. Can read unlocked keys from memory during use. Cannot take away a file it can open later without the device and a touch |
| Malicious web page | Browser access to the device | Not relevant | Blocked. The relying party ID is a name no web origin can claim (section 4.6), and the PRF input exists only in the key file |
| Someone who can write the key file but has no keys | File write | Can delete or replace the file | A changed slot no longer opens (slot AAD). A slot copied in from another copy of the file breaks the private block (its AAD binds the whole slot list). Cost parameters are checked on read. Deleting the file or slots is denial of service only (hence the backup rule). A changed private key fails the check that each private key gives its public key |
| Someone holding an older copy of the file | Older copy | The old password opens it | The ways in that existed then open it. Nothing cryptographic can stop an older copy from opening with what opened it at the time: rotating the key pair is the answer (section 5.6) |
| Quantum adversary storing key files now | Copies of key files | Symmetric throughout: holds | Symmetric throughout: holds |
| Compromised DeepSecret server | Server data | Not relevant: keys never leave the device | Not relevant: nothing about security keys reaches the server |

What a security key does not do:

- **It does not stop malware already on the machine.** A security key turns
  "copy the file and guess" into "be present on the machine while the user
  touches the key". Only keys that never leave the token would go further,
  which this design rules out for the post-quantum reason above. Even then,
  malware could use the token while it is plugged in.
- **Removing a slot does not reach older copies of the file.** If a lost key
  and its PIN, or a seen recovery code, may be in an attacker's hands
  together with an older copy, rotate the key pair.
- **Losing every way in loses the key pair.** Secrets sent to it cannot be
  read, and senders must resend to a new key.
- **A live unlock is classical on the wire.** CTAP encrypts the salt and the
  output between host and device under a shared secret from ECDH P-256. Two
  consequences:
  - An attacker who records the USB traffic of an unlock and also has the key
    file could, with a future quantum computer, recover the output and so
    the private keys. Recording that traffic needs local access during an
    unlock, where process memory is a simpler target.
  - Stored files alone are not affected.
- **A whole other key pair is a different identity.** A file holding another,
  self-consistent key pair has another fingerprint. It is not the identity
  the server lists or a peer has pinned; the safety number tells them apart.

## 4. Design

### 4.1 Envelope and slots (version 5)

- **File key.** `FK` is 32 random bytes from `crypto/rand`, created when a
  key pair is first protected by a security key and kept when slots change.
- **Private block.** The four private keys, as canonical CBOR, sealed with
  AES-256-GCM under `FK`, with this AAD:

  ```
  "deepsecret/keystore/v5/private/" || fp || 0x00 || SHA-256(CBOR(slot list, wraps included))
  ```

- **Slots.** Each slot holds `FK` sealed with AES-256-GCM under that slot's
  key-encryption key (`KEK`), with a fresh random 96-bit nonce, and this AAD:

  ```
  "deepsecret/keystore/v5/slot/" || fp || 0x00 || CBOR(every slot field but the wrap)
  ```

- **Unlocking** opens one slot, then the private block, then checks that
  each private key gives its public key.
- **Why the file key is not rotated when a slot is removed.** Rotation
  protects nothing: an attacker who could use the removed slot needs an
  older copy of the file, and that copy opens on its own. Binding the slot
  list into the private block's AAD stops slots from being mixed between
  copies.

### 4.2 Key derivation

| Slot | Factor | `KEK` |
|---|---|---|
| `fido2` | Security key (PIN + touch) | `HKDF-SHA256(ikm = S, salt = empty, info = "deepsecret/keystore/v5/fido2/" \|\| fp \|\| "/" \|\| slot_id)` |
| `recovery_code` | Printed recovery code | `HKDF-SHA256(ikm = the code's 20 bytes, salt = salt16, info = "deepsecret/keystore/v5/recovery/" \|\| fp \|\| "/" \|\| slot_id)`. No Argon2: the code carries 160 random bits |

The security key output `S`:

- `S = HMAC-SHA-256(CredRandomWithUV, SHA-256("WebAuthn PRF" || 0x00 || prf_input))`.
- `prf_input` is 32 random bytes kept in the slot.
- The SDK hashes `prf_input` into the salt itself (`crypto.PRFSalt`). This is
  the salt that WebAuthn PRF, and Windows' webauthn.dll by default, give the
  device, so one credential gives one output on every platform.
- Both derivations are pinned by test vectors, checked against an
  independent HKDF implementation.

The recovery code:

- 20 random bytes, shown once as 32 Crockford base32 characters in 8 groups
  of 4.
- Entry ignores case, spaces and hyphens, and reads I and L as 1 and O as 0.
- Creating one asks for two groups chosen at random to be typed back.

### 4.3 Slot rules

| Mode | Storage | Ways in |
|---|---|---|
| `none` | version 4 | none: private keys in clear |
| `password` | version 4 | the password |
| `security_key` | version 5 | 1 to 4 security keys, and at most 1 recovery code |

- **Two ways in by default.** Writing a version 5 file needs two ways in (two
  security keys, or one plus a recovery code), unless the user explicitly
  accepts a single security key. This is checked only when a file is
  written. Reading never asks for it, so a file the user chose to keep with
  one key still opens.
- **No password slot in version 5.** A password beside a security key would
  bring back offline guessing: a copied file plus a guessed password would
  skip the security key. The recovery code is the fallback instead. It is
  never typed in normal use, so it is much less exposed.
- **Changes need an unlock first.** Every change to the slots needs an unlock
  first, even removing one.
- **Switching mode is one write.** Protecting a version 4 file writes a
  version 5 file. Removing security key protection writes a version 4 file
  under a new password, or unprotected.
- **Writes check before they replace.** Before the old file is replaced, the
  new bytes are read back: every slot added in this edit, and the private
  block, must open.
- **A file changed meanwhile is not overwritten.** The write is refused if
  the file on disk changed since it was read, for example by another client.

### 4.4 File format, version 5

```json
{
  "storage_version": 5,
  "ed25519_public": "<base64>",
  "x25519_public": "<base64>",
  "mlkem768_pk": "<base64>",
  "mldsa65_pk": "<base64>",
  "private": {"nonce": "<base64, 12 bytes>", "ciphertext": "<base64>"},
  "slots": [
    {
      "id": "3f9c1a7e2b4d6081",
      "type": "fido2",
      "label": "YubiKey 5C NFC (keyring)",
      "created_at": "2026-11-02T10:00:00Z",
      "fido2": {
        "rp_id": "deepsecret-keystore.invalid",
        "credential_id": "<base64>",
        "aaguid": "<32 hex or empty>",
        "prf_input": "<base64, 32 bytes>",
        "uv": true,
        "discoverable": false
      },
      "wrap": {"nonce": "<base64, 12 bytes>", "wrapped_key": "<base64, 48 bytes>"}
    },
    {
      "id": "a1b2c3d4e5f60718",
      "type": "recovery_code",
      "label": "Recovery code",
      "created_at": "2026-11-02T10:01:00Z",
      "recovery_code": {"salt": "<base64, 16 bytes>"},
      "wrap": {"nonce": "<base64, 12 bytes>", "wrapped_key": "<base64, 48 bytes>"}
    }
  ]
}
```

### 4.5 Checks on read (fail closed)

- Every key file is refused if an object repeats a field, in any mix of case.
  `encoding/json` matches names without regard to case and keeps the last
  value, so `"Storage_Version": 4` could otherwise steer a version 5 file to
  the version 4 reader.
- `storage_version` 4 goes to the unchanged version 4 reader. 5 goes to the
  strict reader. A higher version says the file "needs a newer version of
  DeepSecret", so nobody is told to regenerate a working key.
- Before protecting a version 4 file, the editor checks that its private keys
  give its public keys.
- The strict reader refuses:
  - unknown fields and data after the object;
  - any size outside: nonces 12 bytes, wrapped keys 48, salts 16, PRF inputs
    32, credential IDs 1 to 1023, labels 1 to 64 characters without control
    or layout characters;
  - a shape other than exactly a private block plus 1 to 4 security keys and
    at most 1 recovery code;
  - `uv` other than true, or an `rp_id` other than the constant;
  - public keys that do not hash to the file name.

### 4.6 FIDO2 parameters

- **Relying party ID: `deepsecret-keystore.invalid`.** The credential ID and
  PRF input are in the file in clear. Anyone who can claim the relying party
  ID can ask the device for the same output, with a touch and the PIN.
  - `.invalid` never resolves, and WebAuthn needs a secure origin, so no web
    page can claim the name.
  - With a real domain, a script injected into a page on that domain could.
- **User verification is always required:** the PIN, or a fingerprint on a
  key with a built-in reader. There are two reasons:
  - The lost-bag case.
  - CTAP 2.1 keeps one secret per credential for assertions with user
    verification and another without, and enrollment and unlock must use the
    same one.
- **Enrollment and unlock share one path.** Enrollment gets its output
  through exactly the assertion path unlock uses.
- **Credentials are not discoverable.** They use none of the device's limited
  credential storage, and a credential manager cannot delete them by mistake.
  credProtect level 2 is set when the device supports it.
- **Finding the right device.** Unlock asks each connected device, silently
  (no touch, no PIN), which enrolled credential it holds, then asks only that
  one for the PIN and a touch. A device that cannot be asked silently is used
  directly when it is the only device and the file has one credential.
- **Enrollment** needs exactly one device plugged in. A device already
  enrolled for the key pair is refused, so a key cannot be its own backup.
  It takes two touches: one to create the credential, one to derive.

## 5. Flows (CLI)

### 5.1 Protect a key pair

| Command | Does |
|---|---|
| `secret identity generate --security-key` (`--backup`, `--recovery-code` or `--single`) | Writes a new key pair straight to a version 5 file. It is never on disk unprotected |
| `secret identity security-key protect` (`--backup`, `--recovery-code` or `--single`) | Turns a password or unprotected key pair into a security-key one. Asks for the password first |

Without `--backup`, `--recovery-code` or `--single`, both refuse before any
touch, and explain the three choices.

`secret identity generate` registers every new key pair and makes it the
primary key, whatever protects it; `--local` keeps it on this device only.
The account is checked with a request (the registered keys are listed)
before any PIN or touch, so a missing or revoked login leaves nothing
behind, and a security-key key pair is registered from memory, with no
further touch. The desktop app's New key
pair dialog does the same (`GenerateRequest.Local`).

### 5.2 Unlock

`secret encrypt`, `secret decrypt` and `secret identity sync` find out the key
pair's mode without unlocking it, and ask only for what it needs:

- nothing for an unprotected key;
- the password, as before;
- nothing up front for a security key. The SDK asks for the PIN and a touch
  once, when the key is used.

When no enrolled security key is connected, the SDK asks to plug one in
(`Prompter.Insert`, naming the enrolled keys) and waits about 2 minutes
(checked between looks, so one slow device can add to it), looking every
half second with the silent check; Ctrl-C, or Cancel in the
desktop app, stops the wait. Enrolling waits the same way for a key to
enroll.

`--recovery-code` unlocks with the recovery code instead. Without a terminal,
a security-key key pair is refused before any device is contacted.

### 5.3 Manage the ways in

| Command | Does |
|---|---|
| `secret identity security-key add` | Unlock, swap in the new key, enroll it |
| `secret identity security-key list` | Lists the slots without unlocking |
| `secret identity security-key remove <slot-id>` | Removes a slot. Refused if it would leave one way in, unless `--single` |
| `secret identity security-key recovery-code` | Creates or replaces the recovery code |
| `secret identity security-key unprotect` | Back to a password (version 4), or `--no-password` |

Every command that unlocks accepts `--recovery-code`.

### 5.4 Diagnostics

`secret doctor` reports security key support (the libfido2 path, connected
devices, and the Linux udev hint) only when a key pair uses a security key.
Users without one see nothing new.

### 5.5 Messages

- **PIN prompts** show the attempts left, and a wrong PIN is asked for again
  up to three times.
- **The recovery code goes to the terminal only**, never to a redirected
  stderr. If saving fails after the code was shown, the command says the
  code was not saved and should be discarded.
- **A blocked PIN** comes with an explanation: a FIDO reset clears it, and
  erases every FIDO2 credential on the key.
- **When no enrolled key is connected**, the message names the enrolled keys
  by label.

### 5.6 A lost security key or a seen recovery code

1. Unlock with the backup key or the recovery code.
2. Remove the lost slot.
3. Add a replacement.
4. If an older copy of the file may be with the attacker, rotate the key
   pair: `secret identity generate --security-key`.

The remove command says this.

### 5.7 The security key label in key lists

Only the device holding a key file knows how it is protected, so the
server stores what the owner's client reports: one boolean per registered
key, `security_key`. It is not signed and decides nothing; it only labels
the owner's own key lists. Other users never get it: the lookup senders use
(`GET /api/v1/identities/actor/:email`) keeps its fields, and only the
owner's responses (`GET /api/v1/identities`, `GET /:id`, the response to
registering) carry it.

- Registering sends it (`SyncIdentity(kp, securityKey)`), from the key
  file on the registering device.
- `PUT /api/v1/identities/:id/security-key {"security_key": bool}` changes
  it, for the owner's keys only (another actor's key is not found), audited
  as a configuration change. The CLI's `security-key protect` and
  `unprotect`, and the desktop app's Protect and Unprotect, call it when the
  key is registered and the client is signed in; a failure leaves the local
  change in place and only says so.
- `secret identity sync` on a key already registered refreshes the label
  from the key file, without unlocking it.

Where a key file is on the device, the CLI and the desktop app show its own
protection; for a key elsewhere they show the label. Shown in: `secret
identity list` (and `--remote`), `identity show`, `whoami`, `doctor`, the
encrypt and decrypt summaries and `describe` (for the user's own keys), the
desktop Keys page, and the web app's Identities page.

## 6. One implementation

| Layer | Contents | cgo |
|---|---|---|
| `sdk/crypto` | Version 5 format, checks, slot rules, derivation, `ReadKeyFileInfo`, `UnlockKeyPair`, `EditKeyFile` / `NewSecurityKeyFile` (the slot editor), the `Authenticator` interface, typed errors | No |
| `sdk` client | `EncryptOptions` and `DecryptOptions` gain `SecurityKey` and `RecoveryCode` beside `Password`. `LoadPrimaryIdentityWith(Unlock)` and `PrimaryFingerprint()` are new. The identity is unlocked once per operation | No |
| `sdk/fido2` | libfido2 through purego: device list, silent check, PIN, make credential, assertion with `hmac-secret`, cancel. Implements `crypto.Authenticator` behind a `Prompter` (PIN, Touch, TouchDone, Insert) that each client provides | No |
| CLI | Terminal prompter and the commands in section 5 | No |
| Graphical clients | A window prompter (PIN dialog, touch state, cancel) and the same flows | Unchanged |

Notes on the API:

- **Additive, not breaking.** Callers of `LoadKeyPair`,
  `LoadPrimaryIdentity(password)` and `Password` work as before. Given a
  version 5 file, they get `crypto.ErrSecurityKeyRequired`.
- **The recovery code is pure Go.** It works in every build, including the
  ones without device support.

## 7. Loading libfido2

**Why at run time.** Linking libfido2 statically through cgo would have
needed a C toolchain and static OpenSSL, libcbor, zlib and libudev for every
release target, which is a different release process. Loading it at run
time instead:

- keeps security keys optional: nothing extra is needed until one is used;
- keeps the CLI release cgo-free;
- leaves fixes to libfido2 and OpenSSL to the operating system's package
  manager instead of new DeepSecret releases.

**How it is loaded.**

- **Fixed absolute paths only.** No search path and no environment variable.
  - macOS: `/opt/homebrew/lib`, `/usr/local/lib`, `/opt/local/lib`
  - Linux: `/usr/lib/<multiarch>`, `/usr/lib64`, `/usr/lib`, `/usr/local/lib`
- **Trusted files only.** The resolved file, and every directory above it,
  must be owned by root or the current user (Homebrew installs as the user).
  Nobody else may be able to write them: not others (except a sticky
  directory), and no group other than root's or, on macOS, admin's, whose
  members can become root anyway.
- **Every function must be present** before any is bound. A missing one means
  the library is too old, and it is refused with that reason.
- **`FIDO_DEBUG` is cleared** before `fido_init`, so libfido2 never dumps
  device exchanges to the terminal.
- **Cancelling is safe.** A device call is cancelled when its context ends,
  and the device is freed only after the cancel has finished.

**Builds without it.**

- The `nofido2` build tag, and Windows and other systems, compile a stub that
  returns `crypto.ErrNoSecurityKeySupport`.
- On Linux, purego makes the binary depend on glibc's loader. So the CLI ships
  two Linux archives:
  - `secret-linux-<arch>.tar.gz` stays fully static (`nofido2`) and runs
    anywhere, Alpine included.
  - `secret-linux-<arch>-fido2.tar.gz` adds security keys.

  `install.sh` picks the `-fido2` one only when `getconf GNU_LIBC_VERSION`
  shows glibc.
- macOS binaries always link libSystem, so they need no second archive.

**Dependency.** `github.com/ebitengine/purego` v0.11.1 (Apache-2.0) is a Go
module, so the existing license and vulnerability scans cover it. libfido2
itself is the user's system package.

## 8. Platform support

| Platform | Status |
|---|---|
| macOS, arm64 and amd64 | libfido2 from Homebrew or MacPorts (`brew install libfido2`) |
| Linux, glibc, amd64 and arm64 | The distribution's libfido2 (`apt install libfido2-1`, `dnf install libfido2`), and access to the device node: systemd 244 and later grant it to the logged-in user, and `secret doctor` hints otherwise |
| Linux, musl | The static archive: recovery codes work, security keys do not |
| Windows | Stub (no security key support). Since Windows 10 1903 a program without admin rights must go through webauthn.dll, which only enables `hmac-secret` for discoverable credentials and shows its own dialog. That backend needs a hardware test first |
| SSH sessions, remote desktop, containers | The security key must be attached to the machine running the client |

**Devices.** Any FIDO2 key that lists `hmac-secret` and has a PIN or a
built-in reader. This covers YubiKey 5 series (firmware 5.2 and later),
Security Key series and YubiKey Bio. A key without `hmac-secret` is refused
at enrollment.

## 9. Compliance (SOC 2, ISO 27001)

Controls this touches:

- SOC 2 CC6.1 (logical access to keys) and CC8.1 (change management).
- ISO 27001:2022:
  - A.5.17 (authentication information).
  - A.8.5 (secure authentication).
  - A.8.24 (use of cryptography).
  - A.8.28 (secure coding).
  - A.5.21 (ICT supply chain).

Evidence:

- This design and its approval.
- The unit, tamper, vector and flow test output.
- A hardware checklist for each release (section 12).
- The usual license and vulnerability reports.

Unlocking is local: nothing about it is sent to the server.

## 10. Decisions taken

| Decision | Choice | Why |
|---|---|---|
| Mechanism | FIDO2 `hmac-secret` unlocking an envelope-encrypted file; keys stay in the file | PIV would wrap the file key with classical ECDH. OTP HMAC-SHA1 has no PIN |
| Format | Version 5 only for security-key files; version 4 unchanged | Existing key files keep working exactly as before, with no migration code |
| Slot rules | No password slot in version 5. Two ways in unless explicitly waived, checked on write | A password slot would allow offline guessing |
| User verification | Always required | It covers the lost-bag case and keeps outputs consistent |
| API | Additive fields and functions | No break for SDK callers |
| FIDO2 library | System libfido2 loaded at run time with purego | Optional at run time; CLI release unchanged; the operating system patches the C libraries |
| Linux artifacts | Static archive kept, `-fido2` archive added, installer picks by libc | Nobody without a security key loses anything |

## 11. Open points

- **Windows backend.** Either a pure Go webauthn.dll binding or libfido2's
  Windows Hello backend. Both need a hardware test.
- **macOS signing.** Once the desktop app is signed with hardened runtime,
  library validation will block a Homebrew libfido2. It will need a
  team-signed copy inside the app bundle, or an entitlement.
- **Unprotected key files.** Whether they stay allowed is a separate
  decision.
- **Model allowlist.** An AAGUID allowlist, if organizations ask to restrict
  key models.
- **Password strength.** The rules for version 4 passwords are unchanged by
  this work.

## 12. Verification

Done:

- **Keystore tests:**
  - round trips from password and unprotected keys;
  - recovery code entry with look-alike characters;
  - slot rules, including the waiver being honoured on read;
  - a backup key, and removal;
  - a user-verification mismatch, which does not open;
  - a tamper case for every field, and a slot copied from another copy;
  - repeated JSON fields, and the future-version message;
  - the private-to-public check, and the derivation vectors.
- **Fuzzing:** a fuzz target for the version 5 parser, plus a 20-second run.
- **SDK flow test:** a security-key sender sends, sends to themselves and
  decrypts, with one unlock per operation, and also with the recovery code.
- **CLI tests:** reading security-key files, the second-way-in rule, and
  doctor staying silent without security keys.
- **Graphical client tests:** unlock routing, the prompt flow (PIN, touch,
  cancel, switching to the recovery code) and every protection flow, against
  a fake security key.
- **libfido2 loading:** the real Homebrew libfido2 1.17.0 loads and lists
  devices through the cgo-free macOS binary.
- **Linux archives:** the static ones are statically linked, and the `-fido2`
  ones are dynamically linked.
- **Real security key, 2026-11-02:** a YubiKey Security Key series (AAGUID
  `e77e3c64-05e3-428b-8824-0cbeb04b829d`, PIN set) on macOS with Homebrew
  libfido2 1.17.0:
  - the hardware test passed (five touches): enrolling created a 64-byte
    non-discoverable credential, two unlocks returned the same output as
    enrolling, and a different PRF input gave a different output;
  - a touch not given in time comes back as `OPERATION_DENIED` after about
    30 seconds. It was reported as "cancelled" (the desktop showed only
    "Stopped."), and is now the touch timeout error.

  The test, for each release and each new kind of key:

  ```
  DEEPSECRET_TEST_PIN=... go test -tags fido2hw -run TestHardware -v ./fido2/
  ```

Not done:

- **Other keys and the full flows on hardware.** On the same key, the CLI's
  `secret identity generate --security-key --single` (PIN, two touches) and
  `secret identity list` worked. Not tried yet: encrypt and decrypt unlocking
  with the key, protect, add, remove, recovery-code and unprotect, the
  desktop flows, a key with a fingerprint reader (YubiKey Bio), and a second
  key as backup.
- **Linux binaries were not run.** They were not run in Alpine or a glibc
  image (no container runtime was available), and libfido2 has not been
  loaded on Linux.
- **Windows** is not implemented.
