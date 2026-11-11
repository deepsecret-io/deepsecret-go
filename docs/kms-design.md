# AWS KMS protection for key files

Status: implemented 2026-11-11 in the SDK (`keystore`, `awskms`) and the CLI
(`secret identity generate --kms-arn`, `secret identity kms`,
`secret identity import`). The real-AWS test (section 10) is run per release;
it first passed on 2026-11-12.

## 1. Summary

Servers, containers, CI runners and AI agents need to open secrets with
nobody at a keyboard. A key pair can now be protected by the user's own AWS KMS key:
it opens with no password and no security key, for the AWS identities the
KMS key policy and IAM policies allow, on a machine that has its key file.

- **The private keys stay in the key file.** AWS KMS has no X25519 or
  ML-KEM-768 decapsulation, so the HPKE half of an identity cannot live there.
  All four private keys (Ed25519, ML-DSA-65, X25519, ML-KEM-768) stay in the
  file, encrypted, exactly as with a security key.
- **KMS unlocks the file.** The file key `FK` seals the private keys. Each KMS
  slot holds a random 32-byte slot secret `S`, encrypted by KMS `Encrypt`
  under a symmetric KMS key with an encryption context bound to the key
  fingerprint, the DeepSecret account and the slot. At unlock, KMS `Decrypt`
  returns `S`, HKDF turns it into the key that unwraps `FK`.
- **Storage version 6.** The envelope and slots of version 5
  ([yubikey-design.md](yubikey-design.md)), with their own domain labels and
  rules: 1 to 4 AWS KMS keys and at most one recovery code. Versions 4 and 5 do
  not change, byte for byte. A file never mixes KMS keys with security keys.
- **The trust boundary moves.** Anyone the key policy and IAM let call
  `kms:Decrypt` with the file's encryption context, and who has the file, can
  open it; so can anyone who can change that policy. In return every unlock is
  a CloudTrail event, and revoking access stops every copy of the file.
- **It is for machines.** For a person a security key is stronger.

## 2. Threat model

### 2.1 Who can open a KMS-protected key file

With the file, and one of:

1. an AWS principal allowed `kms:Decrypt` on the KMS key with this file's
   encryption context, by the key policy, IAM policies, grants, SCPs and
   permission boundaries together;
2. anyone who can change who that is: key administrators (`kms:PutKeyPolicy`,
   `kms:CreateGrant`), IAM administrators when the key policy delegates to IAM
   (the default key policy's account-root statement does), and the account's
   root user;
3. AWS KMS itself: `S` is in the `Encrypt` request at enrollment and in every
   `Decrypt` response. An external key store keeps the KMS key in the
   customer's HSM, but `S` still passes through KMS;
4. the recovery code, if the file has one: offline, with no IAM decision and no
   CloudTrail record.

The DeepSecret service is not on this list. Nothing about KMS reaches it, and
DeepSecret never owns, hosts or offers a KMS key: the key is always the
customer's own.

### 2.2 Attackers

| Attacker | Has | Unprotected key file | KMS key file (version 6) |
|---|---|---|---|
| Leaked CI secret, backup, repository or log | A copy of the file | Full compromise | Nothing without `kms:Decrypt` and the right context |
| Stolen credentials of the unlocking role | AWS credentials | Not relevant | Nothing without the file. With it, an unlock recorded in CloudTrail with its source IP. `aws:SourceVpce` or `aws:SourceIp` conditions make credentials used elsewhere useless |
| Code running on the runner (malicious dependency, compromised step, prompt injection) | File, credentials, memory | Full compromise | Unlock, and copying the keys from memory. Recorded, but it looks normal. Revocation stops later unlocks only: rotate the key pair |
| Misconfigured OIDC trust | Can assume the role | Not relevant | Unlock if it also has the file. Scope the trust policy's `sub`; keep the file in an environment-scoped secret |
| Key or IAM administrator of the key's account | Can change the policy | Not relevant | Can grant themselves `Decrypt`, leaving CloudTrail records |
| Other users of a shared KMS key | `Decrypt` on the same key | Not relevant | Can open the file unless the policy restricts by context. Use a dedicated key |
| Someone who can write the file but has no KMS access | File write | Can replace or read it | A changed slot does not open (slot AAD, and KMS checks the context). A slot from another file or copy breaks the private block's AAD. Denial of service, and one leak: pointing a slot's `key_arn` at a KMS key of their own makes the next unlock call it, so their CloudTrail learns when it ran and from which AWS identity and address. Nothing can check a slot before KMS answers, since its wrap needs the secret KMS returns |
| Someone who edits the enrolling machine's AWS environment | `AWS_ENDPOINT_URL*`, `endpoint_url`, `ca_bundle` | Not relevant | Would get `S` from the `Encrypt` request if the client followed them. `awskms` ignores every endpoint and CA override (section 6) |
| Holder of an older copy of the file | Older copy | Opens it | Opens while any KMS key it names still allows `Decrypt` |
| Quantum adversary storing files | Copies of files | Keys in clear | Holds: everything stored is symmetric (KMS `SYMMETRIC_DEFAULT`, HKDF-SHA256, AES-256-GCM). Asymmetric KMS keys are refused |
| Quantum adversary recording traffic | TLS of an unlock, plus the file | Not relevant | Safe if the TLS session used a hybrid post-quantum key exchange. Go offers X25519MLKEM768 first, and on 2026-11-12 the standard and FIPS endpoints of us-east-1, and those of eu-central-1 and ap-southeast-2, agreed to it. The client does not require it yet (section 11) |

### 2.3 What changes in "only you can open it"

With a password or a security key, "you" is a person with the file and
something only they have. With KMS, it is whoever the customer's AWS access
policies say it is, on a machine that has the file. DeepSecret still never can.
Hence the rules: KMS keys never share a file with security keys, and the
documentation presents KMS as the protection for automation.

## 3. Key file format, version 6

### 3.1 Envelope

The version 5 construction with version 6 labels:

- `FK`: 32 random bytes from `crypto/rand`, kept when slots change.
- Private block: the four private keys as canonical CBOR, AES-256-GCM under
  `FK`, AAD
  `"deepsecret/keystore/v6/private/" || fp || 0x00 || SHA-256(CBOR(slot list, wraps included))`.
- Slot wrap: `FK` under the slot's `KEK`, AES-256-GCM with a fresh nonce, AAD
  `"deepsecret/keystore/v6/slot/" || fp || 0x00 || CBOR([type, id, label, created_at, key_arn, account, ciphertext, recovery_salt])`.
- Unlocking opens one slot, then the private block, then checks that each
  private key gives its public key.

### 3.2 Key derivation

| Slot | Factor | `KEK` |
|---|---|---|
| `aws_kms` | `S` = KMS `Decrypt` of the slot's ciphertext | `HKDF-SHA256(ikm = S, salt = empty, info = "deepsecret/keystore/v6/aws_kms/" \|\| fp \|\| "/" \|\| slot_id)` |
| `recovery_code` | The printed code | `HKDF-SHA256(ikm = code, salt = salt16, info = "deepsecret/keystore/v6/recovery/" \|\| fp \|\| "/" \|\| slot_id)` |

`S` is fresh for each slot and sent to KMS once, at enrollment. Going through
`S` and HKDF keeps one slot structure for every way in. Both derivations, and
the AAD encodings of versions 5 and 6, are pinned by test vectors; the KEK
vectors are checked against an independent HKDF implementation.

### 3.3 Rules

- 1 to 4 `aws_kms` slots and at most one `recovery_code`; no `fido2` slot, and
  no KMS slot in a version 5 file. The editor refuses the other kind once the
  first key is added, and a recovery code needs a key first.
- Every KMS slot names the same DeepSecret account; no KMS key twice.
- Two ways in on write unless the caller waives it; reading never asks for it.
- Every change needs an unlock first. Writes are read back and opened before
  they replace the file, and a file changed meanwhile is not overwritten.

### 3.4 Layout

```json
{
  "storage_version": 6,
  "ed25519_public": "<base64>", "x25519_public": "<base64>",
  "mlkem768_pk": "<base64>", "mldsa65_pk": "<base64>",
  "private": {"nonce": "<base64, 12 bytes>", "ciphertext": "<base64>"},
  "slots": [
    {
      "id": "3f9c1a7e2b4d6081", "type": "aws_kms", "label": "AWS KMS key 1234abcd (eu-west-1)",
      "created_at": "2026-11-11T10:00:00Z",
      "aws_kms": {
        "key_arn": "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "account": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f",
        "ciphertext": "<base64, the KMS CiphertextBlob>"
      },
      "wrap": {"nonce": "<base64, 12 bytes>", "wrapped_key": "<base64, 48 bytes>"}
    }
  ]
}
```

`account` is the DeepSecret account id; the AWS account is in `key_arn`. The
encryption context is not stored: it is rebuilt from the fingerprint, the slot
id and `account`.

### 3.5 Checks on read

The strict reader refuses repeated fields in any case, unknown fields, data
after the object, public keys that do not hash to the file name, every size out
of range (the KMS ciphertext 1 to 6144 bytes), a `key_arn` that is not a full
key ARN in `aws`, `aws-us-gov` or `aws-cn` (an alias never passes), an
`account` that is not a lower-case UUID, slots that name different accounts, a
`fido2` slot ("a KMS key file holds no security key"), and any other type
("needs a newer version of DeepSecret"). Version 7 and above say "needs a newer
version"; SDK v0.5.0 and older already say so for version 6.

Every reader of key files switches over versions 4, 5 and 6 and refuses
anything else; a test calls every exported function on one file of each.

## 4. Encryption context

| Key | Value |
|---|---|
| `deepsecret:purpose` | `keystore/v6/aws_kms` |
| `deepsecret:fingerprint` | the key fingerprint, 64 lower-case hex characters |
| `deepsecret:account` | the DeepSecret account id, a lower-case UUID |
| `deepsecret:slot` | the slot id, 16 lower-case hex characters |

KMS binds it to the ciphertext, refuses any other at `Decrypt`, and writes it
to CloudTrail in clear; none of it is secret. A policy on the account survives
key pair rotation; one on the fingerprint allows one key pair. Everything is
lower case because IAM condition keys match without regard to case while the
context is case sensitive. `keystore.KMSContext` builds it.

The account comes from the server when the slot is made. `identity.Sync`
refuses to register a version 6 key pair under another account than its slots
name.

## 5. KMS rules

- **Accepted keys.** `keystore.DescribeKMSKey` and `AddKMS` take a full key ARN
  only, refusing a key id or an alias (`ErrKMSNotKeyARN`) before any call:
  anyone with `kms:UpdateAlias` can re-point an alias. KMS must describe that
  same ARN, and the key must be customer managed, enabled, `SYMMETRIC_DEFAULT`
  with usage `ENCRYPT_DECRYPT`, in a supported partition.
- **Encrypt** names the ARN and `SYMMETRIC_DEFAULT`; the answer must name the
  same key and be 1 to 6144 bytes.
- **Decrypt** always names the slot's ARN (so KMS refuses a ciphertext of any
  other key) and `SYMMETRIC_DEFAULT`; the answer must name the same key and be
  exactly 32 bytes. These checks live in `keystore`, so every `KMS`
  implementation is held to them.
- **Several KMS slots** are tried in order. Unlock moves on only when a key is
  unreachable or unusable (`ErrKMSUnreachable`, `ErrKMSKeyUnavailable`); a
  refusal or a wrong answer is returned at once.
- **No cache.** One unlock makes one `Decrypt` per KMS slot it tries: one,
  unless a key is unreachable or unusable. `S`, `KEK` and `FK` are cleared
  after use; the AWS SDK's own buffers and the private keys (Go strings) cannot
  be.

## 6. The AWS client (`awskms`)

- **Endpoint:** every call names a full key ARN and goes to
  `https://kms.<region>.<partition DNS suffix>` of that key's own region, or `kms-fips.` when the standard AWS FIPS setting is on. It is set as
  the client's base endpoint, so `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_KMS` and
  a profile's `endpoint_url` are ignored. VPC endpoints work through private DNS.
- **TLS:** an HTTP client of its own that trusts the system's roots only
  (`AWS_CA_BUNDLE` and `ca_bundle` are ignored), TLS 1.2 or later, Go's default
  key exchanges, no redirects, proxies from the environment.
- **Credentials:** the AWS default chain with an optional profile; roles come
  from the profile (`role_arn`), never from DeepSecret code. Require IMDSv2 on
  EC2 instances; a client-side setting would not stop a request forgery that
  reaches the metadata service directly.
- **Logging:** client log mode zero and a discarding logger, whatever the
  environment says: an `Encrypt` request body and a `Decrypt` response body
  hold `S`.
- **User agent:** an app id such as `deepsecret-cli/1.2.3`, which CloudTrail
  records.
- **Errors** become `ErrKMSNoCredentials`, `ErrKMSCredentialsRejected` (AWS
  refused the credentials themselves: unknown, deactivated or expired keys, or
  a bad signature), `ErrKMSAccessDenied` (a known identity without permission),
  `ErrKMSKeyUnavailable`, `ErrKMSMismatch`, `ErrKMSUnreachable` or
  `ErrKMSKeyRejected`, with AWS's message stripped of control characters. The
  CLI's hint for credentials names where they came from (`--aws-profile`,
  `AWS_ACCESS_KEY_ID`, `AWS_PROFILE` or the default profile, in the AWS SDK's
  order).

Only `awskms` imports the AWS SDK (enforced by `structure_test.go`).

## 7. Policy guidance

- A dedicated KMS key for DeepSecret key files, ideally one per environment.
- The enrolling identity needs `kms:DescribeKey` and `kms:Encrypt`; the
  unlocking one needs `kms:Decrypt` only.
- Restrict by context: `StringEquals` on `kms:EncryptionContext:deepsecret:purpose`
  and on the account or fingerprint, plus `ForAllValues:StringEquals` on
  `kms:EncryptionContextKeys` (which alone is true for an empty context).
- The default key policy's account-root statement lets any IAM principal whose
  policy allows `kms:Decrypt` on `*` unlock every key file. Drop that delegation
  for `Encrypt` and `Decrypt`, or add an explicit `Deny` for everyone but the
  named roles (`ArnNotEquals` on `aws:PrincipalArn`).
- Keep KMS events in CloudTrail, alert on unexpected `Decrypt` principals and on
  `PutKeyPolicy`, `CreateGrant`, `DisableKey` or `ScheduleKeyDeletion`, and turn
  on automatic rotation of the KMS key (old ciphertexts keep opening).

```json
{
  "Sid": "UnlockDeepSecretKeyPairs",
  "Effect": "Allow",
  "Principal": {"AWS": "arn:aws:iam::111122223333:role/ci-deploy"},
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:deepsecret:purpose": "keystore/v6/aws_kms",
      "kms:EncryptionContext:deepsecret:account": "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"
    },
    "ForAllValues:StringEquals": {
      "kms:EncryptionContextKeys": ["deepsecret:purpose", "deepsecret:fingerprint", "deepsecret:account", "deepsecret:slot"]
    }
  }
}
```

## 8. Recovery code

The version 5 recovery code, with a version 6 label: it opens the file with no
AWS access at all, and so skips IAM and CloudTrail. It is shown once, on a
terminal only. Never store it next to the key file; keep it offline and record
each use. Enrollment needs an explicit choice: a second KMS key, the recovery
code, or the waiver (`--single` in the CLI).

## 9. API

```go
// keystore
type KMS interface {
	DescribeKey(ctx, keyARN string) (*KMSKey, error)
	Encrypt(ctx, keyARN string, encryptionContext map[string]string, plaintext []byte) (*KMSResult, error)
	Decrypt(ctx, keyARN string, encryptionContext map[string]string, ciphertext []byte) (*KMSResult, error)
}
type Unlock struct { Password string; SecurityKey Authenticator; RecoveryCode string; KMS KMS }
func NewKMSKeyFile(dir string, kp *keys.Pair) (*SlotEditor, error)
func (e *SlotEditor) AddKMS(ctx, k KMS, keyARN, account, label string) (SlotInfo, error)
func DescribeKMSKey(ctx, k KMS, keyARN string) (*KMSKey, error)
func KMSContext(fingerprint, slotID, account string) map[string]string
func Import(dir string, data []byte, replace bool) (string, error)

// awskms
func New(ctx, Options{Profile, AppID}) (*Client, error)
func (c *Client) CallerARN(ctx, region string) (string, error)
```

`secrets.EncryptOptions` and `DecryptOptions` carry one `Unlock` field: the
next SDK release (v0.6.0) replaces the separate `Password`, `SecurityKey` and
`RecoveryCode` fields with it.

`Import` accepts version 5 and 6 files only: an unprotected file must never be
copied between machines, and a password file cannot be unlocked unattended.
It writes the file private to the user (mode 0600, or a protected DACL on
Windows), and refuses different bytes for a key pair already present unless
`replace` is set.

## 10. Verification

- **Keystore:** round trips; the exact context on every call; tampering with
  every slot field, the wrap and the private block; slots from another copy;
  swapped ciphertexts; every size bound; mixing refused both ways; the slot
  limits; wrong KMS answers (another key, 31 or 33 bytes); failing over only on
  outages; every entry point on every version; `Import`; vectors; a fuzz target
  for the version 6 parser and `Import`; no slot secret in any error.
- **`awskms`:** with `AWS_ENDPOINT_URL*`, `endpoint_url`, `AWS_CA_BUNDLE` and
  `ca_bundle` all set, the tests check that the HTTP client `New` built
  carries the transport `New` configured. That transport trusts the system's
  roots only. The tests then swap that transport for a recorder, which shows
  that the KMS and STS clients send through that client to the regional
  endpoint. They also cover FIPS endpoints, that requests always name a key
  ARN, the error mapping, and that no credentials means no request. The real
  TLS handshake is exercised by the real-AWS test.
- **SDK flows:** a KMS sender and recipient send and decrypt with one unlock per
  operation, and with the recovery code; registration refuses a key pair bound
  to another account.
- **Real AWS**, per release, with a real key:

  ```
  DEEPSECRET_TEST_KMS_KEY=arn:aws:kms:<region>:<account>:key/<id> go test -tags kmsaws -run TestRealKMS -v ./awskms/
  ```

  Enrollment and unlock round trip; a wrong encryption context is refused; the
  negotiated TLS group is recorded. A manual check confirms the `Decrypt` in
  CloudTrail with the four context values and the DeepSecret user agent.
  First run, 2026-11-12, us-east-1: passed. The IAM policy limited to the key
  and the context conditions of section 7 allowed every call. An identity
  without a policy got `ErrKMSAccessDenied` naming the user. TLS 1.3 used
  X25519MLKEM768.

## 11. Open points

- Decrypting through a multi-region replica with the primary's ARN in the slot
  (today a second slot under the replica's own ARN does it).
- KMS `DryRun` for a permission check that unlocks nothing.
- Pinning hybrid post-quantum TLS: the endpoints tried so far accept it; the
  GovCloud and China partitions have not been tried.
- AWS ISO partitions.
- KMS plus a local secret in one slot, for teams that distrust their IAM
  administrators.
