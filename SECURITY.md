# Security policy

The SDK is the part of DeepSecret that encrypts, decrypts and handles keys, and it is open so that anyone can check it. If you find a flaw, please tell us privately first.

## Reporting a vulnerability

Report it through GitHub: open this repository's [Security tab](https://github.com/deepsecret-io/deepsecret-go/security) and choose **Report a vulnerability**. Only you and the maintainers can see the report.

Please do not open a public issue, pull request or discussion about a security problem. We will reply in the report, work on the fix with you there, and agree with you when to publish the details.

## What to report

Anything that breaks what [PROTOCOL_V4.md](PROTOCOL_V4.md) promises, or lets someone get at a secret or a key. For example:

- **Confidentiality:** anyone other than a listed recipient can read a payload or a content key.
- **Authenticity and integrity:** a forged, altered, reordered, truncated or replayed payload, manifest or wrap is accepted, or plaintext is released before the payload digest is verified.
- **A dishonest server:** the server can pass off its own key as someone else's, add or swap a recipient unnoticed, or present one secret's revision as another's. The server is not trusted with content, so this is in scope.
- **Key handling:** private keys or content keys are written, logged or left somewhere they should not be, or the key store can be read or replaced by someone else.
- **Parsing untrusted input:** path traversal or other unsafe extraction from an archive, decompression bombs, or a crash or memory exhaustion caused by a crafted manifest or payload.
- **Credentials:** API keys, tokens or presigned URLs leak through logs, errors or plaintext connections.
- **Cryptographic mistakes:** nonce reuse, weak randomness, or a difference from the specification or its test vectors.

The limits that §8 of the specification states are known and are not vulnerabilities: for example, a recipient can re-share what they decrypted, and a client cannot detect a rollback to an older revision before it has seen the newer one.

## What to include

- The version or commit you tested.
- What goes wrong and what an attacker gains.
- The steps to reproduce it, ideally a small test or proof of concept.
- Your operating system and Go version, if they matter.

Do not include real secrets, private keys or anyone else's data.

## Supported versions

The SDK is before version 1.0, so security fixes go into the latest release only. Please check that the problem exists there or on `main` before you report it.

## Scope

- **This repository:** all of the SDK's code and the specification.
- **The CLI:** its repository is not public yet, so report problems in its code here too.
- **The hosted service** (`api.deepsecret.io`, `app.deepsecret.io` and `deepsecret.io`): use the same channel.

This policy does not give permission to test the hosted service. The [Terms of Service](https://deepsecret.io/terms.html) forbid probing it without written authorization, so report what you noticed and ask before testing further. Never access or change anyone else's account or data.
