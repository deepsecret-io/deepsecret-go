// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package deepsecret provides a high-level Go SDK for the DeepSecret API.
//
// DeepSecret uses protocol v4 (PROTOCOL_V4.md): each revision's payload is
// encrypted once with AES-256-GCM in 1 MiB chunks under a fresh content
// key, that key is wrapped for every recipient with hybrid post-quantum
// HPKE (X25519-ML-KEM-768, HKDF-SHA256, AES-256-GCM), and the sender signs
// a manifest covering the payload and every wrap with Ed25519 and
// ML-DSA-65. All cryptographic operations happen client-side: private keys
// never leave the device.
//
// # Package Structure
//
//	deepsecret : the client and its setup: NewClient, its options, Logout
//	identity   : account, org, groups and the keys registered on the server (Client.Identity)
//	secrets    : send, receive, local files, list, revoke, policy, resume, storage (Client.Secrets)
//	trust      : the keys this device knows: list, accept, verify, forget (Client.Trust)
//	keys       : key pairs, fingerprints and safety numbers; no file access
//	keystore   : key files, password and security key protection, recovery codes
//	fido2      : security keys, through libfido2; pass one as a keystore.Authenticator
//	apierror   : what the server answered: Error, ErrNotFound and the others
//	transfer   : a transfer's state, its phases and limits
//
// The protocol, transport and file handling behind them are internal.
// PROTOCOL_V4.md specifies the protocol for ports to other languages.
//
// # Contexts
//
// Every call that can block takes a context first, and ends when it does:
// requests in flight, a transfer between its parts, and a prompt for a security
// key.
//
// # Recipients
//
// One send seals the payload once for any number of recipients and uploads
// it once. The sender is a recipient only when listed. Sending again under
// an existing name adds a revision, and must list everyone who has access
// now unless secrets.EncryptOptions.RevokeMissing is set. Secrets.RevokeRecipient removes
// one recipient.
//
// # Memory Model
//
// Files stream, so memory stays flat at any size, up to 100 GiB a secret:
//
//   - Each file is read once, encoded into the CBOR payload, compressed and
//     sealed chunk by chunk into a private temporary file that holds only
//     ciphertext
//   - The object is uploaded from that file, in parts above the server's
//     multipart threshold
//
// On decrypt the object is downloaded into a temporary file, so its digest
// can be checked against the signed manifest before any plaintext is
// released. WriteFiles (and DecryptToDir) then decrypt it once to check
// every file and again to write them. Both sides need free disk space for
// the encrypted payload, in EncryptOptions.TempDir or DecryptOptions.TempDir,
// else $DEEPSECRET_TMPDIR, else the system temp directory.
//
// Messages and key-value data are small and are handled in memory, as is
// Secrets.Decrypt for payloads up to 256 MiB.
//
// # Quick Start
//
//	client, err := deepsecret.NewClient("https://api.deepsecret.io", "your-api-key")
//	if err != nil { log.Fatal(err) }
//
//	// Encrypt a message for two recipients in one send
//	res, _ := client.Secrets.EncryptText(ctx, []string{"alice@example.com", "bob@example.com"}, "sensitive data", secrets.EncryptOptions{})
//
//	// Decrypt a secret (as one of its recipients)
//	result, _ := client.Secrets.Decrypt(ctx, res.Secret.ID, secrets.DecryptOptions{})
//	fmt.Println(result.Decrypted.Message)
//
//	// Write a files secret of any size to disk
//	_, written, _ := client.Secrets.DecryptToDir(ctx, secretID, "./out", secrets.DecryptOptions{}, secrets.WriteOptions{})
//	fmt.Println(len(written.Files), "files")
//
// # Secret Management
//
//	list, total, _ := client.Secrets.ListReceived(ctx, secrets.ListOptions{Limit: 50})
//	info, _ := client.Secrets.Describe(ctx, secretID)
//	client.Secrets.RevokeRecipient(ctx, secretID, "bob@example.com")
//	client.Secrets.Delete(ctx, secretID)
package deepsecret
