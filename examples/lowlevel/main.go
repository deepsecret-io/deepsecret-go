// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Example lowlevel demonstrates direct usage of the crypto and archive
// packages without the high-level SDK client.
//
// This shows how the low-level primitives can be used independently for
// offline encryption, custom workflows, or porting to other languages.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/deepsecret-io/sdk/archive"
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/crypto"
)

func main() {
	fmt.Println("DeepSecret SDK: low-level crypto & archive example")
	fmt.Println()

	// ────────────────────────────────────────────────────────────────────────
	// 1. Key Generation & Management
	// ────────────────────────────────────────────────────────────────────────

	fmt.Println("=== Key Generation ===")

	// Generate two key pairs (simulating sender and recipient)
	senderKP, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal("sender keygen: ", err)
	}
	senderFP, _ := crypto.Fingerprint(senderKP)
	fmt.Printf("Sender fingerprint:    %s\n", senderFP)

	recipientKP, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal("recipient keygen: ", err)
	}
	recipientFP, _ := crypto.Fingerprint(recipientKP)
	fmt.Printf("Recipient fingerprint: %s\n", recipientFP)

	// Sign and verify key bundle (dual: Ed25519 + ML-DSA-65)
	edSig, mldsaSig, err := crypto.SignKeyBundle(senderKP)
	if err != nil {
		log.Fatal("sign bundle: ", err)
	}
	if err := crypto.VerifyKeyBundleSignature(
		senderKP.ED25519Public,
		senderKP.X25519Public,
		senderKP.MLKEM768PK,
		senderKP.MLDSA65PK,
		edSig,
		mldsaSig,
	); err != nil {
		log.Fatal("verify bundle: ", err)
	}
	fmt.Println("Key bundle signature: verified ✓")

	// Save and reload keys (with password)
	tmpDir := filepath.Join(os.TempDir(), "deepsecret-example")
	os.MkdirAll(tmpDir, 0700)
	defer os.RemoveAll(tmpDir)

	if err := crypto.SaveKeyPairTo(tmpDir, senderFP, senderKP, "test-password"); err != nil {
		log.Fatal("save key: ", err)
	}
	loaded, err := crypto.LoadKeyPairFrom(tmpDir, senderFP, "test-password")
	if err != nil {
		log.Fatal("load key: ", err)
	}
	loadedFP, _ := crypto.Fingerprint(loaded)
	fmt.Printf("Saved & loaded key:    %s (match=%v)\n", loadedFP, loadedFP == senderFP)

	// List local keys
	keyList, _ := crypto.ListLocalKeysIn(tmpDir)
	fmt.Printf("Keys in temp dir:      %v\n\n", keyList)

	// ────────────────────────────────────────────────────────────────────────
	// 2. Seal / Open (protocol v4)
	// ────────────────────────────────────────────────────────────────────────

	fmt.Println("=== Seal/Open (protocol v4) ===")

	plaintext := []byte("Top secret message: the launch code is 42.")
	fmt.Printf("Plaintext: %q (%d bytes)\n", string(plaintext), len(plaintext))

	// Build recipient public keys from the key pair
	recipientPub := &crypto.PublicKeys{
		ED25519:     recipientKP.ED25519Public,
		X25519:      recipientKP.X25519Public,
		MLKEM768:    recipientKP.MLKEM768PK,
		MLDSA65:     recipientKP.MLDSA65PK,
		Fingerprint: recipientFP,
	}

	// Seal once for every recipient. The revision id is bound into the
	// payload, the wraps and the manifest; the API assigns it at create.
	revisionID := "4f9c1e5a-8b2d-4c3e-9f1a-2b3c4d5e6f70"
	sealedPayload, sealed, err := crypto.SealBytes(plaintext, senderKP, []*crypto.PublicKeys{recipientPub}, crypto.SealParams{
		RevisionID:  revisionID,
		PayloadType: "message",
	})
	if err != nil {
		log.Fatal("seal: ", err)
	}
	fmt.Printf("Payload size:  %d bytes\n", len(sealedPayload))
	fmt.Printf("Manifest size: %d bytes\n", len(sealed.ManifestData))

	// Inspect the manifest without opening it
	m, _ := crypto.UnmarshalManifest(sealed.ManifestData)
	fmt.Printf("Manifest metadata:\n")
	fmt.Printf("  Protocol:    v%s\n", m.Version)
	fmt.Printf("  Suite:       %s\n", m.CipherSuite)
	fmt.Printf("  Sender FP:   %s\n", m.SenderFingerprint)
	fmt.Printf("  Recipients:  %d\n", len(m.Recipients))
	fmt.Printf("  Type:        %s\n", m.PayloadType)

	// Open as the recipient, then decrypt the payload
	wrap, _ := sealed.Wrap(recipientFP)
	opened, err := crypto.Open(sealed.ManifestData, wrap, recipientKP, crypto.OpenParams{
		RevisionID:    revisionID,
		SenderED25519: senderKP.ED25519Public,
	})
	if err != nil {
		log.Fatal("open: ", err)
	}
	decrypted, err := opened.Decrypt(sealedPayload)
	opened.Close()
	if err != nil {
		log.Fatal("decrypt: ", err)
	}
	fmt.Printf("Decrypted: %q\n", string(decrypted))
	fmt.Printf("Match: %v\n\n", string(decrypted) == string(plaintext))

	// With compression
	fmt.Println("=== With Compression ===")

	longText := make([]byte, 10000)
	for i := range longText {
		longText[i] = byte('A' + (i % 26))
	}

	compressed, _ := compress.CompressZstd(longText)
	fmt.Printf("Original: %d bytes → Compressed: %d bytes (%.1f%% ratio)\n",
		len(longText), len(compressed), float64(len(compressed))/float64(len(longText))*100)

	compPayload, compSealed, err := crypto.SealBytes(compressed, senderKP, []*crypto.PublicKeys{recipientPub}, crypto.SealParams{
		RevisionID:  revisionID,
		PayloadType: "message",
		Compressed:  true,
		Compression: "zstd",
	})
	if err != nil {
		log.Fatal("seal compressed: ", err)
	}

	compWrap, _ := compSealed.Wrap(recipientFP)
	compOpened, err := crypto.Open(compSealed.ManifestData, compWrap, recipientKP, crypto.OpenParams{RevisionID: revisionID})
	if err != nil {
		log.Fatal("open compressed: ", err)
	}
	compPlain, err := compOpened.Decrypt(compPayload)
	compOpened.Close()
	if err != nil {
		log.Fatal("decrypt compressed: ", err)
	}

	decompressed, _ := compress.DecompressZstd(compPlain)
	fmt.Printf("Roundtrip match: %v (compressed=%v, algo=%s)\n\n",
		string(decompressed) == string(longText), compOpened.Manifest.Compressed, compOpened.Manifest.Compression)

	// ────────────────────────────────────────────────────────────────────────
	// 3. Archive & Compression
	// ────────────────────────────────────────────────────────────────────────

	fmt.Println("=== Archive Operations ===")

	// Expand paths
	files, err := archive.ExpandPaths([]string{"./sdk/examples"}, true)
	if err != nil {
		log.Fatal("expand: ", err)
	}
	fmt.Printf("Expanded %d files from ./sdk/examples\n", len(files))
	for _, f := range files {
		fmt.Printf("  %s\n", f.RelPath)
	}

	// Create tar.zst archive
	tarZst, err := archive.CreateTar(files, compress.Zstd)
	if err != nil {
		log.Fatal("tar zstd: ", err)
	}
	fmt.Printf("\ntar.zst archive: %d bytes\n", len(tarZst))

	// Extract to disk (the SDK only supports streaming on-disk extraction).
	extractDir := filepath.Join(tmpDir, "extracted")
	count, err := archive.ExtractTar(tarZst, extractDir, compress.Zstd, nil)
	if err != nil {
		log.Fatal("extract disk: ", err)
	}
	fmt.Printf("\nExtracted %d files to %s\n", count, extractDir)

	// ────────────────────────────────────────────────────────────────────────
	// 4. Compression Roundtrip
	// ────────────────────────────────────────────────────────────────────────

	fmt.Println("\n=== Compression ===")

	testData := make([]byte, 50000)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	zstdOut, _ := compress.Compress(testData, compress.Zstd)
	fmt.Printf("Original: %d bytes\n", len(testData))
	fmt.Printf("Zstd:     %d bytes (%.1f%%)\n", len(zstdOut), float64(len(zstdOut))/float64(len(testData))*100)

	zstdBack, _ := compress.Decompress(zstdOut, compress.Zstd, nil)
	fmt.Printf("Match:    %v\n", string(zstdBack) == string(testData))

	// Path validation
	fmt.Println("\n=== Path Validation ===")
	cases := []string{"../secret.txt", "../../a/b/c.go", "normal/path.go", ".."}
	for _, c := range cases {
		clean, err := archive.ValidateArchivePath(c)
		if err != nil {
			fmt.Printf("  %-25s → REJECTED: %v\n", c, err)
		} else {
			fmt.Printf("  %-25s → OK: %q\n", c, clean)
		}
	}

	fmt.Println("\nDone.")
}
