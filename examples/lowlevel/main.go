// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Example: lowlevel — demonstrates direct usage of the crypto and archive
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
	fmt.Println("DeepSecret SDK — low-level crypto & archive example")
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
	// 2. Hybrid Encryption / Decryption
	// ────────────────────────────────────────────────────────────────────────

	fmt.Println("=== Hybrid Encrypt/Decrypt ===")

	plaintext := []byte("Top secret message: the launch code is 42.")
	fmt.Printf("Plaintext: %q (%d bytes)\n", string(plaintext), len(plaintext))

	// Build recipient public keys from the key pair
	recipientPub := &crypto.PublicKeys{
		ED25519:     recipientKP.ED25519Public,
		X25519:      recipientKP.X25519Public,
		MLKEM768:    recipientKP.MLKEM768PK,
		Fingerprint: recipientFP,
	}

	// Encrypt
	envelope, err := crypto.HybridEncrypt(plaintext, senderKP, recipientPub, crypto.EncryptParams{
		PayloadType: "message",
	})
	if err != nil {
		log.Fatal("encrypt: ", err)
	}
	fmt.Printf("Envelope size: %d bytes (%.1fx expansion)\n", len(envelope), float64(len(envelope))/float64(len(plaintext)))

	// Inspect envelope without decrypting
	env, _ := crypto.UnmarshalEnvelope(envelope)
	fmt.Printf("Envelope metadata:\n")
	fmt.Printf("  Protocol:    v%s\n", env.Version)
	fmt.Printf("  Suite:       %s\n", env.CipherSuite)
	fmt.Printf("  Sender FP:   %s\n", env.SenderFingerprint)
	fmt.Printf("  Recipient FP:%s\n", env.RecipientFingerprint)
	fmt.Printf("  Type:        %s\n", env.PayloadType)

	// Decrypt
	result, err := crypto.HybridDecrypt(envelope, recipientKP, senderKP.ED25519Public)
	if err != nil {
		log.Fatal("decrypt: ", err)
	}
	fmt.Printf("Decrypted: %q\n", string(result.Plaintext))
	fmt.Printf("Match: %v\n\n", string(result.Plaintext) == string(plaintext))

	// With compression
	fmt.Println("=== With Compression ===")

	longText := make([]byte, 10000)
	for i := range longText {
		longText[i] = byte('A' + (i % 26))
	}

	compressed, _ := compress.CompressZstd(longText)
	fmt.Printf("Original: %d bytes → Compressed: %d bytes (%.1f%% ratio)\n",
		len(longText), len(compressed), float64(len(compressed))/float64(len(longText))*100)

	envComp, err := crypto.HybridEncrypt(compressed, senderKP, recipientPub, crypto.EncryptParams{
		PayloadType: "message",
		Compressed:  true,
		Compression: "zstd",
	})
	if err != nil {
		log.Fatal("encrypt compressed: ", err)
	}

	resultComp, err := crypto.HybridDecrypt(envComp, recipientKP, senderKP.ED25519Public)
	if err != nil {
		log.Fatal("decrypt compressed: ", err)
	}

	decompressed, _ := compress.DecompressZstd(resultComp.Plaintext)
	fmt.Printf("Roundtrip match: %v (compressed=%v, algo=%s)\n\n",
		string(decompressed) == string(longText), resultComp.Compressed, resultComp.Compression)

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
