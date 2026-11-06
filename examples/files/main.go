// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Example files demonstrates file, directory, and archive encryption with
// the DeepSecret SDK.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deepsecret-io/sdk"
)

func main() {
	apiURL := envOr("DS_API_URL", "http://localhost:80")
	apiKey := envOr("DS_API_KEY", "")
	// One send encrypts once for every recipient listed.
	recipients := []string{envOr("DS_RECIPIENT", "you@example.com")}

	if apiKey == "" {
		log.Fatal("DS_API_KEY is required")
	}

	fmt.Print("DeepSecret SDK: files example\n\n")

	client, err := sdk.NewClient(apiURL, apiKey)
	if err != nil {
		log.Fatal("new client: ", err)
	}

	me, err := client.WhoAmI(context.Background())
	if err != nil {
		log.Fatal("whoami: ", err)
	}
	fmt.Printf("Authenticated: %s (%s)\n\n", me.Email, me.TierName)

	var cleanupIDs []string

	// ── Single file ──
	fileSecret, err := client.EncryptPaths(context.Background(), recipients, []string{"./sdk/examples/files/main.go"}, sdk.EncryptOptions{
		Name: "sdk-file-example",
	})
	if err != nil {
		log.Fatal("encrypt file: ", err)
	}
	cleanupIDs = append(cleanupIDs, fileSecret.Secret.ID)
	fmt.Printf("Encrypted file → %s (name=%s)\n", fileSecret.Secret.ID, fileSecret.Secret.Name)

	fileResult, err := client.DecryptSecret(context.Background(), fileSecret.Secret.ID, sdk.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt file: ", err)
	}
	fmt.Printf("Decrypted: %d files\n", len(fileResult.Decrypted.Files))
	for _, f := range fileResult.Decrypted.Files {
		fmt.Printf("  %s (%d bytes, sha256=%s…)\n", f.Name, len(f.Data), f.SHA256[:16])
	}
	fmt.Println()

	// ── Multiple files ──
	multiSecret, err := client.EncryptPaths(context.Background(), recipients, []string{
		"./sdk/examples/files/main.go",
		"./sdk/examples/basic/main.go",
	}, sdk.EncryptOptions{
		Name:     "sdk-multi-files",
		Compress: sdk.CompressZstd,
	})
	if err != nil {
		log.Fatal("encrypt files: ", err)
	}
	cleanupIDs = append(cleanupIDs, multiSecret.Secret.ID)
	fmt.Printf("Encrypted %d files → %s\n", 2, multiSecret.Secret.ID)

	multiResult, err := client.DecryptSecret(context.Background(), multiSecret.Secret.ID, sdk.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt files: ", err)
	}
	for _, f := range multiResult.Decrypted.Files {
		fmt.Printf("  %s (%d bytes)\n", f.Name, len(f.Data))
	}
	fmt.Println()

	// ── Directory (individual files) ──
	dirSecret, err := client.EncryptPaths(context.Background(), recipients, []string{"./sdk/examples"}, sdk.EncryptOptions{
		Name:       "sdk-dir-example",
		SkipHidden: true,
	})
	if err != nil {
		log.Fatal("encrypt dir: ", err)
	}
	cleanupIDs = append(cleanupIDs, dirSecret.Secret.ID)
	fmt.Printf("Encrypted directory → %s\n", dirSecret.Secret.ID)

	dirResult, err := client.DecryptSecret(context.Background(), dirSecret.Secret.ID, sdk.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt dir: ", err)
	}
	fmt.Printf("Decrypted: %d files\n", len(dirResult.Decrypted.Files))
	for _, f := range dirResult.Decrypted.Files {
		fmt.Printf("  %s (%d bytes)\n", f.Name, len(f.Data))
	}
	fmt.Println()

	// ── Directory as archive (privacy mode with zstd) ──
	archiveSecret, err := client.EncryptPaths(context.Background(), recipients, []string{"./sdk/examples"}, sdk.EncryptOptions{
		Name:       "sdk-archive-zstd",
		Archive:    true,
		Compress:   sdk.CompressZstd,
		SkipHidden: true,
	})
	if err != nil {
		log.Fatal("encrypt archive: ", err)
	}
	cleanupIDs = append(cleanupIDs, archiveSecret.Secret.ID)
	fmt.Printf("Encrypted archive (zstd) → %s\n", archiveSecret.Secret.ID)

	archiveResult, err := client.DecryptSecret(context.Background(), archiveSecret.Secret.ID, sdk.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt archive: ", err)
	}
	fmt.Printf("Decrypted: %d file(s), archive name: %s\n", len(archiveResult.Decrypted.Files), archiveResult.Decrypted.Files[0].Name)
	fmt.Printf("  Archive size: %d bytes\n", len(archiveResult.Decrypted.Files[0].Data))
	fmt.Println()

	// ── Mixed paths ──
	mixedSecret, err := client.EncryptPaths(context.Background(), recipients, []string{
		"./sdk/examples/basic",
		"./sdk/examples/files/main.go",
	}, sdk.EncryptOptions{
		Name:       "sdk-mixed-paths",
		SkipHidden: true,
	})
	if err != nil {
		log.Fatal("encrypt paths: ", err)
	}
	cleanupIDs = append(cleanupIDs, mixedSecret.Secret.ID)
	fmt.Printf("Encrypted mixed paths → %s\n", mixedSecret.Secret.ID)

	mixedResult, err := client.DecryptSecret(context.Background(), mixedSecret.Secret.ID, sdk.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt paths: ", err)
	}
	fmt.Printf("Decrypted: %d files\n", len(mixedResult.Decrypted.Files))
	for _, f := range mixedResult.Decrypted.Files {
		fmt.Printf("  %s (%d bytes)\n", f.Name, len(f.Data))
	}

	// ── Cleanup ──
	if err := client.DeleteSecrets(context.Background(), cleanupIDs); err != nil {
		log.Fatal("delete: ", err)
	}
	fmt.Printf("\nCleaned up %d example secrets.\n", len(cleanupIDs))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
