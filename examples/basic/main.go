// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Example: basic — demonstrates text, key-value, and byte encryption with the
// DeepSecret SDK.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/secrets"
)

func main() {
	apiURL := envOr("DS_API_URL", "http://localhost:80")
	apiKey := envOr("DS_API_KEY", "")
	recipient := envOr("DS_RECIPIENT", "you@example.com")

	if apiKey == "" {
		log.Fatal("DS_API_KEY is required")
	}

	fmt.Printf("DeepSecret SDK v%s — basic example\n\n", sdk.Version)

	client, err := sdk.NewClient(apiURL, apiKey)
	if err != nil {
		log.Fatal("new client: ", err)
	}

	// ── Authenticate ──
	me, err := client.WhoAmI()
	if err != nil {
		log.Fatal("whoami: ", err)
	}
	fmt.Printf("Authenticated: %s %s (%s)\n", me.FirstName, me.LastName, me.Email)
	fmt.Printf("Plan: %s | Status: %s\n\n", me.TierName, me.SubscriptionStatus)

	// ── Identity ──
	_, fp, err := client.LoadPrimaryIdentity("")
	if err != nil {
		log.Fatal("identity: ", err)
	}
	fmt.Printf("Primary key: %s\n\n", fp)

	// ── Encrypt text ──
	secret, err := client.EncryptText(recipient, "Hello from the DeepSecret Go SDK!", sdk.EncryptOptions{
		Name: "sdk-basic-text",
	})
	if err != nil {
		log.Fatal("encrypt text: ", err)
	}
	fmt.Printf("Encrypted text → %s (name=%s)\n", secret.Secret.ID, secret.Secret.Name)

	// Decrypt it back
	result, err := client.DecryptSecret(secret.Secret.ID)
	if err != nil {
		log.Fatal("decrypt text: ", err)
	}
	fmt.Printf("Decrypted: type=%s message=%q\n\n", result.Type, result.Message)

	// ── Encrypt key-value data ──
	kvSecret, err := client.EncryptData(recipient, map[string]string{
		"DB_HOST":     "db.internal:5432",
		"DB_PASSWORD": "super-secret-password",
		"API_KEY":     "ak_live_xyz123",
	}, sdk.EncryptOptions{
		Name:     "sdk-basic-data",
		Compress: compress.Zstd,
	})
	if err != nil {
		log.Fatal("encrypt data: ", err)
	}
	fmt.Printf("Encrypted data → %s\n", kvSecret.Secret.ID)

	kvResult, err := client.DecryptSecret(kvSecret.Secret.ID)
	if err != nil {
		log.Fatal("decrypt data: ", err)
	}
	fmt.Printf("Decrypted: type=%s\n", kvResult.Type)
	for _, kv := range kvResult.Entries {
		fmt.Printf("  %s = %s\n", kv.Key, kv.Value)
	}
	fmt.Println()

	// ── Encrypt raw bytes ──
	jsonPayload := []byte(`{"event":"deploy","version":"2.1.0","env":"production"}`)
	byteSecret, err := client.EncryptBytes(recipient, jsonPayload, sdk.EncryptOptions{
		Name: "sdk-basic-bytes",
	})
	if err != nil {
		log.Fatal("encrypt bytes: ", err)
	}
	fmt.Printf("Encrypted bytes → %s\n", byteSecret.Secret.ID)

	byteResult, err := client.DecryptSecret(byteSecret.Secret.ID)
	if err != nil {
		log.Fatal("decrypt bytes: ", err)
	}
	fmt.Printf("Decrypted: %s\n\n", byteResult.Message)

	// ── List secrets ──
	sent, total, err := client.ListSentSecrets(secrets.ListOptions{Limit: 5})
	if err != nil {
		log.Fatal("list sent: ", err)
	}
	fmt.Printf("Sent secrets: %d (showing %d)\n", total, len(sent))
	for _, s := range sent {
		fmt.Printf("  %s  %s  → %s\n", s.ID[:8], s.Name, s.RecipientEmail)
	}

	// ── Describe secret ──
	info, err := client.DescribeSecret(secret.Secret.ID)
	if err != nil {
		log.Fatal("describe: ", err)
	}
	fmt.Printf("\nSecret detail: %s\n", info.Name)
	fmt.Printf("  From: %s → To: %s\n", info.SenderEmail, info.RecipientEmail)
	fmt.Printf("  Size: %d bytes, Revisions: %d\n", info.TotalSize, info.RevisionCount)

	// ── Delete secrets ──
	if err := client.DeleteSecrets([]string{secret.Secret.ID, kvSecret.Secret.ID, byteSecret.Secret.ID}); err != nil {
		log.Fatal("delete: ", err)
	}
	fmt.Println("\nCleaned up example secrets.")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
