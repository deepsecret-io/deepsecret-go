// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Example basic demonstrates text, key-value, and byte encryption with the
// DeepSecret SDK.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	deepsecret "github.com/deepsecret-io/deepsecret-go"
	"github.com/deepsecret-io/deepsecret-go/keystore"
	"github.com/deepsecret-io/deepsecret-go/secrets"
)

func main() {
	apiURL := envOr("DS_API_URL", "http://localhost:80")
	apiKey := envOr("DS_API_KEY", "")
	// One send encrypts once for every recipient listed.
	recipients := []string{envOr("DS_RECIPIENT", "you@example.com")}

	if apiKey == "" {
		log.Fatal("DS_API_KEY is required")
	}

	fmt.Print("DeepSecret SDK: basic example\n\n")

	client, err := deepsecret.NewClient(apiURL, apiKey)
	if err != nil {
		log.Fatal("new client: ", err)
	}

	// ── Authenticate ──
	me, err := client.Identity.WhoAmI(context.Background())
	if err != nil {
		log.Fatal("whoami: ", err)
	}
	fmt.Printf("Authenticated: %s (%s)\n", me.Name, me.Email)
	fmt.Printf("Plan: %s | Status: %s\n\n", me.TierName, me.SubscriptionStatus)

	// ── Identity ──
	_, fp, err := client.Identity.LoadPrimary(context.Background(), keystore.Unlock{})
	if err != nil {
		log.Fatal("identity: ", err)
	}
	fmt.Printf("Primary key: %s\n\n", fp)

	// ── Encrypt text ──
	secret, err := client.Secrets.EncryptText(context.Background(), recipients, "Hello from the DeepSecret Go SDK!", secrets.EncryptOptions{
		Name: "sdk-basic-text",
	})
	if err != nil {
		log.Fatal("encrypt text: ", err)
	}
	fmt.Printf("Encrypted text → %s (name=%s)\n", secret.Secret.ID, secret.Secret.Name)

	// Decrypt it back
	result, err := client.Secrets.Decrypt(context.Background(), secret.Secret.ID, secrets.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt text: ", err)
	}
	fmt.Printf("Decrypted: type=%s message=%q\n\n", result.Decrypted.Type, result.Decrypted.Message)

	// ── Encrypt key-value data ──
	kvSecret, err := client.Secrets.EncryptData(context.Background(), recipients, map[string]string{
		"DB_HOST":     "db.internal:5432",
		"DB_PASSWORD": "super-secret-password",
		"API_KEY":     "ak_live_xyz123",
	}, secrets.EncryptOptions{
		Name:     "sdk-basic-data",
		Compress: secrets.CompressZstd,
	})
	if err != nil {
		log.Fatal("encrypt data: ", err)
	}
	fmt.Printf("Encrypted data → %s\n", kvSecret.Secret.ID)

	kvResult, err := client.Secrets.Decrypt(context.Background(), kvSecret.Secret.ID, secrets.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt data: ", err)
	}
	fmt.Printf("Decrypted: type=%s\n", kvResult.Decrypted.Type)
	for _, kv := range kvResult.Decrypted.Entries {
		fmt.Printf("  %s = %s\n", kv.Key, kv.Value)
	}
	fmt.Println()

	// ── Encrypt raw bytes ──
	jsonPayload := []byte(`{"event":"deploy","version":"2.1.0","env":"production"}`)
	byteSecret, err := client.Secrets.EncryptBytes(context.Background(), recipients, jsonPayload, secrets.EncryptOptions{
		Name: "sdk-basic-bytes",
	})
	if err != nil {
		log.Fatal("encrypt bytes: ", err)
	}
	fmt.Printf("Encrypted bytes → %s\n", byteSecret.Secret.ID)

	byteResult, err := client.Secrets.Decrypt(context.Background(), byteSecret.Secret.ID, secrets.DecryptOptions{})
	if err != nil {
		log.Fatal("decrypt bytes: ", err)
	}
	fmt.Printf("Decrypted: %s\n\n", byteResult.Decrypted.Message)

	// ── List secrets ──
	sent, total, err := client.Secrets.ListSent(context.Background(), secrets.ListOptions{Limit: 5})
	if err != nil {
		log.Fatal("list sent: ", err)
	}
	fmt.Printf("Sent secrets: %d (showing %d)\n", total, len(sent))
	for _, s := range sent {
		fmt.Printf("  %s  %s  → %s\n", s.ID[:8], s.Name, recipientEmails(s.Recipients))
	}

	// ── Describe secret ──
	info, err := client.Secrets.Describe(context.Background(), secret.Secret.ID)
	if err != nil {
		log.Fatal("describe: ", err)
	}
	fmt.Printf("\nSecret detail: %s\n", info.Name)
	fmt.Printf("  From: %s → To: %s\n", info.SenderEmail, recipientEmails(info.Recipients))
	fmt.Printf("  Size: %d bytes, Revisions: %d\n", info.TotalSize, info.RevisionCount)

	// ── Delete secrets ──
	if err := client.Secrets.Delete(context.Background(), secret.Secret.ID, kvSecret.Secret.ID, byteSecret.Secret.ID); err != nil {
		log.Fatal("delete: ", err)
	}
	fmt.Println("\nCleaned up example secrets.")
}

func recipientEmails(rs []secrets.SecretRecipient) string {
	emails := make([]string, len(rs))
	for i, r := range rs {
		emails[i] = r.Email
	}
	return strings.Join(emails, ", ")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
