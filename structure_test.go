// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package deepsecret_test

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The import graph is part of the SDK's security: key handling never reaches
// the network code, the domains stay apart, programs that do not use
// security keys do not link package fido2, and programs that do not use AWS
// KMS do not link the AWS SDK.
func TestImportRules(t *testing.T) {
	const mod = "github.com/deepsecret-io/deepsecret-go"
	transport := mod + "/internal/transport"
	aws := "github.com/aws/aws-sdk-go-v2/aws"
	rules := []struct {
		pkg string
		not []string
	}{
		{"./keys", []string{"net/http", transport}},
		{"./keystore", []string{"net/http", transport, mod + "/awskms", aws}},
		{"./internal/protocol", []string{transport}},
		{"./internal/payload", []string{transport}},
		{"./internal/archive", []string{transport}},
		{"./internal/compress", []string{transport}},
		{"./identity", []string{mod + "/secrets", mod + "/trust", mod + "/awskms", aws}},
		{"./trust", []string{mod + "/secrets", mod + "/identity"}},
		{"./secrets", []string{mod + "/awskms", aws}},
		{".", []string{mod + "/fido2", mod + "/awskms", aws}},
	}
	for _, r := range rules {
		// A package that no longer exists fails here rather than passing unchecked.
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", r.pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", r.pkg, err)
		}
		deps := strings.Split(string(out), "\n")
		for _, n := range r.not {
			if slices.Contains(deps, n) {
				t.Errorf("%s imports %s", r.pkg, n)
			}
		}
	}
}

// The root package is client setup only: domain code goes in its own package.
func TestRootStaysSmall(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{.GoFiles}}", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "[client.go doc.go]" {
		t.Errorf("root files = %s", got)
	}
}

func TestModulePath(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(raw), "\n"); first != "module github.com/deepsecret-io/deepsecret-go" {
		t.Errorf("first line = %q", first)
	}
}
