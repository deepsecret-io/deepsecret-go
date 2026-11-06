// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"fmt"
	"strings"
)

// validateSymlinkTarget rejects only obviously malformed symlink targets.
// The link string itself is stored verbatim: including absolute paths and
// "../" segments: so the original filesystem state round-trips faithfully.
//
// The extractor relies on a separate guarantee for safety: every regular
// file write goes through ensureInsideDir + O_NOFOLLOW, so even if a symlink
// resolves outside the extraction root, no subsequent write can escape
// through it. The link itself is just an inode pointing at a string.
func validateSymlinkTarget(linkname string) error {
	if linkname == "" {
		return fmt.Errorf("symlink target is empty")
	}
	if strings.ContainsRune(linkname, 0) {
		return fmt.Errorf("symlink target contains null byte")
	}
	return nil
}

// ValidateArchivePath checks that a tar entry name conforms to the portable
// archive path specification. It returns the cleaned path or an error.
//
// # Rules (cross-language specification)
//
//  1. Must not be empty
//  2. Must not contain null bytes
//  3. Must not contain backslash characters (prevents Windows ambiguity)
//  4. Split on "/" into segments
//  5. No empty segments (rejects leading "/", trailing "/", and "a//b")
//  6. No "." segments
//  7. No ".." segments
//  8. Rejoin with "/" and return
//
// This function operates purely on strings with no filesystem access. It is
// deterministic and platform-independent.
func ValidateArchivePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("archive path must not be empty")
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("archive path contains null byte: %q", name)
	}
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("archive path contains backslash (use forward slashes): %q", name)
	}

	segments := strings.Split(name, "/")
	var clean []string
	for _, seg := range segments {
		if seg == "" {
			return "", fmt.Errorf("archive path has empty segment (leading/trailing slash or double slash): %q", name)
		}
		if seg == "." {
			return "", fmt.Errorf("archive path contains '.' segment: %q", name)
		}
		if seg == ".." {
			return "", fmt.Errorf("archive path contains '..' segment: %q", name)
		}
		clean = append(clean, seg)
	}

	return strings.Join(clean, "/"), nil
}

// NormalizeToArchivePath converts a host filesystem relative path to a portable
// archive path. This replaces OS-specific path separators with forward slashes
// and validates the result.
//
// Use this when converting ExpandedFile.RelPath (which may use OS separators)
// to a tar entry name.
func NormalizeToArchivePath(hostRelPath string) (string, error) {
	// Replace OS separators with forward slash for portability
	normalized := strings.ReplaceAll(hostRelPath, "\\", "/")
	return ValidateArchivePath(normalized)
}
