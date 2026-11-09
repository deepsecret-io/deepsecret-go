// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package disktest checks, in tests, that a file or folder is private to
// this user the way the disk package makes it: mode 0600 or 0700 on Unix,
// an owner-only ACL on Windows. Only tests import it.
package disktest
