// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package archive

import "os"

// openNoFollow opens path for reading. Windows has no O_NOFOLLOW here:
// OpenCaptured compares the opened file with the capture, which refuses a
// link to another file.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- a file the caller chose to send, checked against its capture.
}
