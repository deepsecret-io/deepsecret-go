// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/deepsecret-io/deepsecret-go/internal/payload"
)

// errLink is a path that is a symbolic link where a regular file was
// captured.
var errLink = errors.New("is a symbolic link")

// Capture takes the os.Lstat of path that OpenCaptured later compares the
// opened file with. On Windows a FileInfo learns its file's id only when it
// is first compared, from the path at that moment; Capture compares it
// once here, so the id is the one the file had at the capture.
func Capture(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, info) {
		return nil, fmt.Errorf("%s: its file id could not be read", path)
	}
	return info, nil
}

// OpenCaptured opens the regular file at path for reading, but only while
// path still holds the file captured in info (see Capture). A path that now
// holds another file, a link or nothing fails with an error that wraps
// payload.ErrFileChanged and names path, so a file swapped in after the
// capture is never read under the captured name. The open neither follows a
// symbolic link nor blocks on a FIFO. Identity is the file's device and
// inode (its id on Windows): a rewrite in place keeps it, so the caller
// still checks the byte count it reads against the capture.
func OpenCaptured(path string, info os.FileInfo) (*os.File, error) {
	f, err := openNoFollow(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s %w: it was removed", path, payload.ErrFileChanged)
	case errors.Is(err, errLink):
		return nil, fmt.Errorf("%s %w: it was replaced by a link", path, payload.ErrFileChanged)
	case err != nil:
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	now, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !now.Mode().IsRegular() || !os.SameFile(info, now) {
		_ = f.Close()
		return nil, fmt.Errorf("%s %w: it was replaced", path, payload.ErrFileChanged)
	}
	return f, nil
}
