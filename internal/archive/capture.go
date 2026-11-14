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
		return nil, &payload.FileChangedError{Path: path, Detail: "it was removed"}
	case errors.Is(err, errLink):
		return nil, &payload.FileChangedError{Path: path, Detail: "it was replaced by a link"}
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
		return nil, &payload.FileChangedError{Path: path, Detail: "it was replaced"}
	}
	return f, nil
}

// Captured is a regular file as Capture took it.
type Captured struct {
	Path string
	Info os.FileInfo
}

// Changed lists, in their order, the files that are no longer as captured:
// removed, replaced, or with another size or modification time. In a
// snapshot, a file that only grew is no change: it is sent as captured.
// It reads no file, so it is cheap to run once a send stopped on one.
func Changed(files []Captured, snapshot bool) []string {
	var changed []string
	for _, c := range files {
		now, err := os.Lstat(c.Path)
		switch {
		case err != nil || !now.Mode().IsRegular() || !os.SameFile(c.Info, now):
		case snapshot && now.Size() >= c.Info.Size():
			continue
		case now.Size() == c.Info.Size() && now.ModTime().Equal(c.Info.ModTime()):
			continue
		}
		changed = append(changed, c.Path)
	}
	return changed
}
