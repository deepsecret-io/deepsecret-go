// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
)

// Output is the directory a write lands in, opened once as an os.Root.
// Every file, folder and link the write makes, and everything it removes
// when it fails, is named relative to that root, so the kernel resolves
// each name inside it: no write leaves the directory through a link, even
// one another account swaps in for a folder while the write runs, and the
// write goes on in the directory that was opened even if it is moved.
// Content and metadata go only to files and folders the write created,
// through their own handles, so a hard link to a file elsewhere is never
// written either.
//
// Output records what the write creates and the files it overwrites, so
// Remove can take a write that fails midway away again. It never records
// anything that was there before and left as it was.
type Output struct {
	dir  string   // the path it was opened at, for messages
	root *os.Root // the output directory
	made []string // what the write made inside root, oldest first

	// above is the nearest folder above dir that existed, when OpenOutput
	// made dir; madeAbove the folders it made there, dir last.
	above     *os.Root
	madeAbove []string
}

// OpenOutput opens dir for a write, creating it and any missing folders
// above it, each private to this user (0700 with the umask applied; on
// Windows an ACL only this user is on), and records those, so Remove
// takes them away again. dir must be a real directory: a folder above it
// may be a link (such as /tmp on macOS), but dir itself may not, and it is
// checked after it is opened, so a link another account swaps in for it
// around the open is refused too.
func OpenOutput(dir string) (*Output, error) {
	if dir == "" {
		return nil, errors.New("no output directory")
	}
	dir = filepath.Clean(dir)
	base, missing, err := nearestExisting(dir)
	if err != nil {
		return nil, err
	}
	o := &Output{dir: dir}
	if len(missing) == 0 {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, fmt.Errorf("open output directory: %w", err)
		}
		o.root = root
		info, err := os.Lstat(dir)
		if err := o.checkOpened(info, err); err != nil {
			return nil, o.Remove(err)
		}
		return o, nil
	}

	above, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("open %s, the folder that holds the output directory: %w", base, err)
	}
	o.above = above
	rel := ""
	for _, part := range missing {
		rel = filepath.Join(rel, part)
		if err := disk.MkdirIn(above, rel, 0o700); err != nil {
			// Made by someone else in the meantime: not ours to remove.
			if info, lerr := above.Lstat(rel); errors.Is(err, os.ErrExist) && lerr == nil && info.IsDir() {
				continue
			}
			return nil, o.Remove(fmt.Errorf("create output directory %s: %w", filepath.Join(base, rel), err))
		}
		o.madeAbove = append(o.madeAbove, rel)
	}
	root, err := above.OpenRoot(rel)
	if err != nil {
		return nil, o.Remove(fmt.Errorf("open output directory: %w", err))
	}
	o.root = root
	info, err := above.Lstat(rel)
	if err := o.checkOpened(info, err); err != nil {
		return nil, o.Remove(err)
	}
	return o, nil
}

// nearestExisting returns the nearest folder at or above dir that exists,
// and the names of the missing ones below it, outermost first.
func nearestExisting(dir string) (string, []string, error) {
	base := dir
	var missing []string
	for {
		_, err := os.Lstat(base)
		if err == nil {
			return base, missing, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", nil, fmt.Errorf("check output directory %s: %w", dir, err)
		}
		parent := filepath.Dir(base)
		if parent == base {
			return "", nil, fmt.Errorf("output directory %s: no folder above it exists", dir)
		}
		missing = append([]string{filepath.Base(base)}, missing...)
		base = parent
	}
}

// CheckOutputDir refuses dir before a write when what is at it is not a
// real directory, a link to one included, as OpenOutput would. A dir that
// does not exist yet passes. It goes by path: OpenOutput checks again.
func CheckOutputDir(dir string) error {
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check output directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return notADirectory(dir)
	}
	return nil
}

// notADirectory is the error for an output directory that is a link, or
// anything else that is not a real directory.
func notADirectory(dir string) error {
	return fmt.Errorf("output directory %s is not a directory (a link to one is refused: give the directory itself)", dir)
}

// checkOpened refuses the root OpenOutput opened unless info, dir looked
// up after the open without following a link at it, is a real directory
// and the same one.
func (o *Output) checkOpened(info os.FileInfo, err error) error {
	if err != nil {
		return fmt.Errorf("check output directory %s: %w", o.dir, err)
	}
	if !info.IsDir() {
		return notADirectory(o.dir)
	}
	opened, err := o.root.Stat(".")
	if err != nil {
		return fmt.Errorf("check output directory %s: %w", o.dir, err)
	}
	if !os.SameFile(opened, info) {
		return fmt.Errorf("output directory %s changed while it was opened", o.dir)
	}
	return nil
}

// Lstat looks name, a portable path, up inside the output directory
// without following a link at it.
func (o *Output) Lstat(name string) (os.FileInfo, error) {
	return o.root.Lstat(filepath.FromSlash(name))
}

// Close closes the output directory and keeps what the write made.
func (o *Output) Close() error {
	var err error
	if o.root != nil {
		err = o.root.Close()
		o.root = nil
	}
	if o.above != nil {
		err = errors.Join(err, o.above.Close())
		o.above = nil
	}
	o.made, o.madeAbove = nil, nil
	return err
}

// Remove removes what the write made, newest first, the folders OpenOutput
// made last, closes the output directory, and returns err joined with each
// path it could not remove. A folder is removed only when empty, so
// anything someone else put in it stays, and is reported.
func (o *Output) Remove(err error) error {
	if o.root != nil {
		for i := len(o.made) - 1; i >= 0; i-- {
			if rmErr := o.root.Remove(o.made[i]); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("%s is left behind: %w", o.path(o.made[i]), rmErr))
			}
		}
		// Closed before the folders above go: Windows may not remove a
		// folder that is open.
		_ = o.root.Close() // a directory handle, only read
		o.root = nil
	}
	if o.above != nil {
		for i := len(o.madeAbove) - 1; i >= 0; i-- {
			if rmErr := o.above.Remove(o.madeAbove[i]); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("%s is left behind: %w", filepath.Join(o.above.Name(), o.madeAbove[i]), rmErr))
			}
		}
		_ = o.above.Close() // a directory handle, only read
		o.above = nil
	}
	o.made, o.madeAbove = nil, nil
	return err
}

// path is the path of rel, a name inside the output directory, for
// messages and results.
func (o *Output) path(rel string) string {
	return filepath.Join(o.dir, rel)
}

// WriteFile writes one file into the output directory the way extraction
// writes a regular entry: name is checked as a portable path, missing
// folders on the way are created, a folder on the way that is a link or
// not a folder is refused, and the file is created new, never through a
// link at its name and, unless allowOverwrite, never over anything.
// Missing folders are private (0700), and so is the file whatever mode
// asks for: 0600, or 0700 when mode has the owner's execute bit
// (privatePerm), with the umask applied, also when it replaces an old
// file. It writes at most maxSize bytes from r and returns the file's path
// and the bytes written.
func (o *Output) WriteFile(name string, mode os.FileMode, r io.Reader, maxSize int64, allowOverwrite bool) (string, int64, error) {
	cleanName, err := ValidateArchivePath(name)
	if err != nil {
		return "", 0, fmt.Errorf("unsafe file name: %w", err)
	}
	rel := filepath.FromSlash(cleanName)
	if err := o.walkParents(rel, true); err != nil {
		return "", 0, fmt.Errorf("file %q: %w", cleanName, err)
	}
	written, err := o.writeNew(rel, privatePerm(mode, false), r, maxSize, allowOverwrite, nil)
	if err != nil {
		return "", 0, fmt.Errorf("write %q: %w", cleanName, err)
	}
	o.made = append(o.made, rel)
	return o.path(rel), written, nil
}

// walkParents checks that every folder above rel inside the output
// directory that is there is a real folder, not a link or a file. With
// create it creates the missing ones, private (0700), and records them;
// without, it stops at the first missing one. So no entry is created,
// linked or recorded through a link that is there when it is checked, and
// no later entry can redirect a name an earlier one used (cleanup,
// directory times). A link another account swaps in for a folder after
// the check is followed only inside the output directory (os.Root): it can
// move a write elsewhere inside the output directory, never out of it.
func (o *Output) walkParents(rel string, create bool) error {
	dir := filepath.Dir(rel)
	if dir == "." {
		return nil
	}
	p := ""
	for _, part := range strings.Split(dir, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		info, err := o.root.Lstat(p)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", o.path(p))
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !create {
			return nil
		}
		if err := disk.MkdirIn(o.root, p, 0o700); err != nil {
			// Made by someone else in the meantime: not ours to remove.
			if info, lerr := o.root.Lstat(p); errors.Is(err, os.ErrExist) && lerr == nil && info.IsDir() {
				continue
			}
			return fmt.Errorf("mkdir %s: %w", o.path(p), err)
		}
		o.made = append(o.made, p)
	}
	return nil
}

// writeNew writes at most maxSize bytes from r into a new file at rel and
// returns how many it wrote. Without allowOverwrite it creates rel itself,
// refusing one that exists, a link included. With it, it writes a new
// file beside rel and renames it over rel once complete, so rel gets mode
// (with the umask applied; private to this user on Windows) instead of
// keeping an old file's, a link at rel is replaced rather than written
// through, and a reader never sees half a file. finish, when not nil, sets
// the new file's metadata through its handle before it is closed.
func (o *Output) writeNew(rel string, mode os.FileMode, r io.Reader, maxSize int64, allowOverwrite bool, finish func(*os.File)) (int64, error) {
	name := rel
	if allowOverwrite {
		name = tempName(rel)
	}
	f, err := disk.CreateIn(o.root, name, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return 0, fmt.Errorf("destination already exists: %s", o.path(name))
		}
		return 0, fmt.Errorf("open %s: %w", o.path(name), err)
	}

	// One byte past maxSize tells a source that is too long; maxSize+1
	// would overflow when maxSize is math.MaxInt64.
	limit := maxSize
	if limit < math.MaxInt64 {
		limit++
	}
	written, err := io.Copy(f, io.LimitReader(r, limit))
	if err == nil && written > maxSize {
		err = fmt.Errorf("content exceeds size limit %d", maxSize)
	}
	if err == nil && finish != nil {
		finish(f)
	}
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err == nil && name != rel {
		if rnErr := o.root.Rename(name, rel); rnErr != nil {
			err = fmt.Errorf("replace %s: %w", o.path(rel), rnErr)
		}
	}
	if err != nil {
		return 0, o.removeAfter(name, err)
	}
	return written, nil
}

// removeAfter removes name, a file err left incomplete, and returns err,
// joined with the reason when the file could not be removed, so a partly
// written file is never left behind unreported.
func (o *Output) removeAfter(name string, err error) error {
	if rmErr := o.root.Remove(name); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return errors.Join(err, fmt.Errorf("the partly written %s is left behind: %w", o.path(name), rmErr))
	}
	return err
}

// replaceLeaf makes room for a link at rel: nothing there is fine; an
// existing file or link is removed only with allowOverwrite; a directory
// is never removed, so no name an earlier entry used can change meaning.
func (o *Output) replaceLeaf(rel string, allowOverwrite bool) error {
	info, err := o.root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowOverwrite || info.IsDir() {
		return fmt.Errorf("destination already exists: %s", o.path(rel))
	}
	if err := o.root.Remove(rel); err != nil {
		return fmt.Errorf("remove existing %s: %w", o.path(rel), err)
	}
	return nil
}

// tempName returns a fresh name for a temporary file beside rel, of a
// fixed length, so a long target name cannot push it past the system's
// limit.
func tempName(rel string) string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails; it aborts the program instead.
	return filepath.Join(filepath.Dir(rel), ".deepsecret-"+hex.EncodeToString(b[:])+".partial")
}
