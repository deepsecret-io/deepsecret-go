// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Undo records the files, links and directories a write creates, and the
// files it overwrites, so a write that fails midway can remove them. It
// never records anything that was there before and left as it was. A nil
// *Undo records nothing.
type Undo struct {
	paths []string // in the order they were created
}

func (u *Undo) add(path string) {
	if u != nil {
		u.paths = append(u.paths, path)
	}
}

// MkdirAll creates path and its missing parents with perm, as os.MkdirAll
// does, and records each directory it creates.
func (u *Undo) MkdirAll(path string, perm os.FileMode) error {
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("mkdir %s: not a directory", path)
		}
		return nil
	}
	if parent := filepath.Dir(path); parent != path {
		if err := u.MkdirAll(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(path, perm); err != nil {
		// Made by someone else in the meantime: not ours to remove.
		if info, lerr := os.Lstat(path); lerr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	u.add(path)
	return nil
}

// Remove removes what u recorded, newest first, and returns err joined
// with each path it could not remove. A directory is removed only when
// empty, so anything someone else put in it stays, and is reported.
func (u *Undo) Remove(err error) error {
	if u == nil {
		return err
	}
	for i := len(u.paths) - 1; i >= 0; i-- {
		if rmErr := os.Remove(u.paths[i]); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("%s is left behind: %w", u.paths[i], rmErr))
		}
	}
	u.paths = nil
	return err
}

// tempPath returns a fresh name for a temporary file in dir, of a fixed
// length, so a long target name cannot push it past the system's limit.
func tempPath(dir string) string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails; it aborts the program instead.
	return filepath.Join(dir, ".deepsecret-"+hex.EncodeToString(b[:])+".partial")
}
