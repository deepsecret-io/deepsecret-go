// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ExpandedFile represents a file, directory, or symlink discovered during
// path expansion. The kind flags distinguish them:
//
//   - IsDir: directory entry; FullPath is never opened for content.
//   - IsSymlink: symlink entry; LinkTarget holds the link's target as read
//     from the host filesystem (relative or absolute, exactly as on disk).
//   - Otherwise: a regular file; FullPath is opened and streamed.
//
// Directories are emitted so empty trees survive a round trip. Symlinks are
// emitted so node_modules/.bin-style trees stay faithful; the extractor
// validates that the link target stays inside the extracted root.
type ExpandedFile struct {
	FullPath   string
	RelPath    string // portable archive path (forward-slash separated, validated)
	IsDir      bool
	IsSymlink  bool
	LinkTarget string // raw target as read from os.Readlink; only set when IsSymlink
}

// ExpandPaths resolves a list of file and directory paths into a flat,
// deduplicated, sorted list of files suitable for archive creation.
//
// Directories are walked recursively. When skipHidden is true, files and
// directories whose names start with "." are excluded.
//
// # Security
//
//   - Symlinks are never followed (including symlinked input roots)
//   - All relative paths are validated via [ValidateArchivePath]
//   - Duplicate archive paths are rejected (two source files mapping to the
//     same archive name)
//
// # Determinism
//
//   - Results are sorted lexicographically by RelPath
//   - Archive paths use forward slashes on all platforms
//
// # Direct file inputs
//
// When a path is a regular file (not a directory), its archive name is
// filepath.Base(path) — just the filename, not any parent directory. This
// means two files at different host paths with the same basename (e.g.,
// "/a/config.yaml" and "/b/config.yaml") will collide and produce an error.
// To include files from different directories without collision, pass the
// parent directory instead and let the walker preserve the directory structure.
func ExpandPaths(paths []string, skipHidden bool) ([]ExpandedFile, error) {
	var result []ExpandedFile
	seenFullPath := make(map[string]bool)
	seenRelPath := make(map[string]string) // relPath → fullPath (for collision detection)

	for _, p := range paths {
		// Use Lstat to detect symlinks at input roots (don't follow them)
		info, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", p, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("input path is a symlink (not followed): %s", p)
		}

		if info.IsDir() {
			dir := filepath.Clean(p)
			base := filepath.Dir(dir)
			err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					// Propagate real errors instead of silently skipping.
					// This catches permission denied, broken mounts, etc.
					return fmt.Errorf("access %s: %w", path, err)
				}
				if skipHidden && path != dir && strings.HasPrefix(d.Name(), ".") {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				// The walk root itself is recorded by the parent directory's
				// own entry; skip emitting it.
				if path == dir {
					return nil
				}
				rel, err := filepath.Rel(base, path)
				if err != nil {
					return fmt.Errorf("compute relative path: %w", err)
				}
				archivePath, err := NormalizeToArchivePath(rel)
				if err != nil {
					return fmt.Errorf("invalid archive path for %s: %w", path, err)
				}
				if seenFullPath[path] {
					return nil
				}

				// Symlinks: capture the link string verbatim, regardless of
				// where it points. The extractor validates each subsequent
				// write through ensureInsideDir, so a symlink pointing
				// outside the extraction root cannot be used to escape — it
				// just becomes a (possibly dangling) link on the recipient's
				// disk. Symlinked directories are never traversed.
				if d.Type()&os.ModeSymlink != 0 {
					target, lerr := os.Readlink(path)
					if lerr != nil {
						return fmt.Errorf("readlink %s: %w", path, lerr)
					}
					if existing, ok := seenRelPath[archivePath]; ok && existing != path {
						return fmt.Errorf("archive path collision: %q maps to both %s and %s", archivePath, existing, path)
					}
					seenFullPath[path] = true
					seenRelPath[archivePath] = path
					result = append(result, ExpandedFile{
						FullPath:   path,
						RelPath:    archivePath,
						IsSymlink:  true,
						LinkTarget: target,
					})
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if existing, ok := seenRelPath[archivePath]; ok && existing != path {
					return fmt.Errorf("archive path collision: %q maps to both %s and %s", archivePath, existing, path)
				}
				seenFullPath[path] = true
				seenRelPath[archivePath] = path
				result = append(result, ExpandedFile{FullPath: path, RelPath: archivePath, IsDir: d.IsDir()})
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("walk directory %s: %w", p, err)
			}
			// Emit the walk root itself so an entirely empty directory still
			// shows up in the archive. The walker above intentionally skips
			// it to avoid double-recording.
			rel, relErr := filepath.Rel(base, dir)
			if relErr == nil {
				archivePath, archErr := NormalizeToArchivePath(rel)
				if archErr == nil && !seenFullPath[dir] {
					seenFullPath[dir] = true
					seenRelPath[archivePath] = dir
					result = append(result, ExpandedFile{FullPath: dir, RelPath: archivePath, IsDir: true})
				}
			}
		} else {
			archivePath, err := NormalizeToArchivePath(filepath.Base(p))
			if err != nil {
				return nil, fmt.Errorf("invalid archive path for %s: %w", p, err)
			}
			if seenFullPath[p] {
				continue
			}
			if existing, ok := seenRelPath[archivePath]; ok && existing != p {
				return nil, fmt.Errorf("archive path collision: %q maps to both %s and %s", archivePath, existing, p)
			}
			seenFullPath[p] = true
			seenRelPath[archivePath] = p
			result = append(result, ExpandedFile{FullPath: p, RelPath: archivePath})
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no files found in the specified paths")
	}

	// Sort for deterministic archive creation
	sort.Slice(result, func(i, j int) bool {
		return result[i].RelPath < result[j].RelPath
	})

	return result, nil
}
