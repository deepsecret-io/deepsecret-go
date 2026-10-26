// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"github.com/deepsecret-io/sdk/compress"
	"sort"
	"strings"
	"time"
)

// TarEntry represents an in-memory file for archive creation or extraction.
type TarEntry struct {
	Name string      // portable archive path (forward-slash separated)
	Data []byte      // file content
	Mode os.FileMode // permission bits only (e.g. 0644). Non-permission bits are stripped.
}

// canonicalTime is the fixed timestamp used for deterministic tar headers.
var canonicalTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// modeBits masks a Unix-style mode to the bits we preserve in tar: nine
// permission bits plus setuid (04000), setgid (02000), and sticky (01000).
// Type bits (S_IFMT) are excluded — tar carries those in Typeflag.
const modeBits int64 = 0o7777

// goModeToUnix translates a Go os.FileMode into its Unix equivalent for
// tar's int64 Mode field. Go puts setuid/setgid/sticky at bits 23/22/20
// rather than the canonical Unix positions 11/10/9, so a naive `int64(m)`
// loses those special bits. This helper is the only correct way to round
// trip them through tar.
func goModeToUnix(m os.FileMode) int64 {
	out := int64(m.Perm())
	if m&os.ModeSetuid != 0 {
		out |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		out |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		out |= 0o1000
	}
	return out
}

// unixModeToGo is the inverse of goModeToUnix: it translates a tar header
// Mode (Unix bits 0–11) back into an os.FileMode whose ModeSetuid/Setgid/
// Sticky flags match. Used when applying the mode via os.Chmod, which
// reads those flags from their Go-native bit positions.
func unixModeToGo(m int64) os.FileMode {
	out := os.FileMode(m & 0o0777)
	if m&0o4000 != 0 {
		out |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		out |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		out |= os.ModeSticky
	}
	return out
}

// xattrPrefix is the PAX extended-header prefix Schily / GNU tar use for
// extended attributes. Format: SCHILY.xattr.<attr-name>=<value>. Compatible
// with `tar --xattrs --xattrs-include='*'` and BSD tar.
const xattrPrefix = "SCHILY.xattr."

// attachXattrs adds extended-attribute records to a tar header in the
// SCHILY.xattr.* PAX namespace. No-op when xattrs is empty or nil so callers
// don't have to branch.
func attachXattrs(hdr *tar.Header, xattrs map[string]string) {
	if len(xattrs) == 0 {
		return
	}
	if hdr.PAXRecords == nil {
		hdr.PAXRecords = make(map[string]string, len(xattrs))
	}
	for name, value := range xattrs {
		hdr.PAXRecords[xattrPrefix+name] = value
	}
}

// extractXattrs is the inverse of attachXattrs: pulls SCHILY.xattr.* entries
// out of a header's PAXRecords back into a name → value map.
func extractXattrs(hdr *tar.Header) map[string]string {
	if len(hdr.PAXRecords) == 0 {
		return nil
	}
	var out map[string]string
	for k, v := range hdr.PAXRecords {
		if strings.HasPrefix(k, xattrPrefix) {
			if out == nil {
				out = map[string]string{}
			}
			out[k[len(xattrPrefix):]] = v
		}
	}
	return out
}

// applyXattrsBestEffort writes each xattr to path. Per-attribute failures
// are silent — common reasons (cross-platform name namespaces, unsupported
// FS, missing capabilities for security.*) are routine and shouldn't
// derail extraction. Critical bytes (file content, mode, mtime) are
// written unconditionally elsewhere; xattrs are pure metadata.
func applyXattrsBestEffort(path string, xattrs map[string]string) {
	for name, value := range xattrs {
		_ = writeXattr(path, name, value)
	}
}

// ── Streaming creation APIs (primary) ────────────────────────────────────────

// WriteTar streams files into a compressed tar archive written to w.
//
// This is the primary creation API. File contents are streamed from disk
// through the tar writer and compressor to w without buffering the full
// archive in memory.
//
// Files are written in the order provided (use [ExpandPaths] for sorted input).
// Each RelPath is validated and used as the tar entry name. Duplicate paths
// are rejected. See [CreateTar] docs for header normalization details.
func WriteTar(w io.Writer, files []ExpandedFile, algo compress.Algorithm) error {
	return writeTar(w, files, algo, false)
}

// TarSize returns the exact length of the uncompressed archive WriteTar
// writes for files, without reading their contents: each regular file is
// written as zeros of its current size. If a file changes before WriteTar
// runs, the archive's length can differ.
func TarSize(files []ExpandedFile) (int64, error) {
	var cw countingWriter
	if err := writeTar(&cw, files, compress.None, true); err != nil {
		return 0, err
	}
	return cw.n, nil
}

// writeTar is WriteTar; with zeros it writes each regular file's content as
// zeros of its size instead of reading it, which gives TarSize.
func writeTar(w io.Writer, files []ExpandedFile, algo compress.Algorithm, zeros bool) error {
	if len(files) == 0 {
		return fmt.Errorf("no files to archive")
	}

	seen := make(map[string]bool, len(files))
	for _, ef := range files {
		archivePath, err := ValidateArchivePath(ef.RelPath)
		if err != nil {
			return fmt.Errorf("invalid archive path for %s: %w", ef.FullPath, err)
		}
		if seen[archivePath] {
			return fmt.Errorf("duplicate archive path: %q", archivePath)
		}
		seen[archivePath] = true
	}

	wc, err := compress.NewCompressWriter(w, algo)
	if err != nil {
		return fmt.Errorf("compression writer: %w", err)
	}
	tw := tar.NewWriter(wc)

	// Track inodes we've already emitted so subsequent occurrences are
	// stored as hard links instead of duplicated content. Keyed by the
	// composite (dev, ino) — see sysFileInfo.hardLinkKey.
	inodeIndex := map[uint64]string{}

	for _, ef := range files {
		info, err := os.Lstat(ef.FullPath)
		if err != nil {
			return fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		archivePath, _ := ValidateArchivePath(ef.RelPath)
		sys := sysStat(info)

		// xattrs are best-effort backup metadata. Capture per-entry; PAX
		// records carry them through unchanged.
		xattrs, _ := readXattrs(ef.FullPath)

		if ef.IsSymlink {
			if info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("%s declared as symlink but is not", ef.FullPath)
			}
			hdr := &tar.Header{
				Format:   tar.FormatPAX,
				Typeflag: tar.TypeSymlink,
				Name:     archivePath,
				Linkname: ef.LinkTarget,
				Mode:     0o777, // kernel ignores symlink mode
				ModTime:  info.ModTime().UTC(),
				Uid:      sys.Uid, Gid: sys.Gid,
			}
			attachXattrs(hdr, xattrs)
			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("tar symlink header %s: %w", archivePath, err)
			}
			continue
		}

		if ef.IsDir {
			if !info.IsDir() {
				return fmt.Errorf("%s declared as dir but is not", ef.FullPath)
			}
			name := archivePath
			if !strings.HasSuffix(name, "/") {
				name += "/"
			}
			hdr := &tar.Header{
				Format:   tar.FormatPAX,
				Typeflag: tar.TypeDir,
				Name:     name,
				Mode:     goModeToUnix(info.Mode()),
				ModTime:  info.ModTime().UTC(),
				Uid:      sys.Uid, Gid: sys.Gid,
			}
			attachXattrs(hdr, xattrs)
			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("tar dir header %s: %w", name, err)
			}
			continue
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", ef.FullPath)
		}

		// Hard-link detection: if this inode has already been emitted as a
		// regular file, emit a TypeLink referencing the first occurrence.
		// Skipped on platforms where inode info is unavailable.
		if sys.Nlink > 1 {
			if key, ok := sys.hardLinkKey(); ok {
				if first, seen := inodeIndex[key]; seen {
					hdr := &tar.Header{
						Format:   tar.FormatPAX,
						Typeflag: tar.TypeLink,
						Name:     archivePath,
						Linkname: first,
						ModTime:  info.ModTime().UTC(),
						Uid:      sys.Uid, Gid: sys.Gid,
					}
					if err := tw.WriteHeader(hdr); err != nil {
						return fmt.Errorf("tar hardlink header %s: %w", archivePath, err)
					}
					continue
				}
				inodeIndex[key] = archivePath
			}
		}

		hdr := &tar.Header{
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
			Name:     archivePath,
			Size:     info.Size(),
			Mode:     goModeToUnix(info.Mode()),
			ModTime:  info.ModTime().UTC(),
			Uid:      sys.Uid, Gid: sys.Gid,
		}
		attachXattrs(hdr, xattrs)
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", archivePath, err)
		}

		if zeros {
			if _, err := io.CopyN(tw, zeroReader{}, info.Size()); err != nil {
				return fmt.Errorf("tar write %s: %w", archivePath, err)
			}
			continue
		}
		f, err := os.Open(ef.FullPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", ef.FullPath, err)
		}
		_, copyErr := io.Copy(tw, f)
		f.Close()
		if copyErr != nil {
			return fmt.Errorf("tar write %s: %w", archivePath, copyErr)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return wc.Close()
}

// WriteTarFromBytes streams in-memory entries into a compressed tar archive
// written to w.
//
// Entries are sorted lexicographically by name for determinism. Headers are
// fully normalized for byte-identical output. See [CreateTarFromBytes] docs.
func WriteTarFromBytes(w io.Writer, entries []TarEntry, algo compress.Algorithm) error {
	if len(entries) == 0 {
		return fmt.Errorf("no entries to archive")
	}

	sorted := make([]TarEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	seen := make(map[string]bool, len(sorted))
	for i := range sorted {
		archivePath, err := ValidateArchivePath(sorted[i].Name)
		if err != nil {
			return fmt.Errorf("invalid archive entry name: %w", err)
		}
		if seen[archivePath] {
			return fmt.Errorf("duplicate archive entry: %q", archivePath)
		}
		seen[archivePath] = true
		sorted[i].Name = archivePath
		sorted[i].Mode = sorted[i].Mode & os.FileMode(modeBits)
	}

	wc, err := compress.NewCompressWriter(w, algo)
	if err != nil {
		return fmt.Errorf("compression writer: %w", err)
	}
	tw := tar.NewWriter(wc)

	for _, e := range sorted {
		mode := e.Mode
		if mode == 0 {
			mode = 0644
		}
		hdr := &tar.Header{
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
			Name:     e.Name,
			Size:     int64(len(e.Data)),
			Mode:     int64(mode),
			ModTime:  canonicalTime,
			Uid:      0, Gid: 0, Uname: "", Gname: "",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", e.Name, err)
		}
		if _, err := tw.Write(e.Data); err != nil {
			return fmt.Errorf("tar write %s: %w", e.Name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return wc.Close()
}

// TarStreamEntry represents a file whose content is provided by a reader,
// enabling end-to-end streaming without loading file data into memory.
//
// Size MUST be set to the exact number of bytes the Reader will produce.
// WriteTarStream reads exactly Size bytes from Reader and verifies the count.
// Reader must not be nil. Size must not be negative.
type TarStreamEntry struct {
	Name   string      // portable archive path (forward-slash separated)
	Size   int64       // exact content size in bytes (must be >= 0)
	Mode   os.FileMode // permission bits (e.g. 0644). Non-permission bits are stripped.
	Reader io.Reader   // content source — exactly Size bytes are read
}

// WriteTarStream streams reader-backed entries into a compressed tar archive.
//
// This is the fully streaming creation API — no entry content is buffered in
// memory. Each entry's Reader is read for exactly Size bytes and streamed
// directly into the tar writer.
//
// # Entry order
//
// Entries are written in the order provided. Unlike [WriteTarFromBytes], this
// function does NOT sort entries — the caller is responsible for ordering if
// deterministic output is needed (readers cannot be rewound for sorting).
//
// # Validation
//
//   - Names are validated via [ValidateArchivePath]; duplicates are rejected
//   - Negative Size is rejected
//   - Nil Reader is rejected
//   - If Reader produces fewer than Size bytes, an error is returned
//   - If Reader would produce more than Size bytes, only Size bytes are read
//     (excess remains unread in the source reader)
//
// Headers use canonical metadata (ModTime: 2000-01-01, uid/gid: 0).
func WriteTarStream(w io.Writer, entries []TarStreamEntry, algo compress.Algorithm) error {
	if len(entries) == 0 {
		return fmt.Errorf("no entries to archive")
	}

	// Validate all entries upfront
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		archivePath, err := ValidateArchivePath(e.Name)
		if err != nil {
			return fmt.Errorf("entry %d: invalid archive name: %w", i, err)
		}
		if seen[archivePath] {
			return fmt.Errorf("duplicate archive entry: %q", archivePath)
		}
		seen[archivePath] = true
		if e.Size < 0 {
			return fmt.Errorf("entry %q: negative size %d", archivePath, e.Size)
		}
		if e.Reader == nil {
			return fmt.Errorf("entry %q: reader must not be nil", archivePath)
		}
	}

	wc, err := compress.NewCompressWriter(w, algo)
	if err != nil {
		return fmt.Errorf("compression writer: %w", err)
	}
	tw := tar.NewWriter(wc)

	for _, e := range entries {
		archivePath, _ := ValidateArchivePath(e.Name) // already validated
		mode := e.Mode & os.FileMode(modeBits)
		if mode == 0 {
			mode = 0644
		}
		hdr := &tar.Header{
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
			Name:     archivePath,
			Size:     e.Size,
			Mode:     int64(mode),
			ModTime:  canonicalTime,
			Uid:      0, Gid: 0, Uname: "", Gname: "",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", archivePath, err)
		}

		// Read exactly Size bytes: LimitReader caps the read, then verify count
		written, err := io.Copy(tw, io.LimitReader(e.Reader, e.Size))
		if err != nil {
			return fmt.Errorf("tar write %s: %w", archivePath, err)
		}
		if written != e.Size {
			return fmt.Errorf("tar entry %s: declared size %d but reader produced only %d bytes",
				archivePath, e.Size, written)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return wc.Close()
}

// ── Streaming extraction APIs (primary) ──────────────────────────────────────

// ExtractTarReader extracts a compressed tar archive from a reader to outputDir.
//
// This is the primary extraction API. It streams data from r through the
// decompressor and tar reader to disk without buffering the full archive in
// memory.
//
// All security guarantees from [ExtractTar] apply: path validation, duplicate
// rejection, type rejection, size limits, symlink escape checks, atomic writes.
//
// outputDir is created if it does not exist.
//
// Returns the number of files successfully extracted.
func ExtractTarReader(r io.Reader, outputDir string, algo compress.Algorithm, limits *Limits) (int, error) {
	lim := limits.resolve()

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return 0, fmt.Errorf("create output directory %q: %w", outputDir, err)
	}
	if info, err := os.Stat(outputDir); err != nil {
		return 0, fmt.Errorf("stat output directory %q: %w", outputDir, err)
	} else if !info.IsDir() {
		return 0, fmt.Errorf("output path %q exists but is not a directory", outputDir)
	}

	rc, err := compress.NewDecompressReader(r, algo)
	if err != nil {
		return 0, fmt.Errorf("decompression reader: %w", err)
	}
	defer rc.Close()

	return extractTarFromReader(rc, outputDir, lim)
}

// ValidateTarReader checks an archive the way ExtractTarReader would
// extract it, without writing anything: entry types, paths and their
// lengths, duplicates, symlink and hard-link targets, and the limits. A hard
// link must point at a regular file earlier in the archive, and no entry may
// sit under an earlier entry that is not a directory. It returns the paths
// of the entries that create files or links, in order, so the caller can
// check their destinations, and the regular files' total size.
func ValidateTarReader(r io.Reader, algo compress.Algorithm, limits *Limits) ([]string, int64, error) {
	lim := limits.resolve()
	rc, err := compress.NewDecompressReader(r, algo)
	if err != nil {
		return nil, 0, fmt.Errorf("decompression reader: %w", err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	var names []string
	kinds := make(map[string]byte) // entry type by path
	var totalSize, nameBytes int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names, totalSize, nil
		}
		if err != nil {
			return nil, 0, fmt.Errorf("tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir &&
			hdr.Typeflag != tar.TypeSymlink && hdr.Typeflag != tar.TypeLink {
			return nil, 0, fmt.Errorf("unsupported tar entry type %d for %q (only regular files, directories, symlinks, and hard links allowed)",
				hdr.Typeflag, hdr.Name)
		}
		if err := checkNameLimits(hdr.Name, &nameBytes, lim); err != nil {
			return nil, 0, err
		}
		cleanName, err := ValidateArchivePath(strings.TrimRight(hdr.Name, "/"))
		if err != nil {
			return nil, 0, fmt.Errorf("unsafe archive entry: %w", err)
		}
		if _, dup := kinds[cleanName]; dup {
			return nil, 0, fmt.Errorf("duplicate archive entry: %q", cleanName)
		}
		// Extraction cannot create an entry under a file or a link.
		for i := strings.Index(cleanName, "/"); i >= 0; i = nextSlash(cleanName, i) {
			if kind, seen := kinds[cleanName[:i]]; seen && kind != tar.TypeDir {
				return nil, 0, fmt.Errorf("entry %q is inside %q, which is not a directory", cleanName, cleanName[:i])
			}
		}
		kinds[cleanName] = hdr.Typeflag
		if len(kinds) > lim.MaxEntries {
			return nil, 0, fmt.Errorf("archive exceeds maximum entry count (%d)", lim.MaxEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeSymlink:
			if err := validateSymlinkTarget(hdr.Linkname); err != nil {
				return nil, 0, fmt.Errorf("unsafe symlink %q -> %q: %w", cleanName, hdr.Linkname, err)
			}
		case tar.TypeLink:
			target, err := ValidateArchivePath(hdr.Linkname)
			if err != nil {
				return nil, 0, fmt.Errorf("hardlink %q has invalid target %q: %w", cleanName, hdr.Linkname, err)
			}
			if kinds[target] != tar.TypeReg {
				return nil, 0, fmt.Errorf("hardlink %q points at %q, which is not an earlier file", cleanName, target)
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return nil, 0, fmt.Errorf("entry %q has negative size %d", cleanName, hdr.Size)
			}
			if hdr.Size > lim.MaxEntrySize {
				return nil, 0, fmt.Errorf("entry %q declares size %d exceeding limit %d", cleanName, hdr.Size, lim.MaxEntrySize)
			}
			if totalSize+hdr.Size > lim.MaxTotalSize {
				return nil, 0, fmt.Errorf("entry %q (size %d) would exceed total size limit %d (current total: %d)",
					cleanName, hdr.Size, lim.MaxTotalSize, totalSize)
			}
			totalSize += hdr.Size
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, 0, fmt.Errorf("tar read %q: %w", cleanName, err)
			}
		}
		names = append(names, cleanName)
	}
}

// nextSlash returns the index of the next "/" in name after i, or -1.
func nextSlash(name string, i int) int {
	j := strings.Index(name[i+1:], "/")
	if j < 0 {
		return -1
	}
	return i + 1 + j
}

// checkNameLimits refuses an entry name over MaxNameLen, or one that takes
// all names past MaxNameBytes.
func checkNameLimits(name string, total *int64, lim *Limits) error {
	if len(name) > lim.MaxNameLen {
		return fmt.Errorf("archive entry name is %d bytes, the limit is %d", len(name), lim.MaxNameLen)
	}
	*total += int64(len(name))
	if *total > lim.MaxNameBytes {
		return fmt.Errorf("archive entry names exceed %d bytes in all", lim.MaxNameBytes)
	}
	return nil
}

// extractTarFromReader is the shared extraction core used by both
// ExtractTarReader and ExtractTar.
func extractTarFromReader(r io.Reader, outputDir string, lim *Limits) (int, error) {
	tr := tar.NewReader(r)
	count := 0
	var totalSize int64
	seenNames := make(map[string]bool)
	// Restoring directory mtimes is deferred to the end of extraction
	// because writing files into a directory updates that directory's
	// mtime. We collect (path, mtime) pairs as we go and apply them in
	// reverse depth order once all entries are written.
	type pendingDirTime struct {
		path  string
		mtime time.Time
	}
	var dirTimes []pendingDirTime
	var nameBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("tar read: %w", err)
		}
		if err := checkNameLimits(hdr.Name, &nameBytes, lim); err != nil {
			return count, err
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir &&
			hdr.Typeflag != tar.TypeSymlink && hdr.Typeflag != tar.TypeLink {
			return count, fmt.Errorf("unsupported tar entry type %d for %q (only regular files, directories, symlinks, and hard links allowed)",
				hdr.Typeflag, hdr.Name)
		}

		// Tar conventionally encodes directories with a trailing slash. Strip
		// it for path validation (which rejects them) but remember the kind.
		rawName := strings.TrimRight(hdr.Name, "/")
		cleanName, err := ValidateArchivePath(rawName)
		if err != nil {
			return count, fmt.Errorf("unsafe archive entry: %w", err)
		}

		if seenNames[cleanName] {
			return count, fmt.Errorf("duplicate archive entry: %q", cleanName)
		}
		seenNames[cleanName] = true

		if len(seenNames) > lim.MaxEntries {
			return count, fmt.Errorf("archive exceeds maximum entry count (%d)", lim.MaxEntries)
		}

		target := filepath.Join(outputDir, filepath.FromSlash(cleanName))

		if err := ensureInsideDir(outputDir, target); err != nil {
			return count, fmt.Errorf("symlink escape for %q: %w", cleanName, err)
		}

		if hdr.Typeflag == tar.TypeDir {
			mode := lim.entryMode(hdr.Mode)
			if mode.Perm() == 0 {
				mode |= 0o755
			}
			if err := os.MkdirAll(target, mode.Perm()); err != nil {
				return count, fmt.Errorf("mkdir %q: %w", cleanName, err)
			}
			// chown first so its sgid-clearing doesn't undo our chmod.
			if lim.KeepOwnership {
				_ = lchown(target, hdr.Uid, hdr.Gid)
			}
			// MkdirAll only sets mode when creating; restore explicitly so
			// pre-existing dirs and special bits (sgid, sticky) round-trip.
			_ = os.Chmod(target, mode)
			applyXattrsBestEffort(target, extractXattrs(hdr))
			if !hdr.ModTime.IsZero() {
				dirTimes = append(dirTimes, pendingDirTime{path: target, mtime: hdr.ModTime})
			}
			continue
		}

		if hdr.Typeflag == tar.TypeSymlink {
			if err := validateSymlinkTarget(hdr.Linkname); err != nil {
				return count, fmt.Errorf("unsafe symlink %q -> %q: %w", cleanName, hdr.Linkname, err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, fmt.Errorf("mkdir for symlink %q: %w", cleanName, err)
			}
			if _, err := os.Lstat(target); err == nil {
				if !lim.AllowOverwrite {
					return count, fmt.Errorf("destination already exists: %s", target)
				}
				if rmErr := os.Remove(target); rmErr != nil {
					return count, fmt.Errorf("remove existing %s: %w", target, rmErr)
				}
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return count, fmt.Errorf("symlink %q: %w", cleanName, err)
			}
			if lim.KeepOwnership {
				_ = lchown(target, hdr.Uid, hdr.Gid)
			}
			applyXattrsBestEffort(target, extractXattrs(hdr))
			if !hdr.ModTime.IsZero() {
				_ = lchtimes(target, hdr.ModTime)
			}
			continue
		}

		if hdr.Typeflag == tar.TypeLink {
			// Hard link to a previously-extracted file. Resolve the target
			// inside outputDir and verify it stays in-tree, then create
			// the link. Falls through to file-create on platforms / FS that
			// don't support hard links.
			if hdr.Linkname == "" {
				return count, fmt.Errorf("hardlink %q has empty target", cleanName)
			}
			linkSrcRel, err := ValidateArchivePath(hdr.Linkname)
			if err != nil {
				return count, fmt.Errorf("hardlink %q has invalid target %q: %w", cleanName, hdr.Linkname, err)
			}
			linkSrc := filepath.Join(outputDir, filepath.FromSlash(linkSrcRel))
			if err := ensureInsideDir(outputDir, linkSrc); err != nil {
				return count, fmt.Errorf("hardlink target escape for %q: %w", cleanName, err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, fmt.Errorf("mkdir for hardlink %q: %w", cleanName, err)
			}
			if _, err := os.Lstat(target); err == nil {
				if !lim.AllowOverwrite {
					return count, fmt.Errorf("destination already exists: %s", target)
				}
				if rmErr := os.Remove(target); rmErr != nil {
					return count, fmt.Errorf("remove existing %s: %w", target, rmErr)
				}
			}
			if err := os.Link(linkSrc, target); err != nil {
				return count, fmt.Errorf("hardlink %q -> %q: %w", cleanName, linkSrcRel, err)
			}
			count++
			continue
		}

		if hdr.Size < 0 {
			return count, fmt.Errorf("entry %q has negative size %d", cleanName, hdr.Size)
		}
		if hdr.Size > lim.MaxEntrySize {
			return count, fmt.Errorf("entry %q declares size %d exceeding limit %d",
				cleanName, hdr.Size, lim.MaxEntrySize)
		}
		if totalSize+hdr.Size > lim.MaxTotalSize {
			return count, fmt.Errorf("entry %q (size %d) would exceed total size limit %d (current total: %d)",
				cleanName, hdr.Size, lim.MaxTotalSize, totalSize)
		}

		targetDir := filepath.Dir(target)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return count, fmt.Errorf("mkdir for %q: %w", cleanName, err)
		}

		// Re-verify after MkdirAll to detect a race where a directory was
		// swapped for a symlink between the checks.
		if err := ensureInsideDir(outputDir, target); err != nil {
			return count, fmt.Errorf("symlink escape (post-mkdir) for %q: %w", cleanName, err)
		}

		mode := lim.entryMode(hdr.Mode)
		if mode.Perm() == 0 {
			mode |= 0o644
		}

		// writeFileAtomicBounded only honours the standard 9-bit perm in
		// the open(2) mode argument; setuid/setgid/sticky get applied by
		// the os.Chmod(target, mode) call after the write completes.
		written, err := writeFileAtomicBounded(target, targetDir, mode.Perm(), tr, lim.MaxEntrySize, lim.AllowOverwrite)
		if err != nil {
			return count, fmt.Errorf("write %q: %w", cleanName, err)
		}

		totalSize += written
		if totalSize > lim.MaxTotalSize {
			os.Remove(target)
			return count, fmt.Errorf("archive exceeds total size limit %d", lim.MaxTotalSize)
		}

		// Restore owner first — POSIX chown(2) clears setuid/setgid for
		// security, so any chmod has to come after to keep those bits.
		// Then mode (covers setuid/setgid/sticky), xattrs, and finally
		// mtime so attribute writes don't bump it. Each step is
		// best-effort; missing privileges or unsupported FS features
		// must not fail the whole extraction.
		if lim.KeepOwnership {
			_ = lchown(target, hdr.Uid, hdr.Gid)
		}
		_ = os.Chmod(target, mode)
		applyXattrsBestEffort(target, extractXattrs(hdr))
		if !hdr.ModTime.IsZero() {
			_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
		}

		count++
	}

	// Apply directory mtimes from deepest to shallowest so writing into a
	// child doesn't roll the parent's mtime forward after we restore it.
	for i := len(dirTimes) - 1; i >= 0; i-- {
		_ = os.Chtimes(dirTimes[i].path, dirTimes[i].mtime, dirTimes[i].mtime)
	}

	return count, nil
}

// ── Convenience APIs ([]byte, for small payloads) ────────────────────────────
//
// These buffer the full archive in memory. For large archives, prefer the
// streaming APIs: [WriteTar], [WriteTarFromBytes], [ExtractTarReader].

// CreateTar bundles files into a compressed tar archive, returning the bytes.
// This is a convenience wrapper over [WriteTar].
//
// See [WriteTar] for full documentation on security, determinism, and headers.
func CreateTar(files []ExpandedFile, algo compress.Algorithm) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteTar(&buf, files, algo); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CreateTarFromBytes bundles in-memory entries into a compressed tar archive.
// This is a convenience wrapper over [WriteTarFromBytes].
//
// See [WriteTarFromBytes] for full documentation on determinism and validation.
func CreateTarFromBytes(entries []TarEntry, algo compress.Algorithm) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteTarFromBytes(&buf, entries, algo); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExtractTar extracts a compressed tar archive from bytes to outputDir.
// This is a convenience wrapper over [ExtractTarReader].
//
// See [ExtractTarReader] for full documentation on security and behavior.
func ExtractTar(data []byte, outputDir string, algo compress.Algorithm, limits *Limits) (int, error) {
	return ExtractTarReader(bytes.NewReader(data), outputDir, algo, limits)
}

// WriteFile writes one file into outputDir the way extraction writes a
// regular entry: name is checked as a portable path and must stay inside
// outputDir after symlinks resolve, missing parents are created, and the
// file is opened without following a symlink at its leaf and, unless
// allowOverwrite, without replacing anything. It writes at most maxSize
// bytes from r and returns the file's path and the bytes written.
func WriteFile(outputDir, name string, mode os.FileMode, r io.Reader, maxSize int64, allowOverwrite bool) (string, int64, error) {
	cleanName, err := ValidateArchivePath(name)
	if err != nil {
		return "", 0, fmt.Errorf("unsafe file name: %w", err)
	}
	target := filepath.Join(outputDir, filepath.FromSlash(cleanName))
	if err := ensureInsideDir(outputDir, target); err != nil {
		return "", 0, fmt.Errorf("symlink escape for %q: %w", cleanName, err)
	}
	targetDir := filepath.Dir(target)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", 0, fmt.Errorf("mkdir for %q: %w", cleanName, err)
	}
	// Re-verify after MkdirAll to detect a directory swapped for a symlink.
	if err := ensureInsideDir(outputDir, target); err != nil {
		return "", 0, fmt.Errorf("symlink escape (post-mkdir) for %q: %w", cleanName, err)
	}
	written, err := writeFileAtomicBounded(target, targetDir, mode.Perm(), r, maxSize, allowOverwrite)
	if err != nil {
		return "", 0, fmt.Errorf("write %q: %w", cleanName, err)
	}
	return target, written, nil
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// zeroReader yields zeros forever.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// countingWriter counts what is written to it and discards it.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// writeFileAtomicBounded writes data from r directly to target, refusing to
// follow a symlink at the leaf component (Unix only — see safeOpenForWrite).
// When allowOverwrite is false, an existing destination is rejected (O_EXCL);
// when true, it is truncated (O_TRUNC). Either way the kernel honours
// O_NOFOLLOW so an attacker cannot redirect the write through a symlink even
// if they win the TOCTOU race against ensureInsideDir.
func writeFileAtomicBounded(target, dir string, mode os.FileMode, r io.Reader, maxSize int64, allowOverwrite bool) (int64, error) {
	_ = dir
	f, err := safeOpenForWrite(target, mode, allowOverwrite)
	if err != nil {
		return 0, err
	}

	written, err := io.Copy(f, io.LimitReader(r, maxSize+1))
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(target)
		return 0, err
	}

	if written > maxSize {
		os.Remove(target)
		return 0, fmt.Errorf("content exceeds size limit %d", maxSize)
	}

	return written, nil
}

// ensureInsideDir verifies that target resolves to a path inside dir after
// symlink resolution. This is best-effort and NOT race-free: a concurrent
// local filesystem attacker could swap a directory for a symlink between this
// check and the subsequent file write. For full race safety, extraction would
// need openat/O_NOFOLLOW-style fd-based operations, which are platform-specific
// and not portable to other SDK languages. The current approach is safe against
// all non-concurrent attack vectors (pre-existing symlinks, tar-slip, etc.).
//
// Both inputs are normalized to canonical absolute paths before comparison:
//   - filepath.Abs converts to absolute form (joins with CWD if relative).
//   - filepath.EvalSymlinks resolves any symlinks in the existing prefix.
// On systems where common roots are themselves symlinks (e.g. macOS
// `/tmp` → `/private/tmp`) the two-step normalization keeps both sides in
// the same canonical form so a legitimate path inside `dir` doesn't get
// reported as an escape.
func ensureInsideDir(dir, target string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(absDir); err == nil {
		absDir = resolved
	}

	// Make target absolute up front. If it was relative (relative to CWD),
	// EvalSymlinks below would otherwise return a relative result and the
	// later filepath.Abs would re-resolve via os.Getwd(), which on macOS
	// often holds the unresolved /tmp form even when absDir is already
	// /private/tmp — the comparison would then fail on a legitimate path.
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}

	check := absTarget
	for {
		resolved, err := filepath.EvalSymlinks(check)
		if err == nil {
			// EvalSymlinks may still return a path containing symlinked
			// roots (rare but observed); run filepath.Abs to canonicalize.
			absResolved, err := filepath.Abs(resolved)
			if err != nil {
				return err
			}
			if !strings.HasPrefix(absResolved+string(filepath.Separator), absDir+string(filepath.Separator)) &&
				absResolved != absDir {
				return fmt.Errorf("resolved path %s escapes output directory %s", absResolved, absDir)
			}
			return nil
		}
		parent := filepath.Dir(check)
		if parent == check {
			return nil
		}
		check = parent
	}
}
