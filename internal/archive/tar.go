// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deepsecret-io/deepsecret-go/internal/compress"
	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/internal/payload"
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
// Type bits (S_IFMT) are excluded: tar carries those in Typeflag.
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

// restorableXattr reports whether extraction restores the extended
// attribute name. Linux's security, trusted and system namespaces are left
// out: they hold file capabilities, SELinux labels and ACLs, with which an
// archive could grant privileges or access that its modes do not show.
func restorableXattr(name string) bool {
	for _, ns := range []string{"security.", "trusted.", "system."} {
		if strings.HasPrefix(name, ns) {
			return false
		}
	}
	return true
}

// setMeta restores an entry's metadata on f, a file or folder extraction
// created, through its handle, so nothing another account puts at its name
// meanwhile (a link, or a hard link to a file elsewhere) is changed: the
// owner with KeepOwnership, then the special bits (chown clears setuid and
// setgid), the extended attributes, and last mtime when not zero, so the
// other changes do not move it. Each step is best-effort: missing
// privileges or file system features do not fail the extraction.
func setMeta(f *os.File, hdr *tar.Header, mode os.FileMode, lim *Limits, mtime time.Time) {
	if lim.KeepOwnership {
		_ = setOwner(f, hdr.Uid, hdr.Gid)
	}
	keepSpecialBits(f, mode)
	for name, value := range extractXattrs(hdr) {
		if restorableXattr(name) {
			_ = setXattr(f, name, value)
		}
	}
	if !mtime.IsZero() {
		_ = disk.SetTimes(f, mtime)
	}
}

// keepSpecialBits adds mode's setuid, setgid and sticky bits to f, which
// open(2) and mkdir(2) leave out. They are set only with KeepSpecialModes
// (see Limits.entryMode). The permission bits stay as the file or folder
// was created, with the umask applied.
func keepSpecialBits(f *os.File, mode os.FileMode) {
	special := mode & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if special == 0 {
		return
	}
	if info, err := f.Stat(); err == nil {
		_ = f.Chmod(info.Mode().Perm() | special)
	}
}

// ── Streaming creation APIs (primary) ────────────────────────────────────────

// WriteTar streams files into a compressed tar archive written to w.
//
// This is the primary creation API. File contents are streamed from disk
// through the tar writer and compressor to w without buffering the full
// archive in memory. It is [NewTar] and [Tar.Write] in one step.
//
// Files are written in the order provided (use [ExpandPaths] for sorted input).
// Each RelPath is validated and used as the tar entry name. Duplicate paths
// are rejected. See [CreateTar] docs for header normalization details.
func WriteTar(w io.Writer, files []ExpandedFile, algo compress.Algorithm) error {
	t, err := NewTar(files)
	if err != nil {
		return err
	}
	return t.Write(w, algo)
}

// Tar is a tar archive of files on disk, captured by [NewTar] without
// reading their contents. Every entry's header, a regular file's size among
// them, is fixed at the capture, so Size is the exact length Write writes.
// A file that changes after the capture (a log that grows, a file cut
// short, replaced or removed) fails Write with an error that wraps
// payload.ErrFileChanged and names it, instead of archiving bytes the
// capture did not measure.
type Tar struct {
	entries []tarEntry
	Size    int64 // the uncompressed archive's length

	// Snapshot sends a regular file that grew after the capture with its
	// first captured-size bytes, instead of failing: for files that are only
	// appended to, such as logs, those are the bytes it had then. A file
	// cut short, replaced or removed still fails Write. A file truncated and
	// written again past its captured size (copy-and-truncate log rotation)
	// cannot be told from one that grew.
	Snapshot bool
}

// tarEntry is one captured entry: its header and, for a regular file, the
// file it was captured from.
type tarEntry struct {
	hdr  *tar.Header
	path string      // a regular file's path on disk
	info os.FileInfo // a regular file's capture, for OpenCaptured
}

// NewTar captures files for an archive.
func NewTar(files []ExpandedFile) (*Tar, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files to archive")
	}

	seen := make(map[string]bool, len(files))
	for _, ef := range files {
		archivePath, err := ValidateArchivePath(ef.RelPath)
		if err != nil {
			return nil, fmt.Errorf("invalid archive path for %s: %w", ef.FullPath, err)
		}
		if seen[archivePath] {
			return nil, fmt.Errorf("duplicate archive path: %q", archivePath)
		}
		seen[archivePath] = true
	}

	t := &Tar{entries: make([]tarEntry, 0, len(files))}

	// Track inodes we've already captured so subsequent occurrences are
	// stored as hard links instead of duplicated content. Keyed by the
	// composite (dev, ino): see sysFileInfo.hardLinkKey.
	inodeIndex := map[[2]uint64]string{}

	for _, ef := range files {
		info, err := Capture(ef.FullPath)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", ef.FullPath, err)
		}
		archivePath, _ := ValidateArchivePath(ef.RelPath)
		sys := sysStat(info)

		// xattrs are best-effort backup metadata. Capture per-entry; PAX
		// records carry them through unchanged.
		xattrs, _ := readXattrs(ef.FullPath)

		if ef.IsSymlink {
			if info.Mode()&os.ModeSymlink == 0 {
				return nil, fmt.Errorf("%s declared as symlink but is not", ef.FullPath)
			}
			hdr := &tar.Header{
				Format:   tar.FormatPAX,
				Typeflag: tar.TypeSymlink,
				Name:     archivePath,
				Linkname: ef.LinkTarget,
				Mode:     0o777, // kernel ignores symlink mode
				ModTime:  info.ModTime().UTC(),
				Uid:      sys.UID, Gid: sys.GID,
			}
			attachXattrs(hdr, xattrs)
			t.entries = append(t.entries, tarEntry{hdr: hdr})
			continue
		}

		if ef.IsDir {
			if !info.IsDir() {
				return nil, fmt.Errorf("%s declared as dir but is not", ef.FullPath)
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
				Uid:      sys.UID, Gid: sys.GID,
			}
			attachXattrs(hdr, xattrs)
			t.entries = append(t.entries, tarEntry{hdr: hdr})
			continue
		}

		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", ef.FullPath)
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
						Uid:      sys.UID, Gid: sys.GID,
					}
					t.entries = append(t.entries, tarEntry{hdr: hdr})
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
			Uid:      sys.UID, Gid: sys.GID,
		}
		attachXattrs(hdr, xattrs)
		t.entries = append(t.entries, tarEntry{hdr: hdr, path: ef.FullPath, info: info})
	}

	var cw countingWriter
	if err := t.write(&cw, compress.None, true); err != nil {
		return nil, err
	}
	t.Size = cw.n
	return t, nil
}

// Captured lists the regular files the archive reads, as NewTar captured
// them.
func (t *Tar) Captured() []Captured {
	var files []Captured
	for _, e := range t.entries {
		if e.hdr.Typeflag == tar.TypeReg {
			files = append(files, Captured{Path: e.path, Info: e.info})
		}
	}
	return files
}

// Write writes the archive to w, compressed with algo, reading each regular
// file as it goes.
func (t *Tar) Write(w io.Writer, algo compress.Algorithm) error {
	return t.write(w, algo, false)
}

// write is Write; with zeros it writes each regular file's content as zeros
// of its captured size instead of reading it, which gives Size.
func (t *Tar) write(w io.Writer, algo compress.Algorithm, zeros bool) error {
	wc, err := compress.NewCompressWriter(w, algo)
	if err != nil {
		return fmt.Errorf("compression writer: %w", err)
	}
	tw := tar.NewWriter(wc)
	for _, e := range t.entries {
		if err := tw.WriteHeader(e.hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", e.hdr.Name, err)
		}
		if e.hdr.Typeflag != tar.TypeReg {
			continue
		}
		if zeros {
			if _, err := io.CopyN(tw, zeroReader{}, e.hdr.Size); err != nil {
				return fmt.Errorf("tar write %s: %w", e.hdr.Name, err)
			}
			continue
		}
		if err := copyCaptured(tw, e, t.Snapshot); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	return wc.Close()
}

// copyCaptured copies a regular file's captured size into tw. It fails,
// naming the file, when the path no longer holds the file captured or the
// file's length changed; in a snapshot, a file that grew is no failure.
func copyCaptured(tw io.Writer, e tarEntry, snapshot bool) error {
	f, err := OpenCaptured(e.path, e.info)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // f was only read
	n, err := io.CopyN(tw, f, e.hdr.Size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return &payload.FileChangedError{Path: e.path, Detail: fmt.Sprintf("%d of %d bytes", n, e.hdr.Size)}
		}
		return fmt.Errorf("tar write %s: %w", e.hdr.Name, err)
	}
	if !snapshot {
		var probe [1]byte
		if m, _ := f.Read(probe[:]); m > 0 {
			return &payload.FileChangedError{Path: e.path, Detail: fmt.Sprintf("it is longer than %d bytes", e.hdr.Size)}
		}
	}
	return nil
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
	Reader io.Reader   // content source: exactly Size bytes are read
}

// WriteTarStream streams reader-backed entries into a compressed tar archive.
//
// This is the fully streaming creation API: no entry content is buffered in
// memory. Each entry's Reader is read for exactly Size bytes and streamed
// directly into the tar writer.
//
// # Entry order
//
// Entries are written in the order provided. Unlike [WriteTarFromBytes], this
// function does NOT sort entries: the caller is responsible for ordering if
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
// memory. It opens outputDir once ([OpenOutput]) and extracts through it
// ([Output.ExtractTar]); see those for its security guarantees: path
// validation, duplicate rejection, type rejection, size limits, no write
// through or out of a link, atomic writes.
//
// When extraction fails, everything it created is removed, files it
// overwrote among them; what was there before stays. The error names
// anything that could not be removed.
//
// Returns the number of files successfully extracted.
func ExtractTarReader(r io.Reader, outputDir string, algo compress.Algorithm, limits *Limits) (int, error) {
	out, err := OpenOutput(outputDir)
	if err != nil {
		return 0, err
	}
	n, err := out.ExtractTar(r, algo, limits)
	if err != nil {
		return 0, out.Remove(err)
	}
	return n, out.Close()
}

// ExtractTar extracts a compressed tar archive from r into the output
// directory, and records what it creates and overwrites, for Remove. It
// leaves all of it in place when it fails: the caller removes the whole
// write with [Output.Remove], also when checks of its own after extraction
// fail.
//
// Every name resolves inside the output directory (see [Output]). No entry
// is created, and no hard link's source is read, through a folder that is
// a link or not a folder when the entry is checked (Output.walkParents). Everything extraction creates is private to its
// owner, whatever modes the archive asks for: directories are 0700, and
// files 0600, or 0700 when the entry has its owner's execute bit, with the
// umask applied (on Windows, private to this user). The owner is the user
// who extracts it, or with KeepOwnership when extracting as root, the
// archive's owner. Directories that already exist keep their mode, owner,
// attributes and times. With AllowOverwrite, a file is replaced by a new
// one renamed over it, so it gets the private mode, not the old file's. A
// symlink entry keeps its target as written, wherever it points, and gets
// the extracting user as owner and the time it is made: a link's own
// metadata cannot be set through a handle, and setting it by name could
// reach a file another account put there.
func (o *Output) ExtractTar(r io.Reader, algo compress.Algorithm, limits *Limits) (int, error) {
	rc, err := compress.NewDecompressReader(r, algo)
	if err != nil {
		return 0, fmt.Errorf("decompression reader: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return o.extract(rc, limits.resolve())
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
	defer func() { _ = rc.Close() }()

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
			if hdr.Size > lim.MaxTotalSize-totalSize {
				return nil, 0, fmt.Errorf("entry %q (size %d) would exceed total size limit %d (current total: %d)",
					cleanName, hdr.Size, lim.MaxTotalSize, totalSize)
			}
			totalSize += hdr.Size
			// #nosec G110 -- tr yields exactly hdr.Size bytes, checked against MaxEntrySize and MaxTotalSize above.
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

// extract is the extraction core of ExtractTar, reading the uncompressed
// archive from r.
func (o *Output) extract(r io.Reader, lim *Limits) (int, error) {
	tr := tar.NewReader(r)
	count := 0
	var totalSize int64
	seenNames := make(map[string]bool)
	// Restoring directory mtimes is deferred to the end of extraction
	// because writing files into a directory updates that directory's
	// mtime. We collect (name, mtime) pairs as we go and apply them in
	// reverse depth order once all entries are written.
	type pendingDirTime struct {
		rel   string
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

		rel := filepath.FromSlash(cleanName)
		if err := o.walkParents(rel, true); err != nil {
			return count, fmt.Errorf("entry %q: %w", cleanName, err)
		}

		if hdr.Typeflag == tar.TypeDir {
			// A directory that is already there stays as it is: the
			// archive does not change the mode, owner, attributes or
			// times of what it did not create.
			if info, err := o.root.Lstat(rel); err == nil {
				if !info.IsDir() {
					return count, fmt.Errorf("mkdir %q: %s exists and is not a directory", cleanName, o.path(rel))
				}
				continue
			}
			mode := lim.entryMode(hdr.Mode, true)
			// MkdirIn applies the umask to the private permission bits;
			// on Windows the folder is private to this user.
			if err := disk.MkdirIn(o.root, rel, mode.Perm()); err != nil {
				return count, fmt.Errorf("mkdir %q: %w", cleanName, err)
			}
			o.made = append(o.made, rel)
			if d, err := disk.OpenDirIn(o.root, rel); err == nil {
				setMeta(d, hdr, mode, lim, time.Time{})
				_ = d.Close() // metadata only
			}
			if !hdr.ModTime.IsZero() {
				dirTimes = append(dirTimes, pendingDirTime{rel: rel, mtime: hdr.ModTime})
			}
			continue
		}

		if hdr.Typeflag == tar.TypeSymlink {
			if err := validateSymlinkTarget(hdr.Linkname); err != nil {
				return count, fmt.Errorf("unsafe symlink %q -> %q: %w", cleanName, hdr.Linkname, err)
			}
			if err := o.replaceLeaf(rel, lim.AllowOverwrite); err != nil {
				return count, err
			}
			if err := o.root.Symlink(hdr.Linkname, rel); err != nil {
				return count, fmt.Errorf("symlink %q: %w", cleanName, err)
			}
			o.made = append(o.made, rel)
			continue
		}

		if hdr.Typeflag == tar.TypeLink {
			// Hard link to a previously-extracted file. The source must be
			// a regular file reached through real folders only; both names
			// resolve inside the output directory.
			if hdr.Linkname == "" {
				return count, fmt.Errorf("hardlink %q has empty target", cleanName)
			}
			linkSrcRel, err := ValidateArchivePath(hdr.Linkname)
			if err != nil {
				return count, fmt.Errorf("hardlink %q has invalid target %q: %w", cleanName, hdr.Linkname, err)
			}
			src := filepath.FromSlash(linkSrcRel)
			if err := o.walkParents(src, false); err != nil {
				return count, fmt.Errorf("hardlink %q: %w", cleanName, err)
			}
			if info, err := o.root.Lstat(src); err != nil || !info.Mode().IsRegular() {
				return count, fmt.Errorf("hardlink %q: %q is not a regular file", cleanName, linkSrcRel)
			}
			if err := o.replaceLeaf(rel, lim.AllowOverwrite); err != nil {
				return count, err
			}
			if err := o.root.Link(src, rel); err != nil {
				return count, fmt.Errorf("hardlink %q -> %q: %w", cleanName, linkSrcRel, err)
			}
			o.made = append(o.made, rel)
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
		if hdr.Size > lim.MaxTotalSize-totalSize {
			return count, fmt.Errorf("entry %q (size %d) would exceed total size limit %d (current total: %d)",
				cleanName, hdr.Size, lim.MaxTotalSize, totalSize)
		}

		mode := lim.entryMode(hdr.Mode, false)

		// open(2) applies the umask to the private permission bits, for a
		// new file and for one replacing an old file alike. The owner,
		// special bits, xattrs and mtime are set through the new file's
		// handle once its content is written (setMeta).
		written, err := o.writeNew(rel, mode.Perm(), tr, lim.MaxEntrySize, lim.AllowOverwrite, func(f *os.File) {
			setMeta(f, hdr, mode, lim, hdr.ModTime)
		})
		if err != nil {
			return count, fmt.Errorf("write %q: %w", cleanName, err)
		}
		o.made = append(o.made, rel)

		totalSize += written
		if totalSize > lim.MaxTotalSize {
			return count, fmt.Errorf("archive exceeds total size limit %d", lim.MaxTotalSize)
		}
		count++
	}

	// Apply directory mtimes from deepest to shallowest so writing into a
	// child doesn't roll the parent's mtime forward after we restore it.
	// Only a real folder is changed, through its own handle.
	for i := len(dirTimes) - 1; i >= 0; i-- {
		if d, err := disk.OpenDirIn(o.root, dirTimes[i].rel); err == nil {
			_ = disk.SetTimes(d, dirTimes[i].mtime)
			_ = d.Close() // metadata only
		}
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
