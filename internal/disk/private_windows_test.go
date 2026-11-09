// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disk

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/deepsecret-io/deepsecret-go/internal/disk/disktest"
)

// Only this user, SYSTEM and Administrators may own or open what the SDK
// keeps. Anything else, and anything the check cannot read, is refused.
func TestExposure(t *testing.T) {
	me := disktest.CurrentUser(t).String()
	for _, c := range []struct {
		name, sddl string
		refused    string // part of the reason, or "" when accepted
	}{
		{"owner only", "O:" + me + "D:P(A;;FA;;;" + me + ")", ""},
		{"a profile folder's inherited entries", "O:" + me + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;" + me + ")", ""},
		{"owned by Administrators", "O:BAD:P(A;;FA;;;" + me + ")", ""},
		{"owned by SYSTEM", "O:SYD:P(A;;FA;;;" + me + ")", ""},
		{"an empty DACL", "O:" + me + "D:P", ""},
		{"a deny entry for Everyone", "O:" + me + "D:P(D;;FA;;;WD)(A;;FA;;;" + me + ")", ""},
		{"owned by Everyone", "O:WDD:P(A;;FA;;;" + me + ")", "belongs to"},
		{"no owner", "D:P(A;;FA;;;" + me + ")", "no owner"},
		{"no DACL", "O:" + me, "no access list"},
		{"a NULL DACL", "O:" + me + "D:NO_ACCESS_CONTROL", "no access list"},
		{"Everyone may read", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)", "may open it"},
		{"Users inherit read", "O:" + me + "D:AI(A;ID;FR;;;BU)(A;;FA;;;" + me + ")", "may open it"},
		{"Everyone inherit-only", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;OICIIO;FA;;;WD)", "may open it"},
		{"Authenticated Users may write", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FW;;;AU)", "may open it"},
		{"a conditional allow entry", "O:" + me + "D:P(A;;FA;;;" + me + ")(XA;;FR;;;WD;(Member_of {SID(BA)}))", "type 9"},
		{"an object allow entry", "O:" + me + "D:P(A;;FA;;;" + me + ")(OA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)", "type 5"},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		who, _ := exposure(sd, disktest.CurrentUser(t))
		switch {
		case c.refused == "" && who != "":
			t.Errorf("%s (%s): refused: %s", c.name, c.sddl, who)
		case c.refused != "" && !strings.Contains(who, c.refused):
			t.Errorf("%s (%s): %q, want a refusal saying %q", c.name, c.sddl, who, c.refused)
		}
	}
}

// Files and folders are private from the moment they exist, whatever mode
// is asked for, and a rename keeps a file's own ACL.
func TestCreatedFilesArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, dir)
	disktest.AssertPrivate(t, filepath.Dir(dir))
	if err := CheckPrivateDir(dir); err != nil {
		t.Errorf("a private folder: %v", err)
	}
	sub := filepath.Join(dir, "shared")
	if err := Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, sub)
	if err := Mkdir(sub, 0o755); !os.IsExist(err) {
		t.Errorf("Mkdir of a folder already there: %v, want exist", err)
	}

	path := filepath.Join(dir, "entry.txt")
	f, err := CreateNew(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("plaintext"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, path)
	if _, err := CreateNew(path, 0o600); !os.IsExist(err) {
		t.Errorf("CreateNew of a file already there: %v, want exist", err)
	}
	if data, err := ReadPrivate(path); err != nil || string(data) != "plaintext" {
		t.Errorf("ReadPrivate: %q, %v", data, err)
	}

	tmp, err := CreateTemp(dir, ".key.json-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(tmp.Name()); !strings.HasPrefix(base, ".key.json-") || len(base) <= len(".key.json-") {
		t.Errorf("temporary file %s", base)
	}
	disktest.AssertPrivate(t, tmp.Name())
	if err := os.Rename(tmp.Name(), path+".renamed"); err != nil {
		t.Fatal(err)
	}
	disktest.AssertPrivate(t, path+".renamed")

	readOnly := filepath.Join(dir, "read-only.txt")
	f, err = CreateNew(readOnly, 0o444)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Errorf("a read-only file is still written once: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(readOnly); err != nil || info.Mode().Perm()&0o200 != 0 {
		t.Errorf("a 0444 entry: %v, %v; want the read-only attribute", info, err)
	}
	disktest.AssertPrivate(t, readOnly)
	if err := os.Chmod(readOnly, 0o600); err != nil { // so t.TempDir can remove it
		t.Fatal(err)
	}
}

// A file or folder someone else may open is refused, as is a folder that
// is a link or not a folder at all.
func TestOthersMayOpenIsRefused(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "key.json")
	f, err := CreateNew(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	disktest.Expose(t, path)
	if _, err := ReadPrivate(path); err == nil || !strings.Contains(err.Error(), "open to other users") ||
		!strings.Contains(err.Error(), `icacls "`+path+`" /inheritance:r /grant:r`) {
		t.Errorf("an exposed file: %v", err)
	}
	if err := CheckPrivateDir(path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file as a folder: %v", err)
	}

	dir := filepath.Join(base, "resume")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	disktest.SetDACL(t, dir, "D:P(A;OICI;FA;;;"+disktest.CurrentUser(t).String()+")(A;OICI;0x1301bf;;;BU)")
	if err := CheckPrivateDir(dir); err == nil || !strings.Contains(err.Error(), "open to other users") ||
		!strings.Contains(err.Error(), "(OI)(CI)F") {
		t.Errorf("a folder Users may change: %v", err)
	}
	if err := CheckPrivateDir(filepath.Join(base, "missing")); !os.IsNotExist(err) {
		t.Errorf("a missing folder: %v, want not-exist", err)
	}

	private := filepath.Join(base, "private")
	if err := MkdirPrivate(private); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
	}
	if err := CheckPrivateDir(link); err == nil {
		t.Error("a symlink to a private folder was accepted")
	}
	// CreateNew refuses a link at its path rather than create its target.
	target := filepath.Join(base, "target.txt")
	fileLink := filepath.Join(base, "file-link")
	if err := os.Symlink(target, fileLink); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateNew(fileLink, 0o600); !os.IsExist(err) {
		t.Errorf("CreateNew through a dangling link: %v, want exist", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("the link's target was created: %v", err)
	}
}

// A file another handle may write is not read: that handle may have been
// opened before the file's ACL was fixed.
func TestReadPrivateRefusesAFileOpenForWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.json")
	f, err := CreateNew(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Errorf("a file open for writing: %v, want a sharing violation", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadPrivate(path); err != nil || string(data) != "{}" {
		t.Errorf("after the writer closed: %q, %v", data, err)
	}
}
