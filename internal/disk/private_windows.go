// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disk

// Windows ignores file modes apart from the read-only attribute, so what
// keeps a file private here is the security descriptor it is created with:
// owned by this user, with a protected DACL (nothing inherited from the
// folder above) that grants this user full control and nobody else
// anything. A folder's entry is inheritable, so what other code creates in
// it is private too. The descriptor goes to CreateFile and CreateDirectory,
// never on afterwards: another user could open the file in the moment
// between creating it and fixing its ACL, and keep that handle.
//
// The CLI (github.com/deepsecret-io/cli) holds the same code in
// internal/safefile: change both.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// currentUser is the SID of the user this process runs as: the owner of
// what it creates, and the one account its private files grant access to.
// An elevated process would otherwise make Administrators the owner.
var currentUser = sync.OnceValues(func() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the user this process runs as: %w", err)
	}
	return tu.User.Sid.Copy()
})

// privateAttrs is the security of a new file, or with folder of a new
// folder, private to this user.
func privateAttrs(folder bool) (*windows.SecurityAttributes, error) {
	user, err := currentUser()
	if err != nil {
		return nil, err
	}
	inherit := "" // a file passes nothing on
	if folder {
		inherit = "OICI" // what is created inside gets the same entry
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;" + inherit + ";FA;;;" + user.String() + ")")
	if err != nil {
		return nil, fmt.Errorf("build a private security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

// CreateNew creates path, which must not exist, for writing, private to
// this user whatever mode says; a mode without the owner's write bit makes
// it read-only, as os.OpenFile does. FILE_FLAG_OPEN_REPARSE_POINT makes it
// refuse a link at path instead of creating the file the link points at;
// folders above path are still followed.
func CreateNew(path string, mode os.FileMode) (*os.File, error) {
	sa, err := privateAttrs(false)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if mode&0o200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.CREATE_NEW, attrs|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// CreateTemp creates a new file in dir for writing, private to this user,
// as os.CreateTemp does: its name is pattern with the last "*" replaced by
// a random string, or with one added.
func CreateTemp(dir, pattern string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\`) {
		return nil, &os.PathError{Op: "createtemp", Path: pattern, Err: errors.New("pattern contains path separator")}
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	for range 10 {
		f, err := CreateNew(filepath.Join(dir, prefix+rand.Text()+suffix), 0o600)
		if !errors.Is(err, os.ErrExist) {
			return f, err
		}
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, prefix+"*"+suffix), Err: os.ErrExist}
}

// Mkdir creates the folder path, private to this user whatever the
// permission bits say.
func Mkdir(path string, _ os.FileMode) error {
	sa, err := privateAttrs(true)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}

// MkdirPrivate creates dir and any missing parents, each private to this
// user, as os.MkdirAll does: folders already there are left as they are.
func MkdirPrivate(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if info.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := MkdirPrivate(parent); err != nil {
			return err
		}
	}
	if err := Mkdir(dir, 0o700); err != nil {
		// Made in the meantime: fine when it is a folder.
		if info, lerr := os.Lstat(dir); lerr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

// ReadPrivate reads the file path, and refuses one that someone other
// than this user, SYSTEM and Administrators owns or may open: a key or a
// credential in it is no longer private, and someone else may have put it
// there. The check and the read use one handle, so the file cannot be
// swapped in between. The handle shares no write access: the open fails
// while another handle may write the file, such as one opened before its
// ACL was fixed, and nothing can open it to write until the read is done.
// It shares delete access, so the file can be replaced meanwhile.
func ReadPrivate(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	defer func() { _ = f.Close() }() // read only.
	if err := checkPrivate(h, path, false); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// checkPrivate refuses the file, or with folder the folder, open as h at
// path unless only this user, SYSTEM and Administrators own it and may
// open it (exposure).
func checkPrivate(h windows.Handle, path string, folder bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &os.PathError{Op: "read the access list of", Path: path, Err: err}
	}
	user, err := currentUser()
	if err != nil {
		return err
	}
	who, other := exposure(sd, user)
	if who == "" {
		return nil
	}
	if other == nil {
		return fmt.Errorf("%s is open to other users: %s", path, who)
	}
	grant := "F"
	if folder {
		grant = "(OI)(CI)F"
	}
	return fmt.Errorf("%s is open to other users: %s (to keep it to your account, run: icacls \"%s\" /inheritance:r /grant:r \"%s:%s\" /remove:g \"%s\")",
		path, who, path, account(user), grant, account(other))
}

// Deny entries of the kinds the windows package has no names for. Each
// only takes access away.
const (
	accessDeniedObjectACEType         = 6
	accessDeniedCallbackACEType       = 10
	accessDeniedCallbackObjectACEType = 12
)

// exposure says who other than user, SYSTEM and Administrators owns sd or
// is granted access by it, and other is that account when one entry of
// the DACL names it; who is "" when nobody is. A missing owner, a missing
// or NULL DACL (everyone may open the object) and an allow entry of a kind
// this does not read all count against it, so anything unexpected is
// refused. Inherited entries count like explicit ones, deny entries only
// take access away, and an allow entry counts whatever its flags, an
// inherit-only one included: on a folder it grants access to what is
// created inside.
func exposure(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) (who string, other *windows.SID) {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "it has no owner", nil
	}
	if !trusted(owner, user) {
		return "it belongs to " + account(owner), nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return "it has no access list, so everyone may open it", nil
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Sprintf("its access list cannot be read (%v)", err), nil
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedObjectACEType, accessDeniedCallbackACEType, accessDeniedCallbackObjectACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Sprintf("its access list has an entry of type %d, which this check does not read", ace.Header.AceType), nil
		}
		if ace.Mask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid, user) {
			return account(sid) + " may open it", sid
		}
	}
	return "", nil
}

// trusted is whether sid is user, SYSTEM or Administrators, who may open
// whatever this user keeps.
func trusted(sid, user *windows.SID) bool {
	return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// account is sid's account name, as DOMAIN\name when it has a domain, or
// the SID itself when it names no account this machine knows.
func account(sid *windows.SID) string {
	name, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil || name == "":
		return sid.String()
	case domain == "":
		return name
	}
	return domain + `\` + name
}
