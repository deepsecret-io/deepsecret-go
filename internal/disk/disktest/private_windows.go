// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package disktest

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, what "FA" grants in SDDL.
const fileAllAccess = 0x1F01FF

// AssertPrivate fails t unless path has the security descriptor the SDK
// gives what it keeps: owned by this user, with a protected DACL holding
// one explicit entry, full control for this user, which a folder passes on
// to what is created inside and a file does not.
func AssertPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the security of %s: %v", path, err)
	}
	user := CurrentUser(t)
	if owner, _, err := sd.Owner(); err != nil || owner == nil || !owner.Equals(user) {
		t.Errorf("%s: %s, want this user (%s) as the owner", path, sd, user)
	}
	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: %s, want a protected DACL", path, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("%s: %s, want a DACL of one entry", path, sd)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	flags := uint8(0)
	if info.IsDir() {
		flags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != flags || ace.Mask != fileAllAccess || !sid.Equals(user) {
		t.Errorf("%s: %s, want only full control for this user (%s)", path, sd, user)
	}
}

// CurrentUser is the SID of the user the test runs as.
func CurrentUser(t *testing.T) *windows.SID {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := tu.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// Expose gives path a DACL that also lets Everyone read it, as a file
// someone shared, or one copied in with a folder's open ACL, would have.
func Expose(t *testing.T, path string) {
	t.Helper()
	SetDACL(t, path, "D:P(A;;FA;;;"+CurrentUser(t).String()+")(A;;FR;;;WD)")
}

// SetDACL replaces path's DACL with the one in sddl, a security
// descriptor string such as "D:P(A;;FA;;;WD)".
func SetDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("set the DACL of %s: %v", path, err)
	}
}

// MakePrivate makes the folder dir private to this user: a protected DACL
// that grants only this user, passed on to what is created inside, as a
// test that hands it to the SDK needs. Windows ignores chmod.
func MakePrivate(t *testing.T, dir string) {
	t.Helper()
	SetDACL(t, dir, "D:P(A;OICI;FA;;;"+CurrentUser(t).String()+")")
}
