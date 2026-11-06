// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build !nofido2 && (darwin || linux) && (amd64 || arm64)

package fido2

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/deepsecret-io/sdk/crypto"
)

// Constants from libfido2's fido.h, fido/param.h and fido/err.h (1.17.0).
const (
	fidoDisableU2FFallback = 0x02

	coseES256 = -7

	fidoExtHMACSecret   = 0x01
	fidoExtCredProtect  = 0x02
	fidoCredProtUVOptID = 0x02 // FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID

	fidoOptOmit  = 0
	fidoOptFalse = 1
	fidoOptTrue  = 2

	fidoOK                    = 0x00
	fidoErrUnsupportedExt     = 0x16
	fidoErrCredentialExcluded = 0x19
	fidoErrOperationDenied    = 0x27
	fidoErrUnsupportedOption  = 0x2b
	fidoErrInvalidOption      = 0x2c
	fidoErrKeepaliveCancel    = 0x2d
	fidoErrNoCredentials      = 0x2e
	fidoErrUserActionTimeout  = 0x2f
	fidoErrPINInvalid         = 0x31
	fidoErrPINBlocked         = 0x32
	fidoErrPINAuthInvalid     = 0x33
	fidoErrPINAuthBlocked     = 0x34
	fidoErrPINNotSet          = 0x35
	fidoErrActionTimeout      = 0x3a
	fidoErrUVBlocked          = 0x3c
	fidoErrUVInvalid          = 0x3f
	fidoErrRX                 = -2
)

const (
	maxDevices = 16
	// deviceTimeoutMS bounds one exchange with a device. The device gives
	// up waiting for a touch on its own after about 30 seconds.
	deviceTimeoutMS = 60000
	pinAttempts     = 3
)

// How long a request waits for a security key to be plugged in, and how
// often it looks; variables so tests can shorten them.
var (
	insertWait = 2 * time.Minute
	insertPoll = 500 * time.Millisecond
)

// errNotPlugged ends a wait for a security key that was not plugged in.
var errNotPlugged = errors.New("no security key was plugged in")

// waitForKey calls try until it reports done or fails. In between it asks
// once, through p, to plug in want, and looks again every insertPoll until
// ctx ends (crypto.ErrCancelled) or insertWait passes (errNotPlugged).
func waitForKey(ctx context.Context, p Prompter, want string, try func() (done bool, err error)) error {
	deadline := time.Now().Add(insertWait)
	asked := false
	for {
		if done, err := try(); done || err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return errNotPlugged
		}
		if !asked {
			p.Insert(want)
			asked = true
		}
		t := time.NewTimer(insertPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%w: %v", crypto.ErrCancelled, ctx.Err())
		case <-t.C:
		}
	}
}

// libraryPaths are the only places libfido2 is loaded from: absolute paths
// in system and package-manager library directories, never a search path
// or an environment variable.
func libraryPaths() []string {
	if runtime.GOOS == "darwin" {
		return []string{
			"/opt/homebrew/lib/libfido2.1.dylib",
			"/usr/local/lib/libfido2.1.dylib",
			"/opt/local/lib/libfido2.1.dylib",
		}
	}
	return []string{
		"/usr/lib/x86_64-linux-gnu/libfido2.so.1",
		"/usr/lib/aarch64-linux-gnu/libfido2.so.1",
		"/usr/lib64/libfido2.so.1",
		"/usr/lib/libfido2.so.1",
		"/usr/local/lib/libfido2.so.1",
	}
}

// lib is libfido2's functions. C pointers are unsafe.Pointer; buffers and
// C strings are []byte (NUL-terminated for strings, nil for NULL).
type lib struct {
	path string

	init   func(int32)
	strerr func(int32) string

	devInfoNew      func(uintptr) unsafe.Pointer
	devInfoManifest func(unsafe.Pointer, uintptr, *uintptr) int32
	devInfoPtr      func(unsafe.Pointer, uintptr) unsafe.Pointer
	devInfoPath     func(unsafe.Pointer) string
	devInfoProduct  func(unsafe.Pointer) string
	devInfoFree     func(*unsafe.Pointer, uintptr)

	devNew           func() unsafe.Pointer
	devOpen          func(unsafe.Pointer, []byte) int32
	devClose         func(unsafe.Pointer) int32
	devFree          func(*unsafe.Pointer)
	devIsFIDO2       func(unsafe.Pointer) bool
	devHasPIN        func(unsafe.Pointer) bool
	devHasUV         func(unsafe.Pointer) bool
	devSetTimeout    func(unsafe.Pointer, int32) int32
	devCancel        func(unsafe.Pointer) int32
	devGetRetryCount func(unsafe.Pointer, *int32) int32
	devGetCborInfo   func(unsafe.Pointer, unsafe.Pointer) int32
	devMakeCred      func(unsafe.Pointer, unsafe.Pointer, []byte) int32
	devGetAssert     func(unsafe.Pointer, unsafe.Pointer, []byte) int32

	cborInfoNew    func() unsafe.Pointer
	cborInfoFree   func(*unsafe.Pointer)
	cborInfoExtPtr func(unsafe.Pointer) unsafe.Pointer
	cborInfoExtLen func(unsafe.Pointer) uintptr

	credNew               func() unsafe.Pointer
	credFree              func(*unsafe.Pointer)
	credSetType           func(unsafe.Pointer, int32) int32
	credSetClientdataHash func(unsafe.Pointer, []byte, uintptr) int32
	credSetRP             func(unsafe.Pointer, []byte, []byte) int32
	credSetUser           func(unsafe.Pointer, []byte, uintptr, []byte, []byte, []byte) int32
	credSetExtensions     func(unsafe.Pointer, int32) int32
	credSetProt           func(unsafe.Pointer, int32) int32
	credSetRK             func(unsafe.Pointer, int32) int32
	credSetUV             func(unsafe.Pointer, int32) int32
	credIDPtr             func(unsafe.Pointer) unsafe.Pointer
	credIDLen             func(unsafe.Pointer) uintptr
	credAAGUIDPtr         func(unsafe.Pointer) unsafe.Pointer
	credAAGUIDLen         func(unsafe.Pointer) uintptr

	assertNew               func() unsafe.Pointer
	assertFree              func(*unsafe.Pointer)
	assertSetClientdataHash func(unsafe.Pointer, []byte, uintptr) int32
	assertSetRP             func(unsafe.Pointer, []byte) int32
	assertAllowCred         func(unsafe.Pointer, []byte, uintptr) int32
	assertSetExtensions     func(unsafe.Pointer, int32) int32
	assertSetHMACSalt       func(unsafe.Pointer, []byte, uintptr) int32
	assertSetUP             func(unsafe.Pointer, int32) int32
	assertSetUV             func(unsafe.Pointer, int32) int32
	assertCount             func(unsafe.Pointer) uintptr
	assertHMACSecretPtr     func(unsafe.Pointer, uintptr) unsafe.Pointer
	assertHMACSecretLen     func(unsafe.Pointer, uintptr) uintptr
	assertIDPtr             func(unsafe.Pointer, uintptr) unsafe.Pointer
	assertIDLen             func(unsafe.Pointer, uintptr) uintptr
}

func (l *lib) symbols() map[string]any {
	return map[string]any{
		"fido_init": &l.init, "fido_strerr": &l.strerr,
		"fido_dev_info_new": &l.devInfoNew, "fido_dev_info_manifest": &l.devInfoManifest,
		"fido_dev_info_ptr": &l.devInfoPtr, "fido_dev_info_path": &l.devInfoPath,
		"fido_dev_info_product_string": &l.devInfoProduct, "fido_dev_info_free": &l.devInfoFree,
		"fido_dev_new": &l.devNew, "fido_dev_open": &l.devOpen, "fido_dev_close": &l.devClose,
		"fido_dev_free": &l.devFree, "fido_dev_is_fido2": &l.devIsFIDO2, "fido_dev_has_pin": &l.devHasPIN,
		"fido_dev_has_uv": &l.devHasUV, "fido_dev_set_timeout": &l.devSetTimeout, "fido_dev_cancel": &l.devCancel,
		"fido_dev_get_retry_count": &l.devGetRetryCount, "fido_dev_get_cbor_info": &l.devGetCborInfo,
		"fido_dev_make_cred": &l.devMakeCred, "fido_dev_get_assert": &l.devGetAssert,
		"fido_cbor_info_new": &l.cborInfoNew, "fido_cbor_info_free": &l.cborInfoFree,
		"fido_cbor_info_extensions_ptr": &l.cborInfoExtPtr, "fido_cbor_info_extensions_len": &l.cborInfoExtLen,
		"fido_cred_new": &l.credNew, "fido_cred_free": &l.credFree, "fido_cred_set_type": &l.credSetType,
		"fido_cred_set_clientdata_hash": &l.credSetClientdataHash, "fido_cred_set_rp": &l.credSetRP,
		"fido_cred_set_user": &l.credSetUser, "fido_cred_set_extensions": &l.credSetExtensions,
		"fido_cred_set_prot": &l.credSetProt, "fido_cred_set_rk": &l.credSetRK, "fido_cred_set_uv": &l.credSetUV,
		"fido_cred_id_ptr": &l.credIDPtr, "fido_cred_id_len": &l.credIDLen,
		"fido_cred_aaguid_ptr": &l.credAAGUIDPtr, "fido_cred_aaguid_len": &l.credAAGUIDLen,
		"fido_assert_new": &l.assertNew, "fido_assert_free": &l.assertFree,
		"fido_assert_set_clientdata_hash": &l.assertSetClientdataHash, "fido_assert_set_rp": &l.assertSetRP,
		"fido_assert_allow_cred": &l.assertAllowCred, "fido_assert_set_extensions": &l.assertSetExtensions,
		"fido_assert_set_hmac_salt": &l.assertSetHMACSalt, "fido_assert_set_up": &l.assertSetUP,
		"fido_assert_set_uv": &l.assertSetUV, "fido_assert_count": &l.assertCount,
		"fido_assert_hmac_secret_ptr": &l.assertHMACSecretPtr, "fido_assert_hmac_secret_len": &l.assertHMACSecretLen,
		"fido_assert_id_ptr": &l.assertIDPtr, "fido_assert_id_len": &l.assertIDLen,
	}
}

var (
	loadOnce sync.Once
	loaded   *lib
	loadErr  error
)

func load() (*lib, error) {
	loadOnce.Do(func() { loaded, loadErr = openLibrary() })
	return loaded, loadErr
}

func errNoLibrary() error {
	hint := "install libfido2 (Debian and Ubuntu: apt install libfido2-1; Fedora: dnf install libfido2)"
	if runtime.GOOS == "darwin" {
		hint = "install libfido2 with Homebrew (brew install libfido2)"
	}
	return fmt.Errorf("%w: libfido2 was not found; %s", crypto.ErrNoSecurityKeySupport, hint)
}

// openLibrary loads the first libfido2 found that passes trustedLibrary
// and has every function this package calls.
func openLibrary() (*lib, error) {
	var refused []string
	for _, p := range libraryPaths() {
		resolved, err := trustedLibrary(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		h, err := purego.Dlopen(resolved, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		l := &lib{path: resolved}
		var missing []string
		syms := l.symbols()
		for name := range syms {
			if _, err := purego.Dlsym(h, name); err != nil {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			_ = purego.Dlclose(h)
			refused = append(refused, fmt.Sprintf("%s: too old, lacks %d functions such as %s", p, len(missing), missing[0]))
			continue
		}
		for name, fn := range syms {
			purego.RegisterLibFunc(fn, h, name)
		}
		// FIDO_DEBUG in the environment makes libfido2 dump every exchange
		// with the device on stderr; keep it off, so nothing derived from a
		// PIN or a key file reaches a terminal or a log.
		_ = os.Unsetenv("FIDO_DEBUG")
		l.init(fidoDisableU2FFallback)
		return l, nil
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("%w: no usable libfido2 (%v)", crypto.ErrNoSecurityKeySupport, refused)
	}
	return nil, errNoLibrary()
}

// trustedLibrary resolves path and accepts it only as a regular file, in
// directories, that root or the current user owns and that nobody else can
// write: not others, and not a group other than root's (or, on macOS,
// admin's, whose members can become root anyway). Homebrew's files belong
// to the user who installed it, with the admin group.
func trustedLibrary(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if err := trustedEntry(fi); err != nil {
		return "", err
	}
	// The directories above it must pass too, or the file could be swapped
	// between this check and loading it.
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		di, err := os.Stat(dir)
		if err != nil {
			return "", err
		}
		if err := trustedEntry(di); err != nil {
			return "", fmt.Errorf("%s: %w", dir, err)
		}
		if dir == filepath.Dir(dir) {
			return resolved, nil
		}
	}
}

// adminGID is the macOS admin group.
const adminGID = 80

// trustedEntry accepts a file or directory owned by root or the current
// user that only they, root's group or the macOS admin group can write. A
// sticky directory (such as /tmp) may be writable by others: nobody can
// rename or remove another user's entries in it.
func trustedEntry(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner")
	}
	if st.Uid != 0 && int(st.Uid) != os.Getuid() {
		return errors.New("owned by another user")
	}
	perm := fi.Mode().Perm()
	if perm&0o002 != 0 && (!fi.IsDir() || fi.Mode()&os.ModeSticky == 0) {
		return errors.New("writable by others")
	}
	if perm&0o020 != 0 && st.Gid != 0 && (runtime.GOOS != "darwin" || st.Gid != adminGID) {
		return errors.New("writable by its group")
	}
	return nil
}

// Check loads libfido2 and lists the FIDO2 devices connected.
func Check() (Status, error) {
	l, err := load()
	if err != nil {
		return Status{}, err
	}
	devs, err := l.devices()
	st := Status{Library: l.path}
	for _, d := range devs {
		st.Devices = append(st.Devices, d.name)
	}
	return st, err
}

// cstr is s as a NUL-terminated C string.
func cstr(s string) []byte { return append([]byte(s), 0) }

// goBytes copies n bytes of C memory at p.
func goBytes(p unsafe.Pointer, n uintptr) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return bytes.Clone(unsafe.Slice((*byte)(p), n)) // #nosec G103 -- p and n come from libfido2 for one of its own buffers.
}

// goString reads a NUL-terminated C string at p, at most 1024 bytes.
func goString(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	var b []byte
	for i := uintptr(0); i < 1024; i++ {
		c := *(*byte)(unsafe.Add(p, i)) // #nosec G103 -- p is a C string from libfido2.
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

type deviceInfo struct {
	path string
	name string
}

// devices lists the connected FIDO devices.
func (l *lib) devices() ([]deviceInfo, error) {
	list := l.devInfoNew(maxDevices)
	if list == nil {
		return nil, errors.New("libfido2: out of memory")
	}
	defer l.devInfoFree(&list, maxDevices)
	var n uintptr
	if rc := l.devInfoManifest(list, maxDevices, &n); rc != fidoOK {
		return nil, fmt.Errorf("list security keys: %s", l.strerr(rc))
	}
	out := make([]deviceInfo, 0, n)
	for i := uintptr(0); i < n; i++ {
		di := l.devInfoPtr(list, i)
		out = append(out, deviceInfo{path: l.devInfoPath(di), name: deviceName(l.devInfoProduct(di))})
	}
	return out, nil
}

// session is one open device and how the user is verified on it.
type session struct {
	l        *lib
	dev      unsafe.Pointer
	name     string
	prompter Prompter
	pin      []byte // NUL-terminated, nil before it is asked or with built-in verification
	builtIn  bool   // the device verifies the user itself (a fingerprint)
}

func (l *lib) open(d deviceInfo, p Prompter) (*session, error) {
	dev := l.devNew()
	if dev == nil {
		return nil, errors.New("libfido2: out of memory")
	}
	if rc := l.devOpen(dev, cstr(d.path)); rc != fidoOK {
		l.devFree(&dev)
		return nil, fmt.Errorf("open %s: %s", d.name, l.strerr(rc))
	}
	s := &session{l: l, dev: dev, name: d.name, prompter: p}
	_ = l.devSetTimeout(dev, deviceTimeoutMS)
	return s, nil
}

func (s *session) close() {
	clear(s.pin)
	_ = s.l.devClose(s.dev)
	s.l.devFree(&s.dev)
}

// call runs a blocking device call, cancelling it when ctx ends. The
// cancel goroutine has always finished when call returns, so the device is
// never freed while it may still be used.
func (s *session) call(ctx context.Context, f func() int32) int32 {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = s.l.devCancel(s.dev)
		case <-done:
		}
	}()
	rc := f()
	close(done)
	wg.Wait()
	return rc
}

func (s *session) retries() int {
	var n int32
	if s.l.devGetRetryCount(s.dev, &n) != fidoOK {
		return -1
	}
	return int(n)
}

// verifyUser decides how the user is verified: the device's own reader
// when it has one set up, or else the PIN, asked through the prompter.
func (s *session) verifyUser(ctx context.Context) error {
	if s.l.devHasUV(s.dev) {
		s.builtIn = true
		return nil
	}
	return s.askPIN(ctx, false)
}

// askPIN asks for the PIN; wrong says the last one given was refused.
func (s *session) askPIN(ctx context.Context, wrong bool) error {
	s.builtIn = false
	if !s.l.devHasPIN(s.dev) {
		return crypto.ErrPINNotSet
	}
	pin, err := s.prompter.PIN(ctx, s.name, s.retries(), wrong)
	if err != nil {
		clear(pin)
		return err
	}
	if len(pin) == 0 || bytes.IndexByte(pin, 0) >= 0 {
		clear(pin)
		return crypto.ErrCancelled
	}
	clear(s.pin)
	s.pin = make([]byte, len(pin)+1) // NUL-terminated, in a buffer of its own
	copy(s.pin, pin)
	clear(pin)
	return nil
}

// withUser runs op with user verification, asking for the PIN again after
// a wrong one, up to pinAttempts times, and falling back from a blocked
// fingerprint reader to the PIN.
func (s *session) withUser(ctx context.Context, op func() int32) error {
	for attempt := 1; ; attempt++ {
		rc := op()
		switch {
		case rc == fidoOK:
			return nil
		case ctx.Err() != nil:
			return fmt.Errorf("%w: %v", crypto.ErrCancelled, ctx.Err())
		case s.builtIn && (rc == fidoErrUVBlocked || rc == fidoErrUVInvalid):
			if err := s.askPIN(ctx, false); err != nil {
				return err
			}
		case !s.builtIn && (rc == fidoErrPINInvalid || rc == fidoErrPINAuthInvalid) && attempt < pinAttempts:
			s.prompter.TouchDone()
			if err := s.askPIN(ctx, true); err != nil {
				return err
			}
		default:
			return s.err(rc)
		}
	}
}

// err maps a libfido2 error to the crypto package's errors.
func (s *session) err(rc int32) error {
	switch rc {
	case fidoErrPINInvalid, fidoErrPINAuthInvalid:
		return &crypto.PINError{Retries: s.retries()}
	case fidoErrPINAuthBlocked:
		return fmt.Errorf("%w: too many wrong PINs in a row; unplug the security key, plug it back in and try again", crypto.ErrPINInvalid)
	case fidoErrPINBlocked:
		return crypto.ErrPINBlocked
	case fidoErrPINNotSet:
		return crypto.ErrPINNotSet
	case fidoErrNoCredentials:
		return crypto.ErrNoSecurityKey
	case fidoErrCredentialExcluded:
		return crypto.ErrSecurityKeyEnrolled
	case fidoErrUnsupportedExt:
		return crypto.ErrSecurityKeyNoHMAC
	case fidoErrActionTimeout, fidoErrUserActionTimeout, fidoErrOperationDenied:
		// CTAP2 answers OPERATION_DENIED when no touch came in time; a
		// YubiKey has no way to deny, so that is all it means there.
		return crypto.ErrTouchTimeout
	case fidoErrKeepaliveCancel:
		return crypto.ErrCancelled
	case fidoErrRX:
		return fmt.Errorf("%w: no answer from %s (unplugged, or it waited too long)", crypto.ErrTouchTimeout, s.name)
	}
	return fmt.Errorf("%s: %s", s.name, s.l.strerr(rc))
}

func clientDataHash() []byte {
	h := make([]byte, 32)
	_, _ = rand.Read(h) // crypto/rand.Read does not fail.
	return h
}

// probe asks the device silently, without a touch or a PIN, which of creds
// it holds. found is nil when it holds none.
func (s *session) probe(ctx context.Context, creds [][]byte) (found []byte, err error) {
	l := s.l
	a := l.assertNew()
	if a == nil {
		return nil, errors.New("libfido2: out of memory")
	}
	defer l.assertFree(&a)
	cdh := clientDataHash()
	if rc := l.assertSetClientdataHash(a, cdh, uintptr(len(cdh))); rc != fidoOK {
		return nil, s.err(rc)
	}
	if rc := l.assertSetRP(a, cstr(crypto.SecurityKeyRPID)); rc != fidoOK {
		return nil, s.err(rc)
	}
	for _, c := range creds {
		if rc := l.assertAllowCred(a, c, uintptr(len(c))); rc != fidoOK {
			return nil, s.err(rc)
		}
	}
	if rc := l.assertSetUP(a, fidoOptFalse); rc != fidoOK {
		return nil, s.err(rc)
	}
	rc := s.call(ctx, func() int32 { return l.devGetAssert(s.dev, a, nil) })
	switch rc {
	case fidoOK:
		if l.assertCount(a) < 1 {
			return nil, nil
		}
		return goBytes(l.assertIDPtr(a, 0), l.assertIDLen(a, 0)), nil
	case fidoErrNoCredentials:
		return nil, nil
	case fidoErrUnsupportedOption, fidoErrInvalidOption, fidoErrOperationDenied:
		// The device refuses to answer without a touch: no touch was asked
		// for here, so OPERATION_DENIED is not a touch timeout.
		return nil, errNoProbe
	}
	return nil, s.err(rc)
}

var errNoProbe = errors.New("the security key cannot be asked without a touch")

// prf gets the PRF output of credential id for input, with a touch and user
// verification: the one assertion path both enrolling and unlocking use.
func (s *session) prf(ctx context.Context, id, input []byte, reason string) ([]byte, error) {
	l := s.l
	salt := crypto.PRFSalt(input)
	var out []byte
	err := s.withUser(ctx, func() int32 {
		a := l.assertNew()
		if a == nil {
			return fidoErrRX
		}
		defer l.assertFree(&a)
		cdh := clientDataHash()
		for _, rc := range []int32{
			l.assertSetClientdataHash(a, cdh, uintptr(len(cdh))),
			l.assertSetRP(a, cstr(crypto.SecurityKeyRPID)),
			l.assertAllowCred(a, id, uintptr(len(id))),
			l.assertSetExtensions(a, fidoExtHMACSecret),
			l.assertSetHMACSalt(a, salt[:], uintptr(len(salt))),
			l.assertSetUP(a, fidoOptTrue),
		} {
			if rc != fidoOK {
				return rc
			}
		}
		if s.builtIn {
			if rc := l.assertSetUV(a, fidoOptTrue); rc != fidoOK {
				return rc
			}
		}
		s.prompter.Touch(s.name, reason)
		rc := s.call(ctx, func() int32 { return l.devGetAssert(s.dev, a, s.pin) })
		s.prompter.TouchDone()
		if rc != fidoOK {
			return rc
		}
		if l.assertCount(a) != 1 || l.assertHMACSecretLen(a, 0) != 32 {
			return fidoErrUnsupportedExt
		}
		if got := goBytes(l.assertIDPtr(a, 0), l.assertIDLen(a, 0)); !bytes.Equal(got, id) {
			return fidoErrNoCredentials
		}
		out = goBytes(l.assertHMACSecretPtr(a, 0), 32)
		return fidoOK
	})
	return out, err
}

// extensions lists the device's CTAP2 extensions.
func (s *session) extensions() ([]string, error) {
	l := s.l
	ci := l.cborInfoNew()
	if ci == nil {
		return nil, errors.New("libfido2: out of memory")
	}
	defer l.cborInfoFree(&ci)
	if rc := l.devGetCborInfo(s.dev, ci); rc != fidoOK {
		return nil, s.err(rc)
	}
	n := l.cborInfoExtLen(ci)
	p := l.cborInfoExtPtr(ci)
	if p == nil || n == 0 {
		return nil, nil
	}
	ptrs := unsafe.Slice((*unsafe.Pointer)(p), n) // #nosec G103 -- libfido2's array of n C strings.
	out := make([]string, 0, n)
	for _, sp := range ptrs {
		out = append(out, goString(sp))
	}
	return out, nil
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Enroll creates a credential on the one security key connected, asking
// to plug one in when none is, and gets its first PRF output. Two touches:
// one to create, one to derive.
func (a *Authenticator) Enroll(ctx context.Context, req crypto.EnrollRequest) (*crypto.EnrollResult, error) {
	l, err := load()
	if err != nil {
		return nil, err
	}
	var devs []deviceInfo
	err = waitForKey(ctx, a.prompter, "the security key to enroll", func() (bool, error) {
		var err error
		devs, err = l.devices()
		return len(devs) > 0, err
	})
	switch {
	case errors.Is(err, errNotPlugged):
		return nil, errors.New("no security key is connected: plug in the one to enroll")
	case err != nil:
		return nil, err
	case len(devs) > 1:
		return nil, errors.New("more than one security key is connected: leave only the one to enroll")
	}
	s, err := l.open(devs[0], a.prompter)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if !l.devIsFIDO2(s.dev) {
		return nil, crypto.ErrSecurityKeyNoHMAC
	}
	exts, err := s.extensions()
	if err != nil {
		return nil, err
	}
	if !has(exts, "hmac-secret") {
		return nil, crypto.ErrSecurityKeyNoHMAC
	}
	if len(req.Exclude) > 0 {
		found, err := s.probe(ctx, req.Exclude)
		if err != nil && !errors.Is(err, errNoProbe) {
			return nil, err
		}
		if found != nil {
			return nil, crypto.ErrSecurityKeyEnrolled
		}
	}
	if err := s.verifyUser(ctx); err != nil {
		return nil, err
	}

	var id, aaguid []byte
	err = s.withUser(ctx, func() int32 {
		c := l.credNew()
		if c == nil {
			return fidoErrRX
		}
		defer l.credFree(&c)
		cdh := clientDataHash()
		ext := int32(fidoExtHMACSecret)
		if has(exts, "credProtect") {
			ext |= fidoExtCredProtect
		}
		for _, rc := range []int32{
			l.credSetType(c, coseES256),
			l.credSetClientdataHash(c, cdh, uintptr(len(cdh))),
			l.credSetRP(c, cstr(req.RPID), cstr("DeepSecret")),
			l.credSetUser(c, req.UserID, uintptr(len(req.UserID)), cstr(req.UserName), cstr(req.DisplayName), nil),
			l.credSetExtensions(c, ext),
			l.credSetRK(c, fidoOptFalse),
		} {
			if rc != fidoOK {
				return rc
			}
		}
		if ext&fidoExtCredProtect != 0 {
			if rc := l.credSetProt(c, fidoCredProtUVOptID); rc != fidoOK {
				return rc
			}
		}
		if s.builtIn {
			if rc := l.credSetUV(c, fidoOptTrue); rc != fidoOK {
				return rc
			}
		}
		a.prompter.Touch(s.name, "to create the credential (touch 1 of 2)")
		rc := s.call(ctx, func() int32 { return l.devMakeCred(s.dev, c, s.pin) })
		a.prompter.TouchDone()
		if rc != fidoOK {
			return rc
		}
		id = goBytes(l.credIDPtr(c), l.credIDLen(c))
		aaguid = goBytes(l.credAAGUIDPtr(c), l.credAAGUIDLen(c))
		return fidoOK
	})
	if err != nil {
		return nil, err
	}
	if len(id) == 0 {
		return nil, errors.New("the security key returned no credential")
	}
	out, err := s.prf(ctx, id, req.PRFInput, "to confirm the credential (touch 2 of 2)")
	if err != nil {
		return nil, err
	}
	return &crypto.EnrollResult{CredentialID: id, AAGUID: aaguid, Device: s.name, Output: out}, nil
}

// Derive finds the connected security key that holds one of the
// credentials, without a touch, asking to plug it in when none does, and
// gets its PRF output with the PIN and a touch.
func (a *Authenticator) Derive(ctx context.Context, req crypto.DeriveRequest) (*crypto.DeriveResult, error) {
	l, err := load()
	if err != nil {
		return nil, err
	}
	ids := make([][]byte, len(req.Credentials))
	for i, c := range req.Credentials {
		ids[i] = c.ID
	}
	var res *crypto.DeriveResult
	var openErr error
	probed := map[string]bool{} // connected devices that hold none of the credentials
	pass := 0
	err = waitForKey(ctx, a.prompter, wantedKeys(req), func() (bool, error) {
		pass++
		openErr = nil
		devs, err := l.devices()
		if err != nil {
			return false, err
		}
		present := map[string]bool{}
		var failed error
		for _, d := range devs {
			present[d.path] = true
			if probed[d.path] {
				continue
			}
			s, err := l.open(d, a.prompter)
			if err != nil {
				// A key connected from the start that does not open is an
				// error; one just plugged in may need a moment, and is
				// tried again.
				openErr = err
				if pass == 1 {
					failed = err
				}
				continue
			}
			found, err := s.probe(ctx, ids)
			if errors.Is(err, errNoProbe) && len(ids) == 1 && len(devs) == 1 {
				found, err = ids[0], nil
			}
			if err != nil || found == nil {
				if err != nil {
					failed = err
				}
				probed[d.path] = true
				s.close()
				continue
			}
			res, err = a.derive(ctx, s, req, found)
			s.close()
			return true, err
		}
		for p := range probed {
			if !present[p] {
				delete(probed, p) // unplugged: looked at again when plugged back in
			}
		}
		return false, failed
	})
	if errors.Is(err, errNotPlugged) {
		if openErr != nil {
			return nil, openErr
		}
		return nil, fmt.Errorf("%w: plug in %s", crypto.ErrNoSecurityKey, wantedKeys(req))
	}
	return res, err
}

func (a *Authenticator) derive(ctx context.Context, s *session, req crypto.DeriveRequest, id []byte) (*crypto.DeriveResult, error) {
	var input []byte
	for _, c := range req.Credentials {
		if bytes.Equal(c.ID, id) {
			input = c.PRFInput
		}
	}
	if input == nil {
		return nil, crypto.ErrNoSecurityKey
	}
	if err := s.verifyUser(ctx); err != nil {
		return nil, err
	}
	out, err := s.prf(ctx, id, input, "to unlock key "+crypto.ShortFingerprint(req.Fingerprint))
	if err != nil {
		return nil, err
	}
	return &crypto.DeriveResult{CredentialID: id, Output: out}, nil
}

// wantedKeys names the enrolled security keys, for the prompt to plug one
// in and the error when none was.
func wantedKeys(req crypto.DeriveRequest) string {
	if len(req.Credentials) == 1 {
		return fmt.Sprintf("the security key %q", req.Credentials[0].Label)
	}
	names := make([]string, len(req.Credentials))
	for i, c := range req.Credentials {
		names[i] = fmt.Sprintf("%q", c.Label)
	}
	return "one of the security keys " + strings.Join(names, " or ")
}
