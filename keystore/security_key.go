// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keystore

// Slot files: key storage versions 5 (security keys, docs/yubikey-design.md)
// and 6 (AWS KMS, kms.go).
//
// A slot file keeps the four private keys sealed with AES-256-GCM under a
// random file key. Each slot wraps that file key under one way in: a FIDO2
// security key (its hmac-secret output, the WebAuthn PRF value, given only
// after the device's PIN and a touch), an AWS KMS key (a slot secret only
// KMS can decrypt), or a printed recovery code. Opening any one slot opens
// the file. The private block's AAD binds the whole slot list, so a slot
// copied in from another copy of the file does not open it. Version 5 holds
// security keys and version 6 KMS keys, never both: a file is as weak as its
// weakest way in. Every label the AADs and key derivations use names the
// version, so nothing from one version opens in the other. Password-protected
// and unprotected key files stay at version 4 and never touch this code.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/deepsecret-io/deepsecret-go/internal/canon"
	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/keys"
	"github.com/fxamacker/cbor/v2"
)

// securityKeyStorageVersion is the key file format of a key pair protected
// by security keys.
const securityKeyStorageVersion = 5

// SecurityKeyRPID is the FIDO2 relying party ID of every security key
// credential that protects a key file. A name under .invalid never
// resolves, so no web page can claim it and ask a security key for the
// same output.
const SecurityKeyRPID = "deepsecret-keystore.invalid"

const (
	maxSecurityKeySlots = 4
	maxSlotLabelRunes   = 64
	maxCredentialIDLen  = 1023
	prfInputSize        = 32
	prfOutputSize       = 32
	fileKeySize         = 32
	slotIDSize          = 8
	userIDSize          = 16
	saltSize            = 16
	gcmNonceSize        = 12
	wrappedKeySize      = fileKeySize + 16
)

// Protection names how a key file keeps its private keys.
type Protection string

const (
	// ProtectionNone is a version 4 file with the private keys in clear.
	ProtectionNone Protection = "none"
	// ProtectionPassword is a version 4 file encrypted under a password.
	ProtectionPassword Protection = "password"
	// ProtectionSecurityKey is a version 5 file opened by a security key
	// or its recovery code.
	ProtectionSecurityKey Protection = "security_key"
	// ProtectionKMS is a version 6 file opened by an AWS KMS key or its
	// recovery code.
	ProtectionKMS Protection = "aws_kms"
)

// SlotType names a way into a slot file (version 5 or 6).
type SlotType string

const (
	// SlotSecurityKey is a FIDO2 security key credential (version 5).
	SlotSecurityKey SlotType = "fido2"
	// SlotAWSKMS is an AWS KMS key (version 6).
	SlotAWSKMS SlotType = "aws_kms"
	// SlotRecoveryCode is a printed recovery code (versions 5 and 6).
	SlotRecoveryCode SlotType = "recovery_code"
)

// SlotInfo describes one way into a key file. It holds nothing secret.
type SlotInfo struct {
	ID        string
	Type      SlotType
	Label     string
	CreatedAt time.Time
	// AAGUID names the security key model in hex, when the device gave one.
	AAGUID string
	// KMSKeyARN is the AWS KMS key of a KMS slot.
	KMSKeyARN string
	// Account is the DeepSecret account (actor id) a KMS slot is bound to.
	Account string
}

// KeyFileInfo describes a stored key pair without unlocking it.
type KeyFileInfo struct {
	Fingerprint string
	Protection  Protection
	Public      keys.PublicKeys
	Slots       []SlotInfo
}

// Errors of security key protection. Device errors are defined here too,
// so callers can tell them apart with errors.Is without importing the
// package that talks to devices.
var (
	ErrSecurityKeyRequired  = errors.New("key pair is protected by a security key")
	ErrNoRecoveryCode       = errors.New("key pair has no recovery code")
	ErrWrongRecoveryCode    = errors.New("wrong recovery code")
	ErrSecurityKeyMismatch  = errors.New("the security key's answer does not open this key file")
	ErrSlotRules            = errors.New("not allowed for this key file")
	ErrKeyFileChanged       = errors.New("the key file changed while it was being edited; try again")
	ErrNoSecurityKeySupport = errors.New("security keys are not supported by this build")
	ErrNoSecurityKey        = errors.New("no enrolled security key is connected")
	ErrSecurityKeyEnrolled  = errors.New("this security key is already enrolled for the key pair")
	ErrSecurityKeyNoHMAC    = errors.New("this security key does not support hmac-secret")
	ErrPINNotSet            = errors.New("this security key has no PIN; set one first (Yubico Authenticator, or ykman fido access change-pin)")
	ErrPINInvalid           = errors.New("wrong security key PIN")
	ErrPINBlocked           = errors.New("the security key PIN is blocked; only a FIDO reset clears it, and a reset erases every FIDO2 credential on the key")
	ErrTouchTimeout         = errors.New("the security key was not touched in time")
	ErrCancelled            = errors.New("security key request cancelled")
)

// PINError is a wrong security key PIN with the attempts left, or -1 when
// the device did not say. errors.Is(err, ErrPINInvalid) holds.
type PINError struct{ Retries int }

func (e *PINError) Error() string {
	if e.Retries >= 0 {
		return fmt.Sprintf("%s (%d attempts left)", ErrPINInvalid, e.Retries)
	}
	return ErrPINInvalid.Error()
}

// Unwrap returns ErrPINInvalid.
func (e *PINError) Unwrap() error { return ErrPINInvalid }

// Authenticator talks to FIDO2 security keys. Package fido2 implements it.
// Both calls must use user verification (the device PIN, or a built-in
// fingerprint reader): a credential gives a different output with and
// without it, and a key file is always written with it.
type Authenticator interface {
	// Enroll creates a credential on the one security key connected and
	// returns it with the PRF output for req.PRFInput, from an assertion
	// made exactly the way Derive makes one.
	Enroll(ctx context.Context, req EnrollRequest) (*EnrollResult, error)
	// Derive finds a connected security key holding one of
	// req.Credentials and returns its PRF output for that credential.
	Derive(ctx context.Context, req DeriveRequest) (*DeriveResult, error)
}

// EnrollRequest asks for a new security key credential.
type EnrollRequest struct {
	RPID        string
	UserID      []byte
	UserName    string
	DisplayName string
	// PRFInput is the slot's PRF input; the device is given PRFSalt of it.
	PRFInput []byte
	// Exclude lists credentials already in the key file: a device holding
	// one is refused with ErrSecurityKeyEnrolled.
	Exclude [][]byte
}

// EnrollResult is a new credential and its first PRF output.
type EnrollResult struct {
	CredentialID []byte
	AAGUID       []byte
	Discoverable bool
	// Device is the security key's product name, for a default label.
	Device string
	Output []byte
}

// DeriveCredential is one enrolled credential Derive may use.
type DeriveCredential struct {
	ID       []byte
	PRFInput []byte
	Label    string
}

// DeriveRequest asks a security key for a PRF output.
type DeriveRequest struct {
	RPID string
	// Fingerprint is the key pair being unlocked, for prompts.
	Fingerprint string
	Credentials []DeriveCredential
}

// DeriveResult is the credential that answered and its PRF output.
type DeriveResult struct {
	CredentialID []byte
	Output       []byte
}

// PRFSalt is the hmac-secret salt for a PRF input, as WebAuthn PRF defines
// it: SHA-256("WebAuthn PRF" || 0x00 || input). Every platform gives the
// device this salt, so one credential gives one output everywhere.
func PRFSalt(input []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("WebAuthn PRF"))
	h.Write([]byte{0})
	h.Write(input)
	var salt [32]byte
	copy(salt[:], h.Sum(nil))
	return salt
}

// Unlock is what unlocking a key file may need. Password opens a version 4
// password-protected file. A version 5 file is opened with RecoveryCode
// when it is set, and otherwise with SecurityKey. A version 6 file is
// opened with RecoveryCode when it is set, and otherwise with KMS.
type Unlock struct {
	Password     string
	SecurityKey  Authenticator
	RecoveryCode string
	KMS          KMS
}

// ── On-disk layout (versions 5 and 6) ────────────────────────────────────────

type slotFile struct {
	StorageVersion int        `json:"storage_version"`
	ED25519Public  string     `json:"ed25519_public"`
	X25519Public   string     `json:"x25519_public"`
	MLKEM768PK     string     `json:"mlkem768_pk"`
	MLDSA65PK      string     `json:"mldsa65_pk"`
	Private        sealedV5   `json:"private"`
	Slots          []fileSlot `json:"slots"`
}

type sealedV5 struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type fileSlot struct {
	ID           string          `json:"id"`
	Type         SlotType        `json:"type"`
	Label        string          `json:"label"`
	CreatedAt    string          `json:"created_at"`
	FIDO2        *fido2SlotV5    `json:"fido2,omitempty"`
	RecoveryCode *recoverySlotV5 `json:"recovery_code,omitempty"`
	AWSKMS       *kmsSlotV6      `json:"aws_kms,omitempty"`
	Wrap         wrapV5          `json:"wrap"`
}

type fido2SlotV5 struct {
	RPID         string `json:"rp_id"`
	CredentialID string `json:"credential_id"`
	AAGUID       string `json:"aaguid"`
	PRFInput     string `json:"prf_input"`
	UV           bool   `json:"uv"`
	Discoverable bool   `json:"discoverable"`
}

type recoverySlotV5 struct {
	Salt string `json:"salt"`
}

type wrapV5 struct {
	Nonce      string `json:"nonce"`
	WrappedKey string `json:"wrapped_key"`
}

// privateKeysV5 is the plaintext of the private block, canonical CBOR.
type privateKeysV5 struct {
	_              struct{} `cbor:",toarray"`
	ED25519Private []byte
	X25519Private  []byte
	MLKEM768Seed   []byte
	MLDSA65Seed    []byte
}

// slotFields is what a version 5 slot's AAD covers: every field but the
// wrap.
type slotFields struct {
	_            struct{} `cbor:",toarray"`
	Type         string
	ID           string
	Label        string
	CreatedAt    string
	RPID         string
	CredentialID string
	AAGUID       string
	PRFInput     string
	UV           bool
	Discoverable bool
	RecoverySalt string
}

// slotFieldsV6 is what a version 6 slot's AAD covers: every field but the
// wrap.
type slotFieldsV6 struct {
	_            struct{} `cbor:",toarray"`
	Type         string
	ID           string
	Label        string
	CreatedAt    string
	KeyARN       string
	Account      string
	Ciphertext   string
	RecoverySalt string
}

// slotListEntry is one version 5 slot as the private block's AAD covers it.
type slotListEntry struct {
	_          struct{} `cbor:",toarray"`
	Fields     slotFields
	Nonce      string
	WrappedKey string
}

// slotListEntryV6 is one version 6 slot as the private block's AAD covers
// it.
type slotListEntryV6 struct {
	_          struct{} `cbor:",toarray"`
	Fields     slotFieldsV6
	Nonce      string
	WrappedKey string
}

var b64 = base64.RawStdEncoding.Strict()

func (s *fileSlot) fields() slotFields {
	f := slotFields{Type: string(s.Type), ID: s.ID, Label: s.Label, CreatedAt: s.CreatedAt}
	if s.FIDO2 != nil {
		f.RPID, f.CredentialID, f.AAGUID = s.FIDO2.RPID, s.FIDO2.CredentialID, s.FIDO2.AAGUID
		f.PRFInput, f.UV, f.Discoverable = s.FIDO2.PRFInput, s.FIDO2.UV, s.FIDO2.Discoverable
	}
	if s.RecoveryCode != nil {
		f.RecoverySalt = s.RecoveryCode.Salt
	}
	return f
}

func (s *fileSlot) fieldsV6() slotFieldsV6 {
	f := slotFieldsV6{Type: string(s.Type), ID: s.ID, Label: s.Label, CreatedAt: s.CreatedAt}
	if s.AWSKMS != nil {
		f.KeyARN, f.Account, f.Ciphertext = s.AWSKMS.KeyARN, s.AWSKMS.Account, s.AWSKMS.Ciphertext
	}
	if s.RecoveryCode != nil {
		f.RecoverySalt = s.RecoveryCode.Salt
	}
	return f
}

// errSlotVersion refuses a storage version that is not a slot file's.
var errSlotVersion = errors.New("not a slot file version")

// slotAAD binds a slot's wrap to the key pair, the file's version and every
// field of the slot.
func slotAAD(version int, fp string, s *fileSlot) ([]byte, error) {
	switch version {
	case securityKeyStorageVersion:
		enc, err := canon.Marshal(s.fields())
		if err != nil {
			return nil, err
		}
		return append([]byte("deepsecret/keystore/v5/slot/"+fp+"\x00"), enc...), nil
	case kmsStorageVersion:
		enc, err := canon.Marshal(s.fieldsV6())
		if err != nil {
			return nil, err
		}
		return append([]byte("deepsecret/keystore/v6/slot/"+fp+"\x00"), enc...), nil
	}
	return nil, errSlotVersion
}

// privateAAD binds the private block to the key pair, the file's version and
// the whole slot list as written, wraps included.
func privateAAD(version int, fp string, slots []fileSlot) ([]byte, error) {
	var enc []byte
	var err error
	var label string
	switch version {
	case securityKeyStorageVersion:
		list := make([]slotListEntry, len(slots))
		for i := range slots {
			list[i] = slotListEntry{Fields: slots[i].fields(), Nonce: slots[i].Wrap.Nonce, WrappedKey: slots[i].Wrap.WrappedKey}
		}
		enc, err = canon.Marshal(list)
		label = "deepsecret/keystore/v5/private/"
	case kmsStorageVersion:
		list := make([]slotListEntryV6, len(slots))
		for i := range slots {
			list[i] = slotListEntryV6{Fields: slots[i].fieldsV6(), Nonce: slots[i].Wrap.Nonce, WrappedKey: slots[i].Wrap.WrappedKey}
		}
		enc, err = canon.Marshal(list)
		label = "deepsecret/keystore/v6/private/"
	default:
		return nil, errSlotVersion
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(enc)
	return append([]byte(label+fp+"\x00"), sum[:]...), nil
}

func securityKeyKEK(output []byte, fp, slotID string) ([]byte, error) {
	return hkdf.Key(sha256.New, output, nil, "deepsecret/keystore/v5/fido2/"+fp+"/"+slotID, fileKeySize)
}

func recoveryKEK(version int, code, salt []byte, fp, slotID string) ([]byte, error) {
	switch version {
	case securityKeyStorageVersion:
		return hkdf.Key(sha256.New, code, salt, "deepsecret/keystore/v5/recovery/"+fp+"/"+slotID, fileKeySize)
	case kmsStorageVersion:
		return hkdf.Key(sha256.New, code, salt, "deepsecret/keystore/v6/recovery/"+fp+"/"+slotID, fileKeySize)
	}
	return nil, errSlotVersion
}

func gcmSeal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

func gcmOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func freshBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ── Reading and checking ─────────────────────────────────────────────────────

// parseSlotFile decodes a slot file (version 5 or 6) named name strictly:
// unknown or repeated fields, a wrong size, a value out of range, a slot
// that does not belong in the version, or public keys that do not hash to
// name all refuse it.
func parseSlotFile(data []byte, name string) (*slotFile, error) {
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f slotFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
	}
	if dec.More() {
		return nil, fmt.Errorf("key file %s: data after the key file", keys.ShortFingerprint(name))
	}
	if err := f.check(name); err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
	}
	return &f, nil
}

// check refuses a slot file that is not exactly what this SDK writes. It
// does not ask for two ways in: a user may have waived the backup when the
// file was written, and that file must still open.
func (f *slotFile) check(name string) error {
	if f.StorageVersion != securityKeyStorageVersion && f.StorageVersion != kmsStorageVersion {
		return fmt.Errorf("storage version %d is not %d or %d", f.StorageVersion, securityKeyStorageVersion, kmsStorageVersion)
	}
	fp, err := keys.FingerprintFromPubs(f.ED25519Public, f.X25519Public, f.MLKEM768PK, f.MLDSA65PK)
	if err != nil {
		return err
	}
	if fp != name {
		return fmt.Errorf("holds the keys of %s", keys.ShortFingerprint(fp))
	}
	if err := checkB64(f.Private.Nonce, gcmNonceSize, gcmNonceSize); err != nil {
		return fmt.Errorf("private nonce: %w", err)
	}
	if err := checkB64(f.Private.Ciphertext, 17, 1<<16); err != nil {
		return fmt.Errorf("private block: %w", err)
	}
	var secKeys, kmsKeys, codes int
	ids := map[string]bool{}
	creds := map[string]bool{}
	kmsARNs := map[string]bool{}
	account := ""
	for i := range f.Slots {
		s := &f.Slots[i]
		if !validSlotID(s.ID) || ids[s.ID] {
			return fmt.Errorf("slot %d: bad or repeated id", i)
		}
		ids[s.ID] = true
		if err := validateLabel(s.Label); err != nil {
			return fmt.Errorf("slot %s: %w", s.ID, err)
		}
		if _, err := time.Parse(time.RFC3339, s.CreatedAt); err != nil {
			return fmt.Errorf("slot %s: created_at: %w", s.ID, err)
		}
		if err := checkB64(s.Wrap.Nonce, gcmNonceSize, gcmNonceSize); err != nil {
			return fmt.Errorf("slot %s: wrap nonce: %w", s.ID, err)
		}
		if err := checkB64(s.Wrap.WrappedKey, wrappedKeySize, wrappedKeySize); err != nil {
			return fmt.Errorf("slot %s: wrapped key: %w", s.ID, err)
		}
		switch {
		case s.Type == SlotSecurityKey && f.StorageVersion == securityKeyStorageVersion:
			secKeys++
			if s.FIDO2 == nil || s.RecoveryCode != nil || s.AWSKMS != nil {
				return fmt.Errorf("slot %s: a security key slot holds fido2 data only", s.ID)
			}
			k := s.FIDO2
			if k.RPID != SecurityKeyRPID {
				return fmt.Errorf("slot %s: relying party %q is not %q", s.ID, k.RPID, SecurityKeyRPID)
			}
			if !k.UV {
				return fmt.Errorf("slot %s: user verification must be required", s.ID)
			}
			if err := checkB64(k.CredentialID, 1, maxCredentialIDLen); err != nil {
				return fmt.Errorf("slot %s: credential id: %w", s.ID, err)
			}
			if creds[k.CredentialID] {
				return fmt.Errorf("slot %s: repeated credential", s.ID)
			}
			creds[k.CredentialID] = true
			if err := checkB64(k.PRFInput, prfInputSize, prfInputSize); err != nil {
				return fmt.Errorf("slot %s: prf input: %w", s.ID, err)
			}
			if k.AAGUID != "" {
				if b, err := hex.DecodeString(k.AAGUID); err != nil || len(b) != 16 || k.AAGUID != strings.ToLower(k.AAGUID) {
					return fmt.Errorf("slot %s: aaguid is not 32 lower-case hex characters", s.ID)
				}
			}
		case s.Type == SlotAWSKMS && f.StorageVersion == kmsStorageVersion:
			kmsKeys++
			if s.AWSKMS == nil || s.FIDO2 != nil || s.RecoveryCode != nil {
				return fmt.Errorf("slot %s: a KMS slot holds aws_kms data only", s.ID)
			}
			if err := s.AWSKMS.check(); err != nil {
				return fmt.Errorf("slot %s: %w", s.ID, err)
			}
			if kmsARNs[s.AWSKMS.KeyARN] {
				return fmt.Errorf("slot %s: repeated KMS key", s.ID)
			}
			kmsARNs[s.AWSKMS.KeyARN] = true
			if account != "" && s.AWSKMS.Account != account {
				return fmt.Errorf("slot %s: the KMS slots name different accounts", s.ID)
			}
			account = s.AWSKMS.Account
		case s.Type == SlotRecoveryCode:
			codes++
			if s.RecoveryCode == nil || s.FIDO2 != nil || s.AWSKMS != nil {
				return fmt.Errorf("slot %s: a recovery code slot holds recovery data only", s.ID)
			}
			if err := checkB64(s.RecoveryCode.Salt, saltSize, saltSize); err != nil {
				return fmt.Errorf("slot %s: salt: %w", s.ID, err)
			}
		case f.StorageVersion == kmsStorageVersion && s.Type == SlotSecurityKey:
			return fmt.Errorf("slot %s: a KMS key file holds no security key", s.ID)
		case f.StorageVersion == kmsStorageVersion:
			return fmt.Errorf("slot %s: slot type %q needs a newer version of DeepSecret", s.ID, s.Type)
		default:
			return fmt.Errorf("slot %s: unknown type %q", s.ID, s.Type)
		}
	}
	if f.StorageVersion == kmsStorageVersion {
		if kmsKeys < 1 || kmsKeys > maxKMSSlots || codes > 1 {
			return fmt.Errorf("%d KMS keys and %d recovery codes: allowed are 1 to %d and at most 1", kmsKeys, codes, maxKMSSlots)
		}
		return nil
	}
	if secKeys < 1 || secKeys > maxSecurityKeySlots || codes > 1 {
		return fmt.Errorf("%d security keys and %d recovery codes: allowed are 1 to %d and at most 1", secKeys, codes, maxSecurityKeySlots)
	}
	return nil
}

func checkB64(s string, minLen, maxLen int) error {
	b, err := b64.DecodeString(s)
	if err != nil {
		return errors.New("not base64")
	}
	if len(b) < minLen || len(b) > maxLen {
		if minLen == maxLen {
			return fmt.Errorf("%d bytes, want %d", len(b), minLen)
		}
		return fmt.Errorf("%d bytes, want %d to %d", len(b), minLen, maxLen)
	}
	return nil
}

func validSlotID(id string) bool {
	if len(id) != 2*slotIDSize {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidateSlotLabel checks a slot label as the editor will, so a caller can
// refuse a bad one before it unlocks anything or calls a device or KMS.
func ValidateSlotLabel(label string) error { return validateLabel(label) }

// validateLabel accepts 1 to 64 characters of valid UTF-8 without control
// or layout characters, so a label cannot reorder or hide terminal text.
func validateLabel(label string) error {
	if !utf8.ValidString(label) {
		return errors.New("label is not valid UTF-8")
	}
	n := utf8.RuneCountInString(label)
	if n < 1 || n > maxSlotLabelRunes || strings.TrimSpace(label) != label {
		return fmt.Errorf("a label is 1 to %d characters without leading or trailing spaces", maxSlotLabelRunes)
	}
	for _, r := range label {
		if unicode.IsControl(r) || canon.IsLayoutControl(r) {
			return errors.New("label holds a control character")
		}
	}
	return nil
}

// cleanLabel makes a label from a device name: control characters out,
// spaces trimmed, cut to 64 characters, "Security key" when nothing is
// left.
func cleanLabel(name string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.ToValidUTF8(name, "") {
		if unicode.IsControl(r) || canon.IsLayoutControl(r) {
			continue
		}
		if n == maxSlotLabelRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	if label := strings.TrimSpace(b.String()); label != "" {
		return label
	}
	return "Security key"
}

// checkNoDuplicateKeys refuses JSON with an object that repeats a key, in
// any mix of case, which encoding/json would otherwise accept by keeping
// the last value.
func checkNoDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next string token in an object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{object: d == '{', keys: map[string]bool{}, key: d == '{'})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.key {
			k, _ := tok.(string)
			// encoding/json matches field names without regard to case, so
			// "Private" and "private" are the same field to it.
			k = strings.ToLower(k)
			if top.keys[k] {
				return fmt.Errorf("repeated field %q", k)
			}
			top.keys[k] = true
			top.key = false
			continue
		}
		top.key = true
	}
}

func (f *slotFile) publicKeys() keys.PublicKeys {
	return keys.PublicKeys{ED25519: f.ED25519Public, X25519: f.X25519Public, MLKEM768: f.MLKEM768PK, MLDSA65: f.MLDSA65PK}
}

func (f *slotFile) slotInfo() []SlotInfo {
	out := make([]SlotInfo, len(f.Slots))
	for i, s := range f.Slots {
		out[i] = s.info()
	}
	return out
}

func (s *fileSlot) info() SlotInfo {
	created, _ := time.Parse(time.RFC3339, s.CreatedAt)
	info := SlotInfo{ID: s.ID, Type: s.Type, Label: s.Label, CreatedAt: created}
	if s.FIDO2 != nil {
		info.AAGUID = s.FIDO2.AAGUID
	}
	if s.AWSKMS != nil {
		info.KMSKeyARN, info.Account = s.AWSKMS.KeyARN, s.AWSKMS.Account
	}
	return info
}

// ReadInfo reads what the key file <dir>/<fingerprint>.json shows
// without unlocking it: the full fingerprint, the protection, the public
// keys and, for a slot file (security keys or KMS), its slots. fingerprint may be a
// prefix of 16 or more characters. The public keys must hash to the file's
// name.
func ReadInfo(dir, fingerprint string) (*KeyFileInfo, error) {
	fingerprint = strings.ToLower(fingerprint)
	if !validKeyName(fingerprint) {
		return nil, errInvalidKeyName
	}
	name := resolveFingerprint(dir, fingerprint)
	f, err := readKeyFile(dir, name)
	if err != nil {
		return nil, err
	}
	info := &KeyFileInfo{Public: f.publicKeys()}
	fp, err := keys.FingerprintFromPubs(info.Public.ED25519, info.Public.X25519, info.Public.MLKEM768, info.Public.MLDSA65)
	if err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
	}
	if fp != name {
		return nil, fmt.Errorf("key file %s holds the keys of %s", keys.ShortFingerprint(name), keys.ShortFingerprint(fp))
	}
	info.Fingerprint, info.Public.Fingerprint = fp, fp
	if info.Protection, err = f.protection(); err != nil {
		return nil, err
	}
	if f.slots != nil {
		info.Slots = f.slots.slotInfo()
	}
	return info, nil
}

// ── Unlocking ────────────────────────────────────────────────────────────────

// Open loads the key pair stored in <dir>/<fingerprint>.json,
// where fingerprint may be a prefix of 16 or more characters. A version 4
// file is read exactly as Load reads it, with u.Password. A
// version 5 file is opened with u.RecoveryCode when it is set, and
// otherwise with u.SecurityKey; a version 6 file with u.RecoveryCode when
// it is set, and otherwise with u.KMS. The private keys must match the
// public keys.
func Open(ctx context.Context, dir, fingerprint string, u Unlock) (*keys.Pair, error) {
	fingerprint = strings.ToLower(fingerprint)
	if !validKeyName(fingerprint) {
		return nil, errInvalidKeyName
	}
	name := resolveFingerprint(dir, fingerprint)
	f, err := readKeyFile(dir, name)
	if err != nil {
		return nil, err
	}
	switch {
	case f.v4 != nil:
		return loadV4(f.v4, u.Password)
	case f.slots != nil:
		kp, fk, err := f.slots.unlock(ctx, name, u)
		clear(fk)
		return kp, err
	}
	return nil, errNoKeyFile
}

// unlock opens one slot and then the private block. It returns the file
// key too, for an editor; the caller clears it.
func (f *slotFile) unlock(ctx context.Context, fp string, u Unlock) (*keys.Pair, []byte, error) {
	var fk []byte
	var err error
	switch {
	case u.RecoveryCode != "":
		fk, err = f.openRecoveryCode(fp, u.RecoveryCode)
	case f.StorageVersion == securityKeyStorageVersion && u.SecurityKey != nil:
		fk, err = f.openSecurityKey(ctx, fp, u.SecurityKey)
	case f.StorageVersion == securityKeyStorageVersion:
		return nil, nil, ErrSecurityKeyRequired
	case f.StorageVersion == kmsStorageVersion && u.KMS != nil:
		fk, err = f.openKMS(ctx, fp, u.KMS)
	case f.StorageVersion == kmsStorageVersion:
		return nil, nil, ErrKMSRequired
	default:
		return nil, nil, errSlotVersion
	}
	if err != nil {
		return nil, nil, err
	}
	kp, err := f.openPrivate(fp, fk)
	if err != nil {
		clear(fk)
		return nil, nil, err
	}
	return kp, fk, nil
}

func (f *slotFile) openRecoveryCode(fp, typed string) ([]byte, error) {
	var slot *fileSlot
	for i := range f.Slots {
		if f.Slots[i].Type == SlotRecoveryCode {
			slot = &f.Slots[i]
		}
	}
	if slot == nil {
		return nil, ErrNoRecoveryCode
	}
	code, err := parseRecoveryCode(typed)
	if err != nil {
		return nil, err
	}
	defer clear(code)
	salt, _ := b64.DecodeString(slot.RecoveryCode.Salt)
	kek, err := recoveryKEK(f.StorageVersion, code, salt, fp, slot.ID)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	fk, err := openWrap(f.StorageVersion, fp, slot, kek)
	if err != nil {
		return nil, ErrWrongRecoveryCode
	}
	return fk, nil
}

func (f *slotFile) openSecurityKey(ctx context.Context, fp string, a Authenticator) ([]byte, error) {
	req := DeriveRequest{RPID: SecurityKeyRPID, Fingerprint: fp}
	for i := range f.Slots {
		if s := &f.Slots[i]; s.Type == SlotSecurityKey {
			id, _ := b64.DecodeString(s.FIDO2.CredentialID)
			prf, _ := b64.DecodeString(s.FIDO2.PRFInput)
			req.Credentials = append(req.Credentials, DeriveCredential{ID: id, PRFInput: prf, Label: s.Label})
		}
	}
	res, err := a.Derive(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, ErrSecurityKeyMismatch
	}
	defer clear(res.Output)
	var slot *fileSlot
	for i := range f.Slots {
		if s := &f.Slots[i]; s.Type == SlotSecurityKey {
			if id, _ := b64.DecodeString(s.FIDO2.CredentialID); bytes.Equal(id, res.CredentialID) {
				slot = s
			}
		}
	}
	if slot == nil || len(res.Output) != prfOutputSize {
		return nil, ErrSecurityKeyMismatch
	}
	kek, err := securityKeyKEK(res.Output, fp, slot.ID)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	fk, err := openWrap(f.StorageVersion, fp, slot, kek)
	if err != nil {
		return nil, ErrSecurityKeyMismatch
	}
	return fk, nil
}

func openWrap(version int, fp string, s *fileSlot, kek []byte) ([]byte, error) {
	aad, err := slotAAD(version, fp, s)
	if err != nil {
		return nil, err
	}
	nonce, _ := b64.DecodeString(s.Wrap.Nonce)
	wrapped, _ := b64.DecodeString(s.Wrap.WrappedKey)
	fk, err := gcmOpen(kek, nonce, wrapped, aad)
	if err != nil || len(fk) != fileKeySize {
		return nil, errors.New("slot does not open")
	}
	return fk, nil
}

// openPrivate opens the private block with the file key and checks that
// each private key gives its public key.
func (f *slotFile) openPrivate(fp string, fk []byte) (*keys.Pair, error) {
	aad, err := privateAAD(f.StorageVersion, fp, f.Slots)
	if err != nil {
		return nil, err
	}
	nonce, _ := b64.DecodeString(f.Private.Nonce)
	ct, _ := b64.DecodeString(f.Private.Ciphertext)
	plain, err := gcmOpen(fk, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("the private keys do not open: the key file was changed or is corrupted")
	}
	defer clear(plain)
	var priv privateKeysV5
	if err := cbor.Unmarshal(plain, &priv); err != nil {
		return nil, errors.New("the private keys do not decode")
	}
	kp := &keys.Pair{
		ED25519Public:  f.ED25519Public,
		X25519Public:   f.X25519Public,
		MLKEM768PK:     f.MLKEM768PK,
		MLDSA65PK:      f.MLDSA65PK,
		ED25519Private: base64.RawStdEncoding.EncodeToString(priv.ED25519Private),
		X25519Private:  base64.RawStdEncoding.EncodeToString(priv.X25519Private),
		MLKEM768SK:     base64.RawStdEncoding.EncodeToString(priv.MLKEM768Seed),
		MLDSA65Seed:    base64.RawStdEncoding.EncodeToString(priv.MLDSA65Seed),
	}
	clear(priv.ED25519Private)
	clear(priv.X25519Private)
	clear(priv.MLKEM768Seed)
	clear(priv.MLDSA65Seed)
	if err := checkPrivateMatchesPublic(kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// checkPrivateMatchesPublic derives each public key from its private key
// and compares it with the stored one, so a file cannot pair someone's
// public keys with other private keys.
func checkPrivateMatchesPublic(kp *keys.Pair) error {
	dec := func(s string) []byte { b, _ := base64.RawStdEncoding.DecodeString(s); return b }
	edPriv, edPub := dec(kp.ED25519Private), dec(kp.ED25519Public)
	if len(edPriv) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(edPriv[:ed25519.SeedSize]), edPriv) ||
		!bytes.Equal(edPriv[ed25519.SeedSize:], edPub) {
		return errors.New("the Ed25519 private key does not match the public key")
	}
	xPriv, err := ecdh.X25519().NewPrivateKey(dec(kp.X25519Private))
	if err != nil || !bytes.Equal(xPriv.PublicKey().Bytes(), dec(kp.X25519Public)) {
		return errors.New("the X25519 private key does not match the public key")
	}
	dk, err := mlkem.NewDecapsulationKey768(dec(kp.MLKEM768SK))
	if err != nil || !bytes.Equal(dk.EncapsulationKey().Bytes(), dec(kp.MLKEM768PK)) {
		return errors.New("the ML-KEM-768 private key does not match the public key")
	}
	seed := dec(kp.MLDSA65Seed)
	if len(seed) != mldsa65.SeedSize {
		return errors.New("the ML-DSA-65 seed has the wrong size")
	}
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)
	pk, _ := mldsa65.NewKeyFromSeed(&seedArr)
	clear(seedArr[:])
	pub, err := pk.MarshalBinary()
	if err != nil || !bytes.Equal(pub, dec(kp.MLDSA65PK)) {
		return errors.New("the ML-DSA-65 private key does not match the public key")
	}
	return nil
}

// ── Editing slots ────────────────────────────────────────────────────────────

// SlotEditor changes the ways into a key file: it protects a version 4
// file or a new key pair with security keys or KMS keys, adds or removes
// one, and creates or replaces the recovery code. Nothing is written until
// Commit or CommitPassword, which refuse to write when the file changed
// on disk since the editor read it. Close clears the key material it holds.
//
// The editor writes one slot file version: 5 (security keys) or 6 (KMS
// keys). It is the version of the file it read or the new file it makes;
// an editor of a version 4 file takes it from the first key added, and
// refuses the other kind from then on.
type SlotEditor struct {
	dir, fp  string
	original []byte // the file as read, nil for a new key pair
	version  int    // the slot file version written; 0 until a key is added to a version 4 file
	kp       *keys.Pair
	fk       []byte
	slots    []fileSlot
	added    map[string][]byte // key-encryption keys of slots added here, by slot id
	done     bool
}

// errMixedSlots refuses a security key in a KMS file or a KMS key in a
// security-key file.
var errMixedSlots = fmt.Errorf("%w: a key file holds security keys or KMS keys, never both", ErrSlotRules)

// kind fixes the editor's version to want, when it has none yet, and
// refuses any other.
func (e *SlotEditor) kind(want int) error {
	if e.version != 0 && e.version != want {
		return errMixedSlots
	}
	return nil
}

// Edit unlocks the key file <dir>/<fingerprint>.json with u and
// returns an editor for its slots. fingerprint may be a prefix of 16 or
// more characters. A version 4 file (password or none) starts with no
// slots and a new file key; protecting it writes version 5.
func Edit(ctx context.Context, dir, fingerprint string, u Unlock) (*SlotEditor, error) {
	fingerprint = strings.ToLower(fingerprint)
	if !validKeyName(fingerprint) {
		return nil, errInvalidKeyName
	}
	name := resolveFingerprint(dir, fingerprint)
	f, err := readKeyFile(dir, name)
	if err != nil {
		return nil, err
	}
	e := &SlotEditor{dir: dir, original: f.raw, added: map[string][]byte{}}
	switch {
	case f.slots != nil:
		kp, fk, err := f.slots.unlock(ctx, name, u)
		if err != nil {
			return nil, err
		}
		e.kp, e.fk, e.slots = kp, fk, append([]fileSlot(nil), f.slots.Slots...)
		e.version = f.slots.StorageVersion
	case f.v4 != nil:
		kp, err := loadV4(f.v4, u.Password)
		if err != nil {
			return nil, err
		}
		if err := checkPrivateMatchesPublic(kp); err != nil {
			return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
		}
		if e.fk, err = freshBytes(fileKeySize); err != nil {
			return nil, err
		}
		e.kp = kp
	default:
		return nil, errNoKeyFile
	}
	if e.fp, err = keys.Fingerprint(e.kp); err != nil {
		e.Close()
		return nil, err
	}
	if e.fp != name {
		e.Close()
		return nil, fmt.Errorf("key file %s holds the keys of %s", keys.ShortFingerprint(name), keys.ShortFingerprint(e.fp))
	}
	return e, nil
}

// NewSecurityKeyFile returns an editor for a key pair not yet stored, so a
// new key pair is written straight to a version 5 file and never sits on
// disk unprotected. Commit refuses to write over an existing file.
func NewSecurityKeyFile(dir string, kp *keys.Pair) (*SlotEditor, error) {
	return newSlotFileEditor(dir, kp, securityKeyStorageVersion)
}

// newSlotFileEditor returns an editor that writes the new key pair kp as a
// slot file of version.
func newSlotFileEditor(dir string, kp *keys.Pair, version int) (*SlotEditor, error) {
	if err := checkPrivateMatchesPublic(kp); err != nil {
		return nil, err
	}
	fp, err := keys.Fingerprint(kp)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(dir, fp+".json")); err == nil {
		return nil, fmt.Errorf("key file %s already exists", keys.ShortFingerprint(fp))
	}
	fk, err := freshBytes(fileKeySize)
	if err != nil {
		return nil, err
	}
	return &SlotEditor{dir: dir, fp: fp, version: version, kp: kp, fk: fk, added: map[string][]byte{}}, nil
}

// Fingerprint is the full fingerprint of the key pair being edited.
func (e *SlotEditor) Fingerprint() string { return e.fp }

// KeyPair is the unlocked key pair.
func (e *SlotEditor) KeyPair() *keys.Pair { return e.kp }

// Slots lists the slots as they stand, changes included.
func (e *SlotEditor) Slots() []SlotInfo {
	out := make([]SlotInfo, len(e.slots))
	for i := range e.slots {
		out[i] = e.slots[i].info()
	}
	return out
}

func (e *SlotEditor) count(t SlotType) int {
	n := 0
	for _, s := range e.slots {
		if s.Type == t {
			n++
		}
	}
	return n
}

func newSlotID() (string, error) {
	b, err := freshBytes(slotIDSize)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// seal wraps the file key for s under kek, as a slot of a version file,
// and records the wrap in s.
func (e *SlotEditor) seal(version int, s *fileSlot, kek []byte) error {
	aad, err := slotAAD(version, e.fp, s)
	if err != nil {
		return err
	}
	nonce, wrapped, err := gcmSeal(kek, e.fk, aad)
	if err != nil {
		return err
	}
	s.Wrap = wrapV5{Nonce: b64.EncodeToString(nonce), WrappedKey: b64.EncodeToString(wrapped)}
	return nil
}

// AddSecurityKey enrolls the one security key connected through a and
// adds it as a slot. An empty label takes the device's product name.
func (e *SlotEditor) AddSecurityKey(ctx context.Context, a Authenticator, label string) (SlotInfo, error) {
	if e.done {
		return SlotInfo{}, errors.New("editor is closed")
	}
	if err := e.kind(securityKeyStorageVersion); err != nil {
		return SlotInfo{}, err
	}
	if e.count(SlotSecurityKey) >= maxSecurityKeySlots {
		return SlotInfo{}, fmt.Errorf("%w: a key file holds at most %d security keys", ErrSlotRules, maxSecurityKeySlots)
	}
	if label != "" {
		if err := validateLabel(label); err != nil {
			return SlotInfo{}, err
		}
	}
	id, err := newSlotID()
	if err != nil {
		return SlotInfo{}, err
	}
	prf, err := freshBytes(prfInputSize)
	if err != nil {
		return SlotInfo{}, err
	}
	userID, err := freshBytes(userIDSize)
	if err != nil {
		return SlotInfo{}, err
	}
	var exclude [][]byte
	for _, s := range e.slots {
		if s.Type == SlotSecurityKey {
			cid, _ := b64.DecodeString(s.FIDO2.CredentialID)
			exclude = append(exclude, cid)
		}
	}
	short := keys.ShortFingerprint(e.fp)
	res, err := a.Enroll(ctx, EnrollRequest{
		RPID: SecurityKeyRPID, UserID: userID,
		UserName: "deepsecret-" + short, DisplayName: "DeepSecret key " + short,
		PRFInput: prf, Exclude: exclude,
	})
	if err != nil {
		return SlotInfo{}, err
	}
	if res == nil {
		return SlotInfo{}, errors.New("the security key returned no credential")
	}
	defer clear(res.Output)
	if len(res.CredentialID) < 1 || len(res.CredentialID) > maxCredentialIDLen || len(res.Output) != prfOutputSize ||
		(len(res.AAGUID) != 0 && len(res.AAGUID) != 16) {
		return SlotInfo{}, errors.New("the security key returned a malformed credential")
	}
	for _, cid := range exclude {
		if bytes.Equal(cid, res.CredentialID) {
			return SlotInfo{}, ErrSecurityKeyEnrolled
		}
	}
	if label == "" {
		label = cleanLabel(res.Device)
	}
	aaguid := ""
	if len(res.AAGUID) == 16 && !bytes.Equal(res.AAGUID, make([]byte, 16)) {
		aaguid = hex.EncodeToString(res.AAGUID)
	}
	s := fileSlot{
		ID: id, Type: SlotSecurityKey, Label: label, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		FIDO2: &fido2SlotV5{
			RPID: SecurityKeyRPID, CredentialID: b64.EncodeToString(res.CredentialID), AAGUID: aaguid,
			PRFInput: b64.EncodeToString(prf), UV: true, Discoverable: res.Discoverable,
		},
	}
	kek, err := securityKeyKEK(res.Output, e.fp, id)
	if err != nil {
		return SlotInfo{}, err
	}
	if err := e.seal(securityKeyStorageVersion, &s, kek); err != nil {
		clear(kek)
		return SlotInfo{}, err
	}
	e.slots = append(e.slots, s)
	e.added[id] = kek
	e.version = securityKeyStorageVersion
	return s.info(), nil
}

// SetRecoveryCode creates a recovery code, replacing the file's current
// one, and returns it for the user to write down. It is shown once and
// never stored: only a key derived from it wraps the file key.
func (e *SlotEditor) SetRecoveryCode() (string, error) {
	if e.done {
		return "", errors.New("editor is closed")
	}
	if e.version == 0 {
		return "", fmt.Errorf("%w: add a security key or a KMS key before the recovery code", ErrSlotRules)
	}
	code, text, err := newRecoveryCode()
	if err != nil {
		return "", err
	}
	defer clear(code)
	id, err := newSlotID()
	if err != nil {
		return "", err
	}
	salt, err := freshBytes(saltSize)
	if err != nil {
		return "", err
	}
	s := fileSlot{
		ID: id, Type: SlotRecoveryCode, Label: "Recovery code", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		RecoveryCode: &recoverySlotV5{Salt: b64.EncodeToString(salt)},
	}
	kek, err := recoveryKEK(e.version, code, salt, e.fp, id)
	if err != nil {
		return "", err
	}
	if err := e.seal(e.version, &s, kek); err != nil {
		clear(kek)
		return "", err
	}
	for i := range e.slots {
		if e.slots[i].Type == SlotRecoveryCode {
			e.forget(e.slots[i].ID)
			e.slots = append(e.slots[:i], e.slots[i+1:]...)
			break
		}
	}
	e.slots = append(e.slots, s)
	e.added[id] = kek
	return text, nil
}

// Remove takes the slot with the given id out. Commit still checks that
// what is left is allowed.
func (e *SlotEditor) Remove(id string) error {
	for i := range e.slots {
		if e.slots[i].ID == id {
			e.forget(id)
			e.slots = append(e.slots[:i], e.slots[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no slot %q", id)
}

func (e *SlotEditor) forget(id string) {
	if kek, ok := e.added[id]; ok {
		clear(kek)
		delete(e.added, id)
	}
}

// Commit writes the key file as the editor's version: 5 with security keys,
// 6 with KMS keys. It needs at least one such key and, unless allowSingle
// is set, a second way in: another key of the same kind or a recovery
// code. Before the file is replaced, the new bytes are read back and every
// slot added here, and the private block, must open.
func (e *SlotEditor) Commit(allowSingle bool) error {
	if e.done {
		return errors.New("editor is closed")
	}
	codes := e.count(SlotRecoveryCode)
	switch e.version {
	case securityKeyStorageVersion:
		secKeys := e.count(SlotSecurityKey)
		switch {
		case secKeys == 0:
			return fmt.Errorf("%w: a security key file needs at least one security key", ErrSlotRules)
		case secKeys+codes < 2 && !allowSingle:
			return fmt.Errorf("%w: add a second security key or a recovery code, or confirm a single way in", ErrSlotRules)
		}
	case kmsStorageVersion:
		kmsKeys := e.count(SlotAWSKMS)
		switch {
		case kmsKeys == 0:
			return fmt.Errorf("%w: a KMS key file needs at least one KMS key", ErrSlotRules)
		case kmsKeys+codes < 2 && !allowSingle:
			return fmt.Errorf("%w: add a second KMS key or a recovery code, or confirm a single way in", ErrSlotRules)
		}
	default:
		return fmt.Errorf("%w: add a security key or a KMS key first", ErrSlotRules)
	}
	f := slotFile{
		StorageVersion: e.version,
		ED25519Public:  e.kp.ED25519Public,
		X25519Public:   e.kp.X25519Public,
		MLKEM768PK:     e.kp.MLKEM768PK,
		MLDSA65PK:      e.kp.MLDSA65PK,
		Slots:          e.slots,
	}
	plain, err := e.privatePlaintext()
	if err != nil {
		return err
	}
	defer clear(plain)
	aad, err := privateAAD(e.version, e.fp, f.Slots)
	if err != nil {
		return err
	}
	nonce, ct, err := gcmSeal(e.fk, plain, aad)
	if err != nil {
		return err
	}
	f.Private = sealedV5{Nonce: b64.EncodeToString(nonce), Ciphertext: b64.EncodeToString(ct)}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := e.verify(data); err != nil {
		return fmt.Errorf("refusing to write a key file that does not open: %w", err)
	}
	if err := e.write(data); err != nil {
		return err
	}
	e.original = data
	return nil
}

// verify reads data back as a key file and opens every slot added here and
// the private block, so a write can never lock the user out.
func (e *SlotEditor) verify(data []byte) error {
	f, err := parseSlotFile(data, e.fp)
	if err != nil {
		return err
	}
	if f.StorageVersion != e.version {
		return fmt.Errorf("written as version %d, not %d", f.StorageVersion, e.version)
	}
	for i := range f.Slots {
		kek, ok := e.added[f.Slots[i].ID]
		if !ok {
			continue
		}
		fk, err := openWrap(f.StorageVersion, e.fp, &f.Slots[i], kek)
		if err != nil || !bytes.Equal(fk, e.fk) {
			clear(fk)
			return fmt.Errorf("slot %s does not open", f.Slots[i].ID)
		}
		clear(fk)
	}
	kp, err := f.openPrivate(e.fp, e.fk)
	if err != nil {
		return err
	}
	if kp.ED25519Private != e.kp.ED25519Private || kp.MLDSA65Seed != e.kp.MLDSA65Seed {
		return errors.New("the private keys read back differ")
	}
	return nil
}

func (e *SlotEditor) privatePlaintext() ([]byte, error) {
	dec := func(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }
	var p privateKeysV5
	var err error
	if p.ED25519Private, err = dec(e.kp.ED25519Private); err != nil {
		return nil, err
	}
	if p.X25519Private, err = dec(e.kp.X25519Private); err != nil {
		return nil, err
	}
	if p.MLKEM768Seed, err = dec(e.kp.MLKEM768SK); err != nil {
		return nil, err
	}
	if p.MLDSA65Seed, err = dec(e.kp.MLDSA65Seed); err != nil {
		return nil, err
	}
	defer func() {
		clear(p.ED25519Private)
		clear(p.X25519Private)
		clear(p.MLKEM768Seed)
		clear(p.MLDSA65Seed)
	}()
	return canon.Marshal(p)
}

// CommitPassword takes security key protection off: it writes the key
// pair back as a version 4 file under password, or unprotected when
// password is empty, exactly as Save writes one.
func (e *SlotEditor) CommitPassword(password string) error {
	if e.done {
		return errors.New("editor is closed")
	}
	if err := e.unchanged(); err != nil {
		return err
	}
	return Save(e.dir, e.fp, e.kp, password)
}

// unchanged refuses when the key file is no longer what the editor read:
// another process changed it, or a new key pair's file appeared.
func (e *SlotEditor) unchanged() error {
	path := filepath.Join(e.dir, e.fp+".json")
	cur, err := os.ReadFile(path) // #nosec G304 -- the name is a fingerprint, checked with validKeyName or computed.
	switch {
	case e.original == nil && errors.Is(err, os.ErrNotExist):
		return nil
	case e.original == nil && err == nil:
		return ErrKeyFileChanged
	case err != nil:
		return err
	case !bytes.Equal(cur, e.original):
		return ErrKeyFileChanged
	}
	return nil
}

func (e *SlotEditor) write(data []byte) error {
	if err := disk.MkdirPrivate(e.dir); err != nil {
		return err
	}
	if err := e.unchanged(); err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(e.dir, e.fp+".json"), data)
}

// Close clears the file key and the key-encryption keys the editor holds.
// The unlocked key pair's private keys are Go strings and cannot be
// cleared.
func (e *SlotEditor) Close() {
	clear(e.fk)
	for id := range e.added {
		e.forget(id)
	}
	e.done = true
}
