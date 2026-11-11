// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keystore

// AWS KMS protection: key storage version 6 (docs/kms-design.md).
//
// A version 6 key file is a slot file whose ways in are AWS KMS keys and at
// most one recovery code. A KMS slot holds a random 32-byte slot secret,
// encrypted by KMS under a symmetric key with an encryption context bound to
// the key pair's fingerprint, the DeepSecret account and the slot. KMS
// Decrypt gives the secret back, HKDF turns it into the slot's key, and that
// key unwraps the file key. The private keys never go to KMS: it has no
// X25519 or ML-KEM-768 decapsulation. Talking to AWS is package awskms's
// job; this file checks every answer itself, so any implementation of KMS is
// held to the same rules.

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// kmsStorageVersion is the key file format of a key pair protected by AWS
// KMS keys.
const kmsStorageVersion = 6

const (
	maxKMSSlots = 4
	// kmsSecretSize is the size of a KMS slot's secret.
	kmsSecretSize = 32
	// maxKMSCiphertextLen is the largest CiphertextBlob KMS returns or
	// accepts.
	maxKMSCiphertextLen = 6144
	maxKMSKeyARNLen     = 256
	// maxKeyFileSize bounds a key file given to Import.
	maxKeyFileSize = 1 << 20
)

// The encryption context of every KMS call for a key file: exactly these
// four keys, all lower case (IAM condition keys match without regard to
// case, encryption context keys do not). KMS binds the context to the
// ciphertext, refuses a Decrypt with any other, and writes it to CloudTrail
// in clear. None of the values is secret.
const (
	KMSContextKeyPurpose     = "deepsecret:purpose"
	KMSContextKeyFingerprint = "deepsecret:fingerprint"
	KMSContextKeyAccount     = "deepsecret:account"
	KMSContextKeySlot        = "deepsecret:slot"
	// KMSContextPurpose is the value of deepsecret:purpose: it keeps these
	// ciphertexts apart from anything else under the same KMS key, and
	// names the key file format.
	KMSContextPurpose = "keystore/v6/aws_kms"
)

// The KMS key properties a KMS slot needs, as AWS KMS names them.
const (
	KMSKeySpecSymmetric   = "SYMMETRIC_DEFAULT"
	KMSKeyUsageEncrypt    = "ENCRYPT_DECRYPT"
	KMSKeyStateEnabled    = "Enabled"
	KMSKeyManagerCustomer = "CUSTOMER"
)

// KMS is a key management service that protects a KMS slot's secret.
// Package awskms implements it for AWS KMS. Every call names a full key
// ARN: never an alias, which anyone with kms:UpdateAlias can re-point.
type KMS interface {
	// DescribeKey reports what the key keyARN is.
	DescribeKey(ctx context.Context, keyARN string) (*KMSKey, error)
	// Encrypt encrypts plaintext under the key keyARN with the encryption
	// context, using the symmetric algorithm. The result is the ciphertext
	// and the key KMS says it used.
	Encrypt(ctx context.Context, keyARN string, encryptionContext map[string]string, plaintext []byte) (*KMSResult, error)
	// Decrypt decrypts ciphertext with the key keyARN, which it must name
	// in the request, and the encryption context, using the symmetric
	// algorithm. The result is the plaintext and the key KMS says it used.
	Decrypt(ctx context.Context, keyARN string, encryptionContext map[string]string, ciphertext []byte) (*KMSResult, error)
}

// KMSKey describes a KMS key, in AWS KMS's terms.
type KMSKey struct {
	ARN         string
	Spec        string
	Usage       string
	State       string
	Manager     string
	Description string
}

// KMSResult is the answer to Encrypt or Decrypt: the ciphertext or the
// plaintext, and the key ARN KMS reports.
type KMSResult struct {
	KeyARN string
	Data   []byte
}

// Errors of KMS protection. Package awskms wraps AWS's answers in these, so
// callers can tell them apart with errors.Is without importing AWS code.
var (
	ErrKMSRequired      = errors.New("key pair is protected by AWS KMS")
	ErrKMSNoCredentials = errors.New("no AWS credentials were found")
	// ErrKMSCredentialsRejected is AWS refusing the credentials themselves:
	// unknown, deactivated or expired keys, or a request signature it does
	// not accept. ErrKMSAccessDenied is a known identity without permission.
	ErrKMSCredentialsRejected = errors.New("AWS rejected the credentials")
	ErrKMSAccessDenied        = errors.New("AWS KMS refused this AWS identity")
	ErrKMSKeyUnavailable      = errors.New("the KMS key cannot be used")
	ErrKMSMismatch            = errors.New("the KMS answer does not open this key file")
	ErrKMSUnreachable         = errors.New("AWS KMS could not be reached")
	ErrKMSKeyRejected         = errors.New("this KMS key cannot protect a key file")
	ErrKeyFileExists          = errors.New("a different key file for this key pair is already on this device")
)

// kmsSlotV6 is what a KMS slot keeps besides its wrap. The encryption
// context is not stored: it is rebuilt from the fingerprint, the slot id and
// Account, so a file cannot carry a context the code does not expect.
type kmsSlotV6 struct {
	KeyARN     string `json:"key_arn"`
	Account    string `json:"account"`
	Ciphertext string `json:"ciphertext"`
}

// kmsKeyARN is a full KMS key ARN in a partition KMS slots accept. An alias
// never passes: anyone with kms:UpdateAlias can re-point one.
var kmsKeyARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

// ValidKMSKeyARN reports whether s is a full KMS key ARN a KMS slot accepts:
// partition aws, aws-us-gov or aws-cn, and a key id, not an alias.
func ValidKMSKeyARN(s string) bool {
	return len(s) <= maxKMSKeyARNLen && kmsKeyARN.MatchString(s)
}

// KMSKeyRegion is the region of a key ARN ValidKMSKeyARN accepts, or "".
func KMSKeyRegion(arn string) string {
	if !ValidKMSKeyARN(arn) {
		return ""
	}
	return strings.Split(arn, ":")[3]
}

// validAccount accepts a DeepSecret account id: a UUID in canonical lower-case
// form, not the nil UUID.
func validAccount(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u != uuid.Nil && u.String() == s
}

func (k *kmsSlotV6) check() error {
	if !ValidKMSKeyARN(k.KeyARN) {
		return errors.New("key_arn is not a KMS key ARN")
	}
	if !validAccount(k.Account) {
		return errors.New("account is not a lower-case UUID")
	}
	if err := checkB64(k.Ciphertext, 1, maxKMSCiphertextLen); err != nil {
		return fmt.Errorf("ciphertext: %w", err)
	}
	return nil
}

// KMSContext is the encryption context of the KMS slot slotID of the key
// pair fingerprint, bound to account.
func KMSContext(fingerprint, slotID, account string) map[string]string {
	return map[string]string{
		KMSContextKeyPurpose:     KMSContextPurpose,
		KMSContextKeyFingerprint: fingerprint,
		KMSContextKeyAccount:     account,
		KMSContextKeySlot:        slotID,
	}
}

func kmsKEK(secret []byte, fp, slotID string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, "deepsecret/keystore/v6/aws_kms/"+fp+"/"+slotID, fileKeySize)
}

// ── Unlocking ────────────────────────────────────────────────────────────────

// openKMS opens the file key with the first KMS slot whose key answers. It
// moves to the next slot only when a key cannot be reached or used (an
// outage, a disabled key); a refusal or a wrong answer is returned at once,
// since a person must see it.
func (f *slotFile) openKMS(ctx context.Context, fp string, k KMS) ([]byte, error) {
	var last error
	for i := range f.Slots {
		s := &f.Slots[i]
		if s.Type != SlotAWSKMS {
			continue
		}
		fk, err := openKMSSlot(ctx, fp, s, k)
		if err == nil {
			return fk, nil
		}
		if errors.Is(err, ErrKMSUnreachable) || errors.Is(err, ErrKMSKeyUnavailable) {
			last = err
			continue
		}
		return nil, err
	}
	if last == nil {
		return nil, ErrKMSRequired
	}
	return nil, last
}

func openKMSSlot(ctx context.Context, fp string, s *fileSlot, k KMS) ([]byte, error) {
	arn := s.AWSKMS.KeyARN
	ct, err := b64.DecodeString(s.AWSKMS.Ciphertext)
	if err != nil {
		return nil, kmsMismatch(arn)
	}
	res, err := k.Decrypt(ctx, arn, KMSContext(fp, s.ID, s.AWSKMS.Account), ct)
	if err != nil {
		return nil, fmt.Errorf("KMS key %s: %w", arn, err)
	}
	if res == nil {
		return nil, kmsMismatch(arn)
	}
	defer clear(res.Data)
	if res.KeyARN != arn || len(res.Data) != kmsSecretSize {
		return nil, kmsMismatch(arn)
	}
	kek, err := kmsKEK(res.Data, fp, s.ID)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	fk, err := openWrap(kmsStorageVersion, fp, s, kek)
	if err != nil {
		return nil, kmsMismatch(arn)
	}
	return fk, nil
}

func kmsMismatch(arn string) error {
	return fmt.Errorf("%w (KMS key %s)", ErrKMSMismatch, arn)
}

// ── Editing ──────────────────────────────────────────────────────────────────

// NewKMSKeyFile returns an editor for a key pair not yet stored, so a new
// key pair is written straight to a version 6 file and never sits on disk
// unprotected. Commit refuses to write over an existing file.
func NewKMSKeyFile(dir string, kp *keys.Pair) (*SlotEditor, error) {
	return newSlotFileEditor(dir, kp, kmsStorageVersion)
}

// ErrKMSNotKeyARN refuses a KMS key named any other way than by its full
// key ARN.
var ErrKMSNotKeyARN = fmt.Errorf("%w: give the full key ARN, arn:<partition>:kms:<region>:<account>:key/<key id>; a key id or an alias is refused, since anyone with kms:UpdateAlias can re-point an alias", ErrKMSKeyRejected)

// DescribeKMSKey asks k about the key keyARN, a full key ARN in a partition
// KMS slots accept, and returns it only if a KMS slot may use it: a
// customer managed, enabled, symmetric encryption key. An asymmetric key is
// refused: a slot secret encrypted under RSA would leave the stored file
// only as strong as RSA against a quantum computer.
func DescribeKMSKey(ctx context.Context, k KMS, keyARN string) (*KMSKey, error) {
	if k == nil {
		return nil, ErrKMSRequired
	}
	if !ValidKMSKeyARN(keyARN) {
		return nil, ErrKMSNotKeyARN
	}
	key, err := k.DescribeKey(ctx, keyARN)
	if err != nil {
		return nil, err
	}
	switch {
	case key == nil:
		return nil, fmt.Errorf("%w: KMS described no key", ErrKMSKeyRejected)
	case key.ARN != keyARN:
		return nil, fmt.Errorf("%w: KMS described %q for %s", ErrKMSMismatch, key.ARN, keyARN)
	case key.Manager != KMSKeyManagerCustomer:
		return nil, fmt.Errorf("%w: %s is an AWS managed key; use a customer managed key", ErrKMSKeyRejected, key.ARN)
	case key.Spec != KMSKeySpecSymmetric:
		return nil, fmt.Errorf("%w: %s is a %s key; a key file needs a symmetric (%s) key", ErrKMSKeyRejected, key.ARN, key.Spec, KMSKeySpecSymmetric)
	case key.Usage != KMSKeyUsageEncrypt:
		return nil, fmt.Errorf("%w: %s is for %s, not %s", ErrKMSKeyRejected, key.ARN, key.Usage, KMSKeyUsageEncrypt)
	case key.State != KMSKeyStateEnabled:
		return nil, fmt.Errorf("%w: %s is %s, not %s", ErrKMSKeyRejected, key.ARN, key.State, KMSKeyStateEnabled)
	}
	return key, nil
}

// AddKMS adds the AWS KMS key keyARN, a full key ARN, as a slot bound to
// account: the DeepSecret account id the key pair belongs to. Every KMS
// slot of a file names the same account. An empty label becomes one naming
// the key and its region.
func (e *SlotEditor) AddKMS(ctx context.Context, k KMS, keyARN, account, label string) (SlotInfo, error) {
	if e.done {
		return SlotInfo{}, errors.New("editor is closed")
	}
	if err := e.kind(kmsStorageVersion); err != nil {
		return SlotInfo{}, err
	}
	if e.count(SlotAWSKMS) >= maxKMSSlots {
		return SlotInfo{}, fmt.Errorf("%w: a key file holds at most %d KMS keys", ErrSlotRules, maxKMSSlots)
	}
	if !validAccount(account) {
		return SlotInfo{}, fmt.Errorf("%w: %q is not a DeepSecret account id", ErrSlotRules, account)
	}
	for _, s := range e.slots {
		if s.AWSKMS != nil && s.AWSKMS.Account != account {
			return SlotInfo{}, fmt.Errorf("%w: the key pair's KMS keys are bound to account %s, not %s", ErrSlotRules, s.AWSKMS.Account, account)
		}
	}
	if label != "" {
		if err := validateLabel(label); err != nil {
			return SlotInfo{}, err
		}
	}
	key, err := DescribeKMSKey(ctx, k, keyARN)
	if err != nil {
		return SlotInfo{}, err
	}
	for _, s := range e.slots {
		if s.AWSKMS != nil && s.AWSKMS.KeyARN == key.ARN {
			return SlotInfo{}, fmt.Errorf("%w: KMS key %s already protects this key pair", ErrSlotRules, key.ARN)
		}
	}
	id, err := newSlotID()
	if err != nil {
		return SlotInfo{}, err
	}
	secret, err := freshBytes(kmsSecretSize)
	if err != nil {
		return SlotInfo{}, err
	}
	defer clear(secret)
	res, err := k.Encrypt(ctx, key.ARN, KMSContext(e.fp, id, account), secret)
	if err != nil {
		return SlotInfo{}, fmt.Errorf("KMS key %s: %w", key.ARN, err)
	}
	if res == nil || res.KeyARN != key.ARN || len(res.Data) < 1 || len(res.Data) > maxKMSCiphertextLen {
		return SlotInfo{}, fmt.Errorf("%w: KMS answered for another key or with a malformed ciphertext (KMS key %s)", ErrKMSMismatch, key.ARN)
	}
	if label == "" {
		label = kmsLabel(key.ARN)
	}
	s := fileSlot{
		ID: id, Type: SlotAWSKMS, Label: label, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		AWSKMS: &kmsSlotV6{KeyARN: key.ARN, Account: account, Ciphertext: b64.EncodeToString(res.Data)},
	}
	kek, err := kmsKEK(secret, e.fp, id)
	if err != nil {
		return SlotInfo{}, err
	}
	if err := e.seal(kmsStorageVersion, &s, kek); err != nil {
		clear(kek)
		return SlotInfo{}, err
	}
	e.slots = append(e.slots, s)
	e.added[id] = kek
	e.version = kmsStorageVersion
	return s.info(), nil
}

// kmsLabel names a KMS key by the start of its id and its region:
// "AWS KMS key 1234abcd (eu-west-1)".
func kmsLabel(arn string) string {
	id := arn[strings.LastIndex(arn, "/")+1:]
	id = strings.TrimPrefix(id, "mrk-")
	if len(id) > 8 {
		id = id[:8]
	}
	return "AWS KMS key " + id + " (" + KMSKeyRegion(arn) + ")"
}

// ── Import ───────────────────────────────────────────────────────────────────

// Import writes data, a key file made on another machine, into dir as
// <fingerprint>.json, private to this user, and returns the fingerprint.
// Only a slot file (version 5 or 6) is accepted, read strictly, with public
// keys that hash to its fingerprint. A version 4 file is refused: an
// unprotected one must never be copied between machines, and a password one
// cannot be unlocked unattended. Importing the same bytes again changes
// nothing; different bytes for a key pair already here are refused with
// ErrKeyFileExists unless replace is set.
func Import(dir string, data []byte, replace bool) (string, error) {
	if len(data) == 0 || len(data) > maxKeyFileSize {
		return "", fmt.Errorf("a key file is 1 byte to %d bytes", maxKeyFileSize)
	}
	if err := checkNoDuplicateKeys(data); err != nil {
		return "", fmt.Errorf("key file: %w", err)
	}
	var head struct {
		StorageVersion int    `json:"storage_version"`
		ED25519Public  string `json:"ed25519_public"`
		X25519Public   string `json:"x25519_public"`
		MLKEM768PK     string `json:"mlkem768_pk"`
		MLDSA65PK      string `json:"mldsa65_pk"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return "", fmt.Errorf("key file: %w", err)
	}
	switch v := head.StorageVersion; {
	case v == securityKeyStorageVersion || v == kmsStorageVersion:
	case v == keyStorageVersion:
		return "", errors.New("a version 4 key file (password or none) cannot be imported: protect the key pair with AWS KMS or a security key first")
	case v > kmsStorageVersion:
		return "", fmt.Errorf("key storage version %d needs a newer version of DeepSecret", v)
	default:
		return "", fmt.Errorf("unsupported key storage version %d", v)
	}
	fp, err := keys.FingerprintFromPubs(head.ED25519Public, head.X25519Public, head.MLKEM768PK, head.MLDSA65PK)
	if err != nil {
		return "", fmt.Errorf("key file: %w", err)
	}
	if _, err := parseSlotFile(data, fp); err != nil {
		return "", err
	}
	if err := disk.MkdirPrivate(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fp+".json")
	if st, err := os.Lstat(path); err == nil {
		if st.Mode().IsRegular() {
			cur, err := os.ReadFile(path) // #nosec G304 -- the name is a fingerprint computed from the public keys.
			if err != nil {
				return "", err
			}
			if bytes.Equal(cur, data) {
				return fp, nil
			}
		}
		if !replace {
			return "", fmt.Errorf("%w: %s", ErrKeyFileExists, keys.ShortFingerprint(fp))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := writePrivateFile(path, data); err != nil {
		return "", err
	}
	return fp, nil
}
