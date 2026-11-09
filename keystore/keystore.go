// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/deepsecret-io/deepsecret-go/internal/disk"
	"github.com/deepsecret-io/deepsecret-go/keys"
)

// ── Key Storage Version ──────────────────────────────────────────────────────

// keyStorageVersion is the current version of the key file format. Files
// with any other version are rejected on read.
const keyStorageVersion = 4

// Default Argon2id parameters used when encrypting a new key. Stored in the
// file so the same parameters are used at decrypt time. Defaults follow OWASP
// 2023+ guidance for high-value secrets.
const (
	defaultArgon2Memory  uint32 = 128 * 1024 // 128 MiB
	defaultArgon2Time    uint32 = 3
	defaultArgon2Threads uint8  = 4
)

// keyPairOnDisk is the on-wire JSON layout of a stored key. Distinct from
// keys.Pair so keys.Pair can keep its private fields tagged json:"-": accidental
// json.Marshal of a keys.Pair never leaks private material; the keystore is the
// only code that opts into writing this richer struct.
type keyPairOnDisk struct {
	StorageVersion int `json:"storage_version"`

	ED25519Public string `json:"ed25519_public"`
	X25519Public  string `json:"x25519_public"`
	MLKEM768PK    string `json:"mlkem768_pk"`
	MLDSA65PK     string `json:"mldsa65_pk"`

	// Plaintext private keys, only populated for unencrypted keystores.
	ED25519Private string `json:"ed25519_private,omitempty"`
	X25519Private  string `json:"x25519_private,omitempty"`
	MLKEM768SK     string `json:"mlkem768_sk,omitempty"`
	MLDSA65Seed    string `json:"mldsa65_seed,omitempty"`

	// Encrypted-keystore fields.
	Encrypted     bool   `json:"encrypted,omitempty"`
	Salt          string `json:"salt,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	EncryptedBlob string `json:"encrypted_blob,omitempty"`
	Argon2Memory  uint32 `json:"argon2_memory,omitempty"`  // KiB
	Argon2Time    uint32 `json:"argon2_time,omitempty"`    // iterations
	Argon2Threads uint8  `json:"argon2_threads,omitempty"` // parallelism
}

// ── Key Storage ──────────────────────────────────────────────────────────────

// DefaultKeysDir returns the default directory for storing key pairs.
func DefaultKeysDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".deepsecret", "keys")
	}
	return filepath.Join(home, ".deepsecret", "keys")
}

// Save writes a key pair to <dir>/<fingerprint>.json.
// If password is non-empty, private keys are encrypted with Argon2id + AES-256-GCM.
func Save(dir, fingerprint string, kp *keys.Pair, password string) error {
	if !validKeyName(fingerprint) {
		return errInvalidKeyName
	}
	if err := disk.MkdirPrivate(dir); err != nil {
		return err
	}

	onDisk := keyPairOnDisk{
		StorageVersion: keyStorageVersion,
		ED25519Public:  kp.ED25519Public,
		X25519Public:   kp.X25519Public,
		MLKEM768PK:     kp.MLKEM768PK,
		MLDSA65PK:      kp.MLDSA65PK,
	}

	if password != "" {
		if err := encryptOnDisk(&onDisk, kp, password); err != nil {
			return fmt.Errorf("encrypt private keys: %w", err)
		}
	} else {
		onDisk.ED25519Private = kp.ED25519Private
		onDisk.X25519Private = kp.X25519Private
		onDisk.MLKEM768SK = kp.MLKEM768SK
		onDisk.MLDSA65Seed = kp.MLDSA65Seed
	}

	data, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key pair: %w", err)
	}
	return writePrivateFile(filepath.Join(dir, fingerprint+".json"), data)
}

// writePrivateFile replaces path with data through a new file in the same
// directory, private to this user (disk.CreateTemp), synced and renamed
// over it. The key file is then private even when an older one was not, a
// link at path is replaced rather than written through, and a crash leaves
// the old file or the new one, never half of either.
func writePrivateFile(path string, data []byte) error {
	tmp, err := disk.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	// After the rename this finds nothing; after a failure it removes the
	// temporary file.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close() // the write error is returned and the file removed.
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close() // the sync error is returned and the file removed.
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Load loads a key pair from <dir>/<fingerprint>.json, where
// fingerprint may be a prefix of 16 or more characters. It reads version 4
// files (password or none); a security-key file (version 5) needs
// Open and returns ErrSecurityKeyRequired here.
func Load(dir, fingerprint, password string) (*keys.Pair, error) {
	// The fingerprint can come from the server (the primary key it lists),
	// and it names the file read.
	fingerprint = strings.ToLower(fingerprint)
	if !validKeyName(fingerprint) {
		return nil, errInvalidKeyName
	}
	f, err := readKeyFile(dir, resolveFingerprint(dir, fingerprint))
	if err != nil {
		return nil, err
	}
	if f.v5 != nil {
		return nil, ErrSecurityKeyRequired
	}
	return loadV4(f.v4, password)
}

// Errors of password-protected (version 4) key files. Their text is part
// of the contract: callers have matched on it.
var (
	ErrPasswordRequired = errors.New("key pair is password-encrypted, provide a password")
	ErrWrongPassword    = errors.New("wrong password or corrupted key file")
)

// loadV4 reads the private keys of a version 4 key file: in clear, or
// decrypted with password.
func loadV4(disk *keyPairOnDisk, password string) (*keys.Pair, error) {
	kp := &keys.Pair{
		ED25519Public: disk.ED25519Public,
		X25519Public:  disk.X25519Public,
		MLKEM768PK:    disk.MLKEM768PK,
		MLDSA65PK:     disk.MLDSA65PK,
	}

	if disk.Encrypted {
		if password == "" {
			return nil, ErrPasswordRequired
		}
		if err := decryptOnDisk(disk, kp, password); err != nil {
			return nil, err
		}
	} else {
		kp.ED25519Private = disk.ED25519Private
		kp.X25519Private = disk.X25519Private
		kp.MLKEM768SK = disk.MLKEM768SK
		kp.MLDSA65Seed = disk.MLDSA65Seed
	}
	return kp, nil
}

// LoadPublic reads the public keys of the key pair stored in
// <dir>/<fingerprint>.json, without its password: the private keys are not
// read. fingerprint must be a full one, not a prefix, and the stored public
// keys must hash to it.
func LoadPublic(dir, fingerprint string) (*keys.PublicKeys, error) {
	fingerprint = strings.ToLower(fingerprint)
	if len(fingerprint) != keys.FingerprintLen || !validKeyName(fingerprint) {
		return nil, errors.New("a full key fingerprint is 64 hex characters")
	}
	f, err := readKeyFile(dir, fingerprint)
	if err != nil {
		return nil, err
	}
	pubKeys := f.publicKeys()
	pub := &pubKeys
	if pub.Fingerprint, err = keys.FingerprintFromPubs(pub.ED25519, pub.X25519, pub.MLKEM768, pub.MLDSA65); err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(fingerprint), err)
	}
	if pub.Fingerprint != fingerprint {
		return nil, fmt.Errorf("key file %s holds the keys of %s", keys.ShortFingerprint(fingerprint), keys.ShortFingerprint(pub.Fingerprint))
	}
	return pub, nil
}

// keyFile is a key file as read: version 4 (password or none) or version 5
// (security keys), and its bytes.
type keyFile struct {
	raw []byte
	v4  *keyPairOnDisk
	v5  *securityKeyFile
}

func (f *keyFile) publicKeys() keys.PublicKeys {
	if f.v5 != nil {
		return f.v5.publicKeys()
	}
	return keys.PublicKeys{ED25519: f.v4.ED25519Public, X25519: f.v4.X25519Public, MLKEM768: f.v4.MLKEM768PK, MLDSA65: f.v4.MLDSA65PK}
}

// readKeyFile reads <dir>/<name>.json, a key file of storage version 4 or
// 5, and refuses one that someone else may open (disk.ReadPrivate). name
// must be hex only, so it cannot change the path.
func readKeyFile(dir, name string) (*keyFile, error) {
	data, err := disk.ReadPrivate(filepath.Join(dir, name+".json"))
	if err != nil {
		return nil, err
	}
	// One storage_version only, in any case: encoding/json would read
	// "Storage_Version" as storage_version and keep the last of several.
	if err := checkNoDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("key file %s: %w", keys.ShortFingerprint(name), err)
	}
	var head struct {
		StorageVersion int `json:"storage_version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, err
	}
	switch v := head.StorageVersion; {
	case v == keyStorageVersion:
		var v4 keyPairOnDisk
		if err := json.Unmarshal(data, &v4); err != nil {
			return nil, err
		}
		return &keyFile{raw: data, v4: &v4}, nil
	case v == securityKeyStorageVersion:
		f, err := parseSecurityKeyFile(data, name)
		if err != nil {
			return nil, err
		}
		return &keyFile{raw: data, v5: f}, nil
	case v > securityKeyStorageVersion:
		return nil, fmt.Errorf("key storage version %d needs a newer version of DeepSecret", v)
	default:
		return nil, fmt.Errorf("unsupported key storage version %d (this SDK supports versions %d and %d); regenerate the key",
			v, keyStorageVersion, securityKeyStorageVersion)
	}
}

// List returns fingerprints of all key pairs stored in <dir>.
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name()[:len(e.Name())-5])
		}
	}
	return names, nil
}

// errInvalidKeyName refuses a fingerprint that cannot name a key file.
var errInvalidKeyName = errors.New("a key fingerprint is 16 to 64 hex characters")

// validKeyName reports whether fp can name a key file: 16 to 64 lower-case
// hex characters, a fingerprint or a prefix of one. The file's path is
// built from it, so nothing that could change the path passes.
func validKeyName(fp string) bool {
	if len(fp) < 16 || len(fp) > 64 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		if c := fp[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// resolveFingerprint resolves a possibly-truncated fingerprint to the full
// filename in the keys directory. Falls back to a prefix scan when the exact
// match is not found.
func resolveFingerprint(dir, fp string) string {
	if _, err := os.Stat(filepath.Join(dir, fp+".json")); err == nil {
		return fp
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fp
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		name := e.Name()[:len(e.Name())-5]
		if len(fp) >= 16 && len(name) > len(fp) && name[:len(fp)] == fp {
			return name
		}
	}
	return fp
}

// ── Password encryption (Argon2id + AES-256-GCM) ────────────────────────────

type privateKeysJSON struct {
	ED25519Private string `json:"ed25519_private"`
	X25519Private  string `json:"x25519_private"`
	MLKEM768SK     string `json:"mlkem768_sk"`
	MLDSA65Seed    string `json:"mldsa65_seed"`
}

// keystoreAAD binds the encrypted blob to the public-key fingerprint and the
// storage version so an EncryptedBlob cannot be transplanted between
// keystores or replayed against a different format.
func keystoreAAD(fingerprint string) []byte {
	return []byte(fmt.Sprintf("deepsecret/keystore/v%d/%s", keyStorageVersion, fingerprint))
}

func encryptOnDisk(disk *keyPairOnDisk, kp *keys.Pair, password string) error {
	priv := privateKeysJSON{kp.ED25519Private, kp.X25519Private, kp.MLKEM768SK, kp.MLDSA65Seed}
	plaintext, err := json.Marshal(priv)
	if err != nil {
		return fmt.Errorf("marshal private keys: %w", err)
	}

	fp, err := keys.Fingerprint(kp)
	if err != nil {
		return fmt.Errorf("compute fingerprint for AAD: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	memKiB := defaultArgon2Memory
	iter := defaultArgon2Time
	threads := defaultArgon2Threads

	aesKey := argon2.IDKey([]byte(password), salt, iter, memKiB, threads, 32)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, keystoreAAD(fp))

	disk.Encrypted = true
	disk.Salt = base64.RawStdEncoding.EncodeToString(salt)
	disk.Nonce = base64.RawStdEncoding.EncodeToString(nonce)
	disk.EncryptedBlob = base64.RawStdEncoding.EncodeToString(ciphertext)
	disk.Argon2Memory = memKiB
	disk.Argon2Time = iter
	disk.Argon2Threads = threads
	return nil
}

func decryptOnDisk(disk *keyPairOnDisk, kp *keys.Pair, password string) error {
	salt, err := base64.RawStdEncoding.DecodeString(disk.Salt)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(disk.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(disk.EncryptedBlob)
	if err != nil {
		return fmt.Errorf("decode encrypted blob: %w", err)
	}

	if disk.Argon2Memory == 0 || disk.Argon2Time == 0 || disk.Argon2Threads == 0 {
		return fmt.Errorf("key file missing Argon2 parameters; regenerate the key")
	}

	fp, fpErr := keys.Fingerprint(kp)
	if fpErr != nil {
		return fmt.Errorf("compute fingerprint for AAD: %w", fpErr)
	}

	aesKey := argon2.IDKey([]byte(password), salt, disk.Argon2Time, disk.Argon2Memory, disk.Argon2Threads, 32)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, keystoreAAD(fp))
	if err != nil {
		return ErrWrongPassword
	}

	var priv privateKeysJSON
	if err := json.Unmarshal(plaintext, &priv); err != nil {
		return fmt.Errorf("unmarshal private keys: %w", err)
	}
	kp.ED25519Private = priv.ED25519Private
	kp.X25519Private = priv.X25519Private
	kp.MLKEM768SK = priv.MLKEM768SK
	kp.MLDSA65Seed = priv.MLDSA65Seed
	return nil
}
