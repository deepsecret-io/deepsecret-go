// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// ── Key Storage Version ──────────────────────────────────────────────────────

// KeyStorageVersion is the current version of the key file format. Files
// with any other version are rejected on read.
const KeyStorageVersion = 4

// Default Argon2id parameters used when encrypting a new key. Stored in the
// file so the same parameters are used at decrypt time. Defaults follow OWASP
// 2023+ guidance for high-value secrets.
const (
	defaultArgon2Memory  uint32 = 128 * 1024 // 128 MiB
	defaultArgon2Time    uint32 = 3
	defaultArgon2Threads uint8  = 4
)

// keyPairOnDisk is the on-wire JSON layout of a stored key. Distinct from
// KeyPair so KeyPair can keep its private fields tagged json:"-" — accidental
// json.Marshal of a KeyPair never leaks private material; the keystore is the
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

// SaveKeyPair writes a key pair to <DefaultKeysDir>/<fingerprint>.json.
// If password is non-empty, private keys are encrypted with Argon2id + AES-256-GCM.
func SaveKeyPair(fingerprint string, kp *KeyPair, password string) error {
	return SaveKeyPairTo(DefaultKeysDir(), fingerprint, kp, password)
}

// SaveKeyPairTo writes a key pair to <dir>/<fingerprint>.json.
// If password is non-empty, private keys are encrypted with Argon2id + AES-256-GCM.
func SaveKeyPairTo(dir, fingerprint string, kp *KeyPair, password string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	disk := keyPairOnDisk{
		StorageVersion: KeyStorageVersion,
		ED25519Public:  kp.ED25519Public,
		X25519Public:   kp.X25519Public,
		MLKEM768PK:     kp.MLKEM768PK,
		MLDSA65PK:      kp.MLDSA65PK,
	}

	if password != "" {
		if err := encryptOnDisk(&disk, kp, password); err != nil {
			return fmt.Errorf("encrypt private keys: %w", err)
		}
	} else {
		disk.ED25519Private = kp.ED25519Private
		disk.X25519Private = kp.X25519Private
		disk.MLKEM768SK = kp.MLKEM768SK
		disk.MLDSA65Seed = kp.MLDSA65Seed
	}

	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key pair: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, fingerprint+".json"), data, 0600)
}

// LoadKeyPair loads a key pair from the default keys directory.
func LoadKeyPair(fingerprint, password string) (*KeyPair, error) {
	return LoadKeyPairFrom(DefaultKeysDir(), fingerprint, password)
}

// LoadKeyPairFrom loads a key pair from <dir>/<fingerprint>.json. Only
// KeyStorageVersion 4 is accepted; older formats must be regenerated.
func LoadKeyPairFrom(dir, fingerprint, password string) (*KeyPair, error) {
	resolved := resolveFingerprint(dir, fingerprint)
	data, err := os.ReadFile(filepath.Join(dir, resolved+".json"))
	if err != nil {
		return nil, err
	}
	var disk keyPairOnDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, err
	}
	if disk.StorageVersion != KeyStorageVersion {
		return nil, fmt.Errorf("unsupported key storage version %d (this SDK supports version %d only); regenerate the key",
			disk.StorageVersion, KeyStorageVersion)
	}

	kp := &KeyPair{
		StorageVersion: disk.StorageVersion,
		ED25519Public:  disk.ED25519Public,
		X25519Public:   disk.X25519Public,
		MLKEM768PK:     disk.MLKEM768PK,
		MLDSA65PK:      disk.MLDSA65PK,
		Encrypted:      disk.Encrypted,
		Salt:           disk.Salt,
		Nonce:          disk.Nonce,
		EncryptedBlob:  disk.EncryptedBlob,
		Argon2Memory:   disk.Argon2Memory,
		Argon2Time:     disk.Argon2Time,
		Argon2Threads:  disk.Argon2Threads,
	}

	if disk.Encrypted {
		if password == "" {
			return nil, fmt.Errorf("key pair is password-encrypted, provide a password")
		}
		if err := decryptOnDisk(kp, password); err != nil {
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

// ListLocalKeys returns fingerprints of all key pairs stored in the default
// keys directory. Returns nil (not error) if the directory does not exist.
func ListLocalKeys() ([]string, error) {
	return ListLocalKeysIn(DefaultKeysDir())
}

// ListLocalKeysIn returns fingerprints of all key pairs stored in <dir>.
func ListLocalKeysIn(dir string) ([]string, error) {
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
	return []byte(fmt.Sprintf("deepsecret/keystore/v%d/%s", KeyStorageVersion, fingerprint))
}

func encryptOnDisk(disk *keyPairOnDisk, kp *KeyPair, password string) error {
	priv := privateKeysJSON{kp.ED25519Private, kp.X25519Private, kp.MLKEM768SK, kp.MLDSA65Seed}
	plaintext, err := json.Marshal(priv)
	if err != nil {
		return fmt.Errorf("marshal private keys: %w", err)
	}

	fp, err := Fingerprint(kp)
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

func decryptOnDisk(kp *KeyPair, password string) error {
	salt, err := base64.RawStdEncoding.DecodeString(kp.Salt)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(kp.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(kp.EncryptedBlob)
	if err != nil {
		return fmt.Errorf("decode encrypted blob: %w", err)
	}

	if kp.Argon2Memory == 0 || kp.Argon2Time == 0 || kp.Argon2Threads == 0 {
		return fmt.Errorf("key file missing Argon2 parameters; regenerate the key")
	}

	fp, fpErr := Fingerprint(kp)
	if fpErr != nil {
		return fmt.Errorf("compute fingerprint for AAD: %w", fpErr)
	}

	aesKey := argon2.IDKey([]byte(password), salt, kp.Argon2Time, kp.Argon2Memory, kp.Argon2Threads, 32)
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
		return fmt.Errorf("wrong password or corrupted key file")
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
