// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"github.com/deepsecret-io/sdk/compress"
	"github.com/deepsecret-io/sdk/identity"
	"github.com/deepsecret-io/sdk/payload"
	"github.com/deepsecret-io/sdk/secrets"
)

// DefaultMaxPayloadSize is the default client-side preflight cap on the
// total uncompressed input bytes. 100 GiB matches the largest secret the
// API takes (the Organization plan); callers can override per-call via
// EncryptOptions.MaxPayloadSize.
const DefaultMaxPayloadSize int64 = 100 << 30

// DefaultMaxDownloadSize is the largest stored payload a decrypt downloads
// unless DecryptOptions.MaxDownloadSize says otherwise: a 100 GiB secret
// plus its encryption overhead.
const DefaultMaxDownloadSize int64 = 101 << 30

// DefaultMaxInMemorySize is the largest stored payload DecryptSecretFull and
// OpenedSecret.Payload hold in memory. Larger file payloads are written
// to disk with OpenedSecret.WriteFiles or DecryptToDir.
const DefaultMaxInMemorySize int64 = 256 << 20

// MaxRecipientsPerSend is the most recipients one send may have. The API
// enforces the same cap; the protocol itself allows crypto.MaxRecipients.
const MaxRecipientsPerSend = 100

// CompressZstd is the Zstandard compression algorithm identifier.
// Use this with EncryptOptions.Compress.
const CompressZstd = compress.Zstd

// ── Re-exported types ────────────────────────────────────────────────────────
// These allow callers to import only "github.com/deepsecret-io/sdk"
// without reaching into internal sub-packages.

// ActorInfo holds the authenticated user's details and tier limits.
type ActorInfo = identity.ActorInfo

// RemoteKey represents an identity key registered on the server.
type RemoteKey = identity.RemoteKey

// GroupInfo represents an org group with its members.
type GroupInfo = identity.GroupInfo

// GroupMemberInfo represents a single member of a group.
type GroupMemberInfo = identity.GroupMemberInfo

// SecretInfo holds detailed metadata about a secret (returned by list/describe).
type SecretInfo = secrets.SecretInfo

// SecretRecipient is one person with access to a secret.
type SecretRecipient = secrets.SecretRecipient

// ListOptions configures pagination and filtering for secret listing.
type ListOptions = secrets.ListOptions

// DecryptedPayload holds the decrypted content of a secret.
type DecryptedPayload = payload.Decrypted

// DecryptedFile holds a single decrypted file from a secret.
type DecryptedFile = payload.DecryptedFile

// KeyValue holds a single key-value pair from a decrypted data secret.
type KeyValue = payload.KeyValue

// ── Options & Results ────────────────────────────────────────────────────────

// EncryptOptions configures encryption and upload behavior.
type EncryptOptions struct {
	Name       string
	Compress   compress.Algorithm
	Archive    bool
	SkipHidden bool
	TTL        string // "30m", "24h", "7d"
	IPs        []string

	// RevokeMissing confirms that a send under an existing name may leave
	// out people who have access to that secret now, revoking them.
	// Without it such a send fails with api.ErrConflict and the server's
	// message names them.
	RevokeMissing bool

	// MaxPayloadSize limits the total uncompressed payload size in bytes.
	// Zero means use DefaultMaxPayloadSize.
	MaxPayloadSize int64

	// TempDir is where the send keeps its temporary ciphertext file, in a
	// private directory it removes when done. Empty means
	// $DEEPSECRET_TMPDIR, else the system temp directory. It needs free
	// space for the encrypted payload; the send checks before reading.
	TempDir string

	// OnUploadProgress is called during ciphertext upload with bytes transferred
	// and total bytes. Use this for progress UI. Optional.
	OnUploadProgress func(transferred, total int64)

	// OnDebug is called at each step of the encrypt/upload flow with a
	// short context tag ("encrypt", "upload", "confirm", ...) and a message.
	// Wire it to your CLI's debug logger. Optional.
	OnDebug func(step, message string)

	// AutoArchive bundles files into a tar archive when the file count
	// exceeds the tier's MaxFilesPerSecret limit. When true, the SDK fetches
	// tier info and auto-archives if needed.
	AutoArchive bool

	// ValidateTier pre-checks tier limits (MaxUploadBytes, policy flags)
	// before performing encryption. Returns a clear error if limits are exceeded.
	ValidateTier bool

	// Identity specifies a local key fingerprint (or prefix) to use for signing.
	// If empty, the server-registered primary identity is used.
	Identity string

	// Password is the password for decrypting password-protected identity keys.
	// If the primary key is encrypted and this is empty, encryption will fail.
	Password string

	// UploadThreads sets the maximum number of parallel part PUTs the SDK
	// uses for multipart upload. 0 = SDK default (4). 1 = serial. Values
	// are clamped to a sane upper bound. Trades sockets and concurrent
	// memory pressure for faster transfer on high-bandwidth links.
	UploadThreads int

	// PresignExpiryMinutes requests presigned URL lifetime in minutes for
	// the upload. Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30).
	PresignExpiryMinutes int
}

// Recipient is one recipient of a revision: their email and the
// fingerprint of the key their wrap was made for.
type Recipient struct {
	Email       string `json:"email,omitempty" yaml:"email,omitempty"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
}

// EncryptResult is returned by all encrypt methods with full metadata. One
// send encrypts the payload once for every recipient, so the sizes are
// those of the single stored payload.
type EncryptResult struct {
	Secret            secrets.Secret
	EncryptedSize     int64
	SenderFingerprint string
	Recipients        []Recipient       // everyone the revision was sealed for, in the order given
	Revoked           []SecretRecipient // people a send with RevokeMissing removed
	Compressed        bool
	Compression       string  // "zstd", "tar+zstd", ""
	CompressionRatio  float64 // compressed/original * 100
	OriginalSize      int64
	PayloadType       string // "message", "data", "files"
	FilesCount        int    // visible files sent to server metadata (0 when archived)
	Archived          bool
	ArchiveEntryCount int // original file count before archiving (set only when Archived=true)
}

// DecryptOptions configures decrypt behavior.
type DecryptOptions struct {
	// Revision selects a specific revision to decrypt. Empty means latest.
	Revision string

	// Identity specifies a local key fingerprint (or prefix) to use for decryption.
	// If empty, the server-registered primary identity is used.
	Identity string

	// OnDownloadProgress is called during ciphertext download with bytes
	// transferred and total bytes. Use this for progress UI. Optional.
	OnDownloadProgress func(transferred, total int64)

	// OnDebug is called at each step of the download/decrypt flow. Optional.
	OnDebug func(step, message string)

	// Password is the password for decrypting password-protected identity keys.
	Password string

	// DownloadThreads sets the maximum number of parallel Range GETs the SDK
	// uses for downloading the payload. 0 = SDK default (4). 1 = one range
	// at a time. Values are clamped to a sane upper bound by the SDK.
	// Larger values trade more sockets and memory (one range buffer each)
	// for faster transfer on high-RTT or high-bandwidth links.
	DownloadThreads int

	// TempDir is where the download keeps the ciphertext, in a private
	// directory removed on Close: its digest is verified against the signed
	// manifest before any plaintext is released. Empty means
	// $DEEPSECRET_TMPDIR, else the system temp directory.
	TempDir string

	// MaxDownloadSize refuses a stored payload larger than this many bytes
	// before downloading it. Zero means DefaultMaxDownloadSize.
	MaxDownloadSize int64

	// PresignExpiryMinutes requests presigned URL lifetime in minutes for
	// the download. Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30).
	PresignExpiryMinutes int
}

// DecryptResult is returned by full decrypt methods with the metadata of
// the verified manifest.
type DecryptResult struct {
	Decrypted            *payload.Decrypted
	RevisionID           string // UUID of the revision that was decrypted (resolved if Revision was empty)
	SenderFingerprint    string
	RecipientFingerprint string      // the caller's own key, which the wrap was made for
	Recipients           []Recipient // every recipient the sender signed for; Email is the server's label for each fingerprint
	Compressed           bool
	Compression          string
	PayloadType          string
	ProtocolVersion      string // from the signed manifest
	CipherSuite          string // from the signed manifest
	PayloadDigest        string // hex SHA-256 of the stored payload, verified against the signed manifest
	EncryptedSize        int64
}

// RevokeResult is returned by RevokeRecipient.
type RevokeResult struct {
	RecipientID   string // actor id of the revoked recipient
	Email         string
	SecretDeleted bool // revoking the last recipient deleted the secret
}

// SecretDetail holds a secret's full metadata including revisions.
// Returned by DescribeSecretFull.
type SecretDetail struct {
	Secret    SecretInfo     `json:"secret" yaml:"secret"`
	Revisions []RevisionInfo `json:"revisions" yaml:"revisions"`
}

// PolicyUpdate configures which policies to update on a secret.
type PolicyUpdate struct {
	TTLSeconds *int      // nil = don't change, 0 = clear
	AllowedIPs *[]string // nil = don't change, empty = clear
}

// PolicyResult holds the updated policy state after an update.
type PolicyResult struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ExpiresAt  *string  `json:"expires_at,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// RevisionInfo holds metadata for a single revision of a secret.
type RevisionInfo struct {
	ID             string        `json:"id" yaml:"id"`
	RevisionNumber int           `json:"revision_number" yaml:"revision_number"`
	Size           int64         `json:"size" yaml:"size"`
	FilesCount     int           `json:"files_count" yaml:"files_count"`
	StorageName    string        `json:"storage_name" yaml:"storage_name"`
	Integrity      IntegrityInfo `json:"integrity" yaml:"integrity"`
	CreatedAt      string        `json:"created_at" yaml:"created_at"`
	FilesMeta      []FileMeta    `json:"files_meta" yaml:"files_meta"`
}

// IntegrityInfo holds cryptographic integrity metadata for a revision.
type IntegrityInfo struct {
	ProtocolVersion  string  `json:"protocol_version" yaml:"protocol_version"`
	CipherSuite      string  `json:"cipher_suite" yaml:"cipher_suite"`
	KDF              string  `json:"kdf" yaml:"kdf"`
	Encryption       string  `json:"encryption" yaml:"encryption"`
	KEM              string  `json:"kem" yaml:"kem"`
	Signing          string  `json:"signing" yaml:"signing"`
	Serialization    string  `json:"serialization" yaml:"serialization"`
	PayloadType      string  `json:"payload_type" yaml:"payload_type"`
	Compressed       bool    `json:"compressed" yaml:"compressed"`
	Compression      string  `json:"compression" yaml:"compression"`
	CompressionRatio float64 `json:"compression_ratio" yaml:"compression_ratio"`
	OriginalSize     int64   `json:"original_size" yaml:"original_size"`
	KeyFingerprint   string  `json:"key_fingerprint" yaml:"key_fingerprint"` // the sender's
	// Tri-state trust status returned by the API. Drives the colored
	// indicator in the CLI / UI:
	//   "primary"   : fingerprint matches the actor's primary identity
	//   "secondary" : fingerprint matches a known non-primary identity
	//   "invalid"   : fingerprint not found (identity has been deleted)
	SenderKeyStatus *string `json:"sender_key_status" yaml:"sender_key_status"`
	ChecksumSHA256  string  `json:"checksum_sha256" yaml:"checksum_sha256"` // the payload digest
	Etag            string  `json:"etag" yaml:"etag"`

	// Recipients holding a wrap for this revision, with the key each wrap
	// was made for.
	Recipients []RevisionRecipient `json:"recipients" yaml:"recipients"`
}

// RevisionRecipient is one recipient a revision was sealed for: the key
// their wrap was made for, and that key's trust status.
type RevisionRecipient struct {
	ID             string  `json:"id" yaml:"id"`
	Email          string  `json:"email" yaml:"email"`
	KeyFingerprint string  `json:"key_fingerprint" yaml:"key_fingerprint"`
	KeyStatus      *string `json:"key_status,omitempty" yaml:"key_status,omitempty"`
}

// FileMeta holds per-file metadata as stored on the server.
type FileMeta struct {
	Name   string `json:"name" yaml:"name"`
	Size   int64  `json:"size" yaml:"size"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}
