// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package sdk

import (
	"log/slog"
	"time"

	"github.com/deepsecret-io/sdk/api"
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

// TransferStatus is the live state of an upload or a download, for a
// progress display: pass one in the options and read it with Snapshot
// while the call runs.
type TransferStatus = api.TransferStatus

// TransferSnapshot is a TransferStatus at one moment.
type TransferSnapshot = api.TransferSnapshot

// ConnectionStatus is what one connection of a transfer is doing.
type ConnectionStatus = api.ConnectionStatus

// TransferAttempts is how many times a transfer tries a part before it
// fails.
const TransferAttempts = api.TransferAttempts

// DecryptedPayload holds the decrypted content of a secret.
type DecryptedPayload = payload.Decrypted

// DecryptedFile holds a single decrypted file from a secret.
type DecryptedFile = payload.DecryptedFile

// KeyValue holds a single key-value pair from a decrypted data secret.
type KeyValue = payload.KeyValue

// ── Options & Results ────────────────────────────────────────────────────────

// EncryptOptions configures encryption and upload behavior.
type EncryptOptions struct {
	// Name is the secret's name, without surrounding white space: a send
	// under a name the sender already has adds a revision to that secret.
	// The manifest signs it, so recipients can tell which secret a revision
	// belongs to. Empty means "sdk-" and the Unix time.
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

	// UploadStatus, when set, follows the upload for a progress display:
	// what each connection is sending, retries, and how many connections
	// the upload uses. Optional.
	UploadStatus *TransferStatus

	// OnEncryptProgress is called as the payload is read, archived,
	// compressed and encrypted, with the bytes of plaintext done and in
	// all. The total can be an estimate until the last call, where done
	// equals it; done never passes it. Optional.
	OnEncryptProgress func(done, total int64)

	// Logger receives the flow's logs, each naming its module (see
	// api.ModuleKey). Optional: nil logs nothing.
	Logger *slog.Logger

	// AutoArchive bundles the files into one tar archive when there are
	// more than 50 regular files. The server still enforces the plan's
	// files-per-secret limit on what is sent.
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

	// UploadThreads fixes the number of parallel part PUTs of a multipart
	// upload, at most 32. 0 adapts it to the link: the upload starts with
	// one part and adds connections while they raise throughput. 1 =
	// serial.
	UploadThreads int

	// ResumeDir keeps the ciphertext of a large (multipart) send in a
	// folder named after its revision under this directory, so an upload
	// that fails or is cancelled can finish later with ResumeUpload; the
	// send then returns an UploadInterruptedError. Empty means a temporary
	// directory removed when the send ends, and no resume. It is created
	// (mode 0700) when missing, and refused when it is a symlink or, on
	// Unix, another user's or open to other users.
	ResumeDir string

	// PresignExpiryMinutes requests presigned URL lifetime in minutes for
	// the upload. Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30).
	PresignExpiryMinutes int

	// LocalFile writes the sealed secret to this file instead of sending
	// it: nothing is uploaded and no secret is created. Recipients' public
	// keys still come from the API, and they open the file with
	// OpenLocalFile. Name, TTL, IPs and RevokeMissing do not apply. The
	// file is written next to its final path and renamed into place, and
	// an existing file is refused unless LocalOverwrite is set.
	LocalFile      string
	LocalOverwrite bool
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
	Secret            secrets.Secret // empty for a local file
	LocalFile         string         // the file written, for EncryptOptions.LocalFile
	EncryptedSize     int64
	SenderFingerprint string
	Recipients        []Recipient       // everyone the revision was sealed for, in the order given
	FirstUse          []Recipient       // recipients whose key was new to this device, accepted on first use: worth comparing with them
	Revoked           []SecretRecipient // people a send with RevokeMissing removed
	Compressed        bool
	Compression       string  // "zstd", "tar+zstd", ""
	CompressionRatio  float64 // compressed/original * 100
	OriginalSize      int64
	PayloadType       string // "message", "data", "files"
	FilesCount        int    // visible files sent to server metadata (0 when archived)
	Archived          bool
	ArchiveEntryCount int // entries in the archive, folders and links included (set only when Archived=true)
	ArchiveFileCount  int // regular files in the archive (set only when Archived=true)
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

	// DownloadStatus, when set, follows the download for a progress
	// display: what each connection is fetching, retries, and how many
	// connections the download uses. Optional.
	DownloadStatus *TransferStatus

	// OnDecryptProgress is called as the downloaded ciphertext is
	// verified and decrypted, pass by pass: see DecryptStage. In each
	// pass done runs up to total, the ciphertext's size; a pass reads it
	// twice, for its signed digest and then to decrypt, each read half
	// the way. Optional.
	OnDecryptProgress func(stage DecryptStage, done, total int64)

	// Logger receives the flow's logs, as for EncryptOptions. Optional.
	Logger *slog.Logger

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

	// ResumeDir keeps the ciphertext of a download over 4 MiB in a folder
	// named after its revision under this directory, with a record of the
	// byte ranges it holds, instead of in TempDir. A download that fails,
	// is cancelled, or dies with the process then returns a
	// DownloadInterruptedError, and the next decrypt of that revision with
	// the same ResumeDir fetches only the ranges it lacks. The folder stays
	// until the payload is decrypted, so a decrypt that fails after the
	// download does not fetch it again; it is removed once decrypted, when
	// the ciphertext fails its check against the signed manifest, and
	// after a week unused. ListPendingDownloads and DiscardPendingDownload
	// manage them. It is created (mode 0700) when missing, and refused when
	// it is a symlink or, on Unix, another user's or open to other users.
	// Payloads decrypted in memory (DecryptSecretFull) do not use it.
	ResumeDir string

	// MaxDownloadSize refuses a stored payload larger than this many bytes
	// before downloading it. Zero means DefaultMaxDownloadSize.
	MaxDownloadSize int64

	// PresignExpiryMinutes requests presigned URL lifetime in minutes for
	// the download. Allowed range is 1-30 (server clamps at 30). 0 = default
	// (DefaultPresignExpiryMinutes, currently 30).
	PresignExpiryMinutes int

	// BeforeDownload, when set, is called once the revision is verified
	// and before its payload is downloaded, with what the download holds.
	// An error from it stops the decrypt with nothing downloaded: a caller
	// checks there that it can write the result, with CheckDestination for
	// files. It is not called for a local file, which needs no download.
	BeforeDownload func(UpcomingDownload) error
}

// UpcomingDownload is a verified revision about to be downloaded.
type UpcomingDownload struct {
	RevisionID  string
	PayloadType string // from the signed manifest: "files", "message", ...
	Size        int64  // ciphertext bytes, from the signed manifest
	// Files is the server's list of the revision's files: empty for an
	// archive sent without its names. It is not signed, so it only
	// predicts what WriteFiles writes; WriteFiles checks the payload's own
	// names again.
	Files []FileMeta
}

// DecryptResult is returned by full decrypt methods with the metadata of
// the verified manifest.
type DecryptResult struct {
	Decrypted            *payload.Decrypted
	RevisionID           string    // UUID of the revision that was decrypted (resolved if Revision was empty)
	SecretName           string    // the secret name the sender signed: the server names the secret too, so show it or compare it with the secret you meant to open
	SignedAt             time.Time // when the sender signed the revision, by their clock
	SenderFingerprint    string
	SenderEmail          string      // the sender, whose registered key signed the manifest
	SenderFirstUse       bool        // the sender's key was new to this device, accepted on first use: worth comparing with them
	RecipientFingerprint string      // the caller's own key, which the wrap was made for
	Recipients           []Recipient // every recipient the sender signed for; Email is the server's label for each fingerprint, or for a local file the file's label when that account registered the key
	Compressed           bool
	Compression          string
	PayloadType          string
	ProtocolVersion      string // from the signed manifest
	CipherSuite          string // from the signed manifest
	PayloadDigest        string // hex SHA-256 of the stored payload, verified against the signed manifest
	EncryptedSize        int64
	ResumedBytes         int64 // bytes of the payload kept from an earlier download (DecryptOptions.ResumeDir), not fetched again
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
