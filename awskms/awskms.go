// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package awskms talks to AWS KMS for key files protected by a KMS key
// (key storage version 6, docs/kms-design.md). It implements
// keystore.KMS; package keystore checks every answer.
//
// Everything that decides where a slot secret goes is fixed here, whatever
// the environment or the AWS config says:
//
//   - the endpoint is https://kms.<region>.<partition DNS suffix> of the key's
//     own region, or its kms-fips twin when the standard AWS FIPS setting is
//     on. AWS_ENDPOINT_URL, AWS_ENDPOINT_URL_KMS and a profile's endpoint_url
//     are ignored: an Encrypt request carries the secret, so an endpoint taken
//     from the environment would hand it to whoever set it.
//   - the HTTP client trusts the system's roots only: AWS_CA_BUNDLE and a
//     profile's ca_bundle are ignored for KMS.
//   - nothing logs a request or a response body.
//
// A proxy from HTTPS_PROXY is followed: it carries a TLS tunnel to the
// endpoint, checked against the system's roots and the endpoint's name, so
// it sees the host name and nothing else.
//
// Credentials come from the AWS default chain (environment, shared config
// and SSO, web identity, container and instance roles), with an optional
// profile.
package awskms

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/deepsecret-io/deepsecret-go/keystore"
)

// Options configure a Client.
type Options struct {
	// Profile is the AWS shared config profile. Empty uses AWS_PROFILE and
	// the default chain. Every KMS call names a full key ARN and goes to
	// that ARN's region.
	Profile string
	// AppID names the client in the AWS user agent, which CloudTrail
	// records: "deepsecret-cli/1.2.3". At most 50 characters of
	// [A-Za-z0-9./_-].
	AppID string
}

// callTimeout bounds one KMS operation, retries included.
const callTimeout = 60 * time.Second

// Client is an AWS KMS client for key files. It is safe for concurrent use.
type Client struct {
	cfg       aws.Config
	region    string
	transport *http.Transport
	http      *http.Client

	mu  sync.Mutex
	kms map[string]*kms.Client // by region
}

var _ keystore.KMS = (*Client)(nil)

// New loads the AWS configuration (files and environment; no network) and
// returns a client. Credentials are fetched on the first call.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.AppID != "" && !validAppID(o.AppID) {
		return nil, fmt.Errorf("app id %q: at most 50 characters of A-Z a-z 0-9 . / _ -", o.AppID)
	}
	opts := []func(*config.LoadOptions) error{
		config.WithClientLogMode(0),
		config.WithLogger(logging.Nop{}),
		config.WithRetryMaxAttempts(3),
	}
	if o.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(o.Profile))
	}
	if o.AppID != "" {
		opts = append(opts, config.WithAppID(o.AppID))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", keystore.ErrKMSNoCredentials, clean(err.Error()))
	}
	region := cfg.Region
	// The system's roots only, never a CA bundle from the environment, and
	// Go's default key exchanges, which offer X25519MLKEM768 first.
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Client{
		cfg:       cfg,
		region:    region,
		transport: tr,
		// No redirects: KMS never answers with one.
		http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		kms:  map[string]*kms.Client{},
	}, nil
}

func validAppID(s string) bool {
	if len(s) > 50 {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("./_-", r)
		if !ok {
			return false
		}
	}
	return true
}

// partition is the partition and DNS suffix of a region.
func partition(region string) (string, string) {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn", "amazonaws.com.cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov", "amazonaws.com"
	}
	return "aws", "amazonaws.com"
}

// validRegion accepts what a key ARN's region may be.
func validRegion(region string) bool {
	parts := strings.Split(region, "-")
	if len(parts) < 3 || len(parts[0]) != 2 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			last := i == len(parts)-1
			if last && (r < '0' || r > '9') || !last && (r < 'a' || r > 'z') {
				return false
			}
		}
	}
	return true
}

// endpoint is the KMS endpoint of region: its FIPS twin when fips is set.
func endpoint(region string, fips bool) string {
	_, suffix := partition(region)
	host := "kms."
	if fips {
		host = "kms-fips."
	}
	return "https://" + host + region + "." + suffix
}

// client is the KMS client of region, made once.
func (c *Client) client(region string) (*kms.Client, error) {
	if !validRegion(region) {
		return nil, fmt.Errorf("%w: %q is not an AWS region", keystore.ErrKMSKeyRejected, region)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.kms[region]; ok {
		return k, nil
	}
	k := kms.NewFromConfig(c.cfg, func(o *kms.Options) {
		fips := o.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled
		o.Region = region
		o.BaseEndpoint = aws.String(endpoint(region, fips))
		// The endpoint is set above; with these on, the SDK would refuse a
		// set endpoint.
		o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		o.HTTPClient = c.http
		o.ClientLogMode = 0
		o.Logger = logging.Nop{}
		o.RetryMaxAttempts = 3
	})
	c.kms[region] = k
	return k, nil
}

// credentials fetches the credentials (cached by the SDK), so a missing
// one is told apart from anything KMS says.
func (c *Client) credentials(ctx context.Context) error {
	if c.cfg.Credentials == nil {
		return keystore.ErrKMSNoCredentials
	}
	if _, err := c.cfg.Credentials.Retrieve(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %s", keystore.ErrKMSNoCredentials, clean(err.Error()))
	}
	return nil
}

// DescribeKey reports the key keyARN.
func (c *Client) DescribeKey(ctx context.Context, keyARN string) (*keystore.KMSKey, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	k, err := c.keyClient(keyARN)
	if err != nil {
		return nil, err
	}
	if err := c.credentials(ctx); err != nil {
		return nil, err
	}
	out, err := k.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, mapError(ctx, err)
	}
	m := out.KeyMetadata
	if m == nil {
		return nil, fmt.Errorf("%w: KMS described no key", keystore.ErrKMSKeyRejected)
	}
	return &keystore.KMSKey{
		ARN:         aws.ToString(m.Arn),
		Spec:        string(m.KeySpec),
		Usage:       string(m.KeyUsage),
		State:       string(m.KeyState),
		Manager:     string(m.KeyManager),
		Description: clean(aws.ToString(m.Description)),
	}, nil
}

// Encrypt encrypts plaintext under keyARN with the encryption context.
func (c *Client) Encrypt(ctx context.Context, keyARN string, encryptionContext map[string]string, plaintext []byte) (*keystore.KMSResult, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	k, err := c.keyClient(keyARN)
	if err != nil {
		return nil, err
	}
	if err := c.credentials(ctx); err != nil {
		return nil, err
	}
	out, err := k.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               aws.String(keyARN),
		Plaintext:           plaintext,
		EncryptionContext:   encryptionContext,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, mapError(ctx, err)
	}
	if out.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault {
		return nil, fmt.Errorf("%w: KMS encrypted with %s", keystore.ErrKMSMismatch, out.EncryptionAlgorithm)
	}
	return &keystore.KMSResult{KeyARN: aws.ToString(out.KeyId), Data: out.CiphertextBlob}, nil
}

// Decrypt decrypts ciphertext with keyARN, named in the request, and the
// encryption context.
func (c *Client) Decrypt(ctx context.Context, keyARN string, encryptionContext map[string]string, ciphertext []byte) (*keystore.KMSResult, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	k, err := c.keyClient(keyARN)
	if err != nil {
		return nil, err
	}
	if err := c.credentials(ctx); err != nil {
		return nil, err
	}
	out, err := k.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(keyARN),
		CiphertextBlob:      ciphertext,
		EncryptionContext:   encryptionContext,
		EncryptionAlgorithm: kmstypes.EncryptionAlgorithmSpecSymmetricDefault,
	})
	if err != nil {
		return nil, mapError(ctx, err)
	}
	if out.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault {
		clear(out.Plaintext)
		return nil, fmt.Errorf("%w: KMS decrypted with %s", keystore.ErrKMSMismatch, out.EncryptionAlgorithm)
	}
	return &keystore.KMSResult{KeyARN: aws.ToString(out.KeyId), Data: out.Plaintext}, nil
}

// keyClient is the client of a key ARN's region. Only a full key ARN passes.
func (c *Client) keyClient(keyARN string) (*kms.Client, error) {
	if !keystore.ValidKMSKeyARN(keyARN) {
		return nil, keystore.ErrKMSNotKeyARN
	}
	return c.client(keystore.KMSKeyRegion(keyARN))
}

// CallerARN is the AWS identity the client's credentials belong to, from
// STS GetCallerIdentity (which needs no permission), asked in region:
// empty uses the configured region, else us-east-1.
func (c *Client) CallerARN(ctx context.Context, region string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if region == "" {
		region = c.region
	}
	if region == "" {
		region = "us-east-1"
	}
	if !validRegion(region) {
		return "", fmt.Errorf("%q is not an AWS region", region)
	}
	if err := c.credentials(ctx); err != nil {
		return "", err
	}
	_, suffix := partition(region)
	s := sts.NewFromConfig(c.cfg, func(o *sts.Options) {
		o.Region = region
		o.BaseEndpoint = aws.String("https://sts." + region + "." + suffix)
		o.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateDisabled
		o.EndpointOptions.UseDualStackEndpoint = aws.DualStackEndpointStateDisabled
		o.HTTPClient = c.http
		o.ClientLogMode = 0
		o.Logger = logging.Nop{}
	})
	out, err := s.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", mapError(ctx, err)
	}
	return clean(aws.ToString(out.Arn)), nil
}

// mapError turns an AWS error into a keystore error, keeping AWS's message
// (which names the principal on a refusal, never a secret) with control
// characters taken out.
func mapError(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return context.Canceled
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		msg := clean(ae.ErrorCode() + ": " + ae.ErrorMessage())
		switch ae.ErrorCode() {
		case "AccessDeniedException", "AccessDenied":
			return fmt.Errorf("%w: %s", keystore.ErrKMSAccessDenied, msg)
		case "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredTokenException", "ExpiredToken":
			return fmt.Errorf("%w (%s)", keystore.ErrKMSCredentialsRejected, msg)
		case "InvalidSignatureException", "SignatureDoesNotMatch", "RequestExpired", "InvalidSignature":
			return fmt.Errorf("%w: the request signature was refused; check the secret key and this machine's clock (%s)", keystore.ErrKMSCredentialsRejected, msg)
		case "DisabledException", "KMSInvalidStateException", "NotFoundException", "KeyUnavailableException":
			return fmt.Errorf("%w: %s", keystore.ErrKMSKeyUnavailable, msg)
		case "InvalidCiphertextException", "IncorrectKeyException":
			return fmt.Errorf("%w: %s", keystore.ErrKMSMismatch, msg)
		case "InvalidKeyUsageException", "UnsupportedOperationException":
			return fmt.Errorf("%w: %s", keystore.ErrKMSKeyRejected, msg)
		case "ThrottlingException", "KMSInternalException", "DependencyTimeoutException", "LimitExceededException", "ServiceUnavailable", "InternalFailure":
			return fmt.Errorf("%w: %s", keystore.ErrKMSUnreachable, msg)
		}
		return fmt.Errorf("AWS KMS: %s", msg)
	}
	return fmt.Errorf("%w: %s", keystore.ErrKMSUnreachable, clean(err.Error()))
}

// clean takes control and layout characters out of text from AWS or the
// environment, so it cannot rewrite the terminal it is printed on.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
