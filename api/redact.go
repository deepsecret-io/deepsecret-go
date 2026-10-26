// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ── Keeping presigned URLs and storage details out of errors ────────────────
//
// A presigned URL works for anyone who holds it until it expires: its query
// is the signature. Go's HTTP errors quote the request URL whole, and an
// S3 error body can echo the access key ID, the signature and the string
// that was signed. So errors name the storage host at most, and a storage
// error response contributes its status and error code, nothing else.

// doPresigned sends a request to a presigned URL. A transport error quotes
// the URL as its scheme and host only.
func (c *Client) doPresigned(req *http.Request) (*http.Response, error) {
	resp, err := c.presignClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = &url.Error{Op: ue.Op, URL: redactURL(ue.URL), Err: ue.Err}
		}
	}
	return resp, err
}

// redactURL keeps a URL's scheme and host, and drops the rest: user info,
// path, query (the signature) and fragment.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(storage URL)"
	}
	return u.Scheme + "://" + u.Host
}

var (
	storageCodeTag  = regexp.MustCompile(`<Code>([^<]{1,64})</Code>`)
	storageCodeWord = regexp.MustCompile(`^[A-Za-z0-9.]+$`)
)

// storageErrorCode is the error code an S3-compatible storage put in its
// error body, like AccessDenied or SlowDown, or "" when there is none.
func storageErrorCode(body []byte) string {
	m := storageCodeTag.FindSubmatch(body)
	if m == nil || !storageCodeWord.Match(m[1]) {
		return ""
	}
	return string(m[1])
}

// storageFailure describes a storage error response by its status and
// error code.
func storageFailure(what string, status int, body []byte) string {
	if code := storageErrorCode(body); code != "" {
		return fmt.Sprintf("%s (status %d, %s)", what, status, code)
	}
	return fmt.Sprintf("%s (status %d)", what, status)
}

// printableExcerpt is at most n bytes of b with anything but printable
// ASCII replaced, for quoting a response that is not what was expected.
func printableExcerpt(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return '?'
		}
		return r
	}, string(b))
}
