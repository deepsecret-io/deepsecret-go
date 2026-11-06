// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrResponseTooLarge is a response body over the client's bound for it.
var ErrResponseTooLarge = errors.New("response too large")

// ErrInvalidID is an ID that cannot be part of a request path. It is refused
// before anything is sent.
var ErrInvalidID = errors.New(`invalid ID: it cannot be empty, "." or ".."`)

// MaintenanceError is returned when the API is in maintenance mode (HTTP 503 +
// `maintenance: true` flag). Callers can branch on it via [IsMaintenanceError].
type MaintenanceError struct {
	Message string
}

func (e *MaintenanceError) Error() string {
	if e.Message == "" {
		return "API is under maintenance"
	}
	return e.Message
}

// Error is any non-success API response. StatusCode is the
// HTTP status; Code is the server-provided error code (when present); Message
// is the server's human-readable error string. Callers branch with errors.Is
// against the package sentinels (ErrNotFound, ErrUnauthorized, etc.) which
// match the matching HTTP statuses.
type Error struct {
	StatusCode int
	Code       string
	Message    string
	// RetryAfter is parsed from the Retry-After response header when present.
	// Zero means "not provided"; callers should fall back to their own
	// backoff schedule.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error (status %d, %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// Sentinel errors callers can use with errors.Is. Each maps to one or more
// HTTP status codes returned by the backend.
var (
	ErrUnauthorized = errors.New("unauthorized") // 401
	ErrForbidden    = errors.New("forbidden")    // 403
	ErrNotFound     = errors.New("not found")    // 404
	ErrConflict     = errors.New("conflict")     // 409
	ErrTierLimit    = errors.New("tier limit")   // 402, 429 with code=tier_limit
	ErrRateLimited  = errors.New("rate limited") // 429
	ErrServerError  = errors.New("server error") // 5xx (not maintenance)
	ErrBadRequest   = errors.New("bad request")  // 400, 422
)

// Is implements errors.Is so callers can write
//
//	if errors.Is(err, api.ErrNotFound) { ... }
//
// against the high-level sentinels regardless of which concrete Error was
// returned.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrConflict:
		return e.StatusCode == http.StatusConflict
	case ErrTierLimit:
		return e.StatusCode == http.StatusPaymentRequired ||
			(e.StatusCode == http.StatusTooManyRequests && e.Code == "tier_limit")
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests && e.Code != "tier_limit"
	case ErrServerError:
		return e.StatusCode >= 500 && e.StatusCode < 600
	case ErrBadRequest:
		return e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusUnprocessableEntity
	}
	return false
}

// IsMaintenanceError reports whether err (or any error wrapped inside err)
// is a MaintenanceError.
func IsMaintenanceError(err error) bool {
	if err == nil {
		return false
	}
	var m *MaintenanceError
	return errors.As(err, &m)
}

// MaintenanceMessage extracts the server-provided maintenance message from err,
// or returns an empty string if err is not a MaintenanceError.
func MaintenanceMessage(err error) string {
	if err == nil {
		return ""
	}
	var m *MaintenanceError
	if errors.As(err, &m) && m != nil {
		return m.Message
	}
	return ""
}
