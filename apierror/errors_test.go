// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package apierror

import (
	"errors"
	"testing"
)

func TestErrorIsMatchesStatus(t *testing.T) {
	cases := []struct {
		status int
		code   string
		target error
	}{
		{401, "", ErrUnauthorized},
		{403, "", ErrForbidden},
		{404, "", ErrNotFound},
		{409, "", ErrConflict},
		{402, "", ErrTierLimit},
		{429, "tier_limit", ErrTierLimit},
		{429, "", ErrRateLimited},
		{500, "", ErrServerError},
		{400, "", ErrBadRequest},
	}
	for _, c := range cases {
		if !errors.Is(&Error{StatusCode: c.status, Code: c.code}, c.target) {
			t.Errorf("%d %q is not %v", c.status, c.code, c.target)
		}
	}
	if errors.Is(&Error{StatusCode: 429, Code: "tier_limit"}, ErrRateLimited) {
		t.Error("a tier limit reads as a rate limit")
	}
}
