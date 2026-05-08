// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"time"
)

// TrustedDeviceCookie is the cookie name for the long-lived "remember this
// browser for 30 days" token. Distinct from the session cookie so a logged-out
// user retains the trust mark and so the server can clear one without the other.
const TrustedDeviceCookie = "sw_trusted_device"

// TrustedDeviceTTL is how long a "remember this browser" cookie stays valid.
const TrustedDeviceTTL = 30 * 24 * time.Hour

// TOTPChallengeCookie is the short-lived cookie issued during the two-step
// login flow to bind the second-factor request to the first.
const TOTPChallengeCookie = "sw_totp_challenge"

// TOTPChallengeTTL caps how long a user has to complete the second-factor
// step after submitting their password. Five minutes is enough to look up a
// code or recovery sheet without leaving a stale challenge dangling.
const TOTPChallengeTTL = 5 * time.Minute

// TrustedDevice is a row-level record of a browser the user has chosen to
// trust. The cookie body carries enough to verify integrity (id, uid, epoch);
// this struct stores the metadata the user sees in their device list.
type TrustedDevice struct {
	ID         string    `json:"id"`
	UserID     string    `json:"-"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	TOTPEpoch  int64     `json:"-"`
}

// LabelFromUserAgent returns a coarse, human-readable label for the device
// list. We deliberately avoid storing the raw UA string — it's a privacy and
// fingerprinting hazard, and "Firefox on Linux" is what the user actually
// recognises in a list.
//
// Unknown user agents collapse to "Unknown browser" rather than echoing
// arbitrary input back.
func LabelFromUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "Unknown browser"
	}
	lower := strings.ToLower(ua)

	browser := "Unknown browser"
	switch {
	// Order matters: Edge and Opera include "Chrome" tokens; check them first.
	case strings.Contains(lower, "edg/"):
		browser = "Edge"
	case strings.Contains(lower, "opr/"), strings.Contains(lower, "opera"):
		browser = "Opera"
	case strings.Contains(lower, "firefox"):
		browser = "Firefox"
	case strings.Contains(lower, "chrome"):
		browser = "Chrome"
	case strings.Contains(lower, "safari"):
		browser = "Safari"
	}

	os := ""
	switch {
	case strings.Contains(lower, "android"):
		os = "Android"
	case strings.Contains(lower, "iphone"), strings.Contains(lower, "ipad"), strings.Contains(lower, "ios"):
		os = "iOS"
	case strings.Contains(lower, "mac os"), strings.Contains(lower, "macintosh"):
		os = "macOS"
	case strings.Contains(lower, "windows"):
		os = "Windows"
	case strings.Contains(lower, "linux"):
		os = "Linux"
	}

	if os == "" {
		return browser
	}
	return browser + " on " + os
}
