// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"time"
)

// User is the public-facing representation of an account. The bcrypt hash is
// kept in the store and never put on a User. TotpEnabled mirrors the column
// of the same name so the frontend can render the "Two-factor authentication"
// card with the correct state on first paint. Disabled is true when
// disabled_at is non-null — disabled users keep their row (so audit
// references stay valid) but cannot log in.
type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Theme       string     `json:"theme"`
	CreatedAt   time.Time  `json:"createdAt"`
	TotpEnabled bool       `json:"totpEnabled"`
	Disabled    bool       `json:"disabled"`
	DisabledAt  *time.Time `json:"disabledAt,omitempty"`
}

// MinPasswordLen is the only password policy v1 enforces. We deliberately
// don't ship complexity rules — operators run their own and a length floor
// is the one rule that's universally beneficial.
const MinPasswordLen = 8

// MinUsernameLen guards against accidental empty submits; usernames are
// otherwise free-form (no email validation in v1).
const MinUsernameLen = 1

// Theme values persisted on a user. Empty string means "no preference set"
// and the client should fall back to its default.
const (
	ThemeLight = "light"
	ThemeDark  = "dark"
)

// Sentinel errors usable across the package and by callers.
var (
	ErrInvalid       = errors.New("auth: invalid input")
	ErrUnauthorized  = errors.New("auth: unauthorized")
	ErrUserNotFound  = errors.New("auth: user not found")
	ErrUserExists    = errors.New("auth: username already taken")
	ErrSetupComplete = errors.New("auth: setup already complete")
	ErrUserDisabled  = errors.New("auth: user disabled")
	ErrLastEnabled   = errors.New("auth: cannot disable the last enabled user")
)

// ValidTheme reports whether s is a permitted theme value. The empty string
// is allowed and means "use the client default".
func ValidTheme(s string) bool {
	return s == "" || s == ThemeLight || s == ThemeDark
}
