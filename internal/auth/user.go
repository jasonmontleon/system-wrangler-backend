// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"time"
)

// User is the public-facing representation of an account. The bcrypt hash is
// kept in the store and never put on a User.
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Theme     string    `json:"theme"`
	CreatedAt time.Time `json:"createdAt"`
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
)

// ValidTheme reports whether s is a permitted theme value. The empty string
// is allowed and means "use the client default".
func ValidTheme(s string) bool {
	return s == "" || s == ThemeLight || s == ThemeDark
}
