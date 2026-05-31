// SPDX-License-Identifier: Apache-2.0

// Package dashboardlayout persists each user's Dashboard widget layout
// — the ordered list of widgets they want to see, in their preferred
// order. The store is intentionally an opaque-JSON sink: the schema is
// owned by the frontend and evolves there, so the server can stay out
// of the way as widget types are added or parameterised.
package dashboardlayout

import (
	"database/sql"
	"errors"
)

// ErrNotFound is returned by Store.Get when no row exists for the
// requested user. Callers should treat it as "use defaults," not a
// real error.
var ErrNotFound = errors.New("dashboardlayout: not found")

// Store is the persistence contract for per-user dashboard layouts.
// Layout values are stored as opaque JSON strings; the server does not
// interpret the contents beyond verifying the string parses as JSON.
type Store interface {
	// Get returns the JSON layout stored for userID, or ErrNotFound if
	// nothing has been persisted yet.
	Get(userID string) (string, error)
	// Set replaces the JSON layout for userID. Idempotent.
	Set(userID, layoutJSON string) error
	// DeleteByUserTx removes the user's layout inside an existing
	// transaction. Best-effort cleanup wired from the auth user-delete
	// path; never returns "not found."
	DeleteByUserTx(tx *sql.Tx, userID string) error
}
