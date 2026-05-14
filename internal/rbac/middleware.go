// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"net/http"

	"system-wrangler-backend/internal/auth"
)

// Scoper is the minimal slice of Store the middleware needs. Kept
// narrow so tests pass a stub without implementing every method on
// Store.
type Scoper interface {
	Resolve(userID string) ([]Assignment, error)
}

// Middleware resolves the authenticated user's role assignments and
// stamps a Scope onto the request context. Must run AFTER
// auth.RequireUser — it reads the User from context to know whose
// roles to resolve. If no user is on the context, the middleware
// falls through with no scope, leaving authentication errors to the
// upstream middleware that should have refused the request already.
//
// A DB-level failure to resolve the user's roles is a 500: we cannot
// safely fall back to "no permissions" (some handlers might treat
// that as anonymous), nor to "full permissions" (that would be a
// security regression on a transient DB hiccup).
func Middleware(store Scoper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := auth.UserFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			rows, err := store.Resolve(u.ID)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"scope resolution failed"}`))
				return
			}
			ctx := WithScope(r.Context(), NewScope(u.ID, rows))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
