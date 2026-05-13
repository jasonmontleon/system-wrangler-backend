// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"system-wrangler-backend/internal/audit"
)

type ctxKey int

const userKey ctxKey = 0

// WithUser stamps a User onto a context — exported so handlers downstream of
// RequireUser can pull it back out.
func WithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// UserFromContext returns the authenticated user, if any.
func UserFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey).(User)
	return u, ok
}

// RequireUser returns middleware that loads the user from the session cookie
// or responds 401. The user is fetched from the store on every request — no
// in-memory cache, simpler reasoning. now is injected so tests can assert
// expiry behavior deterministically.
func RequireUser(secret []byte, store UserStore, now func() time.Time) func(http.Handler) http.Handler {
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			uid, err := VerifySession(secret, now(), c.Value)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			u, err := store.GetByID(uid)
			if err != nil {
				if errors.Is(err, ErrUserNotFound) {
					writeUnauthorized(w)
					return
				}
				http.Error(w, `{"error":"auth lookup failed"}`, http.StatusInternalServerError)
				return
			}
			if u.Disabled {
				writeUnauthorized(w)
				return
			}
			ctx := WithUser(r.Context(), u)
			ctx = audit.WithActor(ctx, audit.Actor{
				Kind:  audit.ActorUser,
				ID:    u.ID,
				Label: u.Username,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

// RequireFreshPassword wraps next so that any user whose
// must_change_password flag is set is bounced with 403 until they
// rotate the admin-supplied password via /api/auth/password. Must run
// after RequireUser since it reads the User from the request context.
func RequireFreshPassword(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := UserFromContext(r.Context()); ok && u.MustChangePassword {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"password change required"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
