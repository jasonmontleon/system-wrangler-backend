// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"system-wrangler-backend/internal/auth"
)

type stubResolver struct {
	rows []Assignment
	err  error
}

func (s stubResolver) Resolve(_ string) ([]Assignment, error) {
	return s.rows, s.err
}

func TestMiddlewareStashesScope(t *testing.T) {
	stub := stubResolver{rows: []Assignment{
		{UserID: "u1", Role: RoleAdmin},
	}}
	var gotScope Scope
	var hadScope bool
	handler := Middleware(stub)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotScope, hadScope = ScopeFromContext(r.Context())
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(auth.WithUser(req.Context(), auth.User{ID: "u1", Username: "alice"}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !hadScope {
		t.Fatal("expected Scope stamped on context")
	}
	if !gotScope.IsGlobalAdmin() {
		t.Errorf("Scope.IsGlobalAdmin = false, want true")
	}
	if gotScope.UserID != "u1" {
		t.Errorf("Scope.UserID = %q, want u1", gotScope.UserID)
	}
}

func TestMiddlewareFallsThroughWithoutUser(t *testing.T) {
	called := false
	handler := Middleware(stubResolver{})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called {
		t.Error("middleware swallowed request when no user was on context")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMiddlewareResolveError(t *testing.T) {
	stub := stubResolver{err: errors.New("db gone")}
	called := false
	handler := Middleware(stub)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(auth.WithUser(req.Context(), auth.User{ID: "u1"}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if called {
		t.Error("handler ran despite resolver error")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
