// SPDX-License-Identifier: Apache-2.0

// Package secretscan exposes the read-only admin endpoint that lists
// rows whose sealed-at-rest columns cannot be decrypted with the
// currently-loaded vault. The canonical trigger is a database restore
// against a different SW_MASTER_KEY_FILE than the backup was taken
// under — every encrypted column survives the import as ciphertext
// the running process can't open. Design and discipline:
// research/db-backup.md ("Restore with a mismatched key — graceful
// degradation").
//
// The package is a thin aggregator. Each domain package that owns
// sealed columns implements Source; main.go composes them into a
// Handler. v1 ships with one source (auth: TOTP secrets); ansible
// SSH keys and OIDC client secrets will join later by registering
// additional Sources without touching the handler.
package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/secrets"
)

// Item is one undecryptable row. Kind identifies the source ("user_totp",
// "system_ssh_key", ...); Field disambiguates multiple sealed columns on
// the same row ("secret", "pending"). TargetID / TargetLabel let the UI
// link the operator to the matching admin surface without re-looking up
// the row. KeyVersion is the version the row was originally sealed
// under — handy when an operator is trying to figure out which retired
// key they still need.
type Item struct {
	Kind        string `json:"kind"`
	Field       string `json:"field"`
	TargetID    string `json:"targetId"`
	TargetLabel string `json:"targetLabel"`
	KeyVersion  int    `json:"keyVersion"`
}

// Source is a domain package's contribution to the scan. Implementations
// MUST be cheap to call repeatedly — the handler invokes them on every
// request. Errors propagate up; the handler turns the first non-nil
// error into a 500 and logs the rest. CountUndecryptable exists as a
// separate method so the future "just give me a badge count" UI doesn't
// have to pay for the full list.
type Source interface {
	Name() string
	ListUndecryptable(v *secrets.Vault) ([]Item, error)
	CountUndecryptable(v *secrets.Vault) (int, error)
}

// Handler exposes GET /api/admin/secrets/undecryptable. Vault and
// Sources are required; CanScan is an injectable gate (main.go binds
// it to rbac.Scope.IsGlobalAdmin) so this package doesn't need to
// import rbac.
type Handler struct {
	Vault   *secrets.Vault
	Sources []Source
	CanScan func(context.Context) bool
}

// Register wires the read endpoint behind the supplied authenticated-
// user middleware. Mirrors the in-handler scope check pattern used by
// rbac and backup so a missing CanScan defaults to "anyone
// authenticated" — fine for tests, never for production.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/admin/secrets/undecryptable", mw(http.HandlerFunc(h.list)))
}

// Response is the JSON shape returned by the list endpoint. Items are
// sorted by (kind, targetLabel, field) so the UI gets a stable order
// without re-sorting.
type Response struct {
	Count int    `json:"count"`
	Items []Item `json:"items"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if h.CanScan != nil && !h.CanScan(r.Context()) {
		writeError(w, http.StatusForbidden, "scan requires Global Admin")
		return
	}
	if h.Vault == nil {
		writeError(w, http.StatusInternalServerError, "scan unavailable")
		slog.Error("secretscan: vault is nil")
		return
	}
	items := []Item{}
	for _, src := range h.Sources {
		got, err := src.ListUndecryptable(h.Vault)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			slog.Error("secretscan source failed", "source", src.Name(), "err", err)
			return
		}
		items = append(items, got...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		if items[i].TargetLabel != items[j].TargetLabel {
			return items[i].TargetLabel < items[j].TargetLabel
		}
		return items[i].Field < items[j].Field
	})
	writeJSON(w, http.StatusOK, Response{Count: len(items), Items: items})
}

// ErrNoSources is returned by tests / callers that construct a Handler
// with an empty Sources slice and want a typed signal rather than a
// silent empty response. Not used by the HTTP handler — an empty
// Sources is a legitimate "nothing is encrypted yet" state.
var ErrNoSources = errors.New("secretscan: no sources registered")

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("secretscan json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
