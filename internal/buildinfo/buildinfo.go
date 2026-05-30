// SPDX-License-Identifier: Apache-2.0

// Package buildinfo exposes build-time identifiers (backend SHA,
// frontend SHA, UTC build date) injected via -ldflags. Defaults are
// returned when the binary is built without the linker flags.
package buildinfo

import (
	"encoding/json"
	"net/http"
)

// Backend, Frontend, and BuildDate are populated at link time via
// -X system-wrangler-backend/internal/buildinfo.<Name>=<value>.
var (
	Backend   = "dev"
	Frontend  = "dev"
	BuildDate = "unknown"
)

// Info is the JSON payload returned by Handler and the value
// returned by Get.
type Info struct {
	Backend   string `json:"backend"`
	Frontend  string `json:"frontend"`
	BuildDate string `json:"buildDate"`
}

// Get returns a snapshot of the current build identifiers.
func Get() Info {
	return Info{Backend: Backend, Frontend: Frontend, BuildDate: BuildDate}
}

// Handler responds with the JSON-encoded build identifiers.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Get())
	}
}
