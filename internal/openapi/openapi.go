// SPDX-License-Identifier: Apache-2.0

// Package openapi serves the hand-written OpenAPI 3.1 spec at
// /api/openapi.yaml together with a static Redoc page at /api/docs.
// The spec is the source of truth for the API surface; a drift test
// (cmd/server/openapi_drift_test.go) compares it to the patterns
// recorded by populateMux so the two cannot rot apart.
package openapi

import (
	_ "embed"
	"net/http"

	"system-wrangler-backend/internal/router"
)

// Spec is the embedded YAML document served at /api/openapi.yaml. Exposed
// so the drift test can re-parse the same bytes without round-tripping
// through HTTP.
//
//go:embed spec.yaml
var Spec []byte

// docsHTML is the Redoc page served at /api/docs. Redoc is loaded from
// the jsdelivr CDN — keeping the bundle out of the binary trades the
// "no external runtime dep" purity for a tiny, drop-in docs page.
// Swap the script src if the deployment cannot reach jsdelivr.
const docsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>System Wrangler API</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>body { margin: 0; }</style>
</head>
<body>
  <redoc spec-url="/api/openapi.yaml"></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script>
</body>
</html>`

// Handler serves the spec and the docs page. Stateless; the zero value
// is the only one callers ever need.
type Handler struct{}

// Register attaches the two openapi routes to mux. Both endpoints are
// unauthenticated on purpose: the spec describes the public surface of
// the API and is useful to operators (and tooling) before they have
// credentials.
func (Handler) Register(mux router.Mux) {
	mux.Handle("GET /api/openapi.yaml", http.HandlerFunc(serveSpec))
	mux.Handle("GET /api/docs", http.HandlerFunc(serveDocs))
}

func serveSpec(w http.ResponseWriter, _ *http.Request) {
	// text/plain so browsers display the spec inline instead of
	// triggering a download. OpenAPI tooling parses the body
	// regardless of Content-Type, so Redoc / Swagger UI / generators
	// are unaffected.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(Spec)
}

func serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
}
