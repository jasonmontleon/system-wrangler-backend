// SPDX-License-Identifier: Apache-2.0

// Package router defines the minimal mux contract handler packages
// use to register routes. *http.ServeMux satisfies it; tests can
// substitute a recording wrapper to introspect what patterns the
// production wiring would register.
package router

import "net/http"

// Mux is the narrow interface every handler's Register method accepts
// in place of *http.ServeMux. Kept to a single method so a recording
// wrapper (or any future routing layer) doesn't have to reimplement
// the larger ServeMux surface.
type Mux interface {
	Handle(pattern string, h http.Handler)
}
