// SPDX-License-Identifier: Apache-2.0

// Package audit records who did what to whom and when. Every privileged
// state-change in System Wrangler writes a row into audit_log; for changes
// that come with their own SQL write, the audit row commits in the same
// transaction as the change so they cannot diverge. Design and discipline:
// research/audit-log.md.
//
// The package is deliberately small. It defines the Event/Detail surface,
// stamps actor / request-id / remote-IP from request context, and exposes
// LogTx (in-transaction) and Log (no transaction) on a Store. It must not
// import handler packages or domain stores — the arrow always points
// inward.
package audit

import (
	"context"
	"errors"
	"regexp"
)

// ActorKind classifies the subject that triggered the event. Stored as the
// audit_log.actor_kind column. Unauthenticated covers events emitted
// before the request is bound to a user (failed-login attempts, anonymous
// pre-setup), and ActorSystem covers events the server emits to itself
// (background jobs, system-level failures).
type ActorKind string

// Actor kinds stored in audit_log.actor_kind. ActorUnauthenticated
// covers events emitted before the request is bound to a user (failed
// login, anonymous pre-setup), ActorSystem covers events emitted by the
// server to itself (background jobs).
const (
	ActorUser            ActorKind = "user"
	ActorSystem          ActorKind = "system"
	ActorUnauthenticated ActorKind = "unauthenticated"
)

// Outcome is the audit_log.outcome column. Success is the normal path,
// Failure is "the operator tried but the operation didn't take effect"
// (still audit-worthy — we want a record of the attempt), Denied is
// "blocked by authorization."
type Outcome string

// Outcome values stored in audit_log.outcome. Failure means the operator
// attempted the action but it didn't take effect (the attempt is still
// audit-worthy); Denied means authorization blocked it.
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Actor is the resolved-user-or-not bundle threaded through request
// context by middleware. The Label is a frozen snapshot of the username
// at log-time so audit rows render correctly years later even if the
// account is later renamed or deleted.
type Actor struct {
	Kind  ActorKind
	ID    string
	Label string
}

// Event is the input shape callers pass to LogTx / Log. The package fills
// in id, occurred_at, actor_*, request_ip, request_id from ctx.
type Event struct {
	Action      string
	Outcome     Outcome
	TargetKind  string
	TargetID    string
	TargetLabel string
	Detail      Detail
}

// Detail is the action-specific structured payload that lands in the JSON
// detail column. Keys must NOT name passwords, tokens, secret material,
// or recovery codes — even by accident. Use SetSafe to assign keys
// through the denylist filter; direct map writes bypass it and should
// only be used when the key is provably safe.
type Detail map[string]any

// denyKey matches detail key names we never want in the audit log. Coarse
// on purpose: it would rather reject a benign "public_key_fingerprint"
// than admit a "session_token". Callers can rename the field if it
// trips.
var denyKey = regexp.MustCompile(`(?i)password|secret|token|recovery|cookie|bearer|credential|private.?key`)

// ErrUnsafeDetailKey is returned when SetSafe rejects a key. Tests assert
// against this sentinel to keep the denylist honest.
var ErrUnsafeDetailKey = errors.New("audit: detail key matches denylist")

// NewDetail returns an empty Detail ready for SetSafe calls.
func NewDetail() Detail { return Detail{} }

// SetSafe assigns v at k after checking k against the unsafe-name
// denylist. Returns ErrUnsafeDetailKey for any name matching
// password|secret|token|recovery|cookie|bearer|credential|private-key.
func (d Detail) SetSafe(k string, v any) error {
	if denyKey.MatchString(k) {
		return ErrUnsafeDetailKey
	}
	d[k] = v
	return nil
}

// ctxKey is the typed key under which audit threads actor / request_id /
// remote_addr through context. Defined locally so audit imports nobody
// from the handler layer; auth middleware imports audit, never the
// reverse.
type ctxKey int

const (
	actorKey ctxKey = iota
	requestIDKey
	remoteAddrKey
)

// WithActor stamps an Actor on ctx so subsequent LogTx/Log calls pick it
// up automatically. The auth middleware sets this once the user is
// resolved; handlers can override on the fly (e.g. login.success, where
// the user IS the actor but the auth middleware hasn't run yet).
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey, a)
}

// ActorFromContext returns the Actor stamped on ctx, or a zero-value
// Actor with Kind=Unauthenticated when none has been set.
func ActorFromContext(ctx context.Context) Actor {
	if a, ok := ctx.Value(actorKey).(Actor); ok {
		return a
	}
	return Actor{Kind: ActorUnauthenticated}
}

// WithRequestID stamps a per-request UUID into ctx so audit rows can be
// correlated with request-log lines. Set by request-meta middleware.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the request id stamped on ctx, or "".
func RequestIDFromContext(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey).(string)
	return s
}

// WithRemoteAddr stamps the client IP (from http.Request.RemoteAddr) on
// ctx so audit rows record where the action came from.
func WithRemoteAddr(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, remoteAddrKey, ip)
}

// RemoteAddrFromContext returns the client IP stamped on ctx, or "".
func RemoteAddrFromContext(ctx context.Context) string {
	s, _ := ctx.Value(remoteAddrKey).(string)
	return s
}
