// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"system-wrangler-backend/internal/alerts"
	"system-wrangler-backend/internal/secrets"
)

// DefaultSendTimeout bounds a single delivery attempt.
const DefaultSendTimeout = 15 * time.Second

// Dispatcher delivers alert transitions to every enabled channel. It
// implements alerts.Sink: the evaluator hands it each batch of
// fired/resolved transitions and it fans them out, opening each
// channel's sealed secret through the vault and recording the outcome.
// Per-rule routing is a later item — every transition goes to every
// enabled channel.
type Dispatcher struct {
	Store   Store
	Vault   *secrets.Vault
	Senders Senders
	// SystemName resolves a system id to a display name for the message;
	// nil or an empty return falls back to the id.
	SystemName func(systemID string) string
	// Subscribers, if non-nil, resolves which users should receive an alert
	// on their personal channels (subscription match + RBAC visibility).
	// Nil disables the per-user delivery path entirely.
	Subscribers SubscriberResolver
	Now         func() time.Time
	SendTimeout time.Duration
}

// SubscriberResolver returns the ids of users who should receive an alert
// on systemID at the given severity — those whose subscription matches and
// whose RBAC scope can see the system. Implemented in main.go over the
// subscription store + systems + rbac; the dispatcher only sees user ids.
type SubscriberResolver interface {
	Subscribers(systemID, severity string) ([]string, error)
}

// SubscriberResolverFunc adapts a function to the SubscriberResolver
// interface so main.go can wire the resolver as a closure.
type SubscriberResolverFunc func(systemID, severity string) ([]string, error)

// Subscribers implements SubscriberResolver.
func (f SubscriberResolverFunc) Subscribers(systemID, severity string) ([]string, error) {
	return f(systemID, severity)
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d *Dispatcher) timeout() time.Duration {
	if d.SendTimeout > 0 {
		return d.SendTimeout
	}
	return DefaultSendTimeout
}

// Emit applies the delivery policy to each transition, then fans the ones
// that should go out now to the channels their rule routes to. It returns
// promptly: each send runs in a detached goroutine with its own timeout so
// a slow channel can't stall the evaluator tick. The enabled set, policy,
// and per-rule routing are read once and cached for the batch.
//
// Per severity, the policy mode decides the path: dashboard severities are
// recorded as suppressed and never sent; quiet severities are deferred
// (queued for the flusher) while the clock is inside a quiet window and
// delivered immediately otherwise; always severities ignore quiet hours.
func (d *Dispatcher) Emit(_ context.Context, transitions []alerts.Transition) {
	enabled, err := d.Store.ListEnabled()
	if err != nil {
		slog.Error("notifications: list enabled channels", "err", err)
		return
	}
	byID := indexByID(enabled)
	policy, err := d.Store.GetPolicy()
	if err != nil {
		slog.Error("notifications: get policy", "err", err)
		policy = DefaultPolicy()
	}
	now := d.now()
	quiet := policy.InQuietHours(now)
	routingCache := make(map[string]Routing)
	uc := newUserDispatch()
	for _, tr := range transitions {
		msg := d.message(tr)
		sev := string(tr.Rule.Severity)
		// Shared path: the global policy + per-rule routing.
		switch policy.ModeFor(sev) {
		case ModeDashboard:
			d.recordStatus(msg, DeliverySuppressed, "")
		case ModeQuiet:
			if quiet {
				d.enqueue(tr, msg, "")
			} else {
				d.fanOut(d.routedTargets(tr.Rule.ID, enabled, byID, routingCache), msg, "")
			}
		case ModeAlways:
			d.fanOut(d.routedTargets(tr.Rule.ID, enabled, byID, routingCache), msg, "")
		}
		// Personal path: each subscribed user's own policy + channels.
		d.dispatchPersonal(tr, msg, sev, now, uc)
	}
}

// dispatchPersonal fans a transition out to each subscribed user's personal
// channels, applying that user's own delivery policy independently of the
// global one. A nil resolver disables the path.
func (d *Dispatcher) dispatchPersonal(tr alerts.Transition, msg Message, sev string, now time.Time, uc *userDispatch) {
	if d.Subscribers == nil {
		return
	}
	users, err := d.Subscribers.Subscribers(tr.SystemID, sev)
	if err != nil {
		slog.Error("notifications: resolve subscribers", "err", err, "system_id", tr.SystemID)
		return
	}
	for _, uid := range users {
		pol := uc.policy(d, uid)
		switch pol.ModeFor(sev) {
		case ModeDashboard:
			d.recordStatus(msg, DeliverySuppressed, uid)
			continue
		case ModeQuiet:
			if pol.InQuietHours(now) {
				d.enqueue(tr, msg, uid)
				continue
			}
		case ModeAlways:
		}
		d.fanOut(uc.channels(d, uid), msg, uid)
	}
}

// fanOut delivers msg to each channel in detached goroutines.
func (d *Dispatcher) fanOut(channels []Channel, msg Message, userID string) {
	for _, c := range channels {
		go d.deliver(c, msg, userID) //nolint:gosec // detached on purpose: delivery outlives the tick
	}
}

// userDispatch caches each user's policy and enabled channels for the
// duration of one Emit batch, so a user appearing in several transitions
// is loaded once.
type userDispatch struct {
	policies map[string]Policy
	chans    map[string][]Channel
}

func newUserDispatch() *userDispatch {
	return &userDispatch{policies: map[string]Policy{}, chans: map[string][]Channel{}}
}

func (u *userDispatch) policy(d *Dispatcher, uid string) Policy {
	if p, ok := u.policies[uid]; ok {
		return p
	}
	p, err := d.Store.GetUserPolicy(uid)
	if err != nil {
		slog.Error("notifications: get user policy", "err", err, "user_id", uid)
		p = DefaultPolicy()
	}
	u.policies[uid] = p
	return p
}

func (u *userDispatch) channels(d *Dispatcher, uid string) []Channel {
	if c, ok := u.chans[uid]; ok {
		return c
	}
	c, err := d.Store.ListEnabledUserChannels(uid)
	if err != nil {
		slog.Error("notifications: list user channels", "err", err, "user_id", uid)
		c = nil
	}
	u.chans[uid] = c
	return c
}

// routedTargets resolves a rule's routing (cached) to the enabled channels
// that should receive it.
func (d *Dispatcher) routedTargets(ruleID string, enabled []Channel, byID map[string]Channel, cache map[string]Routing) []Channel {
	routing, ok := cache[ruleID]
	if !ok {
		var err error
		routing, err = d.Store.GetRouting(ruleID)
		if err != nil {
			slog.Error("notifications: get routing", "err", err, "rule_id", ruleID)
			routing = Routing{Mode: RouteModeAll}
		}
		cache[ruleID] = routing
	}
	return targetsFor(routing, enabled, byID)
}

func indexByID(channels []Channel) map[string]Channel {
	byID := make(map[string]Channel, len(channels))
	for _, c := range channels {
		byID[c.ID] = c
	}
	return byID
}

// targetsFor resolves a rule's routing to the enabled channels that
// should receive its transitions. All-mode delivers to every enabled
// channel; selected-mode delivers to the chosen ids that are still
// enabled (silently skipping disabled or deleted ones).
func targetsFor(routing Routing, enabled []Channel, byID map[string]Channel) []Channel {
	if routing.Mode != RouteModeSelected {
		return enabled
	}
	out := make([]Channel, 0, len(routing.ChannelIDs))
	for _, id := range routing.ChannelIDs {
		if c, ok := byID[id]; ok {
			out = append(out, c)
		}
	}
	return out
}

// enqueue defers a transition for the flusher and records a deferred row.
// userID is empty for a shared deferral and set for a personal one.
func (d *Dispatcher) enqueue(tr alerts.Transition, msg Message, userID string) {
	if _, err := d.Store.EnqueuePending(PendingDelivery{
		RuleID: tr.Rule.ID, RuleName: tr.Rule.Name, SystemID: tr.SystemID,
		Severity: string(tr.Rule.Severity), Kind: string(tr.Kind), Message: msg,
		EnqueuedAt: d.now(), UserID: userID,
	}); err != nil {
		slog.Error("notifications: enqueue pending", "err", err)
		return
	}
	d.recordStatus(msg, DeliveryDeferred, userID)
}

// recordStatus logs a channel-less delivery row (suppressed or deferred)
// so the policy's effect on a transition is visible in the delivery log.
func (d *Dispatcher) recordStatus(msg Message, status DeliveryStatus, userID string) {
	if _, err := d.Store.RecordDelivery(Delivery{
		Kind: msg.Kind, RuleName: msg.RuleName, SystemID: msg.SystemID,
		Status: status, At: d.now(), UserID: userID,
	}); err != nil {
		slog.Error("notifications: record delivery", "err", err)
	}
}

// deliver sends one message to one channel and records the outcome. The
// message carries the kind/rule/system fields the delivery row needs, so
// it serves both immediate sends and flushed deferred ones. userID is
// empty for a shared channel and set for a personal one.
func (d *Dispatcher) deliver(c Channel, msg Message, userID string) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout())
	defer cancel()
	status, errStr := DeliverySuccess, ""
	if err := d.sendOne(ctx, c, msg); err != nil {
		status, errStr = DeliveryFailed, err.Error()
		slog.Warn("notifications: delivery failed", "channel", c.Name, "type", c.Type, "err", err)
	}
	if _, err := d.Store.RecordDelivery(Delivery{
		ChannelID: c.ID, ChannelName: c.Name, ChannelType: c.Type,
		Kind: msg.Kind, RuleName: msg.RuleName, SystemID: msg.SystemID,
		Status: status, Error: errStr, At: d.now(), UserID: userID,
	}); err != nil {
		slog.Error("notifications: record delivery", "err", err)
	}
}

// Test sends a synthetic notification through one shared channel.
func (d *Dispatcher) Test(ctx context.Context, c Channel) error {
	return d.runTest(ctx, c, "")
}

// TestForUser sends a synthetic notification through one of a user's
// personal channels, recording the attempt against that user's log.
func (d *Dispatcher) TestForUser(ctx context.Context, c Channel, userID string) error {
	return d.runTest(ctx, c, userID)
}

// runTest sends a synthetic notification through one channel synchronously
// and records it, returning the send error so the caller can report it.
// userID is empty for a shared channel and set for a personal one.
func (d *Dispatcher) runTest(ctx context.Context, c Channel, userID string) error {
	msg := Message{
		Subject: "[TEST] System Wrangler notification: " + c.Name,
		Body:    "This is a test notification from System Wrangler. If you received it, the channel is configured correctly.",
		Kind:    "test", RuleName: "(test)", Severity: "info", At: d.now(),
	}
	err := d.sendOne(ctx, c, msg)
	status, errStr := DeliverySuccess, ""
	if err != nil {
		status, errStr = DeliveryFailed, err.Error()
	}
	if _, recErr := d.Store.RecordDelivery(Delivery{
		ChannelID: c.ID, ChannelName: c.Name, ChannelType: c.Type,
		Kind: "test", RuleName: "(test)", Status: status, Error: errStr, At: d.now(), UserID: userID,
	}); recErr != nil {
		slog.Error("notifications: record test delivery", "err", recErr)
	}
	return err
}

// sendOne opens the channel's secret and invokes the matching sender.
func (d *Dispatcher) sendOne(ctx context.Context, c Channel, msg Message) error {
	sender, ok := d.Senders[c.Type]
	if !ok {
		return fmt.Errorf("no sender for channel type %q", c.Type)
	}
	secret := ""
	if !c.Secret.IsZero() {
		if d.Vault == nil {
			return fmt.Errorf("channel secret unavailable (no vault configured)")
		}
		pt, err := OpenWith(d.Vault, c.Secret)
		if err != nil {
			return fmt.Errorf("decrypt channel secret: %w", err)
		}
		secret = string(pt)
	}
	return sender.Send(ctx, c, secret, msg)
}

// message renders the human-readable Subject/Body for a transition and
// carries the structured fields the webhook sender serializes.
func (d *Dispatcher) message(tr alerts.Transition) Message {
	verb := "FIRING"
	if tr.Kind == alerts.TransitionResolved {
		verb = "RESOLVED"
	}
	sysName := tr.SystemID
	if d.SystemName != nil {
		if n := d.SystemName(tr.SystemID); n != "" {
			sysName = n
		}
	}
	subject := fmt.Sprintf("[%s] %s on %s", verb, tr.Rule.Name, sysName)
	body := fmt.Sprintf(
		"Alert: %s\nSystem: %s\nSeverity: %s\nState: %s\nObserved value: %s\nAt: %s",
		tr.Rule.Name, sysName, tr.Rule.Severity, tr.Kind,
		formatValue(tr), tr.At.UTC().Format(time.RFC3339),
	)
	return Message{
		Subject: subject, Body: body, Kind: string(tr.Kind),
		RuleName: tr.Rule.Name, Severity: string(tr.Rule.Severity),
		SystemID: tr.SystemID, SystemName: sysName, Value: tr.Value, At: tr.At,
	}
}

// formatValue renders the observed value; unreachable rules carry a
// sentinel 1, so report the reachability verdict instead of a number.
func formatValue(tr alerts.Transition) string {
	if tr.Rule.ConditionKind == alerts.KindUnreachable {
		return "unreachable"
	}
	return fmt.Sprintf("%g", tr.Value)
}
