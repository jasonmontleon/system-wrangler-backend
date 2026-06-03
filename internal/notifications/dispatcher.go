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
	SystemName  func(systemID string) string
	Now         func() time.Time
	SendTimeout time.Duration
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

// Emit fans each transition out to every enabled channel. It returns
// promptly: each send runs in a detached goroutine with its own timeout
// so a slow channel can't stall the evaluator tick.
func (d *Dispatcher) Emit(_ context.Context, transitions []alerts.Transition) {
	channels, err := d.Store.ListEnabled()
	if err != nil {
		slog.Error("notifications: list enabled channels", "err", err)
		return
	}
	if len(channels) == 0 {
		return
	}
	for _, tr := range transitions {
		msg := d.message(tr)
		for _, c := range channels {
			go d.deliver(c, tr, msg) //nolint:gosec // detached on purpose: delivery outlives the tick
		}
	}
}

// deliver sends one message to one channel and records the outcome.
func (d *Dispatcher) deliver(c Channel, tr alerts.Transition, msg Message) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout())
	defer cancel()
	status, errStr := DeliverySuccess, ""
	if err := d.sendOne(ctx, c, msg); err != nil {
		status, errStr = DeliveryFailed, err.Error()
		slog.Warn("notifications: delivery failed", "channel", c.Name, "type", c.Type, "err", err)
	}
	if _, err := d.Store.RecordDelivery(Delivery{
		ChannelID: c.ID, ChannelName: c.Name, ChannelType: c.Type,
		Kind: string(tr.Kind), RuleName: tr.Rule.Name, SystemID: tr.SystemID,
		Status: status, Error: errStr, At: d.now(),
	}); err != nil {
		slog.Error("notifications: record delivery", "err", err)
	}
}

// Test sends a synthetic notification through one channel synchronously
// and records it, returning the send error so the caller can report it.
func (d *Dispatcher) Test(ctx context.Context, c Channel) error {
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
		Kind: "test", RuleName: "(test)", Status: status, Error: errStr, At: d.now(),
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
