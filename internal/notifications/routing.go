// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"fmt"
	"strings"
)

// RouteMode selects how a rule's transitions are routed to channels.
//
//   - RouteModeAll: deliver to every enabled channel. This is the default
//     for any rule that has never been routed, so behavior is unchanged
//     until an operator narrows a rule. Channels added later are included
//     automatically.
//   - RouteModeSelected: deliver only to the rule's chosen channels (those
//     still enabled). An empty selection delivers nowhere — the alert
//     still surfaces on the dashboard, it just isn't sent to any channel.
type RouteMode string

// RouteMode values.
const (
	RouteModeAll      RouteMode = "all"
	RouteModeSelected RouteMode = "selected"
)

// IsValid reports whether m is a known route mode.
func (m RouteMode) IsValid() bool {
	switch m {
	case RouteModeAll, RouteModeSelected:
		return true
	default:
		return false
	}
}

// Routing is a rule's persisted channel routing. A rule with no stored
// routing is reported as {Mode: RouteModeAll, ChannelIDs: nil}.
type Routing struct {
	RuleID     string    `json:"ruleId"`
	Mode       RouteMode `json:"mode"`
	ChannelIDs []string  `json:"channelIds"`
}

// RoutingInput is the operator-supplied routing for one rule. In
// RouteModeAll the channel list carries no meaning and is cleared.
type RoutingInput struct {
	Mode       RouteMode `json:"mode"`
	ChannelIDs []string  `json:"channelIds"`
}

// Validate normalizes and checks the input. In selected mode the channel
// ids are trimmed and de-duplicated (order preserved); in all mode the
// list is cleared. Unknown ids are not rejected here — the dispatcher
// silently skips ids that aren't enabled channels at send time, so a
// channel can be deleted and re-created without invalidating routing.
func (in *RoutingInput) Validate() error {
	if in.Mode == "" {
		in.Mode = RouteModeAll
	}
	if !in.Mode.IsValid() {
		return fmt.Errorf("%w: routing mode %q is not one of all/selected", ErrInvalid, in.Mode)
	}
	if in.Mode == RouteModeAll {
		in.ChannelIDs = nil
		return nil
	}
	in.ChannelIDs = dedupe(in.ChannelIDs)
	return nil
}

func dedupe(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
