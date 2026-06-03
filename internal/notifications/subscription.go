// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"fmt"
)

// Subscription is one user's opt-in to personal alert delivery. Enabled is
// the master switch; a user with no stored subscription (or Enabled=false)
// receives nothing on their personal channels. Groups limits delivery to
// alerts on systems in those groups (empty = every group the user can
// see); Severities limits by severity (empty = all). Visibility is always
// re-checked against the user's RBAC scope at delivery, so a subscription
// can never widen what a user is allowed to see.
type Subscription struct {
	Enabled    bool     `json:"enabled"`
	Groups     []string `json:"groups"`
	Severities []string `json:"severities"`
}

// UserSubscription pairs a Subscription with its owner, for the resolver
// that fans alerts out to subscribed users.
type UserSubscription struct {
	UserID string `json:"userId"`
	Subscription
}

// Validate normalizes and checks the subscription. Group ids are trimmed
// and de-duplicated; severities must be known and are de-duplicated.
func (s *Subscription) Validate() error {
	s.Groups = dedupe(s.Groups)
	s.Severities = dedupe(s.Severities)
	for _, sev := range s.Severities {
		if _, ok := DefaultSeverities[sev]; !ok {
			return fmt.Errorf("%w: severity %q is not one of info/warning/critical", ErrInvalid, sev)
		}
	}
	return nil
}

// Matches reports whether an alert on a system in groupID at the given
// severity is covered by this subscription. It does not check RBAC
// visibility — the resolver does that separately.
func (s Subscription) Matches(groupID, severity string) bool {
	if !s.Enabled {
		return false
	}
	if len(s.Groups) > 0 && !containsStr(s.Groups, groupID) {
		return false
	}
	if len(s.Severities) > 0 && !containsStr(s.Severities, severity) {
		return false
	}
	return true
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
