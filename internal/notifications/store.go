// SPDX-License-Identifier: Apache-2.0

package notifications

// Store is the persistence contract for channels + the delivery log.
// Channel writes seal the secret through the vault; reads return the
// sealed value, which only the dispatcher/handler (holding the vault)
// can open.
type Store interface {
	Create(in ChannelInput, createdBy string) (Channel, error)
	Get(id string) (Channel, error)
	List() ([]Channel, error)
	// ListEnabled returns only enabled channels — the set the dispatcher
	// fans a transition out to.
	ListEnabled() ([]Channel, error)
	Update(id string, in ChannelInput) (Channel, error)
	Delete(id string) error

	// RecordDelivery appends one send-attempt row. The store fills id +
	// timestamp when zero and returns the stored row.
	RecordDelivery(d Delivery) (Delivery, error)
	// ListDeliveries returns the most recent attempts first, capped at
	// limit (<= 0 means a sane default applied by the store).
	ListDeliveries(limit int) ([]Delivery, error)

	// GetRouting returns the routing for a rule. A rule with no stored
	// routing yields {Mode: RouteModeAll} (never ErrNotFound) so the
	// dispatcher's default is "deliver to every enabled channel."
	GetRouting(ruleID string) (Routing, error)
	// SetRouting upserts a rule's routing, replacing its channel set
	// atomically. An all-mode input clears any stored channel selection.
	SetRouting(ruleID string, in RoutingInput) error
	// ListRouting returns every rule that has an explicit (non-default)
	// routing row, for the routing matrix.
	ListRouting() ([]Routing, error)

	// GetPolicy returns the global delivery policy, or DefaultPolicy when
	// none is stored (never ErrNotFound).
	GetPolicy() (Policy, error)
	// SetPolicy validates and upserts the singleton delivery policy.
	SetPolicy(in PolicyInput) error

	// EnqueuePending appends a deferred delivery. The store fills id +
	// timestamp when zero.
	EnqueuePending(d PendingDelivery) (PendingDelivery, error)
	// ListPending returns deferred deliveries oldest first.
	ListPending() ([]PendingDelivery, error)
	// DeletePending removes the given pending ids (no-op for an empty list).
	DeletePending(ids []string) error

	// Per-user (personal) delivery path. Every method is owner-scoped to
	// userID; a row owned by another user is invisible (ErrNotFound).
	CreateUserChannel(userID string, in ChannelInput) (Channel, error)
	GetUserChannel(userID, id string) (Channel, error)
	ListUserChannels(userID string) ([]Channel, error)
	ListEnabledUserChannels(userID string) ([]Channel, error)
	UpdateUserChannel(userID, id string, in ChannelInput) (Channel, error)
	DeleteUserChannel(userID, id string) error

	GetSubscription(userID string) (Subscription, error)
	SetSubscription(userID string, in Subscription) error
	// ListSubscriptions returns every stored subscription (for the resolver).
	ListSubscriptions() ([]UserSubscription, error)

	GetUserPolicy(userID string) (Policy, error)
	SetUserPolicy(userID string, in PolicyInput) error

	// ListUserDeliveries returns one user's personal delivery log.
	ListUserDeliveries(userID string, limit int) ([]Delivery, error)
}
