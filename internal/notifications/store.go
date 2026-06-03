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
}
