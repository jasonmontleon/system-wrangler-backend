// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"crypto/rand"
	"fmt"
)

// newUUID returns a RFC 4122 v4 UUID. Matches the per-package
// pattern used by systems, groups, audit, and credentials so
// hostkeys doesn't depend on google/uuid directly.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("hostkeys: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
