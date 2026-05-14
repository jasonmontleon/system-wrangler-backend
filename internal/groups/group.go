// SPDX-License-Identifier: Apache-2.0

// Package groups manages named collections of systems. A system belongs to at
// most one group; deleting a group leaves its systems intact and ungrouped
// (the systems.group_id FK is ON DELETE SET NULL).
package groups

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxNameLen = 255

// Sentinel errors returned by the groups store and handler.
var (
	ErrNotFound  = errors.New("group not found")
	ErrInvalid   = errors.New("invalid group")
	ErrDuplicate = errors.New("group name already exists")
)

// Group is a named collection of systems.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	SystemCount int       `json:"systemCount"`
}

// GroupInput is the user-supplied subset accepted on create / rename.
type GroupInput struct {
	Name string `json:"name"`
}

// Validate returns ErrInvalid if the input is unusable.
func (in GroupInput) Validate() error {
	name := strings.TrimSpace(in.Name)
	switch {
	case name == "":
		return fmt.Errorf("%w: name is required", ErrInvalid)
	case len(name) > maxNameLen:
		return fmt.Errorf("%w: name exceeds %d chars", ErrInvalid, maxNameLen)
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("groups: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
