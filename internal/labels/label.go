// SPDX-License-Identifier: Apache-2.0

// Package labels manages N:M (key, value) labels on systems used purely for
// view filtering and selector-driven bulk operations. The model is the
// k8s-subset described in research/system-groups.md: value is nullable so
// the same primitive serves both bare tags (key, NULL) and dimensional
// (key, value) labels, and a system can hold at most one value per key
// (enforced by the (system_id, key) primary key in the SQL store).
package labels

import (
	"errors"
	"fmt"
	"strings"
)

// ReservedPrefix is the key prefix System Wrangler claims for its own
// system-set labels (e.g. system-wrangler.io/discovered-via=ansible).
// User-supplied labels MUST NOT use this prefix; the store layer accepts
// reserved-prefix writes so future internal callers can populate them.
const ReservedPrefix = "system-wrangler.io/"

const (
	maxSegmentLen = 63
	maxKeyLen     = 253
	maxValueLen   = 63
)

// Sentinel errors returned by validation, the store, and the handler.
var (
	ErrNotFound = errors.New("label not found")
	ErrInvalid  = errors.New("invalid label")
	ErrReserved = errors.New("label key uses reserved prefix")
	ErrConflict = errors.New("label key already exists with a different value")
)

// Label is one (key, value) tuple attached to a system. Value is a pointer
// so the JSON encoding distinguishes a bare tag (Value == nil → "value":
// null) from an empty-string value (Value != nil but ""), which the
// schema permits and the selector grammar treats as a legal equality
// target.
type Label struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

// Input is the user-supplied subset accepted on set/update. The handler
// extracts Key from the URL path and Value from the body, so this struct
// only carries Value.
type Input struct {
	Value *string `json:"value"`
}

// ValidateKey checks the key against the k8s-subset charset/length rules
// and rejects the reserved prefix. Pass allowReserved=true from internal
// callers that legitimately set system-managed labels.
func ValidateKey(key string, allowReserved bool) error {
	if key == "" {
		return fmt.Errorf("%w: key is required", ErrInvalid)
	}
	if len(key) > maxKeyLen {
		return fmt.Errorf("%w: key exceeds %d chars", ErrInvalid, maxKeyLen)
	}
	prefix, name, hasPrefix := strings.Cut(key, "/")
	if !hasPrefix {
		// No prefix segment: the whole string is the name segment.
		return validateSegment("key", prefix)
	}
	if !allowReserved && strings.HasPrefix(key, ReservedPrefix) {
		return fmt.Errorf("%w: %q", ErrReserved, ReservedPrefix)
	}
	if err := validateSegment("key prefix", prefix); err != nil {
		return err
	}
	return validateSegment("key", name)
}

// ValidateValue checks the value against the charset/length rules. A
// nil value is legal (bare tag); an empty-string value is legal
// (equality-targetable empty).
func ValidateValue(value *string) error {
	if value == nil {
		return nil
	}
	v := *value
	if len(v) > maxValueLen {
		return fmt.Errorf("%w: value exceeds %d chars", ErrInvalid, maxValueLen)
	}
	if v == "" {
		return nil
	}
	return validateSegment("value", v)
}

// validateSegment enforces [a-zA-Z0-9._-] and the per-segment length cap.
// The label is included in the error message for operator clarity.
func validateSegment(label, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalid, label)
	}
	if len(s) > maxSegmentLen {
		return fmt.Errorf("%w: %s exceeds %d chars", ErrInvalid, label, maxSegmentLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return fmt.Errorf("%w: %s has illegal character %q", ErrInvalid, label, c)
		}
	}
	return nil
}
