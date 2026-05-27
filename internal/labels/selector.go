// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"fmt"
	"strings"
)

// Op is the operator of a single label-selector requirement.
type Op int

const (
	// OpHas matches when the key exists on a system (any value, including NULL).
	OpHas Op = iota
	// OpNotHas matches when the key is absent from a system.
	OpNotHas
	// OpEq matches when the key exists with the exact value. Bare tags
	// (value IS NULL) never satisfy OpEq.
	OpEq
	// OpNotEq matches when the key is absent, or present with a value
	// other than the requirement's value. NULL values satisfy OpNotEq
	// because NULL != any concrete string.
	OpNotEq
	// OpIn matches when the key exists with a value in the value set.
	OpIn
	// OpNotIn matches when the key is absent, or present with a value
	// outside the value set.
	OpNotIn
)

// Requirement is one clause in a selector. Values is empty for OpHas
// and OpNotHas; carries exactly one element for OpEq/OpNotEq; carries
// one or more elements for OpIn/OpNotIn.
type Requirement struct {
	Op     Op
	Key    string
	Values []string
}

// Selector is the AST of a parsed label-selector expression. The empty
// selector matches every system.
type Selector []Requirement

// Matches reports whether the given set of labels (a single system's
// full label list) satisfies every Requirement in the selector. Useful
// for the in-memory MemStore and for tests; the SQLite store evaluates
// selectors via SQL fragments instead.
func (sel Selector) Matches(labels []Label) bool {
	byKey := make(map[string]*string, len(labels))
	for _, l := range labels {
		byKey[l.Key] = l.Value
	}
	for _, r := range sel {
		if !r.matches(byKey) {
			return false
		}
	}
	return true
}

func (r Requirement) matches(byKey map[string]*string) bool {
	v, present := byKey[r.Key]
	switch r.Op {
	case OpHas:
		return present
	case OpNotHas:
		return !present
	case OpEq:
		return present && v != nil && *v == r.Values[0]
	case OpNotEq:
		return !present || v == nil || *v != r.Values[0]
	case OpIn:
		if !present || v == nil {
			return false
		}
		for _, val := range r.Values {
			if *v == val {
				return true
			}
		}
		return false
	case OpNotIn:
		if !present || v == nil {
			return true
		}
		for _, val := range r.Values {
			if *v == val {
				return false
			}
		}
		return true
	}
	return false
}

// SQL translates the selector into a boolean SQL expression referencing
// the system_labels table. systemIDExpr is the column reference for the
// system identifier in the outer query (e.g. "h.id"). Returns the
// fragment and the ordered args slice; an empty selector returns
// ("", nil) so callers can elide the WHERE clause cleanly.
func (sel Selector) SQL(systemIDExpr string) (string, []any) {
	if len(sel) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(sel))
	var args []any
	for _, r := range sel {
		frag, fArgs := r.sql(systemIDExpr)
		parts = append(parts, frag)
		args = append(args, fArgs...)
	}
	return strings.Join(parts, " AND "), args
}

func (r Requirement) sql(idExpr string) (string, []any) {
	switch r.Op {
	case OpHas:
		return fmt.Sprintf(
			"EXISTS (SELECT 1 FROM system_labels WHERE system_id = %s AND key = ?)",
			idExpr,
		), []any{r.Key}
	case OpNotHas:
		return fmt.Sprintf(
			"NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = %s AND key = ?)",
			idExpr,
		), []any{r.Key}
	case OpEq:
		return fmt.Sprintf(
			"EXISTS (SELECT 1 FROM system_labels WHERE system_id = %s AND key = ? AND value = ?)",
			idExpr,
		), []any{r.Key, r.Values[0]}
	case OpNotEq:
		return fmt.Sprintf(
			"NOT EXISTS (SELECT 1 FROM system_labels WHERE system_id = %s AND key = ? AND value = ?)",
			idExpr,
		), []any{r.Key, r.Values[0]}
	case OpIn, OpNotIn:
		placeholders := strings.Repeat("?,", len(r.Values))
		placeholders = placeholders[:len(placeholders)-1]
		op := "EXISTS"
		if r.Op == OpNotIn {
			op = "NOT EXISTS"
		}
		frag := fmt.Sprintf(
			"%s (SELECT 1 FROM system_labels WHERE system_id = %s AND key = ? AND value IN (%s))",
			op, idExpr, placeholders,
		)
		args := make([]any, 0, 1+len(r.Values))
		args = append(args, r.Key)
		for _, v := range r.Values {
			args = append(args, v)
		}
		return frag, args
	}
	// Unreachable; Op is set by the parser only.
	return "1=0", nil
}

// ParseSelector parses an input string into a Selector, validating each
// key and value against the same charset/length rules the store
// enforces on writes. Whitespace around tokens is permitted. An empty
// input (or whitespace-only) is a legal empty selector.
func ParseSelector(s string) (Selector, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return Selector{}, nil
	}
	p := &parser{toks: toks}
	out := Selector{}
	for {
		req, err := p.parseRequirement()
		if err != nil {
			return nil, err
		}
		out = append(out, req)
		if p.eof() {
			break
		}
		if err := p.expect(tokComma); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ---- tokenizer ----

type tokenKind int

const (
	tokIdent tokenKind = iota
	tokEq
	tokNotEq
	tokBang
	tokComma
	tokLParen
	tokRParen
)

type token struct {
	kind tokenKind
	text string
}

func tokenize(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == ',':
			out = append(out, token{kind: tokComma})
			i++
		case c == '(':
			out = append(out, token{kind: tokLParen})
			i++
		case c == ')':
			out = append(out, token{kind: tokRParen})
			i++
		case c == '=':
			out = append(out, token{kind: tokEq})
			i++
		case c == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				out = append(out, token{kind: tokNotEq})
				i += 2
			} else {
				out = append(out, token{kind: tokBang})
				i++
			}
		case isIdentByte(c):
			j := i
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			out = append(out, token{kind: tokIdent, text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("%w: unexpected character %q at offset %d", ErrInvalid, c, i)
		}
	}
	return out, nil
}

// isIdentByte returns true for any byte permitted in a label key or
// value, including '/' (only legal in keys; the parser enforces value
// validation downstream).
func isIdentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
	case c >= 'A' && c <= 'Z':
	case c >= '0' && c <= '9':
	case c == '.' || c == '_' || c == '-' || c == '/':
	default:
		return false
	}
	return true
}

// ---- parser ----

type parser struct {
	toks []token
	pos  int
}

func (p *parser) eof() bool   { return p.pos >= len(p.toks) }
func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) expect(k tokenKind) error {
	if p.eof() || p.peek().kind != k {
		return fmt.Errorf("%w: expected %s", ErrInvalid, tokenKindName(k))
	}
	p.pos++
	return nil
}

func tokenKindName(k tokenKind) string {
	switch k {
	case tokIdent:
		return "identifier"
	case tokEq:
		return "'='"
	case tokNotEq:
		return "'!='"
	case tokBang:
		return "'!'"
	case tokComma:
		return "','"
	case tokLParen:
		return "'('"
	case tokRParen:
		return "')'"
	}
	return "?"
}

func (p *parser) parseRequirement() (Requirement, error) {
	if p.eof() {
		return Requirement{}, fmt.Errorf("%w: empty requirement", ErrInvalid)
	}
	// "!" key — absence
	if p.peek().kind == tokBang {
		p.next()
		if p.eof() || p.peek().kind != tokIdent {
			return Requirement{}, fmt.Errorf("%w: expected key after '!'", ErrInvalid)
		}
		key := p.next().text
		if err := ValidateKey(key, true); err != nil {
			return Requirement{}, err
		}
		return Requirement{Op: OpNotHas, Key: key}, nil
	}
	if p.peek().kind != tokIdent {
		return Requirement{}, fmt.Errorf("%w: expected key, got %s", ErrInvalid, tokenKindName(p.peek().kind))
	}
	key := p.next().text
	if err := ValidateKey(key, true); err != nil {
		return Requirement{}, err
	}
	if p.eof() || p.peek().kind == tokComma {
		return Requirement{Op: OpHas, Key: key}, nil
	}
	switch p.peek().kind {
	case tokEq:
		p.next()
		val, err := p.parseValue()
		if err != nil {
			return Requirement{}, err
		}
		return Requirement{Op: OpEq, Key: key, Values: []string{val}}, nil
	case tokNotEq:
		p.next()
		val, err := p.parseValue()
		if err != nil {
			return Requirement{}, err
		}
		return Requirement{Op: OpNotEq, Key: key, Values: []string{val}}, nil
	case tokIdent:
		// "in" / "notin"
		word := p.peek().text
		switch word {
		case "in":
			p.next()
			vals, err := p.parseValueList()
			if err != nil {
				return Requirement{}, err
			}
			return Requirement{Op: OpIn, Key: key, Values: vals}, nil
		case "notin":
			p.next()
			vals, err := p.parseValueList()
			if err != nil {
				return Requirement{}, err
			}
			return Requirement{Op: OpNotIn, Key: key, Values: vals}, nil
		default:
			return Requirement{}, fmt.Errorf("%w: expected 'in' or 'notin', got %q", ErrInvalid, word)
		}
	default:
		return Requirement{}, fmt.Errorf("%w: expected operator after key, got %s", ErrInvalid, tokenKindName(p.peek().kind))
	}
}

// parseValue accepts either a non-empty identifier or an empty token
// (when "=" is immediately followed by "," or end of input — the empty-
// string value case the schema permits).
func (p *parser) parseValue() (string, error) {
	if p.eof() || p.peek().kind == tokComma {
		// Empty value (env=) is legal per the schema.
		if err := ValidateValue(strPtr("")); err != nil {
			return "", err
		}
		return "", nil
	}
	if p.peek().kind != tokIdent {
		return "", fmt.Errorf("%w: expected value, got %s", ErrInvalid, tokenKindName(p.peek().kind))
	}
	v := p.next().text
	val := v
	if err := ValidateValue(&val); err != nil {
		return "", err
	}
	return v, nil
}

func (p *parser) parseValueList() ([]string, error) {
	if err := p.expect(tokLParen); err != nil {
		return nil, err
	}
	if p.eof() {
		return nil, fmt.Errorf("%w: unterminated value list", ErrInvalid)
	}
	var out []string
	// Allow an empty value as the first element (env in ("",prod)) by
	// treating ")" or "," in the value position as an empty value.
	for {
		if p.peek().kind == tokRParen {
			return nil, fmt.Errorf("%w: empty value list", ErrInvalid)
		}
		v, err := p.parseListValue()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if p.eof() {
			return nil, fmt.Errorf("%w: unterminated value list", ErrInvalid)
		}
		if p.peek().kind == tokRParen {
			p.next()
			return out, nil
		}
		if err := p.expect(tokComma); err != nil {
			return nil, err
		}
	}
}

func (p *parser) parseListValue() (string, error) {
	if p.peek().kind == tokComma || p.peek().kind == tokRParen {
		val := ""
		if err := ValidateValue(&val); err != nil {
			return "", err
		}
		return "", nil
	}
	if p.peek().kind != tokIdent {
		return "", fmt.Errorf("%w: expected value in list, got %s", ErrInvalid, tokenKindName(p.peek().kind))
	}
	v := p.next().text
	val := v
	if err := ValidateValue(&val); err != nil {
		return "", err
	}
	return v, nil
}

func strPtr(s string) *string { return &s }
