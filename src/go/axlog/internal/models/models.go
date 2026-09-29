// Package models defines the core data structures for axlog.
package models

import "time"

// AuditEvent is the canonical audit event model.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Mode      string    `json:"mode"`
	Hook      string    `json:"hook"`
	Subject   Subject   `json:"subject"`
	Object    Object    `json:"object"`
	Action    string    `json:"action"`
	Effect    string    `json:"effect"`
	Decision  string    `json:"decision"`
	RuleID    string    `json:"rule_id,omitempty"`
	RuleName  string    `json:"rule_name,omitempty"`
}

// Subject describes the process that triggered the event.
type Subject struct {
	PID   uint32 `json:"pid"`
	Comm  string `json:"comm"`
	Label string `json:"label,omitempty"`
}

// Object describes the resource being accessed.
type Object struct {
	Path  string `json:"path,omitempty"`
	Inode uint64 `json:"inode,omitempty"`
	Port  uint16 `json:"port,omitempty"`
}

// Filter holds query parameters for filtering events.
type Filter struct {
	Action   string
	Effect   string
	Decision string
	Subject  string
	Since    time.Time
	Limit    int
	Tail     bool
}

// Match reports whether an event satisfies the filter.
//
// Comparisons are case-insensitive. A user typing "DENY" against a
// stored "deny" would otherwise get zero rows and conclude there
// was no activity, which for an audit query is the worst possible
// outcome: a false all-clear.
//
// Every set field constrains (AND). A field left empty does not
// restrict, so the zero Filter matches everything.
func (f Filter) Match(e AuditEvent) bool {
	if f.Action != "" && !eqFold(f.Action, e.Action) {
		return false
	}
	if f.Effect != "" && !eqFold(f.Effect, e.Effect) {
		return false
	}
	if f.Decision != "" && !eqFold(f.Decision, e.Decision) {
		return false
	}
	if f.Subject != "" && !eqFold(f.Subject, e.Subject.Comm) {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	return true
}

// eqFold compares two short strings without regard to case, avoiding
// a strings.ToLower allocation per comparison on a hot path.
func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
