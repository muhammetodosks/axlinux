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
	Action  string
	Effect  string
	Subject string
	Since   time.Time
	Limit   int
	Tail    bool
}

// Match reports whether an event satisfies the filter.
func (f Filter) Match(e AuditEvent) bool {
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.Effect != "" && e.Effect != f.Effect {
		return false
	}
	if f.Subject != "" && e.Subject.Comm != f.Subject {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	return true
}
