// Package protocol defines the audit event types exchanged between
// axdaemon and axlog.
package protocol

import "time"

// AuditEvent is a single audit log entry.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Mode      string    `json:"mode"`
	Hook      string    `json:"hook"`
	Subject   struct {
		PID   uint32 `json:"pid"`
		Comm  string `json:"comm"`
		Label string `json:"label,omitempty"`
	} `json:"subject"`
	Object struct {
		Path  string `json:"path,omitempty"`
		Inode uint64 `json:"inode,omitempty"`
		Port  uint16 `json:"port,omitempty"`
		// Dev, inode ile birlikte dosyayi bulmak icin gereklidir:
		// ayni inode numarasi farkli dosya sistemlerinde olabilir
		// (find / -xdev -inum N).
		Dev uint32 `json:"dev,omitempty"`
		// Truncated: yolun tamami sigmadi, gorunen kisim eksiktir.
		// Alan bos da OLABILIR ama Truncated varsa yola ASLA
		// tam dogrulukla bakilmamalidir.
		Truncated bool `json:"truncated,omitempty"`
	} `json:"object"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
}

// Filter holds query parameters for reading audit events.
type Filter struct {
	Action  string
	Effect  string
	Subject string
	Since   time.Time
	Limit   int
	Tail    bool
}
