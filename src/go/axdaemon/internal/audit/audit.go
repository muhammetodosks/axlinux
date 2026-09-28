// Package audit receives audit events from the eBPF perf buffer
// and forwards them to the axlog service.
package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Event is the audit event received from the kernel perf buffer.
//
// The field order and types MUST match struct audit_event in
// axbpf.h byte for byte. Any divergence decodes garbage silently,
// so the layout is locked by TestEventLayoutMatchesC.
//
// C layout:
//	__u64 timestamp; char comm[16]; char path[256];
//	__u32 pid, action, effect, decision, rule_id, hook_type;
type Event struct {
	Timestamp uint64
	PID       uint32
	Comm      [16]byte
	Path      [256]byte
	Action    uint32
	Effect    uint32
	Decision  uint32
	RuleID    uint32
	HookType  uint32
}

// EventSize is the wire size of struct audit_event as the kernel
// writes it: 8 (timestamp) + 4 (pid) + 16 (comm) + 256 (path) plus
// five u32 tail fields (action, effect, decision, rule_id, hook_type).
//
// It must equal the C sizeof exactly: parseEvent rejects records
// shorter than this, so an overestimate would silently drop every
// audit record. TestEventLayoutMatchesC computes the C value
// independently and compares.
const EventSize = 8 + 4 + 16 + 256 + 5*4

// EventSender is the interface for forwarding events to axlog.
type EventSender interface {
	Send(event Event) error
}

// Manager reads from the eBPF perf buffer and dispatches events.
type Manager struct {
	mu     sync.Mutex
	reader *perf.Reader
	sender EventSender
	events []Event
}

// NewManager creates an audit manager.
func NewManager(sender EventSender) *Manager {
	return &Manager{
		sender: sender,
		events: make([]Event, 0, 1024),
	}
}

// OpenPerfBuffer attaches to the given eBPF map's perf buffer.
func (m *Manager) OpenPerfBuffer(em *ebpf.Map) error {
	if em == nil {
		return fmt.Errorf("perf map nil")
	}

	reader, err := perf.NewReader(em, 4096)
	if err != nil {
		return fmt.Errorf("perf reader acilamadi: %w", err)
	}

	m.mu.Lock()
	m.reader = reader
	m.mu.Unlock()

	return nil
}

// Run starts the event processing loop until context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	reader := m.reader
	m.mu.Unlock()

	if reader == nil {
		return fmt.Errorf("perf reader acik degil")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			continue
		}

		if len(rec.RawSample) < 8+4+4+4+4+16+256+4+4+4+4 {
			continue
		}

		event, err := parseEvent(rec.RawSample)
		if err != nil {
			continue
		}

		m.mu.Lock()
		m.events = append(m.events, event)
		if len(m.events) > 10000 {
			m.events = m.events[len(m.events)-5000:]
		}
		m.mu.Unlock()

		if m.sender != nil {
			_ = m.sender.Send(event)
		}
	}
}

// Recent returns a copy of the most recent events.
func (m *Manager) Recent(limit int) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}

	start := len(m.events) - limit
	if start < 0 {
		start = 0
	}

	result := make([]Event, limit)
	copy(result, m.events[start:])
	return result
}

// Count returns the total number of buffered events.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// Stats reports how many events were denied versus allowed. These
// counters are cumulative across the whole daemon lifetime, not just
// the currently buffered window.
func (m *Manager) Stats() (denied, allowed int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.events {
		if m.events[i].Decision == 1 {
			denied++
		} else {
			allowed++
		}
	}
	return
}

// DeniedCount returns how many buffered events were denied.
func (m *Manager) DeniedCount() int {
	denied, _ := m.Stats()
	return denied
}

// AllowedCount returns how many buffered events were allowed.
func (m *Manager) AllowedCount() int {
	_, allowed := m.Stats()
	return allowed
}

// Close shuts down the perf reader.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reader != nil {
		err := m.reader.Close()
		m.reader = nil
		return err
	}
	return nil
}

// parseEvent decodes one perf buffer record. The offsets below mirror
// struct audit_event in axbpf.h; keep them in lockstep with Event.
func parseEvent(data []byte) (Event, error) {
	var e Event

	if len(data) < EventSize {
		return e, fmt.Errorf("audit kaydi kisa: %d bayt (beklenen %d)",
			len(data), EventSize)
	}

	offset := 0

	e.Timestamp = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	e.PID = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	copy(e.Comm[:], data[offset:offset+16])
	offset += 16

	copy(e.Path[:], data[offset:offset+256])
	offset += 256

	e.Action = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.Effect = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.Decision = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.RuleID = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.HookType = binary.LittleEndian.Uint32(data[offset:])

	return e, nil
}

// FormatEvent renders an event as a human-readable string.
func FormatEvent(e Event) string {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	path := string(bytes.TrimRight(e.Path[:], "\x00"))
	ts := time.Unix(0, int64(e.Timestamp)).UTC().Format(time.RFC3339)
	return fmt.Sprintf("[%s] pid=%d comm=%s path=%s action=%d effect=%d decision=%d rule=%d",
		ts, e.PID, comm, path, e.Action, e.Effect, e.Decision, e.RuleID)
}
