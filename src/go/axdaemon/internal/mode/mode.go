// Package mode manages the enforcement mode of the MAC system.
package mode

import (
	"fmt"
	"sync/atomic"
)

// Mode represents the enforcement state.
type Mode string

const (
	ModeEnforcing  Mode = "enforcing"
	ModePermissive Mode = "permissive"
	ModeDisabled   Mode = "disabled"
)

// Manager holds the current enforcement mode with atomic access.
//
// Once both an atomic.Value and a sync.RWMutex, which suggests two
// synchronisation schemes where one is enough. The mutex was never
// locked anywhere, so every reader either raced or, more likely,
// relied on the atomic load being sufficient. It is correct without
// the mutex: Mode is written and read as a whole value, never
// mutated in place.
//
// The kernel is the other source of truth. This Manager is the Go
// side record; handlers always write mode_map first and only then
// update this, so a failure cannot leave the two disagreeing.
type Manager struct {
	current atomic.Value // stores Mode
}

// NewManager creates a Manager defaulting to permissive.
func NewManager() *Manager {
	m := &Manager{}
	m.current.Store(ModePermissive)
	return m
}

// Get returns the current mode.
func (m *Manager) Get() Mode {
	return m.current.Load().(Mode)
}

// Set atomically switches the mode.
func (m *Manager) Set(mode Mode) error {
	switch mode {
	case ModeEnforcing, ModePermissive, ModeDisabled:
		m.current.Store(mode)
		return nil
	default:
		return fmt.Errorf("gecersiz mod: %s", mode)
	}
}

// IsEnforcing reports whether violations are blocked.
func (m *Manager) IsEnforcing() bool {
	return m.Get() == ModeEnforcing
}

// IsDisabled reports whether enforcement is fully off.
func (m *Manager) IsDisabled() bool {
	return m.Get() == ModeDisabled
}
