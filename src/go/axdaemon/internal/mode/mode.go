// Package mode manages the enforcement mode of the MAC system.
package mode

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Mode represents the enforcement state.
type Mode string

const (
	ModeEnforcing Mode = "enforcing"
	ModePermissive Mode = "permissive"
	ModeDisabled  Mode = "disabled"
)

// Manager holds the current enforcement mode with atomic access.
type Manager struct {
	current atomic.Value // stores Mode
	mu      sync.RWMutex
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
