// Package policy handles parsing, validation, and in-memory storage
// of the compiled MAC policy received from axc.
package policy

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Effect represents the rule outcome.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is a single compiled policy rule.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Subject  []string `json:"subject"`
	Object   string   `json:"object"`
	Action   string   `json:"action"`
	Effect   Effect   `json:"effect"`
	Priority int      `json:"priority"`
}

// Policy is the full compiled policy document.
type Policy struct {
	Version int              `json:"version"`
	Mode   string           `json:"mode"`
	Labels map[string][]string `json:"labels"`
	Rules  []Rule           `json:"rules"`
}

// Snapshot is an immutable view of the loaded policy.
type Snapshot struct {
	Policy       Policy
	LoadedAt     time.Time
	RulesLoaded  int
	LabelsLoaded int
	// Loaded reports whether a policy has ever been loaded. The zero
	// value of a Snapshot is ambiguous otherwise: a policy with zero
	// rules is rejected by validate, so RulesLoaded==0 could mean
	// either "nothing loaded yet" or "loaded and empty".
	Loaded bool
}

// Manager stores the active policy and provides thread-safe access.
type Manager struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

// NewManager creates an empty policy manager.
func NewManager() *Manager {
	return &Manager{}
}

// Load parses and validates a new policy, then stores it.
func (m *Manager) Load(data []byte) (Snapshot, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Snapshot{}, fmt.Errorf("policy JSON parse hatasi: %w", err)
	}

	if err := validate(&p); err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{
		Policy:       p,
		LoadedAt:     time.Now().UTC(),
		RulesLoaded:  len(p.Rules),
		LabelsLoaded: len(p.Labels),
		Loaded:       true,
	}

	m.mu.Lock()
	m.snapshot = snap
	m.mu.Unlock()

	return snap, nil
}

// Get returns the current policy snapshot.
func (m *Manager) Get() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot
}

// RuleCount returns the number of loaded rules.
func (m *Manager) RuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot.RulesLoaded
}

// validate checks the policy structure for correctness.
func validate(p *Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("desteklenmeyen policy versiyonu: %d", p.Version)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy en az bir kural icermeli")
	}
	for i, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("kural %d: id gerekli", i)
		}
		if r.Action == "" {
			return fmt.Errorf("kural %s: action gerekli", r.ID)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("kural %s: gecersiz effect: %s", r.ID, r.Effect)
		}
		if len(r.Subject) == 0 {
			return fmt.Errorf("kural %s: subject gerekli", r.ID)
		}
	}
	return nil
}
