// Package learning implements the learning mode that observes system
// activity and generates YAML policy suggestions.
package learning

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Observation records a single subject-object-action triple.
type Observation struct {
	Subject string
	Object  string
	Action  string
	Count   int
	First   time.Time
	Last    time.Time
}

// Pattern is an aggregated set of observations.
type Pattern struct {
	Subject  string `yaml:"subject"`
	Object   string `yaml:"object"`
	Action   string `yaml:"action"`
	Count    int    `yaml:"count"`
}

// Report is the final learning output.
type Report struct {
	GeneratedAt time.Time `yaml:"generated_at"`
	Duration    string    `yaml:"duration"`
	Patterns   []Pattern `yaml:"patterns"`
	YAML        string    `yaml:"yaml"`
}

// Manager controls the learning lifecycle.
type Manager struct {
	mu          sync.Mutex
	active      bool
	startedAt   time.Time
	observations map[string]*Observation
	cancel      context.CancelFunc
}

// NewManager creates a learning manager.
func NewManager() *Manager {
	return &Manager{
		observations: make(map[string]*Observation),
	}
}

// Start begins learning mode.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active {
		return fmt.Errorf("ogrenme modu zaten aktif")
	}

	m.active = true
	m.startedAt = time.Now().UTC()
	m.observations = make(map[string]*Observation)
	return nil
}

// Stop ends learning mode.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.active = false
}

// Record adds an observation to the aggregate.
func (m *Manager) Record(subject, object, action string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return
	}

	key := fmt.Sprintf("%s|%s|%s", subject, object, action)
	now := time.Now().UTC()

	if obs, ok := m.observations[key]; ok {
		obs.Count++
		obs.Last = now
	} else {
		m.observations[key] = &Observation{
			Subject: subject,
			Object:  object,
			Action:  action,
			Count:   1,
			First:   now,
			Last:    now,
		}
	}
}

// IsActive reports whether learning is running.
func (m *Manager) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// Elapsed returns the learning duration.
func (m *Manager) Elapsed() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		return 0
	}
	return time.Since(m.startedAt)
}

// GenerateReport compiles observations into a YAML suggestion report.
func (m *Manager) GenerateReport() Report {
	m.mu.Lock()
	defer m.mu.Unlock()

	patterns := make([]Pattern, 0, len(m.observations))
	for _, obs := range m.observations {
		patterns = append(patterns, Pattern{
			Subject: obs.Subject,
			Object:  obs.Object,
			Action:  obs.Action,
			Count:   obs.Count,
		})
	}

	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].Count > patterns[j].Count
	})

	duration := time.Since(m.startedAt).Round(time.Second)

	yaml := generateYAML(patterns)

	return Report{
		GeneratedAt: time.Now().UTC(),
		Duration:    duration.String(),
		Patterns:    patterns,
		YAML:        yaml,
	}
}

// ObservationCount returns the number of unique observations.
func (m *Manager) ObservationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.observations)
}

func generateYAML(patterns []Pattern) string {
	if len(patterns) == 0 {
		return "# Gozlemlenecek aktivite yok\n"
	}

	var b string
	b += "# AXlinux ogrenme modu onerileri\n"
	b += "# Bu kurallari axc ile derleyip axctl ile yukleyebilirsiniz\n\n"
	b += "version: 1\n"
b += "mode: permissive\n"
b += "labels: {}\n"
b += "rules:\n"

	for i, p := range patterns {
		b += fmt.Sprintf("  - id: \"rule_%03d\"\n", i+1)
		b += fmt.Sprintf("    name: \"ogrenme: %s %s %s\"\n", p.Subject, p.Action, p.Object)
		b += fmt.Sprintf("    subject: [\"%s\"]\n", p.Subject)
		b += fmt.Sprintf("    object: \"%s\"\n", p.Object)
		b += fmt.Sprintf("    action: \"%s\"\n", p.Action)
		b += "    effect: allow\n"
		b += fmt.Sprintf("    priority: %d\n", 100-i)
	}

	return b
}
