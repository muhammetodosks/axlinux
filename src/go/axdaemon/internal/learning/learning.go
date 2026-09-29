// Package learning implements the learning mode that observes system
// activity and generates YAML policy suggestions.
package learning

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"axlinux/axdaemon/internal/audit"
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
	// startedAt sifirlanmazsa yeniden baslatildiginda Elapsed eski
	// oturumun basindan hesaplanir ve sure yanlis bildirilir.
	m.startedAt = time.Time{}
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

// Observe implements audit.Observer. It is called once per audit event
// at the moment the event is produced, so the aggregate reflects real
// enforcement activity instead of whatever the operator happened to
// read. A compile-time assertion keeps the two packages in sync: if
// the observer interface changes, this stops building.
func (m *Manager) Observe(subject, object, action string) {
	m.Record(subject, object, action)
}

var _ audit.Observer = (*Manager)(nil)

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

	// Start() hic cagrilmadiysa startedAt sifir zaman degeridir
	// ve time.Since sifirdan hesaplanir: rapor "17565 gun" gibi
	// anlamsiz bir sure bildirirdi. Bu durumda sure bildirilmez.
	duration := ""
	if m.active && !m.startedAt.IsZero() {
		duration = time.Since(m.startedAt).Round(time.Second).String()
	}

	return Report{
		GeneratedAt: time.Now().UTC(),
		Duration:    duration,
		Patterns:    patterns,
		YAML:        generateYAML(patterns),
	}
}

// ObservationCount returns the number of unique observations.
func (m *Manager) ObservationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.observations)
}

// yamlQuote renders a value as a double-quoted YAML scalar.
//
// Gozlenen degerler kernelden gelir: yol adlari, surec adlari.
// Bunlar tirnak, backslash, iki nokta veya yeni satir icerebilir
// ("/tmp/a: b", "weird\"name"). Kacis uygulanmadan string
// birleştirilirse uretilen YAML AYRIŞMAZ ve axctl policy'yi
// yukleyemez; kullanici ogrenme raporunu calistirip hata alir ve
// nedenini anlamaz.
//
// YAML double-quoted scalar'da gereken kacisler:
//   \  "  ve satir sonu. Kontrol karakterleri de \xNN ile.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			// Diger kontrol karakterleri dogrudan yazilamaz.
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func generateYAML(patterns []Pattern) string {
	if len(patterns) == 0 {
		return "# Gozlemlenecek aktivite yok\n"
	}

	var b strings.Builder
	b.WriteString("# AXlinux ogrenme modu onerileri\n")
	b.WriteString("# Bu kurallari axc ile derleyip axctl ile yukleyebilirsiniz\n\n")
	b.WriteString("version: 1\n")
	b.WriteString("mode: permissive\n")
	b.WriteString("labels: {}\n")
	b.WriteString("rules:\n")

	for i, p := range patterns {
		fmt.Fprintf(&b, "  - id: \"rule_%03d\"\n", i+1)
		fmt.Fprintf(&b, "    name: %s\n",
			yamlQuote(fmt.Sprintf("ogrenme: %s %s %s",
				p.Subject, p.Action, p.Object)))
		fmt.Fprintf(&b, "    subject: [%s]\n", yamlQuote(p.Subject))
		fmt.Fprintf(&b, "    object: %s\n", yamlQuote(p.Object))
		fmt.Fprintf(&b, "    action: %s\n", yamlQuote(p.Action))
		b.WriteString("    effect: allow\n")
		fmt.Fprintf(&b, "    priority: %d\n", 100-i)
	}

	return b.String()
}
