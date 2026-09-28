// Package lsm loads the eBPF LSM collection and attaches its hook
// programs.
package lsm

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"axlinux/axdaemon/internal/lsmenv"
)

// Hook pairs an LSM attachment point with the C function that
// implements it.
//
// The Go name must match the BPF_PROG function name in the .inc file
// (cilium/ebpf keys Programs by function name), and the sec name must
// match the LSM hook it guards. A mismatch here means the hook is
// silently never attached, so TestHookTableMatchesPrograms guards it.
type Hook struct {
	GoName   string // BPF_PROG function name in C
	Hook     string // LSM hook name (for status reporting)
	Sec      string // section name inside the ELF
	Source   string // .inc file in src/bpf that implements it
	prog     *ebpf.Program
	link     link.Link
	Attached bool
}

// HookTable is the authoritative list of hooks AXlinux implements.
var HookTable = []Hook{
	{
		GoName: "ax_file_open",
		Hook:   "file_open",
		Sec:    "lsm/file_open",
		Source: "hooks_file_open.inc",
	},
	{
		GoName: "ax_inode_permission",
		Hook:   "inode_permission",
		Sec:    "lsm/inode_permission",
		Source: "hooks_inode_permission.inc",
	},
	{
		GoName: "ax_bprm_check",
		Hook:   "bprm_check_security",
		Sec:    "lsm/bprm_check_security",
		Source: "hooks_bprm_check_security.inc",
	},
	{
		GoName: "ax_socket_connect",
		Hook:   "socket_connect",
		Sec:    "lsm/socket_connect",
		Source: "hooks_socket_connect.inc",
	},
	{
		GoName: "ax_socket_bind",
		Hook:   "socket_bind",
		Sec:    "lsm/socket_bind",
		Source: "hooks_socket_bind.inc",
	},
}

// HookNames returns the implemented hook names, for status output.
func HookNames() []string {
	out := make([]string, 0, len(HookTable))
	for _, h := range HookTable {
		out = append(out, h.Hook)
	}
	return out
}

// Manager owns the loaded collection and its hook links.
type Manager struct {
	mu         sync.RWMutex
	collection *ebpf.Collection
	hooks      map[string]*Hook
	loaded     bool
	objPath    string
}

// NewManager creates a manager for the given axbpf object path.
func NewManager(objPath string) *Manager {
	m := &Manager{
		hooks:   make(map[string]*Hook, len(HookTable)),
		objPath: objPath,
	}
	for _, h := range HookTable {
		hh := h
		m.hooks[h.Hook] = &Hook{
			GoName:   hh.GoName,
			Hook:     hh.Hook,
			Sec:      hh.Sec,
			Attached: false,
		}
	}
	return m
}

// Load reads the eBPF collection from disk.
func (m *Manager) Load() error {
	if _, err := os.Stat(m.objPath); err != nil {
		return fmt.Errorf("axbpf.o bulunamadi (%s): %w", m.objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(m.objPath)
	if err != nil {
		return fmt.Errorf("ebpf collection spec yuklenemedi: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("ebpf collection olusturulamadi: %w", err)
	}

	m.mu.Lock()
	m.collection = coll
	m.loaded = true
	m.mu.Unlock()

	return nil
}

// Collection exposes the loaded collection so the maps manager can
// take the very maps the programs use.
func (m *Manager) Collection() *ebpf.Collection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.collection
}

// Attach links each hook program. Individual failures are recorded on
// the hook rather than aborting, so a partially-supported kernel still
// gets the hooks it can take.
func (m *Manager) Attach() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.loaded || m.collection == nil {
		return fmt.Errorf("ebpf collection yuklu degil")
	}

	var firstErr error
	for _, def := range HookTable {
		prog, ok := m.collection.Programs[def.GoName]
		if !ok {
			// A program missing from the ELF is a build problem, not a
			// runtime one; surface it instead of hiding it.
			err := fmt.Errorf("program bulunamadi: %s (bolum %s)",
				def.GoName, def.Sec)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		h := m.hooks[def.Hook]
		h.prog = prog

		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s baglanamadi: %w", def.Hook, err)
			}
			h.Attached = false
			continue
		}

		h.link = l
		h.Attached = true
	}

	return firstErr
}

// EnforcementPossible reports whether this kernel can actually run the
// hooks.
//
// AttachLSM returns success even when 'bpf' is missing from the active
// LSM chain, so AttachedCount() is meaningless on its own. Callers must
// consult this before telling a user their policy is in force.
func (m *Manager) EnforcementPossible() bool {
	return lsmenv.Available()
}

// EnforcementNotice explains the enforcement state, or "" if healthy.
func (m *Manager) EnforcementNotice() string {
	if lsmenv.Available() {
		return ""
	}
	return lsmenv.Summary()
}

// Detach releases all hook links.
func (m *Manager) Detach() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, h := range m.hooks {
		if h.link != nil {
			h.link.Close()
			h.link = nil
		}
		h.Attached = false
	}
}

// Close detaches hooks and frees the collection.
func (m *Manager) Close() error {
	m.Detach()

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}
	m.loaded = false
	return nil
}

// Status returns a snapshot of hook attachment state keyed by hook name.
func (m *Manager) Status() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]bool, len(m.hooks))
	for name, h := range m.hooks {
		status[name] = h.Attached
	}
	return status
}

// IsLoaded reports whether the collection is loaded.
func (m *Manager) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}

// HookCount returns the number of hooks tracked.
func (m *Manager) HookCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.hooks)
}

// AttachedCount returns the number of successfully attached hooks.
func (m *Manager) AttachedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, h := range m.hooks {
		if h.Attached {
			count++
		}
	}
	return count
}
