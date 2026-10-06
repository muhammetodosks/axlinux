// Package lsm loads the eBPF LSM collection and attaches its hook
// programs.
package lsm

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"

	"axlinux/axdaemon/internal/maps"
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
	// noEnforce records that the operator passed --no-enforce, so
	// zero attached hooks is a decision rather than a fault.
	noEnforce bool
	// pinDir is where shared maps live, by name. The loader reuses
	// an existing pin here so policy survives a restart.
	pinDir string
}

// SetPinDir sets the directory shared maps are pinned in.
func (m *Manager) SetPinDir(dir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pinDir = dir
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

	// Paylasilan haritalar ISMINE GORE pinlenir. Bu olmadan
	// her baslatmada YENI harita olusur ve onceki pin artik
	// sahipsiz bir nesneye ait olur:
	//
	//   - pin dosyasi var diye "pinleme calisiyor" gorunur,
	//     ama daemon pinlenen haritayi DEGIL, koleksiyonun
	//     taze haritasini kullanir;
	//   - "kurallar yeniden baslatmayi atlar" vaadi TUTMAZ,
	//     yeniden baslatma tum kurallari SILER;
	//   - bpftool/mapdump bayat veri gosterir (3 anahtar),
	//     oysa status 20 diyor.
	//
	// PinByName, var olan pini YENIDEN KULLANIR; boylece
	// programlar ve yazmalar ayni haritaya gider.
	for _, name := range []string{
		maps.AllowMapName, maps.DenyMapName, maps.ModeMapName,
	} {
		if ms, ok := spec.Maps[name]; ok && ms.Pinning == ebpf.PinNone {
			ms.Pinning = ebpf.PinByName
		}
	}

	// MapOptions.PinPath olmadan PinByName calismaz
	// ("pin by name: missing MapOptions.PinPath").
	var coll *ebpf.Collection
	if m.pinDir != "" {
		// Pin dizini yuklemeden ONCE olmali. Onceki kodda
		// dizini pinMaps() olusturuyordu ve o, koleksiyon
		// yuklendikten sonra calisiyor:
		//
		//   pin map to /sys/fs/bpf/axlinux/allow_map:
		//   no such file or directory
		//
		// Yani ilk kurulumda haritalar hicbir zaman pinlenmiyor,
		// enforcement sessizce hic baslamiyordu.
		if err := os.MkdirAll(m.pinDir, 0700); err != nil {
			return fmt.Errorf("pin dizini olusturulamadi (%s): %w",
				m.pinDir, err)
		}
		coll, err = ebpf.NewCollectionWithOptions(spec,
			ebpf.CollectionOptions{
				// v0.12'de alan adi "Maps" (MapOptions turunde).
				Maps: ebpf.MapOptions{PinPath: m.pinDir},
			})
	} else {
		coll, err = ebpf.NewCollection(spec)
	}
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
// Two conditions must BOTH hold, and checking only the first is the
// most dangerous gap this code has:
//
//  1. 'bpf' is in the active LSM chain. AttachLSM returns success even
//     when it is missing: the bpf_link is created and nothing runs.
//  2. Every hook in HookTable is attached. Attach() deliberately
//     continues past individual failures so a partially-supported
//     kernel still gets the hooks it can take. But 2-of-5 attached
//     is not "enforcement on": a policy denying file reads would be
//     reported as active while only, say, socket_connect enforces.
//
// Reporting true for a partial attach is exactly the silent failure
// this project exists to prevent: the user reads "enforcement
// active", writes a policy, and is unprotected on the missing hooks
// with no indication anything is wrong.
func (m *Manager) EnforcementPossible() bool {
	return lsmenv.Available() && m.AllHooksAttached()
}

// AllHooksAttached reports whether every tracked hook is attached.
func (m *Manager) AllHooksAttached() bool {
	return m.AttachedCount() == m.HookCount() && m.HookCount() > 0
}

// MissingHooks returns the hooks that are not attached, for the
// operator to act on. Empty when all are attached.
func (m *Manager) MissingHooks() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var missing []string
	for _, h := range HookTable {
		hook := m.hooks[h.Hook]
		if hook == nil || !hook.Attached {
			missing = append(missing, h.Hook)
		}
	}
	return missing
}

// SetNoEnforce marks that hooks were deliberately not attached because
// the operator passed --no-enforce. Without this the status output
// reports zero attached hooks as a build or kernel compatibility
// problem, which is a false alarm: nothing is wrong, enforcement was
// asked for and refused.
func (m *Manager) SetNoEnforce() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.noEnforce = true
}

// IsNoEnforce reports whether hooks were deliberately not attached.
func (m *Manager) IsNoEnforce() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.noEnforce
}

// EnforcementNotice explains the enforcement state, or "" if healthy.
func (m *Manager) EnforcementNotice() string {
	if !lsmenv.Available() {
		return lsmenv.Summary()
	}
	// --no-enforce: bilincli bir durum, sorun degil. Kullaniciya
	// "build veya kernel uyumlulugu sorunu" demek yanlislik olur
	// ve dogru taniyi gizler.
	//
	// IsNoEnforce kilit alir; dogrudan m.noEnforce okumak yari
	// yarilmis bir erisim olurdu (SetNoEnforce yaziyor).
	if m.IsNoEnforce() {
		return "--no-enforce verildi; LSM kancalari BILINCCI OLARAK " +
			"baglanmadi. Politika UYGULANMIYOR. enforcement icin " +
			"servisi --no-enforce vermeden yeniden baslatin."
	}
	// Zincirde bpf var ama kancalarin bir kismi baglanmamis:
	// enforcement KISMIDIR, kullaniciya acikca soylemeliyiz.
	if missing := m.MissingHooks(); len(missing) > 0 {
		return fmt.Sprintf(
			"bpf LSM aktif ama %d/%d kanca BAGLANMADI (%s). "+
				"Politika yalnizca bagli kancalarda uygulanir; "+
				"eksik kancalar icin yazilan kurallar ETKISIZ kalir. "+
				"Bu bir build veya kernel uyumlulugu sorunudur; "+
				"axdaemon loglarina bakin.",
			m.AttachedCount(), m.HookCount(),
			strings.Join(missing, ", "))
	}
	return ""
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
