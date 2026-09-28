// Package maps manages the eBPF hash maps that store policy rules
// for the LSM hooks to consult.
//
// The maps MUST come from the loaded eBPF collection. Loading a
// separate pinned copy would give the kernel programs and the daemon
// two different maps: programs would read an empty map forever while
// the daemon wrote rules into one nobody reads. NewFromCollection
// takes ownership of the collection's own maps so the two sides can
// never diverge.
package maps

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
)

// Map names as declared in axbpf.h.
const (
	AllowMapName = "allow_map"
	DenyMapName  = "deny_map"
	ModeMapName  = "mode_map"
	AuditMapName = "audit_buffer"
)

// MapKey is the lookup key used in both allow and deny maps.
// Must match struct policy_key in axbpf.h.
type MapKey struct {
	Comm   [16]byte
	Path   [256]byte
	Action uint32
}

// MapValue is the value stored for each rule entry.
// Must match struct policy_value in axbpf.h.
type MapValue struct {
	RuleID uint32
	Effect uint32
}

// Effect values. These MUST match EFFECT_DENY / EFFECT_ALLOW in axbpf.h.
// Getting these backwards silently disables all deny rules.
const (
	EffectDeny  uint32 = 0
	EffectAllow uint32 = 1
)

// Action values. These MUST match the ACTION_* block in axbpf.h.
const (
	ActionFileRead    uint32 = 1
	ActionFileWrite   uint32 = 2
	ActionFileExec    uint32 = 3
	ActionFileDelete  uint32 = 4
	ActionFileCreate  uint32 = 5
	ActionNetConnect  uint32 = 6
	ActionNetBind     uint32 = 7
	ActionNetAccept   uint32 = 8
	ActionProcessExec uint32 = 9
)

// Mode values. These MUST match MODE_* in axbpf.h.
const (
	ModeDisabled   uint32 = 0
	ModePermissive uint32 = 1
	ModeEnforcing  uint32 = 2
)

// actionToUint converts a string action to its numeric constant.
func actionToUint(action string) uint32 {
	switch action {
	case "file.read":
		return ActionFileRead
	case "file.write":
		return ActionFileWrite
	case "file.execute":
		return ActionFileExec
	case "file.delete":
		return ActionFileDelete
	case "file.create":
		return ActionFileCreate
	case "net.connect":
		return ActionNetConnect
	case "net.bind":
		return ActionNetBind
	case "net.accept":
		return ActionNetAccept
	case "process.exec":
		return ActionProcessExec
	default:
		return 0
	}
}

// actionToString converts a numeric action back to string.
func actionToString(a uint32) string {
	switch a {
	case ActionFileRead:
		return "file.read"
	case ActionFileWrite:
		return "file.write"
	case ActionFileExec:
		return "file.execute"
	case ActionFileDelete:
		return "file.delete"
	case ActionFileCreate:
		return "file.create"
	case ActionNetConnect:
		return "net.connect"
	case ActionNetBind:
		return "net.bind"
	case ActionNetAccept:
		return "net.accept"
	case ActionProcessExec:
		return "process.exec"
	default:
		return "unknown"
	}
}

// Manager wraps the allow and deny eBPF maps plus the mode array map.
type Manager struct {
	allowMap *ebpf.Map
	denyMap  *ebpf.Map
	modeMap  *ebpf.Map
	auditMap *ebpf.Map
}

// NewFromCollection takes the maps out of a loaded collection.
//
// This is the only correct way to obtain them: the collection owns
// the maps, and closing the collection invalidates the handles, so
// the collection must outlive the manager.
func NewFromCollection(coll *ebpf.Collection) (*Manager, error) {
	if coll == nil {
		return nil, fmt.Errorf("collection nil")
	}

	maps := coll.Maps
	mgr := &Manager{
		allowMap: maps[AllowMapName],
		denyMap:  maps[DenyMapName],
		modeMap:  maps[ModeMapName],
		auditMap: maps[AuditMapName],
	}

	var missing []string
	if mgr.allowMap == nil {
		missing = append(missing, AllowMapName)
	}
	if mgr.denyMap == nil {
		missing = append(missing, DenyMapName)
	}
	if mgr.modeMap == nil {
		missing = append(missing, ModeMapName)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("collection icinde map yok: %s "+
			"(axbpf.o guncel mi?)", strings.Join(missing, ", "))
	}

	return mgr, nil
}

// NewManager opens already-pinned maps. Used when a collection was
// pinned by a previous run and should be re-attached rather than
// rebuilt. pinDir may be empty to skip pinning.
func NewManager(allowMapPath, denyMapPath, modeMapPath, pinDir string) (*Manager, error) {
	allow, err := ebpf.LoadPinnedMap(allowMapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("allow map acilamadi (%s): %w", allowMapPath, err)
	}
	deny, err := ebpf.LoadPinnedMap(denyMapPath, nil)
	if err != nil {
		allow.Close()
		return nil, fmt.Errorf("deny map acilamadi (%s): %w", denyMapPath, err)
	}

	mgr := &Manager{allowMap: allow, denyMap: deny}

	if modeMapPath != "" {
		mm, err := ebpf.LoadPinnedMap(modeMapPath, nil)
		if err != nil {
			mgr.Close()
			return nil, fmt.Errorf("mode map acilamadi (%s): %w", modeMapPath, err)
		}
		mgr.modeMap = mm
	}

	// Re-pin so a restarted daemon finds the same maps.
	if pinDir != "" {
		for name, m := range map[string]*ebpf.Map{
			AllowMapName: mgr.allowMap,
			DenyMapName:  mgr.denyMap,
			ModeMapName:  mgr.modeMap,
		} {
			if m == nil {
				continue
			}
			path := filepath.Join(pinDir, name)
			if err := m.Pin(path); err != nil {
				// Already pinned is fine.
				if !strings.Contains(err.Error(), "exists") {
					mgr.Close()
					return nil, fmt.Errorf("map pinlenemedi (%s): %w", path, err)
				}
			}
		}
	}

	return mgr, nil
}

// NewManagerWithMaps injects pre-opened maps (used in tests).
func NewManagerWithMaps(allow, deny, modeMap *ebpf.Map) *Manager {
	return &Manager{allowMap: allow, denyMap: deny, modeMap: modeMap}
}

// AuditMap returns the perf event array used for audit records.
func (m *Manager) AuditMap() *ebpf.Map { return m.Map(AuditMapName) }

// Map returns a named map from the collection, or nil if absent.
func (m *Manager) Map(name string) *ebpf.Map {
	switch name {
	case AllowMapName:
		return m.allowMap
	case DenyMapName:
		return m.denyMap
	case ModeMapName:
		return m.modeMap
	case AuditMapName:
		return m.auditMap
	}
	return nil
}

// SetMode writes the enforcement mode into mode_map so the kernel-side
// hooks can read it without a userspace round trip.
func (m *Manager) SetMode(mode uint32) error {
	if m.modeMap == nil {
		return fmt.Errorf("mode map yok")
	}
	var zero uint32
	if err := m.modeMap.Put(zero, mode); err != nil {
		return fmt.Errorf("mode yazilamadi: %w", err)
	}
	return nil
}

// GetMode reads the current mode back out of mode_map.
func (m *Manager) GetMode() (uint32, error) {
	if m.modeMap == nil {
		return 0, fmt.Errorf("mode map yok")
	}
	var zero uint32
	var mode uint32
	if err := m.modeMap.Lookup(zero, &mode); err != nil {
		return 0, err
	}
	return mode, nil
}

// Close releases the map handles.
func (m *Manager) Close() error {
	var errs []error
	for _, mgr := range []*ebpf.Map{m.allowMap, m.denyMap, m.modeMap} {
		if mgr == nil {
			continue
		}
		if err := mgr.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// WriteRule inserts a single rule into the map matching its effect.
// effect must be EffectAllow or EffectDeny as defined above.
func (m *Manager) WriteRule(comm, path, action string, ruleID uint32, effect uint32) error {
	if effect != EffectAllow && effect != EffectDeny {
		return fmt.Errorf("gecersiz effect: %d", effect)
	}

	key := buildKey(comm, path, action)
	if key.Action == 0 {
		return fmt.Errorf("bilinmeyen aksiyon: %s", action)
	}
	val := MapValue{RuleID: ruleID, Effect: effect}

	target := m.allowMap
	if effect == EffectDeny {
		target = m.denyMap
	}
	if target == nil {
		return fmt.Errorf("hedef map nil (effect=%d)", effect)
	}

	if err := target.Put(key, val); err != nil {
		return fmt.Errorf("kural yazilamadi (%s %s %s): %w", comm, action, path, err)
	}
	return nil
}

// Clear removes all entries from both rule maps.
func (m *Manager) Clear() error {
	for _, mgr := range []*ebpf.Map{m.allowMap, m.denyMap} {
		if mgr == nil {
			continue
		}
		var key MapKey
		var val MapValue
		iter := mgr.Iterate()
		for iter.Next(&key, &val) {
			if err := mgr.Delete(key); err != nil {
				return err
			}
		}
	}
	return nil
}

// Count returns the number of entries in both rule maps.
func (m *Manager) Count() (allowCount, denyCount int) {
	if m.allowMap != nil {
		allowCount = countEntries(m.allowMap)
	}
	if m.denyMap != nil {
		denyCount = countEntries(m.denyMap)
	}
	return
}

func countEntries(m *ebpf.Map) int {
	count := 0
	var key MapKey
	var val MapValue
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count
}

func buildKey(comm, path, action string) MapKey {
	var k MapKey
	copy(k.Comm[:], comm)
	copy(k.Path[:], path)
	k.Action = actionToUint(action)
	return k
}

// KeyToString renders a MapKey for display.
func KeyToString(k MapKey) string {
	comm := strings.TrimRight(string(k.Comm[:]), "\x00")
	path := strings.TrimRight(string(k.Path[:]), "\x00")
	return fmt.Sprintf("comm=%s path=%s action=%s", comm, path, actionToString(k.Action))
}

// SizeOfMapKey returns the compiled size of MapKey.
func SizeOfMapKey() int { return int(unsafe.Sizeof(MapKey{})) }

// SizeOfMapValue returns the compiled size of MapValue.
func SizeOfMapValue() int { return int(unsafe.Sizeof(MapValue{})) }

// RuleIDToUint converts a string rule ID like "rule_001" to uint32.
func RuleIDToUint(id string) uint32 {
	var n uint32
	if _, err := fmt.Sscanf(id, "rule_%d", &n); err != nil {
		return 0
	}
	return n
}

// UintToRuleID converts a uint32 back to a rule ID string.
func UintToRuleID(n uint32) string { return fmt.Sprintf("rule_%03d", n) }

// EncodeKey serializes a MapKey to bytes (for tests / debugging).
func EncodeKey(k MapKey) []byte {
	buf := make([]byte, SizeOfMapKey())
	copy(buf[0:16], k.Comm[:])
	copy(buf[16:272], k.Path[:])
	binary.LittleEndian.PutUint32(buf[272:276], k.Action)
	return buf
}
