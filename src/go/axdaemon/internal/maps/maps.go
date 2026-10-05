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
	// LearnMapName is the single-cell flag the LSM hooks read to
	// decide whether ALLOWED operations become audit events too.
	// Without it the learning mode can never observe anything:
	// normal activity is by definition allowed, and allowed
	// operations produced no events.
	LearnMapName = "learn_map"
	AuditMapName = "audit_buffer"
	// MountArtifactMapName holds the names of MOUNT ROOTS THAT ARE
	// NOT VISIBLE IN ANY PATH.
	//
	// On Fedora the root filesystem is a btrfs SUBVOLUME:
	//
	//	/proc/self/mountinfo: root=/root mountpoint=/
	//	/etc/ax-t -> ax-t -> etc -> root -> /
	//
	// "root" is not part of any visible path; writing it produces
	// "/root/etc/ax-t" while the policy says "/etc/ax-t" and the
	// rule silently never matches.
	//
	// /var and /home are separate subvolume mounts:
	//
	//	root=/var mountpoint=/var     -> "var" IS visible, keep it
	//	root=/   mountpoint=/tmp     -> nothing to hide
	//
	// So the discriminator lives in userspace: a mount root is an
	// artifact iff root != "/" AND root != mountpoint.
	MountArtifactMapName = "mount_artifact_map"
	// MountPointMapName holds MOUNTPOINT prefixes that a dentry walk
	// cannot see.
	//
	// /tmp is a tmpfs mount on Fedora:
	//
	//	/proc/self/mountinfo: root=/ mountpoint=/tmp
	//	/tmp/ax-pintest -> ax-pintest -> "/"
	//
	// "tmp" is a mount attachment, not a directory entry, so the walk
	// produces "/ax-pintest" and the "/tmp" prefix is lost. Rules for
	// /tmp then never match while "reload" reports success.
	//
	// Key: (st_dev, st_ino) of the mount root. Keyed on dev+ino
	// because every tmpfs root shares inode 1.
	MountPointMapName = "mount_point_map"
)

// Yol alani sabit bloklara bolunur. Boylece eBPF tarafinda her
// bilesen kendi bloguna yazilir ve blok ofseti derleme zamaninda
// sabittir; calisma aninda hesaplanan hedef+boyut ikilisi
// kalmaz. Birlestirme burada, Go tarafinda yapilir.
// Toplam boyut degismez: 16 + 8*32 + 4 = 276.
const (
	PathDepth = 8
	PathSlot  = 32
)

// MapKey is the lookup key used in both allow and deny maps.
// Must match struct policy_key in axbpf.h.
type MapKey struct {
	Comm   [16]byte
	Path   [PathDepth][PathSlot]byte
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
	allowMap    *ebpf.Map
	denyMap     *ebpf.Map
	modeMap     *ebpf.Map
	learnMap    *ebpf.Map
	auditMap    *ebpf.Map
	artifactM   *ebpf.Map
	mountPointM *ebpf.Map
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
		allowMap:    maps[AllowMapName],
		denyMap:     maps[DenyMapName],
		modeMap:     maps[ModeMapName],
		learnMap:    maps[LearnMapName],
		auditMap:    maps[AuditMapName],
		artifactM:   maps[MountArtifactMapName],
		mountPointM: maps[MountPointMapName],
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
	if mgr.mountPointM == nil {
		missing = append(missing, MountPointMapName)
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
			LearnMapName: mgr.learnMap,
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
func NewManagerWithMaps(allow, deny, modeMap, learnMap *ebpf.Map) *Manager {
	return &Manager{allowMap: allow, denyMap: deny, modeMap: modeMap,
		learnMap: learnMap}
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
// SetLearning raises or lowers the observation flag the LSM hooks read.
//
// This is what makes the learning mode able to observe anything at
// all. The hooks only emitted events for operations matched by a
// DENY rule; normal activity is by definition allowed, so it
// produced nothing. "axctl learn start" reported success and
// promised "3 gun kayit tutulacak" while collecting zero
// observations forever.
//
// The flag is only set while learning is on: auditing every
// allowed read all the time would be needless system load.
func (m *Manager) SetLearning(on bool) error {
	if m.learnMap == nil {
		// Ogrenme bayragi yoksa gozlem toplanamaz. Sessizce
		// gecmek, kullaniciya "ogrenme basladi" yazip hicbir
		// sey toplanmamasina yol acar; acik hata verilir.
		return fmt.Errorf("ogrenme map'i yok (learn_map); " +
			"ogrenme modu gozlem toplayamaz")
	}
	var zero uint32
	v := uint32(0)
	if on {
		v = 1
	}
	if err := m.learnMap.Put(zero, v); err != nil {
		return fmt.Errorf("ogrenme bayragi yazilamadi: %w", err)
	}
	return nil
}

// GetLearning reads the observation flag back.
func (m *Manager) GetLearning() (bool, error) {
	if m.learnMap == nil {
		return false, fmt.Errorf("ogrenme map'i yok (learn_map)")
	}
	var zero, v uint32
	if err := m.learnMap.Lookup(zero, &v); err != nil {
		return false, err
	}
	return v != 0, nil
}

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

// ProtectedProcesses are the processes AXlinux never applies a rule to.
//
// The kernel enforces this in ax_protected (src/bpf/axbpf.h), but the
// check is duplicated here on purpose. If the eBPF object fails to
// build or an older axbpf.o is installed, the kernel side is absent
// and a rule like "bash cannot exec" would lock the user out of the
// machine with no way back short of a reboot. Rejecting the rule in
// the daemon costs nothing and makes the lockout impossible even
// then.
//
// The list is the RECOVERY PATH, and nothing else:
//
//   - init/session chain (systemd, dbus, polkit, NetworkManager): the
//     machine must stay up and the session must stay functional.
//   - login chain (sshd, login, getty, sudo, su, doas): these are how
//     a user gets a shell in the first place.
//   - shells (bash, sh, dash, zsh, fish): a blocked shell ends the
//     session and removes every in-session way to undo the policy.
//
// Runtimes and development tools are deliberately NOT here. Almost
// every real application runs under an interpreter, so protecting
// python3/node/perl/ruby would make the most common MAC rules
// ("this app must not read /etc/shadow", "this app must not reach
// the network") impossible to write, and the product useless. It
// would also buy nothing: denying python3 does not strand the user,
// because a protected shell is still available to change the mode.
//
// Keep this list in sync with ax_protected; tests/test_protection.py
// checks both sides agree.
var ProtectedProcesses = map[string]bool{
	// calisma ortami
	"systemd": true, "systemd-logind": true, "systemd-userdbd": true,
	"systemd-udevd": true, "systemd-journald": true, "systemd-oomd": true,
	"init": true, "kthreadd": true,
	// oturum acma / yetki
	"sshd": true, "sshd-session": true, "login": true, "agetty": true,
	"getty": true, "sudo": true, "su": true, "doas": true,
	"dbus-daemon": true, "dbus-broker": true, "polkitd": true,
	"rtkit-daemon": true, "NetworkManager": true, "wpa_supplicant": true,
	"gdm3": true, "gdm-session-worke": true,
	// kabuklar
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
}

// IsProtected reports whether a process name is on the protection list.
func IsProtected(comm string) bool { return ProtectedProcesses[comm] }

// UnimplementedActions are actions no AXlinux hook can produce.
//
// Every action here is listed in actionToUint, so a rule using one
// builds a perfectly valid key and is written to the map. The problem
// is on the kernel side: no attached hook ever generates this action
// value, so the entry can never match anything. The daemon reports
// "1 kural yuklendi" and the file is still deleted.
//
// This is the worst class of silent failure, because the user is
// actively relying on a rule they were told was in force. Rejecting
// it at load time costs the user one edit; accepting it costs them a
// false sense of protection. The Python compiler rejects these too;
// this list is the second line of defence for policies sent straight
// over RPC.
var UnimplementedActions = map[string]string{
	"file.delete": "AXlinux'ta silme kanacasi yok " +
		"(lsm/inode_unlink_at bagli degil)",
	"file.create": "AXlinux'ta dosya olusturma kanacasi yok",
	"net.accept": "AXlinux'ta kabul edilen baglanti kanacasi yok " +
		"(lsm/socket_accept bagli degil)",
}

// ValidateRule checks whether a rule can actually be enforced, without
// touching the maps. It returns the same errors WriteRule would, so
// callers can reject a whole policy before clearing the old one: a
// partial load would otherwise leave the system with no rules at all
// while the caller believes the previous policy is still active.
func ValidateRule(comm, path, action string, port int) error {
	if IsProtected(comm) {
		return fmt.Errorf(
			"%q korumali bir sistem sureci; AXlinux bu sureclere "+
				"guvenlik geregi kural uygulamaz "+
				"(engellenirse sistem kilitlenir). Kurali hedef "+
				"uygulamaya yazin", comm)
	}

	// Onceki bir kanca bu aksiyonu uretmiyor. Yazilirsa kural
	// map'e girer, hicbir sey eslesmez ve kullanici yanlis
	// guvenlik varsayimiyla yasar.
	if why, bad := UnimplementedActions[action]; bad {
		return fmt.Errorf(
			"aksiyon %q AXlinux tarafindan uygulanmiyor: %s. "+
				"Kural yazilsaydi hicbir ise yaramazdi, bu "+
				"yuzden yuklenmedi", action, why)
	}

	key := buildKeyPort(comm, path, action, port)
	if key.Action == 0 {
		return fmt.Errorf("bilinmeyen aksiyon: %s", action)
	}
	// Anahtar bos olmamali. Buradaki istisna: yalnizca surec
	// (port'suz, yolsuz) kurallar yolu gerektirmez; onlar zaten
	// bilincli olarak bos yolla yazilir.
	if port == 0 && path == "" {
		return nil
	}
	if keyIsEmpty(&key) {
		return fmt.Errorf(
			"yol anahtari uretilemedi (%s %s port=%d): yolun bir "+
				"bileseni %d karakteri asiyor veya bilesen sayisi "+
				"%d'den fazla",
			action, path, port, PathSlot-1, PathDepth)
	}
	return nil
}

// WriteRule inserts a single rule into the map matching its effect.
// effect must be EffectAllow or EffectDeny as defined above.
func (m *Manager) WriteRule(comm, path, action string, port int, ruleID uint32, effect uint32) error {
	if err := ValidateRule(comm, path, action, port); err != nil {
		return err
	}
	if effect != EffectAllow && effect != EffectDeny {
		return fmt.Errorf("gecersiz effect: %d", effect)
	}

	key := buildKeyPort(comm, path, action, port)
	val := MapValue{RuleID: ruleID, Effect: effect}

	target := m.allowMap
	if effect == EffectDeny {
		target = m.denyMap
	}
	if target == nil {
		return fmt.Errorf("hedef map nil (effect=%d)", effect)
	}

	if err := target.Put(key, val); err != nil {
		return fmt.Errorf("kural yazilamadi (%s %s %s port=%d): %w", comm, action, path, port, err)
	}
	return nil
}

// keyIsEmpty, yol alani tamamen bos olan bir anahtari bildirir.
func keyIsEmpty(k *MapKey) bool {
	for i := range k.Path {
		for _, b := range k.Path[i] {
			if b != 0 {
				return false
			}
		}
	}
	return true
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
	return buildKeyPort(comm, path, action, 0)
}

// buildKeyPort, portu olan kurallar icin anahtari uretir. eBPF
// tarafi ag kurallarini "p:PORT" biciminde yazar (bkz.
// hooks_socket_connect.inc / hooks_socket_bind.inc), bu yuzden
// Go tarafi da AYNI bicimi uretmek zorundadir; aksi halde
// net.bind / net.connect kurallari hicbir zaman tutmaz.
func buildKeyPort(comm, path, action string, port int) MapKey {
	var k MapKey
	copy(k.Comm[:], comm)
	k.Action = actionToUint(action)
	if port > 0 {
		setKeyPath(&k, fmt.Sprintf("p:%d", port))
		return k
	}
	setKeyPath(&k, canonicalPath(path))
	return k
}

// canonicalPath resolves a policy path to the form the kernel reports.
//
// Modern Debian/Ubuntu use "merged /usr": /bin, /sbin, /lib and
// /lib64 are symlinks into /usr. The kernel always reports the
// RESOLVED path, so a policy written as /bin/ls produces the key
// ["/bin","/ls"] while the kernel looks up ["/usr/bin","/ls"].
//
// The rule then loads, the daemon reports "1 kural yuklendi", and it
// can never match. This is the exact silent failure this project
// exists to prevent: the operator reads the policy as active while
// the process is unrestricted.
//
// Resolution happens on the daemon's own filesystem, which is the same
// machine the kernel reports paths from, so the two agree.
//
// A path that does not exist is left untouched: the file may be
// created later, and refusing the rule would be worse than a rule
// that simply does not match yet.
func canonicalPath(p string) string {
	if p == "" || strings.HasPrefix(p, "p:") {
		return p
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	// EvalSymlinks on a directory prefix is handled by the OS; the
	// only thing that matters here is that the result is the same
	// string the kernel will build from the dentry chain.
	return resolved
}

// setKeyPath doldurur. "/" iceren yollar bilesenlere bolunur ve
// en sondan basa dogru bloklara yazilir; boylece eBPF tarafi
// d = 0 (dosya adi) ile en yuksek bloga yazdiginda sira tutar.
func setKeyPath(k *MapKey, path string) {
	// ag adresi gibi "/" icermeyen degerler 0. bloga duz yazilir
	if !strings.Contains(path, "/") {
		// Sigmiyorsa kirpma: sessiz kirpma kuralin yanlis
		// anahtara yazilmasi demektir.
		if len(path) > PathSlot-1 {
			k.Path = [PathDepth][PathSlot]byte{}
			return
		}
		copy(k.Path[0][:], path)
		return
	}

	parts := strings.Split(path, "/")
	idx := PathDepth - 1
	// representable=false ise yol bloga sigmiyordur. Kuralin
	// YANLIS bir yola uygulanmasina yol acmamak icin anahtar
	// tamamen bosaltilir; ValidateRule bunu acik hata olarak
	// bildirir. Kismi doldurulmus bir anahtar kullanilirsa
	// kural hicbir seyi engellemezken kullanici "yuklendi" sanir.
	representable := true
	for i := len(parts) - 1; i >= 1; i-- {
		if parts[i] == "" {
			continue
		}
		// Bloklar tükendiyse ya da bilesen bloga sigmiyorsa
		// yol temsil edilemez.
		if idx < 0 || len(parts[i]) > PathSlot-1 {
			representable = false
			break
		}
		k.Path[idx][0] = '/'
		copy(k.Path[idx][1:], parts[i])
		idx--
	}
	if !representable {
		k.Path = [PathDepth][PathSlot]byte{}
		return
	}
	if path == "/" {
		k.Path[0][0] = '/'
	}
}

// KeyToString renders a MapKey for display. Bloklar birlestirilir.
func KeyToString(k MapKey) string {
	comm := strings.TrimRight(string(k.Comm[:]), "\x00")
	var sb strings.Builder
	for _, blk := range k.Path {
		s := strings.TrimRight(string(blk[:]), "\x00")
		if s == "" {
			continue
		}
		sb.WriteString(s)
	}
	p := sb.String()
	if p == "" {
		p = "/"
	}
	return fmt.Sprintf("comm=%s path=%s action=%s", comm, p, actionToString(k.Action))
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
	for i, blk := range k.Path {
		copy(buf[16+i*PathSlot:16+(i+1)*PathSlot], blk[:])
	}
	binary.LittleEndian.PutUint32(buf[272:276], k.Action)
	return buf
}
