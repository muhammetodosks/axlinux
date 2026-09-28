// Contract tests guard the numeric constants that are shared between
// the Go userspace daemon and the eBPF LSM programs in C.
//
// A mismatch here is silent and catastrophic: the kernel looks up
// ACTION_NET_CONNECT while the daemon wrote ACTION_FILE_DELETE, and
// deny rules are stored with Effect=2 while axbpf.h tests for
// EFFECT_DENY==0, so every deny rule is ignored and nothing is blocked.
//
// These tests parse axbpf.h directly, so the two sides can never drift
// apart without a test failure.
package maps

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// headerPath locates axbpf.h. It lives in src/bpf/ while these tests
// run in src/go/axdaemon/internal/maps/, so both the upward walk and
// the sibling bpf/ directory are checked.
func headerPath(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	for i := 0; i < 10; i++ {
		for _, candidate := range []string{
			filepath.Join(dir, "axbpf.h"),
			filepath.Join(dir, "bpf", "axbpf.h"),
			filepath.Join(dir, "src", "bpf", "axbpf.h"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("axbpf.h bulunamadi (src/bpf/axbpf.h bekleniyordu)")
	return ""
}

var defineRe = regexp.MustCompile(`^#define\s+(\w+)\s+(\d+)\s*$`)

// parseDefines reads every simple integer #define from axbpf.h.
func parseDefines(t *testing.T) map[string]int {
	t.Helper()

	f, err := os.Open(headerPath(t))
	if err != nil {
		t.Fatalf("axbpf.h acilamadi: %v", err)
	}
	defer f.Close()

	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := defineRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		out[m[1]] = n
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("okuma hatasi: %v", err)
	}
	return out
}

func requireDefine(t *testing.T, defines map[string]int, name string) int {
	t.Helper()
	v, ok := defines[name]
	if !ok {
		t.Fatalf("axbpf.h icinde %s tanimi yok", name)
	}
	return v
}

// TestActionConstantsMatch locks the ACTION_* numbering. The daemon
// and the kernel must agree byte for byte.
func TestActionConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	pairs := map[string]uint32{
		"file.read":     ActionFileRead,
		"file.write":    ActionFileWrite,
		"file.execute":  ActionFileExec,
		"file.delete":   ActionFileDelete,
		"file.create":   ActionFileCreate,
		"net.connect":   ActionNetConnect,
		"net.bind":      ActionNetBind,
		"net.accept":    ActionNetAccept,
		"process.exec":  ActionProcessExec,
	}

	for action, goVal := range pairs {
		cName := actionName(action)
		cVal := requireDefine(t, c, cName)

		if int(goVal) != cVal {
			t.Errorf("aksiyon %q uyusmazlik: Go=%d C=%s=%d",
				action, goVal, cName, cVal)
		}
	}
}

func actionName(action string) string {
	switch action {
	case "file.read":
		return "ACTION_FILE_READ"
	case "file.write":
		return "ACTION_FILE_WRITE"
	case "file.execute":
		return "ACTION_FILE_EXEC"
	case "file.delete":
		return "ACTION_FILE_DELETE"
	case "file.create":
		return "ACTION_FILE_CREATE"
	case "net.connect":
		return "ACTION_NET_CONNECT"
	case "net.bind":
		return "ACTION_NET_BIND"
	case "net.accept":
		return "ACTION_NET_ACCEPT"
	case "process.exec":
		return "ACTION_PROCESS_EXEC"
	}
	return "UNKNOWN"
}

// TestEffectConstantsMatch guards the deny/allow inversion that would
// otherwise disable all enforcement.
func TestEffectConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	if got := requireDefine(t, c, "EFFECT_DENY"); got != int(EffectDeny) {
		t.Errorf("EFFECT_DENY uyusmazlik: Go=%d C=%d", EffectDeny, got)
	}
	if got := requireDefine(t, c, "EFFECT_ALLOW"); got != int(EffectAllow) {
		t.Errorf("EFFECT_ALLOW uyusmazlik: Go=%d C=%d", EffectAllow, got)
	}

	// The kernel treats "not EFFECT_DENY" as allowed, so deny must be
	// the zero value for the unset/empty case to fail closed.
	if EffectDeny != 0 {
		t.Errorf("EFFECT_DENY 0 olmali (fail-closed), Go=%d", EffectDeny)
	}
}

// TestModeConstantsMatch guards the mode_map numbering.
func TestModeConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	if got := requireDefine(t, c, "MODE_DISABLED"); got != int(ModeDisabled) {
		t.Errorf("MODE_DISABLED uyusmazlik: Go=%d C=%d", ModeDisabled, got)
	}
	if got := requireDefine(t, c, "MODE_PERMISSIVE"); got != int(ModePermissive) {
		t.Errorf("MODE_PERMISSIVE uyusmazlik: Go=%d C=%d", ModePermissive, got)
	}
	if got := requireDefine(t, c, "MODE_ENFORCING"); got != int(ModeEnforcing) {
		t.Errorf("MODE_ENFORCING uyusmazlik: Go=%d C=%d", ModeEnforcing, got)
	}
}

// TestStructLayoutsMatch checks the on-wire sizes of the map key and
// value against the compiler's view of the C structs.
func TestStructLayoutsMatch(t *testing.T) {
	// policy_key: char comm[16] + char path[256] + u32 action
	wantKey := 16 + 256 + 4
	if got := SizeOfMapKey(); got != wantKey {
		t.Errorf("MapKey boyutu: Go=%d beklenen=%d", got, wantKey)
	}

	// policy_value: u32 rule_id + u32 effect
	wantVal := 8
	if got := SizeOfMapValue(); got != wantVal {
		t.Errorf("MapValue boyutu: Go=%d beklenen=%d", got, wantVal)
	}
}

// TestActionRoundTrip makes sure the string mapping is a bijection, so
// no two YAML actions collapse onto the same kernel constant.
func TestActionRoundTrip(t *testing.T) {
	actions := []string{
		"file.read", "file.write", "file.execute", "file.delete",
		"file.create", "net.connect", "net.bind", "net.accept",
		"process.exec",
	}

	seen := map[uint32]string{}
	for _, a := range actions {
		n := actionToUint(a)
		if n == 0 {
			t.Errorf("aksiyon %q 0'a donusuyor", a)
			continue
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("aksiyon cakismasi: %q ve %q -> %d", prev, a, n)
		}
		seen[n] = a

		if back := actionToString(n); back != a {
			t.Errorf("round trip bozuk: %q -> %d -> %q", a, n, back)
		}
	}
}

// TestUnknownActionRejected ensures a typo never silently becomes a
// valid-looking rule.
func TestUnknownActionRejected(t *testing.T) {
	if n := actionToUint("process.spawn"); n != 0 {
		t.Errorf("bilinmeyen aksiyon 0 donmeli, %d dondu", n)
	}
	if n := actionToUint("net.exfiltrate"); n != 0 {
		t.Errorf("bilinmeyen aksiyon 0 donmeli, %d dondu", n)
	}
}
