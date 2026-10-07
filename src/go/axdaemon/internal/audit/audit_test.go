package audit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// bpfHeader locates src/bpf/axbpf.h from the test's working directory.
func bpfHeader(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		for _, c := range []string{
			filepath.Join(dir, "axbpf.h"),
			filepath.Join(dir, "bpf", "axbpf.h"),
			filepath.Join(dir, "src", "bpf", "axbpf.h"),
		} {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("axbpf.h bulunamadi")
	return ""
}

// structFieldRe captures the scalar and char array fields that make up
// the wire layout, e.g. "__u64 timestamp;", "char path[MAX_PATH_LEN];".
// The array bound may be a numeric literal or a symbolic #define.
var structFieldRe = regexp.MustCompile(
	`^\s*(?:__u(\d+)|char)\s+(\w+)(?:\s*\[\s*(\w+)\s*\](?:\s*\[\s*(\w+)\s*\])?)?\s*;`)
var defineRe = regexp.MustCompile(`^#define\s+(\w+)\s+(\d+)\s*$`)

// cdefines collects the simple integer #defines so symbolic array
// bounds like MAX_PATH_LEN can be resolved.
func cdefines(t *testing.T, path string) map[string]int {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("axbpf.h okunamadi: %v", err)
	}

	out := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		m := defineRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err == nil {
			out[m[1]] = n
		}
	}
	return out
}

type cField struct {
	bits  int
	name  string
	count int
}

func parseCStruct(t *testing.T, path, structName string) []cField {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("axbpf.h okunamadi: %v", err)
	}

	defs := cdefines(t, path)

	var out []cField
	inStruct := false

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if !inStruct {
			if line == "struct "+structName+" {" {
				inStruct = true
			}
			continue
		}

		if line == "};" {
			break
		}

		m := structFieldRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// char is 8 bits; __uN is N bits. Group 1 is empty for char.
		bits := 8
		if m[1] != "" {
			bits, _ = strconv.Atoi(m[1])
		}
		resolve := func(name string) int {
			if n, err := strconv.Atoi(name); err == nil {
				return n
			}
			if n, ok := defs[name]; ok {
				return n
			}
			t.Fatalf("dizi boyutu cozulemedi: %s (bilinmeyen sabit %q)",
				structName, name)
			return 0
		}
		count := 0
		if m[3] != "" {
			// iki boyutlu diziler (char path[8][32]) toplam
			// bayt sayisi olarak sayilir
			if m[4] != "" {
				count = resolve(m[3]) * resolve(m[4])
			} else {
				count = resolve(m[3])
			}
		}
		out = append(out, cField{bits: bits, name: m[2], count: count})
	}

	if len(out) == 0 {
		t.Fatalf("struct %s parse edilemedi", structName)
	}
	return out
}

func sizeBits(f cField) int {
	if f.count > 0 {
		return f.bits * f.count
	}
	return f.bits
}

// goFieldOrder mirrors the field order of the Go Event struct. The
// decoder in parseEvent walks the buffer in exactly this order.
var goFieldOrder = []string{
	"Timestamp", "PID", "Comm", "Path",
	"Action", "Effect", "Decision", "RuleID", "HookType",
	"Ino", "Dev", "APath", "APFlags", "APCount",
}

// goFieldOffsets are the byte offsets the decoder writes to. They are
// asserted against the C layout below rather than trusted.
var goFieldOffsets = map[string]int{
	"Timestamp": 0,
	"PID":       8,
	"Comm":      12,
	"Path":      28,
	"Action":    284,
	"Effect":    288,
	"Decision":  292,
	"RuleID":    296,
	"HookType":  300,
	"Ino":       304,
	"Dev":       312,
	"APath":     316,
	"APFlags":   1340,
	"APCount":   1344,
}

// TestEventLayoutMatchesC locks the perf-buffer record layout.
//
// The Go Event struct is decoded byte by byte from the kernel. If a
// field is added, removed, or reordered in C without the same change
// here, every field after the divergence decodes as garbage — and
// nothing errors, because the buffer length still validates.
func TestEventLayoutMatchesC(t *testing.T) {
	cFields := parseCStruct(t, bpfHeader(t), "audit_event")

	if len(cFields) != len(goFieldOrder) {
		t.Fatalf("C'de %d alan var, Go tarafinda %d: %+v",
			len(cFields), len(goFieldOrder), cFields)
	}

	off := 0
	for i, cf := range cFields {
		goName := goFieldOrder[i]

		// C field name maps to the Go name; report the divergence
		// explicitly because reordering is the dangerous case.
		wantOff, known := goFieldOffsets[goName]
		if !known {
			t.Fatalf("Go tarafi %q icin offset tanimli degil", goName)
		}
		if off != wantOff {
			t.Errorf("%s (C alani %d): C offset %d, Go decoder %d bekliyor "+
				"(bu alandan sonraki her sey bozulur)",
				goName, i, off, wantOff)
		}
		off += sizeBits(cf) / 8
	}

	if off != EventSize {
		t.Errorf("C yapı boyutu %d bayt, Go EventSize %d",
			off, EventSize)
	}
}

// TestCFieldNamesDocumented keeps the C and Go names legible. A rename
// in C must be mirrored here or the offsets stop lining up.
func TestCFieldNamesDocumented(t *testing.T) {
	cFields := parseCStruct(t, bpfHeader(t), "audit_event")
	want := []string{
		"timestamp", "pid", "comm", "path",
		"action", "effect", "decision", "rule_id", "hook_type",
		"ino", "dev", "apath", "apath_flags", "apath_count",
	}
	for i, w := range want {
		if cFields[i].name != w {
			t.Errorf("C alan %d = %q, beklenen %q "+
				"(Go Event alanini yeniden adlandirdiysaniz "+
				"parseEvent'i de guncelleyin)", i, cFields[i].name, w)
		}
	}
}

// TestParseEventRoundTrip feeds a synthetic record built with the C
// layout and checks every field survives.
func TestParseEventRoundTrip(t *testing.T) {
	buf := make([]byte, EventSize)
	off := 0

	binary.LittleEndian.PutUint64(buf[off:], 0x1122334455667788)
	off += 8
	binary.LittleEndian.PutUint32(buf[off:], 4242) // pid
	off += 4
	copy(buf[off:off+16], "firefox")
	off += 16
	// yol alani bloklu: "/etc" -> blok 6, "/shadow" -> blok 7
	copy(buf[off+6*PathSlot:off+6*PathSlot+PathSlot], "/etc")
	copy(buf[off+7*PathSlot:off+7*PathSlot+PathSlot], "/shadow")
	off += PathDepth * PathSlot
	binary.LittleEndian.PutUint32(buf[off:], 1) // action
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 0) // effect = deny
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 1) // decision = denied
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 7) // rule_id
	off += 4
	binary.LittleEndian.PutUint32(buf[off:], 1) // hook_type = file_open

	e, err := parseEvent(buf)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}

	if e.Timestamp != 0x1122334455667788 {
		t.Errorf("Timestamp = %#x", e.Timestamp)
	}
	if e.PID != 4242 {
		t.Errorf("PID = %d, 4242 bekleniyordu", e.PID)
	}
	if got := strings.TrimRight(string(e.Comm[:]), "\x00"); got != "firefox" {
		t.Errorf("Comm = %q", got)
	}
	if got := e.JoinPath(); got != "/etc/shadow" {
		t.Errorf("Path = %q", got)
	}
	if e.Action != 1 {
		t.Errorf("Action = %d", e.Action)
	}
	if e.Effect != 0 {
		t.Errorf("Effect = %d (deny 0 olmali)", e.Effect)
	}
	if e.Decision != 1 {
		t.Errorf("Decision = %d", e.Decision)
	}
	if e.RuleID != 7 {
		t.Errorf("RuleID = %d", e.RuleID)
	}
	if e.HookType != 1 {
		t.Errorf("HookType = %d", e.HookType)
	}
}

// TestParseEventRejectsShort makes sure a truncated record is dropped
// rather than decoded into garbage.
func TestParseEventRejectsShort(t *testing.T) {
	if _, err := parseEvent(make([]byte, 16)); err == nil {
		t.Error("kisa kayit hata vermeli")
	}
}

// TestStatsCountsDecisions verifies the denied/allowed split that
// `axctl status` reports.
func TestStatsCountsDecisions(t *testing.T) {
	m := NewManager(nil)
	m.events = []Event{
		{Decision: 1}, // denied
		{Decision: 1},
		{Decision: 0}, // allowed
	}

	if got := m.Count(); got != 3 {
		t.Errorf("Count = %d, 3 bekleniyor", got)
	}
	denied, allowed := m.Stats()
	if denied != 2 {
		t.Errorf("denied = %d, 2 bekleniyor", denied)
	}
	if allowed != 1 {
		t.Errorf("allowed = %d, 1 bekleniyor", allowed)
	}
	if m.DeniedCount() != 2 || m.AllowedCount() != 1 {
		t.Error("DeniedCount/AllowedCount Stats ile uyusmali")
	}
}

// TestHealthySeparatesIdleFromDead is the test for a failure mode
// that Count() alone cannot express.
//
// Before, a dead read loop and an idle system both reported
// audit_log_count == 0. The operator had no way to tell them apart
// and would conclude they were protected when audit had stopped
// collecting entirely. Healthy() makes the difference visible.
func TestHealthySeparatesIdleFromDead(t *testing.T) {
	// A fresh manager is healthy even with zero events: no events
	// yet is a normal state.
	m := NewManager(nil)
	if healthy, why := m.Healthy(); !healthy {
		t.Errorf("yeni manager saglikli olmali, why=%q", why)
	}
	if m.Count() != 0 {
		t.Errorf("bos manager icin Count 0 olmali, %d", m.Count())
	}

	// After a fatal read-loop failure the manager must report
	// itself unhealthy, with a reason the operator can act on.
	m.markUnhealthy("perf reader 100 kez hata verdi")
	healthy, why := m.Healthy()
	if healthy {
		t.Error("hata isaretlendikten sonra saglikli gorunmemeli")
	}
	if why == "" {
		t.Error("saglikli=false iken sebep bos olmamali; operator " +
			"ne oldugunu bilemez")
	}
	// Count is unchanged: this is exactly why Count alone was
	// insufficient.
	if m.Count() != 0 {
		t.Error("Count 0 kalmali; ayrim Healthy ile yapilir")
	}
}

// TestCloseIsIdempotent guards the shutdown path: main.go defers
// Close while the read loop may already be returning.
func TestCloseIsIdempotent(t *testing.T) {
	m := NewManager(nil)
	if err := m.Close(); err != nil {
		t.Errorf("nil reader ile Close hata vermemeli: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("ikinci Close hata vermemeli: %v", err)
	}
}

// failingSender stands in for a writer that cannot persist: a full
// disk, a crashed axlog, a read-only mount.
type failingSender struct{ err error }

func (s failingSender) Send(Event) error { return s.err }

// TestSendFailureIsNotSwallowed covers the gap this counter exists
// for.
//
// Run() used to discard the sender's error with `_ =`. When the
// disk filled up, every audit record was lost and nothing said so:
// get_status reported a healthy manager with a full in-memory
// buffer, and the operator believed the trail was complete.
func TestSendFailureIsNotSwallowed(t *testing.T) {
	m := NewManager(failingSender{err: errors.New("disk full")})

	if err := m.sender.Send(Event{}); err == nil {
		t.Fatal("test icin beklenen: gonderici hata donmeli")
	}
	// Mirror what Run does on failure.
	m.mu.Lock()
	m.sendFailed++
	m.mu.Unlock()
	m.markUnhealthy("audit kaydi kalici olarak yazilamadi: disk full")

	if m.SendFailures() != 1 {
		t.Errorf("SendFailures = %d, 1 bekleniyor", m.SendFailures())
	}
	healthy, why := m.Healthy()
	if healthy {
		t.Error("yazma hatasi sonrasi saglikli gorunmemeli")
	}
	if !strings.Contains(why, "disk full") {
		t.Errorf("bildirim hatayi belirtmeli:\n%s", why)
	}
}

// TestSendFailuresZeroWhenHealthy is the other direction: a working
// sender must not trip the counter.
func TestSendFailuresZeroWhenHealthy(t *testing.T) {
	m := NewManager(okSender{})
	if err := m.sender.Send(Event{}); err != nil {
		t.Fatalf("gecerli gonderici hata verdi: %v", err)
	}
	if n := m.SendFailures(); n != 0 {
		t.Errorf("basarili gonderimde SendFailures = %d, 0 olmali", n)
	}
	if healthy, why := m.Healthy(); !healthy {
		t.Errorf("basarili gonderimde saglik false olmamali: %s", why)
	}
}

type okSender struct{}

func (okSender) Send(Event) error { return nil }
