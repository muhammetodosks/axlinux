package audit

import (
	"bufio"
	"encoding/binary"
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
	`^\s*(?:__u(\d+)|char)\s+(\w+)(?:\s*\[\s*(\w+)\s*\])?\s*;`)
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
		count := 0
		if m[3] != "" {
			if n, err := strconv.Atoi(m[3]); err == nil {
				count = n
			} else if n, ok := defs[m[3]]; ok {
				count = n
			} else {
				t.Fatalf("dizi boyutu cozulemedi: %s (bilinmeyen sabit %q)",
					structName, m[3])
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
	copy(buf[off:off+256], "/etc/shadow")
	off += 256
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
	if got := strings.TrimRight(string(e.Path[:]), "\x00"); got != "/etc/shadow" {
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
