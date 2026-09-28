package lsm

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// incDir walks up to locate the src/bpf directory holding the .inc
// files and axbpf.c.
func bpfDir(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "bpf")
		if _, err := os.Stat(filepath.Join(candidate, "axbpf.c")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("src/bpf bulunamadi")
	return ""
}

var progRe = regexp.MustCompile(`int\s+BPF_PROG\(\s*(\w+)\s*,`)
var secRe = regexp.MustCompile(`SEC\(\s*"(lsm/[\w/]+)"\s*\)`)

// TestHookTableMatchesPrograms is the guard against silent no-ops.
//
// cilium/ebpf keys Programs by the C function name. If HookTable names
// a function the ELF does not contain, Attach() skips it and no hook
// is ever installed — with no error surfaced to the user.
func TestHookTableMatchesPrograms(t *testing.T) {
	dir := bpfDir(t)

	found := map[string]string{} // goName -> sec
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".inc") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s okunamadi: %v", name, err)
		}
		content := string(data)

		m := progRe.FindStringSubmatch(content)
		if m == nil {
			t.Fatalf("%s icinde BPF_PROG bulunamadi", name)
		}
		s := secRe.FindStringSubmatch(content)
		if s == nil {
			t.Fatalf("%s icinde SEC(\"lsm/...\") bulunamadi", name)
		}
		found[m[1]] = s[1]
	}

	if len(found) == 0 {
		t.Fatal("hicbir .inc dosyasinda program bulunamadi")
	}

	// Every Go table entry must exist in C.
	for _, h := range HookTable {
		sec, ok := found[h.GoName]
		if !ok {
			t.Errorf("HookTable'de %s var ama C'de yok "+
				"(kanca hic baglanmayacak)", h.GoName)
			continue
		}
		if sec != h.Sec {
			t.Errorf("%s: HookTable Sec=%s ama C'de %s",
				h.GoName, h.Sec, sec)
		}
	}

	// Every C program must be in the Go table, or it will never attach.
	for goName, sec := range found {
		foundInTable := false
		for _, h := range HookTable {
			if h.GoName == goName {
				foundInTable = true
				break
			}
		}
		if !foundInTable {
			t.Errorf("C'de %s (%s) var ama HookTable'da yok "+
				"(kanca baglanmayacak)", goName, sec)
		}
	}
}

// TestHookCountIsFive documents the expected attachment surface.
func TestHookCountIsFive(t *testing.T) {
	if len(HookTable) != 5 {
		t.Errorf("HookTable %d kanca iceriyor, 5 bekleniyor", len(HookTable))
	}
	names := HookNames()
	if len(names) != len(HookTable) {
		t.Errorf("HookNames %d isim donuyor, %d bekleniyor",
			len(names), len(HookTable))
	}
}

// TestHookNamesUnique guards against duplicate status keys.
func TestHookNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range HookTable {
		if seen[h.Hook] {
			t.Errorf("yinelenen kanca adi: %s", h.Hook)
		}
		seen[h.Hook] = true
		if h.GoName == "" || h.Sec == "" {
			t.Errorf("eksik kanca tanimi: %+v", h)
		}
	}
}

// TestCollectionContainsAllMaps ensures the ELF ships every map the
// daemon looks up by name. A missing map means enforcement silently
// degrades to a no-op.
func TestCollectionContainsAllMaps(t *testing.T) {
	dir := bpfDir(t)
	header, err := os.ReadFile(filepath.Join(dir, "axbpf.h"))
	if err != nil {
		t.Fatalf("axbpf.h okunamadi: %v", err)
	}

	content := string(header)
	// The .maps section comes from the anonymous struct definitions;
	// the name appears before SEC(".maps").
	required := []string{
		"} allow_map SEC(\".maps\")",
		"} deny_map SEC(\".maps\")",
		"} mode_map SEC(\".maps\")",
		"} audit_buffer SEC(\".maps\")",
	}
	for _, want := range required {
		if !strings.Contains(content, want) {
			t.Errorf("axbpf.h icinde %q tanimi yok", want)
		}
	}

	// And the single translation unit must include every hook.
	main, err := os.ReadFile(filepath.Join(dir, "axbpf.c"))
	if err != nil {
		t.Fatalf("axbpf.c okunamadi: %v", err)
	}
	mainContent := string(main)
	for _, h := range HookTable {
		if h.Source == "" {
			t.Errorf("%s icinde Source dosya adi yok", h.GoName)
			continue
		}
		if !strings.Contains(mainContent, h.Source) {
			t.Errorf("axbpf.c %s dosyasini include etmiyor (%s)",
				h.GoName, h.Source)
		}
		// The declared source file must actually exist and hold the program.
		data, err := os.ReadFile(filepath.Join(dir, h.Source))
		if err != nil {
			t.Errorf("%s bulunamadi: %v", h.Source, err)
			continue
		}
		if !progRe.Match(data) {
			t.Errorf("%s icinde BPF_PROG yok", h.Source)
		}
	}

	// Exactly one license string: a second SEC("license") would make
	// the loader reject the object.
	lic := 0
	sc := bufio.NewScanner(strings.NewReader(mainContent))
	for sc.Scan() {
		if strings.Contains(sc.Text(), `SEC("license")`) {
			lic++
		}
	}
	if lic != 1 {
		t.Errorf("axbpf.c icinde %d lisans tanimi var, 1 olmali", lic)
	}
}
