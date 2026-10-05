package protected

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ContractMatchesBPF fails if the kernel-side list and this package drift
// apart.
//
// The BPF program embeds its own copy because it cannot call into Go. That
// duplication is only safe if something checks it, which is this test.
func TestContractMatchesBPF(t *testing.T) {
	path := findAxbpfHeader(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("axbpf.h okunamadi: %v", err)
	}
	src := string(data)

	start := strings.Index(src, "static __always_inline int ax_protected")
	if start < 0 {
		t.Fatal("ax_protected() bulunamadi")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("ax_protected() sonu bulunamadi")
	}
	body := src[start : start+end]

	re := regexp.MustCompile(`ax_comm_is\(comm, "([^"]+)"\)`)
	var bpfNames []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		bpfNames = append(bpfNames, m[1])
	}
	if len(bpfNames) == 0 {
		t.Fatal("ax_protected() icinde isim bulunamadi")
	}

	want := List()
	wantSet := map[string]bool{}
	for _, n := range want {
		wantSet[n] = true
	}
	gotSet := map[string]bool{}
	for _, n := range bpfNames {
		gotSet[n] = true
	}

	var missing, extra []string
	for n := range wantSet {
		if !gotSet[n] {
			missing = append(missing, n)
		}
	}
	for n := range gotSet {
		if !wantSet[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(extra) > 0 {
		t.Errorf("BPF'te olup Go'da olmayan korumali surecler: %v\n"+
			"Bu surecler kilitlenme korumasi disi kalir.", extra)
	}
	if len(missing) > 0 {
		t.Errorf("Go'da olup BPF'te olmayan korumali surecler: %v\n"+
			"Bu surecler kilitlenebilir.", missing)
	}
}

// TestInitIsProtected guards the reason the PID<=2 numeric check was
// removed from ax_protected(): init must always be covered by name.
func TestInitIsProtected(t *testing.T) {
	want := []string{"systemd", "init", "kthreadd", "swapper", "migration"}
	set := map[string]bool{}
	for _, n := range List() {
		set[n] = true
	}
	for _, n := range want {
		if !set[n] {
			t.Errorf("PID 1/2 korumasi eksik: %q", n)
		}
	}
}

// TestShellsProtected: a rule that denies a shell would lock the operator
// out of the machine.
func TestShellsProtected(t *testing.T) {
	set := map[string]bool{}
	for _, n := range List() {
		set[n] = true
	}
	for _, n := range []string{"bash", "sh", "dash", "zsh", "fish",
		"sudo", "su", "doas", "sshd", "login"} {
		if !set[n] {
			t.Errorf("kabuk/oturum suresi korumali degil: %q", n)
		}
	}
}

func findAxbpfHeader(t *testing.T) string {
	t.Helper()
	dir := "."
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "src", "bpf", "axbpf.h")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("axbpf.h bulunamadi (kaynak agaci disinda)")
	return ""
}
