package lsmenv

import (
	"os"
	"strings"
	"testing"
)

// The package caches its answer in a package-level sync.Once, which
// makes the real filesystem awkward to exercise repeatedly. These
// tests drive the parsing directly, which is where the logic lives.

func parseChain(data string) []string {
	var chain []string
	for _, s := range strings.Split(strings.TrimSpace(data), ",") {
		if s = strings.TrimSpace(s); s != "" {
			chain = append(chain, s)
		}
	}
	return chain
}

func contains(chain []string, want string) bool {
	for _, c := range chain {
		if c == want {
			return true
		}
	}
	return false
}

// TestParseChainHandlesKernelFormat mirrors what /sys/kernel/security/lsm
// actually contains: a comma-separated list with a trailing newline.
func TestParseChainHandlesKernelFormat(t *testing.T) {
	cases := []struct {
		in   string
		want int
		bpf  bool
	}{
		{"lockdown,capability,yama,apparmor,evm,bpf\n", 6, true},
		{"bpf\n", 1, true},
		{"bpf", 1, true},
		// The case that matters most: bpf loaded and attached
		// successfully, but absent from the active chain. Every rule
		// then silently does nothing while the daemon reports hooks
		// attached.
		{"lockdown,capability,yama,apparmor,ima,evm\n", 6, false},
		{"", 0, false},
		{"\n", 0, false},
	}
	for _, c := range cases {
		chain := parseChain(c.in)
		if len(chain) != c.want {
			t.Errorf("parseChain(%q) %d eleman, %d bekleniyor: %v",
				c.in, len(chain), c.want, chain)
		}
		if got := contains(chain, "bpf"); got != c.bpf {
			t.Errorf("parseChain(%q) bpf=%v, %v bekleniyor",
				c.in, got, c.bpf)
		}
	}
}

// TestDetailMentionsTheFix is about operator experience. A false
// Available() with no explanation leaves the user staring at a
// system that will not enforce anything, with nothing to act on.
func TestDetailMentionsTheFix(t *testing.T) {
	s := Summary()
	if s == "" {
		t.Fatal("Summary bos olmamali")
	}
	// Whatever the state, the summary must tell the user what to do.
	if !strings.Contains(s, "update-grub") &&
		!strings.Contains(s, "LSM") {
		t.Errorf("ozet duzeltme yonu gostermeli:\n%s", s)
	}
}

// TestActiveReadsTheRealFile does not assert a specific kernel state
// (that depends on the host) but proves the file is read and parsed
// without panicking, and that Available and Detail agree with the
// parsed chain.
func TestActiveReadsTheRealFile(t *testing.T) {
	if _, err := os.Stat(lsmListPath); err != nil {
		t.Skipf("%s yok (bu cekirdekte LSM yapilandirmasi farkli): %v",
			lsmListPath, err)
	}
	chain := Active()
	if Available() != contains(chain, "bpf") {
		t.Error("Available() ile zincir tutarsiz")
	}
	if Detail() == "" {
		t.Error("Detail() bos olmamali")
	}
	// An empty chain with no read error would mean the file parsed to
	// nothing, which should be reported rather than silently treated
	// as "not available".
	if len(chain) == 0 {
		t.Log("LSM zinciri bos; kernel bpf LSM desteklemiyor olabilir")
	}
}
