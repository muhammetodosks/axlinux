// Package lsmenv detects whether the running kernel can actually
// enforce BPF LSM programs.
//
// This matters more than it looks. link.AttachLSM succeeds even when
// 'bpf' is absent from the active LSM chain: the bpf_link is created,
// the maps are populated, and the daemon happily reports 5/5 hooks
// attached — while nothing is ever enforced. A MAC system that
// silently does nothing is worse than no MAC system at all, so the
// daemon checks this and refuses to report success.
package lsmenv

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

const lsmListPath = "/sys/kernel/security/lsm"

var (
	once     sync.Once
	available bool
	chain    []string
	detail   string
)

// Active returns the kernel's active LSM chain, e.g.
// ["lockdown","capability","bpf",...].
func Active() []string {
	once.Do(func() {
		data, err := os.ReadFile(lsmListPath)
		if err != nil {
			detail = fmt.Sprintf("%s okunamadi: %v", lsmListPath, err)
			return
		}
		for _, s := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if s = strings.TrimSpace(s); s != "" {
				chain = append(chain, s)
			}
		}
		for _, l := range chain {
			if l == "bpf" {
				available = true
				detail = "bpf LSM aktif"
				return
			}
		}
		detail = "bpf LSM zincirde yok"
	})
	return chain
}

// Available reports whether BPF LSM is in the active chain.
func Available() bool {
	Active()
	return available
}

// Detail returns a short human-readable explanation.
func Detail() string {
	Active()
	return detail
}

// Summary renders a multi-line explanation suitable for logging.
func Summary() string {
	Active()
	if available {
		return "bpf LSM aktif: " + strings.Join(chain, ",")
	}
	return "bpf LSM YOK (" + detail + "). Aktif zincir: " +
		strings.Join(chain, ",") +
		"\n  AXlinux politika YOKLAYAMAZ. Duzeltmek icin:" +
		"\n    1) /etc/default/grub icinde: lsm=apparmor,bpf" +
		"\n    2) sudo update-grub && sudo reboot" +
		"\n  Detay: docs/INSTALL.md bolum 1"
}
