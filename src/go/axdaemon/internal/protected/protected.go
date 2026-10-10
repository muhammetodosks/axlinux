// Package protected is the SINGLE SOURCE OF TRUTH for the process list
// that AXlinux never locks out.
//
// # Why this exists
//
// The list was previously duplicated: ax_protected() in the eBPF source
// and a hardcoded "29" in install.sh's summary line. Nothing checked
// that they agreed, so the number printed during installation could be
// wrong while looking authoritative.
//
// The kernel-side list cannot be read at runtime (it lives in the BPF
// object), so the list lives here and ContractMatchesBPF asserts the two
// stay in sync. If someone adds a process to one and not the other, the
// test fails.
//
// # Ordering note
//
// The BPF side checks PID<=2 separately; PID 1 and PID 2 are covered by
// name ("systemd"/"init"/"swapper" and "kthreadd"). Names here follow the
// same set, so a rule may never lock out init.
package protected

// List returns the protected process names.
//
// Order is irrelevant for correctness; it is kept stable so status output
// and tests do not churn.
func List() []string {
	return []string{
		"swapper",
		"migration",
		"systemd",
		"systemd-logind",
		"systemd-userdbd",
		"systemd-udevd",
		"systemd-journald",
		"systemd-oomd",
		"init",
		"kthreadd",
		"sshd",
		"sshd-session",
		"login",
		"agetty",
		"getty",
		"sudo",
		"su",
		"doas",
		"dbus-daemon",
		"dbus-broker",
		"polkitd",
		"rtkit-daemon",
		"NetworkManager",
		"wpa_supplicant",
		"gdm3",
		"gdm-session-worker",
		"bash",
		"sh",
		"dash",
		"zsh",
		"fish",
	}
}

// Count is a convenience for status output.
func Count() int { return len(List()) }
