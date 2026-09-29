// Handler tests cover the policy reload path, which is the only place
// where a mistake turns into an unprotected machine.
//
// The failure this guards against: a policy that is rejected halfway
// through leaves the system with NO rules loaded while the daemon
// reports the old policy as still active. The user believes they are
// protected and are not.
package handlers

import (
	"strings"
	"testing"

	"axlinux/axdaemon/internal/maps"
)

// TestValidateRuleRejectsProtectedProcesses proves the daemon refuses
// rules aimed at processes whose lockout would strand the user,
// even before any map is touched.
func TestValidateRuleRejectsProtectedProcesses(t *testing.T) {
	for _, comm := range []string{"bash", "sh", "sudo", "systemd",
		"sshd", "login", "polkitd"} {
		err := maps.ValidateRule(comm, "", "process.exec", 0)
		if err == nil {
			t.Errorf("korumali surec icin dogrulama gecmeliydi: %q", comm)
			continue
		}
		if !strings.Contains(err.Error(), "korumali") {
			t.Errorf("hata mesaji korumayi anlatmiyor (%q): %v", comm, err)
		}
	}
}

// TestValidateRuleAcceptsInterpreterRules is the counterweight to the
// test above, and the one that keeps the product usable.
//
// Runtimes must NOT be on the protection list. Almost every real
// application runs under an interpreter, so "python3 cannot read
// /etc/shadow" and "node cannot reach the network" are among the most
// common MAC rules there are. A guard that rejected them would leave
// the operator with no way to write the rules they actually need,
// while buying no lockout protection: a protected shell still gives
// them a way back.
func TestValidateRuleAcceptsInterpreterRules(t *testing.T) {
	cases := []struct{ comm, path, action string; port int }{
		{"python3", "/etc/shadow", "file.read", 0},
		{"node", "", "net.connect", 443},
		{"perl", "/etc/passwd", "file.read", 0},
		{"ruby", "", "file.write", 0},
		{"tmux", "", "process.exec", 0},
	}
	for _, c := range cases {
		if err := maps.ValidateRule(c.comm, c.path, c.action, c.port); err != nil {
			t.Errorf("dil/arac sureci reddedildi, MAC islevsizlesir "+
				"(%s %s %s): %v", c.comm, c.action, c.path, err)
		}
	}
}

// TestValidateRuleRejectsUnrepresentablePaths proves a path that
// cannot fit the block layout is refused rather than silently
// truncated. A truncated key matches the wrong file, or none, and the
// rule looks loaded.
func TestValidateRuleRejectsUnrepresentablePaths(t *testing.T) {
	long := "/" + strings.Repeat("a", maps.PathSlot+1)
	if err := maps.ValidateRule("firefox", long, "file.read", 0); err == nil {
		t.Error("asiri uzun yol dogrulamadan gecmeliydi")
	}

	deep := "/" + strings.Repeat("x/", maps.PathDepth+1)
	if err := maps.ValidateRule("firefox", deep, "file.read", 0); err == nil {
		t.Error("asiri derin yol dogrulamadan gecmeliydi")
	}
}

// TestValidateRuleAcceptsNormalRules is the other direction: ordinary
// rules must pass, or the guard would have broken the product.
func TestValidateRuleAcceptsNormalRules(t *testing.T) {
	ok := []struct{ comm, path, action string; port int }{
		{"firefox", "/etc/shadow", "file.read", 0},
		{"nginx", "/var/www", "file.read", 0},
		{"python3", "", "process.exec", 0},
		{"nc", "", "net.bind", 8080},
		{"curl", "", "net.connect", 443},
	}
	for _, c := range ok {
		if err := maps.ValidateRule(c.comm, c.path, c.action, c.port); err != nil {
			t.Errorf("gecerli kural reddedildi (%s %s %s): %v",
				c.comm, c.action, c.path, err)
		}
	}
}

// TestValidateRuleRejectsUnknownAction keeps typos from producing a
// key with Action=0, which would never match any program behaviour.
func TestValidateRuleRejectsUnknownAction(t *testing.T) {
	if err := maps.ValidateRule("firefox", "/etc/shadow", "file.readd", 0); err == nil {
		t.Error("bilinmeyen aksiyon dogrulamadan gecmeliydi")
	}
}
