package maps

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalPathMatchesKernelView is the regression test for a
// silent no-op that shipped once already.
//
// On merged-/usr systems (every current Debian and Ubuntu) /bin is a
// symlink to /usr/bin. The kernel reports the RESOLVED path, so a
// policy written as "/bin/ls" used to produce the key
// ["/bin", "/ls"] while the kernel looked up ["/usr/bin", "/ls"].
// The rule loaded, the daemon reported it as loaded, and it could
// never match anything.
func TestCanonicalPathMatchesKernelView(t *testing.T) {
	// A real symlink in a temp dir: the test must not depend on the
	// host having merged-/usr, or on any particular distro layout.
	dir := t.TempDir()
	realDir := filepath.Join(dir, "usr", "bin")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "ls")
	if err := os.WriteFile(realFile, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bin")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	written := filepath.Join(link, "ls")

	// What the policy says.
	fromPolicy := buildKey("tester", written, "file.execute")
	// What the kernel reports for the same file.
	fromKernel := buildKey("tester", realFile, "file.execute")

	if fromPolicy != fromKernel {
		t.Errorf("politika yolu ile kernel yolu farkli anahtar uretti\n"+
			"  politika %q -> %q\n  kernel  %q -> %q",
			written, joinKey(fromPolicy), realFile, joinKey(fromKernel))
	}
}

// TestCanonicalPathKeepsMissingPaths: a rule for a file that does not
// exist yet must still be writable. The file may appear later, and
// rejecting the rule would be a worse failure than one that does not
// match yet.
func TestCanonicalPathKeepsMissingPaths(t *testing.T) {
	missing := "/definitely/not/here/at/all"
	if got := canonicalPath(missing); got != missing {
		t.Errorf("var olmayan yol degistirildi: %q -> %q", missing, got)
	}
}

// TestCanonicalPathLeavesPortsAndEmptyAlone guards the two non-path
// key forms: network keys are already exact, and empty means
// "process-only rule", which must stay empty.
func TestCanonicalPathLeavesPortsAndEmptyAlone(t *testing.T) {
	if got := canonicalPath("p:8080"); got != "p:8080" {
		t.Errorf("port anahtari degisti: %q", got)
	}
	if got := canonicalPath(""); got != "" {
		t.Errorf("bos yol degisti: %q", got)
	}
}

// TestCanonicalPathOnThisHost documents the host's own layout. On a
// merged-/usr system this is the live version of the bug above; on
// any other system it simply reports that the host is unaffected.
func TestCanonicalPathOnThisHost(t *testing.T) {
	if resolved, err := filepath.EvalSymlinks("/bin"); err == nil &&
		resolved != "/bin" {
		if got := canonicalPath("/bin"); got != resolved {
			t.Errorf("bu makinede /bin symlink (%s) ama canonicalPath "+
				"vermedi: %q", resolved, got)
		}
	}
}

func joinKey(k MapKey) string {
	out := ""
	for i := len(k.Path) - 1; i >= 0; i-- {
		if k.Path[i][0] == 0 {
			continue
		}
		out += string(k.Path[i][:clen(k.Path[i][:])]) + "/"
	}
	return out
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
