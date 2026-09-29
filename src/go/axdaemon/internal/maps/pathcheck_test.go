package maps

import "testing"

func TestPathBlockLayout(t *testing.T) {
	cases := []string{"/etc/hostname", "/usr/bin/cat", "/a/b/c/d/e/f/g/h/i", "p:8080", "/"}
	for _, p := range cases {
		var k MapKey
		setKeyPath(&k, p)
		t.Logf("  %-26q -> %s", p, KeyToString(k))
		for i, b := range k.Path {
			if s := string(trimN(b[:])); s != "" {
				t.Logf("      blok %d = %q", i, s)
			}
		}
	}
}

func trimN(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
