package maps

import "testing"

// Yolsuz kurallar (yalniz subject) haritaya YAZILMALIDIR.
//
// Regresyon: ruleKeysFor icindeki keyIsEmpty kontrolu yolsuz
// kurallarin anahtarini atiyordu. Sonuc "rules_loaded: 1" ama
// "map_deny_entries: 0" — kural hic uygulanmiyordu ve surec
// bazli tum process.exec kurallari sessizce oluyordu.
func TestPathlessRuleIsWritten(t *testing.T) {
	keys := ruleKeysFor("md5sum", "", "process.exec", 0)
	if len(keys) != 1 {
		t.Fatalf("anahtar sayisi %d, beklenen 1", len(keys))
	}
	k := keys[0]
	if string(k.Comm[:6]) != "md5sum" {
		t.Errorf("comm = %q", k.Comm[:8])
	}
	if k.Action == 0 {
		t.Error("action bos")
	}
	for i := range k.Path {
		for _, b := range k.Path[i] {
			if b != 0 {
				t.Fatalf("yolsuz kuralda yol alani bos olmali, [%d]=%q", i, b)
			}
		}
	}
}

// Sembolik bag uzerinden yazilan kurallar cozulmus yolla yazilir.
// /bin/ls -> /usr/bin/ls. Atlanirsa tum file.execute kurallari
// sessizce etkisiz kalir.
func TestRuleKeyUsesCanonicalPath(t *testing.T) {
	keys := ruleKeysFor("python3", "/bin/ls", "file.execute", 0)
	if len(keys) != 1 {
		t.Fatalf("anahtar sayisi %d", len(keys))
	}
	k := keys[0]
	found := false
	for i := 0; i < PathDepth; i++ {
		slot := string(k.Path[i][:])
		if len(slot) > 0 && slot[:4] == "/usr" {
			found = true
		}
	}
	if !found {
		t.Errorf("canonicalPath uygulanmamis: bloklar %q",
			k.Path[0:8])
	}
}
