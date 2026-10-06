package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writePolicy drops a policy file into dir and returns dir.
func writePolicy(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatalf("%s yazilamadi: %v", name, err)
	}
}

func loadAndDecode(t *testing.T, dir string) (Policy, []string) {
	t.Helper()

	data, sources, err := LoadSystem(dir)
	if err != nil {
		t.Fatalf("LoadSystem: %v", err)
	}
	if len(sources) == 0 {
		return Policy{}, sources
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("JSON cozulemedi: %v", err)
	}
	return p, sources
}

// TestLoadSystemMissingDirIsNotAnError, kurulmamis sistemde dizinin
// olmamasi HATA degildir. Hata donerse daemon her acilista "sistem
// politikasi yuklenemedi" der ve cagiran taraf bunu bozuk kurulum
// sanir.
func TestLoadSystemMissingDirIsNotAnError(t *testing.T) {
	data, sources, err := LoadSystem(filepath.Join(t.TempDir(), "yok"))
	if err != nil {
		t.Fatalf("dizin yokken hata dondu: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("kaynak beklenmedi: %v", sources)
	}
	if data != nil {
		t.Errorf("veri beklenmedi ama geldi: %s", data)
	}
}

// TestLoadSystemSingleYAML, tek bir YAML dosyasi JSON'a cevrilip kurallar
// dogru okunur. Politika dili YAML, Go tarafi JSON ayristirir; donusum
// burada kanitlanir.
func TestLoadSystemSingleYAML(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "50-desktop.yaml", `
version: 1
mode: enforcing
rules:
  - id: R001
    name: gizli-anahtar-okuma
    subject: ["firefox"]
    object: /home/axdesktop/.ssh/id_rsa
    action: file.read
    effect: deny
  - id: R002
    name: arac-calistirma
    subject: ["md5sum"]
    action: process.exec
    effect: deny
`)

	p, sources := loadAndDecode(t, dir)

	if len(sources) != 1 || sources[0] != "50-desktop.yaml" {
		t.Fatalf("kaynaklar = %v", sources)
	}
	if p.Mode != "enforcing" {
		t.Errorf("mode = %q, enforcing bekleniyordu", p.Mode)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("kural sayisi = %d, 2 bekleniyordu", len(p.Rules))
	}
	if p.Rules[0].Object != "/home/axdesktop/.ssh/id_rsa" {
		t.Errorf("kural 1 yolu = %q", p.Rules[0].Object)
	}
	if p.Rules[0].Effect != EffectDeny {
		t.Errorf("kural 1 etkisi = %q", p.Rules[0].Effect)
	}
	if p.Rules[1].Action != "process.exec" {
		t.Errorf("kural 2 aksiyonu = %q", p.Rules[1].Action)
	}
}

// TestLoadSystemMergesLexically, birden fazla dosya lexical sirayla
// birlestirilir. Yonetici "once temel, sonra masaustu" diye
// yigin kurar; siranin deterministik olmasi sart.
func TestLoadSystemMergesLexically(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "10-base.yaml", `
version: 1
rules:
  - id: R001
    subject: ["cat"]
    object: /etc/shadow
    action: file.read
    effect: deny
`)
	writePolicy(t, dir, "50-site.yaml", `
version: 1
rules:
  - id: R002
    subject: ["curl"]
    object: /etc/passwd
    action: file.read
    effect: deny
`)

	p, sources := loadAndDecode(t, dir)

	if len(sources) != 2 {
		t.Fatalf("kaynak sayisi = %d", len(sources))
	}
	if sources[0] != "10-base.yaml" || sources[1] != "50-site.yaml" {
		t.Fatalf("siralama = %v, lexical bekleniyordu", sources)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("kural sayisi = %d, 2 bekleniyordu", len(p.Rules))
	}
	if p.Rules[0].ID != "R001" || p.Rules[1].ID != "R002" {
		t.Errorf("sira yanlis: %s, %s", p.Rules[0].ID, p.Rules[1].ID)
	}
}

// TestLoadSystemLabelsUnion, etiketler birlestirilir. Tek bir dosya
// etiketi gecersiz kilarsa digerlerinin tanimi KAYBOLMAMALI: boyle
// bir bagimlilik zinciri sessizce kirilmis sistem uretir.
func TestLoadSystemLabelsUnion(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "10-base.yaml", `
version: 1
labels:
  tarayici: ["firefox"]
  editor: ["gedit"]
rules: []
`)
	writePolicy(t, dir, "50-site.yaml", `
version: 1
labels:
  tarayici: ["chromium"]
rules: []
`)

	p, _ := loadAndDecode(t, dir)

	if len(p.Labels["tarayici"]) != 2 {
		t.Errorf("tarayici etiketi = %v, birlestirilmis olmaliydi",
			p.Labels["tarayici"])
	}
	if len(p.Labels["editor"]) != 1 {
		t.Errorf("editor etiketi KAYBOLDI: %v", p.Labels)
	}
}

// TestLoadSystemIgnoresNonYAML, .md veya .txt dosyalari politika
// sayilmaz. Yonetici dizine not birakirsa daemon hata vermemeli.
func TestLoadSystemIgnoresNonYAML(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "10-base.yaml", `
version: 1
rules:
  - id: R001
    subject: ["cat"]
    object: /etc/shadow
    action: file.read
    effect: deny
`)
	writePolicy(t, dir, "README.md", "Bu dizin politika icindir.")
	writePolicy(t, dir, "notes.txt", "notlar")

	p, sources := loadAndDecode(t, dir)

	if len(sources) != 1 || sources[0] != "10-base.yaml" {
		t.Errorf("kaynaklar = %v, yalnizca YAML sayilmali", sources)
	}
	if len(p.Rules) != 1 {
		t.Errorf("kural sayisi = %d", len(p.Rules))
	}
}

// TestLoadSystemBrokenYAMLIsReported, bozuk politika KISMEN
// uygulanmaz; hata doner. Sessizce gecilirse operator kurallarin
// yuklendigini sanirken sistem hicbir sey kisitlamiyor olur.
func TestLoadSystemBrokenYAMLIsReported(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "10-iyi.yaml", `
version: 1
rules:
  - id: R001
    subject: ["cat"]
    object: /etc/shadow
    action: file.read
    effect: deny
`)
	writePolicy(t, dir, "20-bozuk.yaml", `
version: 1
rules:
  - id: "acik-sozde
    subject: [unclosed
`)

	if _, _, err := LoadSystem(dir); err == nil {
		t.Fatal("bozuk YAML hatasi donmedi")
	}
}
