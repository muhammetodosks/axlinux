package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSystemLoadAcceptsScalarSubject, LoadSystem yolunun AYNI
// kabul kümesini kullanmasını garanti eder.
//
// BU BİR REGRESYON TESTİDİR VE İKİ AYRI AÇIK KAPATIR.
//
// Hata 1: SubjectList eklenmeden once, Go "subject: curl" (tekil
// string) reddediyordu. Kullanici politikasi yolunda fark edildi ve
// duzeltildi. AMA sistem politikasi yolu (/etc/axlinux/policies.d)
// AYRI bir hata mesaji veriyordu:
//
//	sistem politikasi yuklenemedi; sistem KISITLAMASIZ kaliyor
//	error="50-....yaml: policy JSON parse hatasi: json: cannot
//	        unmarshal string into Go struct field
//	        Rule.rules.subject of type []string"
//
// Yani kalici politika konumu olan policies.d, tekil subject'li
// gecerli bir politikayi REDDETTIYOR ve sistem butun korumasiz
// kaliyordu. Kurallar hic yazilmadan. Bu, MAC'te en kotu hata
// modudur: kullanici "korunuyorum" sanir, sistem korunmaz.
//
// Hata 2: policies.d'de TEK BIR bozuk dosya tum sistem
// politikasini dusuruyor. Bu test, duzeltilmis SubjectList'in
// sistem yolunda da gecerli oldugunu kanitlar.
func TestSystemLoadAcceptsScalarSubject(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			"tekil string",
			"version: 1\nmode: enforcing\nrules:\n" +
				"  - {id: a, name: \"tekil\", subject: curl, object: /etc/x, action: file.read, effect: deny}\n",
		},
		{
			"liste",
			"version: 1\nmode: enforcing\nrules:\n" +
				"  - {id: b, name: \"liste\", subject: [curl, wget], object: /etc/x, action: file.read, effect: deny}\n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "50-t.yaml"),
				[]byte(c.body), 0644); err != nil {
				t.Fatal(err)
			}
			out, sources, err := LoadSystem(dir)
			if err != nil {
				t.Fatalf("LoadSystem reddetti (sistem kisitlamasiz kalir): %v", err)
			}
			if len(sources) != 1 {
				t.Fatalf("kaynak sayisi = %d, 1 bekleniyor", len(sources))
			}
			if len(out) == 0 {
				t.Fatal("cikti bos: kural yazilmadi")
			}
			p := mustParsePolicy(t, out)
			if len(p.Rules) != 1 {
				t.Fatalf("kural = %d, 1 bekleniyor", len(p.Rules))
			}
			if len(p.Rules[0].Subject) == 0 {
				t.Error("subject bos: kural hicbir seyi engellemez")
			}
		})
	}
}
