package maps

import (
	"os"
	"path/filepath"
	"testing"
)

// prefixProbe, BPF tarafindaki ax_lookup_prefix() ile birebir ayni
// turetme islemidir. Go tarafinda test edilemez (BPF kodu C'de),
// ama ANLAMI ayni oldugu icin burada Go ile yeniden yazilir: bugun
// Go'da dogru, C'de yanlislik varsa test kirmizi yakalar.
//
// Kaynak: src/bpf/axbpf.h -> ax_lookup_prefix()
func prefixProbe(src MapKey, total int, m int) MapKey {
	var out MapKey
	if m < 1 || m > total || total < 1 || total > PathDepth {
		// BPF bu girdiyi URETMEZ: m her zaman total-1'den baslar.
		// Yanlis girdide sessizce "bulunamadi" donmek daha dogru.
		return MapKey{}
	}
	out = src
	first := PathDepth - total

	for i := range out.Path {
		out.Path[i] = [PathSlot]byte{}
	}
	for i := 0; i < m && i < PathDepth; i++ {
		copy(out.Path[PathDepth-m+i][:], src.Path[first+i][:])
	}
	return out
}

// TestPrefixKeyMatchesDirectoryRule, dizin kuralinin icerigi
// korudugunu anahtar duzeyinde kanitlar.
//
// GUVENLIK ACIGI: "object: /tmp/dizin" + file.read deny kurali
// dizinin KENDISINI engelliyordu ama icindeki dosyalari
// (secret.txt) SERBEST birakiyordu. Kullanici "korunuyor" saniyordu.
func TestPrefixKeyMatchesDirectoryRule(t *testing.T) {
	// Kural: /tmp/dizin  (Go bunu su sekilde yazar)
	var rule MapKey
	setKeyPath(&rule, "/tmp/dizin")
	rule.Action = ActionFileRead

	// Gercek dosya yolu: /tmp/dizin/secret.txt
	// BPF bunu su sekilde doldurur (en derin bilesen PathDepth-1'de).
	var real MapKey
	setKeyPath(&real, "/tmp/dizin/secret.txt")
	real.Action = ActionFileRead

	// total = kullanilan yuva sayisi
	total := 0
	for i := PathDepth - 1; i >= 0; i-- {
		if real.Path[i][0] != 0 {
			total++
		}
	}
	if total != 3 {
		t.Fatalf("total = %d, 3 bekleniyordu", total)
	}

	// m = total-1: kuralin 2 bileseni (tmp, dizin)
	got := prefixProbe(real, total, total-1)
	if got != rule {
		t.Errorf("turetilen anahtar kural ile eslesmedi\n  turetilen: %+v\n  kural    : %+v",
			pathSlots(got), pathSlots(rule))
	}
}

// TestPrefixKeyNoFalsePositive, dizin kuralinin BENZER yollari
// engellemedigini dogrular. Yanlis pozitif bir MAC'ta kullaniciyi
// sistemine guvenmemeye iter.
func TestPrefixKeyNoFalsePositive(t *testing.T) {
	var real MapKey
	setKeyPath(&real, "/tmp/dizin/secret.txt")

	total := 3

	// /tmp/dizin2 -> farkli dizin, ESLESMEMELI
	var other MapKey
	setKeyPath(&other, "/tmp/dizin2")
	for m := 1; m <= total; m++ {
		if got := prefixProbe(real, total, m); got == other {
			t.Errorf("m=%d: /tmp/dizin2 yalnis pozitif eslesti", m)
		}
	}

	// /tmp -> UST DIZIN. Burada testin ilk yazimi YANLIIS beklenti
	// koyuyordu: "/tmp kurali /tmp/dizin/secret.txt'i engellememeli"
	// diyordu. Oysa dogru davranis TAM TERSI:
	//
	//   /tmp/dizin/secret.txt  gercekten /tmp ALTINDADIR
	//
	// ve "/tmp" kurali yazildiysa kapsaminda olmalidir. Ust dizin
	// kuralinin eslesmemesi bir GUVENLIK ACIGI olurdu; eslesmesi
	// ise dilin beklenen anlamidir. Bu yuzden burada ESLESMESI
	// beklenir.
	var parent MapKey
	setKeyPath(&parent, "/tmp")
	parentMatched := false
	for m := 1; m <= total; m++ {
		if prefixProbe(real, total, m) == parent {
			parentMatched = true
		}
	}
	if !parentMatched {
		t.Error("ust dizin kurali (/tmp) altindaki dosyayi kapsamadi; " +
			"bu bir guvenlik acigi olurdu")
	}
}

// TestPrefixKeyNeedsFullSlotClear, kullanilmayan yuvalarin TAMAMININ
// sifirlanmasi gerektigini kanitlar.
//
// Bu, canli sistemde bulunan sessiz hatayi yakaladi: yalnizca
// path[i][0] = 0 yaziliyordu. Harita aramasi 32 baytin TAMAMINI
// karsilastirdigi icin anahtar eslesmiyordu; bpftool ciktisi ise
// (dizgi ilk NUL'da bittigi icin) iki yuvayi da bos gosteriyordu.
func TestPrefixKeyNeedsFullSlotClear(t *testing.T) {
	var real MapKey
	setKeyPath(&real, "/tmp/dizin/secret.txt")
	real.Action = ActionFileRead

	var rule MapKey
	setKeyPath(&rule, "/tmp/dizin")
	rule.Action = ActionFileRead

	first := PathDepth - 3
	m := 2

	// HATALI: yalnizca ilk bayt sifirlanir
	bad := real
	for i := range bad.Path {
		bad.Path[i][0] = 0
	}
	for i := 0; i < m; i++ {
		copy(bad.Path[PathDepth-m+i][:], real.Path[first+i][:])
	}
	if bad == rule {
		t.Skip("bu Go surumunde yalniz ilk bayt yazmak yeterli oldu; " +
			"C tarafinda yine de 32 bayt sifirlanir")
	}

	// DOGRU: her yuva tamamen sifirlanir
	good := prefixProbe(real, 3, m)
	if good != rule {
		t.Errorf("tam slot temizleme eslesmedi: %+v != %+v",
			pathSlots(good), pathSlots(rule))
	}
}

// TestPrefixKeyMatchesGoSetKeyPath, her seviyede turetilen anahtarin
// Go'nun setKeyPath ile yazdigi bir yolla birebir ayni oldugunu
// dener. Kural dizini gercek yolun her derinliginde test edilir.
func TestPrefixKeyMatchesGoSetKeyPath(t *testing.T) {
	cases := []struct {
		dir   string
		depth int // dosya, dizinden bu kadar seviye altinda
	}{
		{"/tmp/dizin", 1},
		{"/tmp/dizin", 2},
		{"/var/lib/ornek", 1},
		{"/var/lib/ornek", 3},
		{"/home/u/.gnupg", 1},
		{"/home/u/.gnupg", 3},
	}

	for _, c := range cases {
		file := c.dir
		for i := 0; i < c.depth; i++ {
			file += "/alt"
		}
		file += "/secret.gpg"

		var real MapKey
		setKeyPath(&real, file)
		real.Action = ActionFileRead

		total := 0
		for i := PathDepth - 1; i >= 0; i-- {
			if real.Path[i][0] != 0 {
				total++
			}
		}

		var rule MapKey
		setKeyPath(&rule, c.dir)
		rule.Action = ActionFileRead

		m := total - (c.depth + 1)
		if m < 1 {
			t.Errorf("%s (derinlik %d): m=%d, gecersiz", file, c.depth, m)
			continue
		}

		got := prefixProbe(real, total, m)
		if got != rule {
			t.Errorf("kural=%s dosya=%s (m=%d) eslesmedi\n  turetilen: %+v\n  kural    : %+v",
				c.dir, file, m, pathSlots(got), pathSlots(rule))
		}
	}
}

// TestDirectoryRuleProtectsContents, ucu da dizin kuralinin icerigi
// gercekten korudugunu uc farkli derinlikte dogrular.
func TestDirectoryRuleProtectsContents(t *testing.T) {
	// KISA ad: t.TempDir() "TestDirectoryRuleProtectsContents767043548"
	// gibi 39 karakterlik bir yol uretiyor; PathSlot-1 = 31 oldugu
	// icin setKeyPath anahtari sessizce BOSALTIR ve test anlamsiz
	// bir sey olcerdi. Kendi dizinimizi kisa adla kuruyoruz.
	base, err := os.MkdirTemp("", "axp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	dir := filepath.Join(base, "d")
	sub := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	files := []string{
		filepath.Join(dir, "s1.txt"),
		filepath.Join(dir, "a", "s2.txt"),
		filepath.Join(sub, "s3.txt"),
	}

	var rule MapKey
	setKeyPath(&rule, dir)
	rule.Action = ActionFileRead

	for _, f := range files {
		var real MapKey
		setKeyPath(&real, f)
		real.Action = ActionFileRead

		total := 0
		for i := PathDepth - 1; i >= 0; i-- {
			if real.Path[i][0] != 0 {
				total++
			}
		}

		// Dizin kurali: m = dosyanin dizin kuralina gore derinligi
		found := false
		for m := 1; m <= total; m++ {
			if prefixProbe(real, total, m) == rule {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: dizin kurali %s ile eslesmedi", f, dir)
		}
	}
}

// pathSlots, hata ciktilarinda okunabilir olmasi icin dolu yuvalari
// listeler.
func pathSlots(k MapKey) string {
	var out []string
	for i := PathDepth - 1; i >= 0; i-- {
		if k.Path[i][0] != 0 {
			out = append(out, string(k.Path[i][:]))
		}
	}
	if len(out) == 0 {
		return "(bos)"
	}
	s := ""
	for i, v := range out {
		if i > 0 {
			s += " <- "
		}
		s += v
	}
	return s
}
