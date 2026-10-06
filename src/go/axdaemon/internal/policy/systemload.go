package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SystemPolicyDir is the administrator-managed policy directory.
//
// NEDEN VAR: daha once politika YALNIZCA axctl API'si uzerinden,
// bellekteki kullanicinin ~/.axlinux/policy.yaml dosyasindan
// yukleniyordu. Boot sirasinda hicbir sey okunmuyordu; BPF
// haritalari bos basliyordu. Yani reboot sonrasi butun kurallar
// KAYBOLUYDU ve sistem sessizce "hicbir sey kisitlanmiyor" durumuna
// donuyordu. Bir MAC icin bu, urunun islevini tamamen bosaltmak
// demektir: operator politika yuklemis, ekranda "enforcing" goruyor,
// reboot sonrasi hicbir sey engellenmiyor.
//
// Bu dizin /etc/axlinux/policies.d altindadir. Kurulum sirasinda
// RPM tarafindan yaratilir ve SELinux etiketi axlinux_etc_t'dir.
const SystemPolicyDir = "/etc/axlinux/policies.d"

// yamlToJSON, YAML belgesini JSON bayt dizisine cevirir.
//
// Go tarafi zaten JSON ayristiriyor ve tum dogrulamayi JSON
// uzerinden yapiyor (anahtar varligi denetimi dahil). YAML'i once
// JSON'a cevirip AYNI hattan gecirmek, ikinci bir dogrulama
// yolunun dogmasini onler: ayni dogrulama, tek kere yazilmis hali.
func yamlToJSON(data []byte) ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("YAML ayristirilamadi: %w", err)
	}

	// YAML'in cozumledigi tipler (map[any]any, []any, int, bool)
	// encoding/json tarafindan islenemez. Bu yuzden JSON'a
	// aktarilirken document yeniden kodlanir.
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("YAML->JSON donusumu basarisiz: %w", err)
	}
	return out, nil
}

// mergePolicy, iki politikanin kural ve etiketlerini birlestirir.
//
// Kurallar EKLENIR (append), etiketler UCUNCA BIRLESTIRILIR:
// policies.d/50-site.yaml, policies.d/10-base.yaml etiketi
// gecersiz kilarsa sonraki dosya onu KURTARIR. Tek dosya bir
// etiketi sildiginde digerlerinin tanimi kaybolmamalidir; boyle
// bir bagimlilik zinciri sessizce kirilmis bir sistem uretir.
func mergePolicy(base, next Policy) Policy {
	merged := base
	merged.Rules = append(append([]Rule{}, base.Rules...), next.Rules...)

	// Mod sonraki dosyadan tasinir. Mode tasinmazsa politika
	// dosyasindaki "mode: enforcing" satiri sessizce ATILIR ve
	// sistem varsayilan modda kalir: operator enforcing yazmis,
	// sistem baska bir modda calisiyor.
	if next.Mode != "" {
		merged.Mode = next.Mode
	}

	for k, v := range next.Labels {
		if merged.Labels == nil {
			merged.Labels = map[string][]string{}
		}
		// Ayni etiket iki dosyada tanimlandiysa birlesir;
		// tekrarlanan degerler korunur.
		seen := make(map[string]bool, len(merged.Labels[k]))
		for _, existing := range merged.Labels[k] {
			seen[existing] = true
		}
		for _, item := range v {
			if !seen[item] {
				merged.Labels[k] = append(merged.Labels[k], item)
				seen[item] = true
			}
		}
	}
	return merged
}

// LoadSystem reads every *.yaml policy from dir in lexical order,
// merges them, and returns the result as JSON ready for Manager.Load.
//
// Siralama lexikaldir (10-base.yaml, 20-desktop.yaml, 50-site.yaml).
// Bu, yoneticiye "once temel, sonra masaustu, en son site
// ayarlari" gibi deterministik bir yigin sirasi verir.
//
// Donusler:
//   - json: birlestirilmis politika (dogrulamadan gecirilebilir)
//   - sources: okunan dosya adlari (denetim izi icin)
//   - err: ilk hatada durur; KISMEN uygulanan politika birakmaz
func LoadSystem(dir string) (jsonData []byte, sources []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Dizinin olmamasi bir hata DEGIL: kurulum tam
			// yapilmamis veya yonetici politika koymak istemiyor.
			// Anlamsiz bir bos politika uretmek de yanlis olur
			// (cagiran taraf bunu "kurulum tamam" sanir).
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("sistem politikasi dizini okunamadi (%s): %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	merged := Policy{Version: 1, Rules: []Rule{}}
	for _, name := range names {
		path := filepath.Join(dir, name)

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, sources, fmt.Errorf("politika okunamadi (%s): %w", path, err)
		}

		asJSON, err := yamlToJSON(raw)
		if err != nil {
			return nil, sources, fmt.Errorf("%s: %w", name, err)
		}

		var p Policy
		if err := json.Unmarshal(asJSON, &p); err != nil {
			return nil, sources, fmt.Errorf("%s: policy JSON parse hatasi: %w", name, err)
		}

		merged = mergePolicy(merged, p)
		sources = append(sources, name)
	}

	if len(sources) == 0 {
		return nil, nil, nil
	}

	out, err := json.Marshal(merged)
	if err != nil {
		return nil, sources, fmt.Errorf("birlestirilmis politika kodlanamadi: %w", err)
	}
	return out, sources, nil
}
