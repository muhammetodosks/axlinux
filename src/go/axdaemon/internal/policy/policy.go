// Package policy handles parsing, validation, and in-memory storage
// of the compiled MAC policy received from axc.
package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Effect represents the rule outcome.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Rule is a single compiled policy rule.
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Subject  []string `json:"subject"`
	Object   string   `json:"object"`
	Action   string   `json:"action"`
	Effect   Effect   `json:"effect"`
	Priority int      `json:"priority"`
	// Port ag kurallari icin gereklidir: eBPF tarafi anahtari
	// "p:PORT" biciminde uretir, bu yuzden object alanindan
	// ayri olarak tasinmasi gerekir.
	Port int `json:"port"`
}

// Policy is the full compiled policy document.
type Policy struct {
	Version int                 `json:"version"`
	Mode    string              `json:"mode"`
	Labels  map[string][]string `json:"labels"`
	Rules   []Rule              `json:"rules"`
}

// Snapshot is an immutable view of the loaded policy.
type Snapshot struct {
	Policy       Policy
	LoadedAt     time.Time
	RulesLoaded  int
	LabelsLoaded int
	// Loaded reports whether a policy has ever been loaded.
	//
	// Once "bos kural listesi reddedilir" diye bir dogrulama
	// vardi ve bu bayrak ona dayaniyordu. Artik "rules: []"
	// gecerli oldugu icin RulesLoaded==0 iki anlama gelebilir:
	// "hicbir sey yuklenmedi" ve "bos politika yuklendi". Ayrim
	// yalnizca bu bayrakla mumkundur; "bos kural = hata"
	// varsayimi yanilticiydi.
	Loaded bool
}

// Manager stores the active policy and provides thread-safe access.
type Manager struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

// NewManager creates an empty policy manager.
func NewManager() *Manager {
	return &Manager{}
}

// Load parses and validates a new policy, then stores it.
func (m *Manager) Load(data []byte) (Snapshot, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Snapshot{}, fmt.Errorf("policy JSON parse hatasi: %w", err)
	}

	// "rules" anahtarinin varligi denetlenir (dolulugu degil).
	// Anahtar yoksa kullanici muhtemelen YANLIS YAZDI ve
	// sistem sessizce "hicbir sey kisitlanmiyor" durumuna
	// gecmemelidir: kullanici guvenlik acik sanilan bir sistemde
	// kalir. Buna karsi "rules: []" acik bir istektir ve
	// gecerlidir.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return Snapshot{}, fmt.Errorf("policy JSON parse hatasi: %w", err)
	}
	if _, ok := probe["rules"]; !ok {
		return Snapshot{}, fmt.Errorf("policy 'rules' anahtari eksik; " +
			"kisitlamasiz sistem icin 'rules: []' yazilmalidir")
	}

	if err := validate(&p); err != nil {
		return Snapshot{}, err
	}

	snap := Snapshot{
		Policy:       p,
		LoadedAt:     time.Now().UTC(),
		RulesLoaded:  len(p.Rules),
		LabelsLoaded: len(p.Labels),
		Loaded:       true,
	}

	m.mu.Lock()
	m.snapshot = snap
	m.mu.Unlock()

	return snap, nil
}

// Get returns the current policy snapshot.
func (m *Manager) Get() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot
}

// RuleCount returns the number of loaded rules.
func (m *Manager) RuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot.RulesLoaded
}

// validate checks the policy structure for correctness.
// isNetAction reports whether the action is matched by the socket
// hooks, which key on "p:PORT" rather than on a path.
func isNetAction(action string) bool {
	switch action {
	case "net.connect", "net.bind", "net.accept":
		return true
	}
	return false
}

func validate(p *Policy) error {
	if p.Version != 1 {
		return fmt.Errorf("desteklenmeyen policy versiyonu: %d", p.Version)
	}
	// KURAL SAYISI DOGRULANMAZ. "rules: []" gecerli bir
	// politikadir: sistem kisitlamasiz kalir.
	//
	// Once burada "policy en az bir kural icermeli" hatasi vardi
	// ve iki yolu birden kirip gecersiz kiliyordu:
	//
	//   1) ACIL KURTARMA. "axctl reload --force-empty" kotu bir
	//      politika yuzunden kilitlenen operatorun enforcement'i
	//      durdurma yoludur. Bos politika reddedildigi icin
	//      komut basarisiz oluyordu:
	//        x policy yukleme hatasi: policy en az bir kural icermeli
	//      Yani kurtarma araci kendisi kilitli birakirdi.
	//
	//   2) ILK KURULUM. "axctl init" bos politika yazar
	//      ("rules: []") ve kullaniciya "axctl reload" demesi
	//      soylenir. O reload her seferinde hata verirdi.
	//
	// Sessiz basarisizliktan kacinmak icin "rules" anahtarinin
	// VARLIGI Load tarafindan ayrica denetlenir; kullanici
	// "rule:" ya da "ruleset:" yazarak kazara bos bir sistem
	// elde etmemelidir.
	// Mod burada dogrulanmazsa gecersiz deger politika uzerinden
	// gelebilir ve handlers'taki modeNumeric onu sessizce
	// "permissive"a esler. Kullanici YAML'a "mod: engelle" yazip
	// enforcement'in aktif oldugunu sanar, halbuki ne engelleme ne
	// serbestlik uygulanir. Bos mod kabul edilmez ama policynin
	// varsayilanini devralmasi normaldir.
	if p.Mode != "" && p.Mode != "enforcing" &&
		p.Mode != "permissive" && p.Mode != "disabled" {
		return fmt.Errorf("gecersiz policy modu: %q "+
			"(gecerli: enforcing, permissive, disabled)", p.Mode)
	}

	// Kural kimlikleri benzersiz olmali. Iki kural ayni id'yi
	// paylasirsa audit kayitlarinda hangisinin tetiklendigi
	// ayirt edilemez ve operator ihlali kaynagina isaret edemez.
	seen := make(map[string]int, len(p.Rules))
	for i, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("kural %d: id gerekli", i)
		}
		if prev, dup := seen[r.ID]; dup {
			return fmt.Errorf("kural id tekrar ediyor: %q "+
				"(kural %d ve %d). Audit kayitlarinda hangi "+
				"kuralin tetiklendigi ayirt edilemez", r.ID, prev, i)
		}
		seen[r.ID] = i

		if r.Action == "" {
			return fmt.Errorf("kural %s: action gerekli", r.ID)
		}
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return fmt.Errorf("kural %s: gecersiz effect: %s", r.ID, r.Effect)
		}
		if len(r.Subject) == 0 {
			return fmt.Errorf("kural %s: subject gerekli", r.ID)
		}
		// Dizin disina cikan gezinme ("..") reddedilir.
		//
		// /etc/a/../../b yazildiginda gorunen hedef /b'dir.
		// Operator /etc altinda bir kural yazdigini sanir ama
		// kural baska bir yere uygulanir. Sessizce normalize
		// edilmez: kullanici ne yazdigini bilmez ve politika
		// beklediginden genis kapsar.
		if strings.Contains(r.Object, "..") {
			for _, seg := range strings.Split(r.Object, "/") {
				if seg == ".." {
					return fmt.Errorf(
						"kural %s: object yolu '..' iceriyor (%q); "+
							"dizin disina cikan gezinme reddedilir",
						r.ID, r.Object)
				}
			}
		}
		// Port negatif veya 65535 ustu olamaz; kernel __u16
		// bekliyor ve tasma sessizce farkli portu hedefler.
		if r.Port < 0 || r.Port > 65535 {
			return fmt.Errorf("kural %s: gecersiz port %d (0-65535)",
				r.ID, r.Port)
		}
		// Bir nesne ayni anda yol ve port olamaz. Ag kurallari
		// "p:PORT" anahtarini uretir, yol kurallari yol blogunu;
		// ikisi birden verilirse Go tarafi portu onceliklendirir
		// ve nesne sessizce yok sayilir.
		if r.Port > 0 && r.Object != "" {
			return fmt.Errorf("kural %s: port ve object birlikte "+
				"verilemez (ag kurallari port, dosya kurallari "+
				"yol kullanir)", r.ID)
		}
		// Ag kurallarinda port ZORUNLUDUR.
		//
		// eBPF tarafi ag kurallarini "p:PORT" anahtariyla yazar
		// (bkz. hooks_socket_connect.inc). Port verilmezse Go
		// buildKeyPort bos yol anahtari uretir, o da hicbir
		// baglantiyla eslesmez. Boyle bir kural haritaya yazilir,
		// "N kural yuklendi" bildirimi cikar ve operator kuralin
		// calistigini sanar - ama HICBIR zaman tetiklenmez.
		//
		// Python dogrulayicisi da bunu reddediyor; ancak politika
		// dogrudan RPC uzerinden de gelebilir ve o zaman Python
		// tamamen devre disi kalir. Enforcement'in son kapisi
		// Go oldugu icin kural burada da uygulanir.
		if isNetAction(r.Action) && r.Port == 0 {
			return fmt.Errorf("kural %s: %s kurali port gerektirir; "+
				"port verilmezse kural hicbir baglantiyla "+
				"eslesmez ve sessizce etkisiz kalir",
				r.ID, r.Action)
		}
	}
	return nil
}
