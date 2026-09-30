package policy

import (
	"strings"
	"sync"
	"testing"
)

func validRule() Rule {
	return Rule{
		ID:      "rule_001",
		Name:    "test",
		Subject: []string{"firefox"},
		Object:  "/etc/shadow",
		Action:  "file.read",
		Effect:  EffectDeny,
	}
}

func validPolicy() Policy {
	return Policy{
		Version: 1,
		Mode:    "enforcing",
		Rules:   []Rule{validRule()},
	}
}

// TestValidateAcceptsGoodPolicy is the baseline: a correct policy must
// not be rejected, or the product is unusable.
func TestValidateAcceptsGoodPolicy(t *testing.T) {
	// validate imzasi *Policy aliyor ve Go, fonksiyon cagri
	// sonucunun adresini almaya izin vermez. Bu yuzden once yerel
	// bir degiskene alinir.
	p := validPolicy()
	if err := validate(&p); err != nil {
		t.Errorf("gecerli politika reddedildi: %v", err)
	}
}

// TestLoadStoresSnapshot covers the happy path and the Loaded flag
// that distinguishes "never loaded" from "loaded and empty".
func TestLoadStoresSnapshot(t *testing.T) {
	m := NewManager()
	if m.Get().Loaded {
		t.Error("baslamada Loaded false olmali")
	}

	snap, err := m.Load([]byte(`{
		"version":1,"mode":"enforcing",
		"rules":[{"id":"rule_001","name":"x","subject":["curl"],
		          "object":"","action":"net.connect","port":443,
		          "effect":"deny","priority":50}]
	}`))
	if err != nil {
		t.Fatalf("Load hata verdi: %v", err)
	}
	if !snap.Loaded {
		t.Error("Loaded true olmali")
	}
	if snap.RulesLoaded != 1 {
		t.Errorf("RulesLoaded = %d, 1 bekleniyor", snap.RulesLoaded)
	}
	// Port, ag kurallarinin yol yerine tasidigi alan; JSON'dan
	// dogru okunmali yoksa anahtar "p:0" olarak uretilir.
	if got := snap.Policy.Rules[0].Port; got != 443 {
		t.Errorf("Port = %d, 443 bekleniyor", got)
	}
	if m.RuleCount() != 1 {
		t.Errorf("RuleCount = %d, 1 bekleniyor", m.RuleCount())
	}
}

// TestLoadRejectsInvalidJSON ensures a malformed document never
// replaces a good policy.
func TestLoadRejectsInvalidJSON(t *testing.T) {
	m := NewManager()
	if _, err := m.Load([]byte("{")); err == nil {
		t.Error("bozuk JSON kabul edildi")
	}
	if m.Get().Loaded {
		t.Error("basarisiz yuklemeden sonra Loaded true olmamali")
	}
}

// TestInvalidModeRejected is the fix this file records.
//
// validate never checked Mode, so a policy carrying "mod: engelle"
// passed validation and reached modeNumeric, which silently maps an
// unknown mode to permissive. The user would see the policy load
// successfully and believe enforcement was on.
func TestInvalidModeRejected(t *testing.T) {
	for _, bad := range []string{"engelle", "ENFORCING", "on", "true"} {
		p := validPolicy()
		p.Mode = bad
		err := validate(&p)
		if err == nil {
			t.Errorf("gecersiz mod %q kabul edildi", bad)
			continue
		}
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("hata mesaji modu belirtmeli (%q): %v", bad, err)
		}
	}
}

// TestEmptyModeAccepted: a policy that omits mode is normal, the
// daemon keeps whatever mode it already had.
func TestEmptyModeAccepted(t *testing.T) {
	p := validPolicy()
	p.Mode = ""
	if err := validate(&p); err != nil {
		t.Errorf("modsuz politika reddedilmeliydi: %v", err)
	}
}

// TestValidModesAccepted guards the other direction.
func TestValidModesAccepted(t *testing.T) {
	for _, ok := range []string{"enforcing", "permissive", "disabled"} {
		p := validPolicy()
		p.Mode = ok
		if err := validate(&p); err != nil {
			t.Errorf("gecerli mod %q reddedildi: %v", ok, err)
		}
	}
}

// TestDuplicateRuleIDRejected.
//
// Two rules sharing an id produce audit records that cannot be traced
// back to a specific rule: the operator sees rule_003 denied a read
// and cannot tell which of the two rules fired.
func TestDuplicateRuleIDRejected(t *testing.T) {
	p := validPolicy()
	dup := validRule()
	dup.Object = "/etc/passwd"
	p.Rules = append(p.Rules, dup)

	err := validate(&p)
	if err == nil {
		t.Fatal("tekrar eden kural id kabul edildi")
	}
	if !strings.Contains(err.Error(), "rule_001") {
		t.Errorf("hata mesaji id'yi belirtmeli: %v", err)
	}
}

// TestPortAndObjectTogetherRejected.
//
// Network rules key on "p:PORT" and file rules key on path blocks.
// buildKeyPort gives port precedence and drops the object, so a rule
// with both looks fine in YAML and silently ignores the path.
func TestPortAndObjectTogetherRejected(t *testing.T) {
	p := validPolicy()
	p.Rules[0].Action = "net.connect"
	p.Rules[0].Object = "/etc/shadow"
	p.Rules[0].Port = 443

	if err := validate(&p); err == nil {
		t.Error("port ve object birlikte kabul edildi")
	}
}

// TestPortWithEmptyObjectAccepted: a network rule legitimately has
// no object. This is the common case and must keep working.
func TestPortWithEmptyObjectAccepted(t *testing.T) {
	p := validPolicy()
	p.Rules[0].Action = "net.bind"
	p.Rules[0].Object = ""
	p.Rules[0].Port = 8080
	if err := validate(&p); err != nil {
		t.Errorf("portsuz-nesnesiz ag kurali reddedildi: %v", err)
	}
}

// TestPortRangeChecked: the kernel side is __u16.
func TestPortRangeChecked(t *testing.T) {
	// 0 da reddedilenler arasindadir: ag kurali icin port 0
	// anlamsizdir. Anahtar "p:0" olur ve hicbir gercek port ile
	// eslesmez, yani kural sessizce etkisiz kalir. Dosya
	// kurallarinda Port varsayilan 0 oldugu icin bu kisit yalniz
	// ag kurallarina uygulanir.
	for _, bad := range []int{-1, 0, 65536, 70000} {
		p := validPolicy()
		p.Rules[0].Action = "net.bind"
		p.Rules[0].Object = ""
		p.Rules[0].Port = bad
		if err := validate(&p); err == nil {
			t.Errorf("gecersiz port %d kabul edildi", bad)
		}
	}
	for _, ok := range []int{1, 443, 65535} {
		// Kural bir AG kurali olmali. validRule bir dosya kurali
		// uretir (object: /etc/shadow); port eklenirken object
		// temizlenmezse dogrulayici "port ve object birlikte
		// verilemez" hatasini verir ve test port araligini hic
		// olcmeden yesil olur.
		p := validPolicy()
		p.Rules[0].Action = "net.bind"
		p.Rules[0].Object = ""
		p.Rules[0].Port = ok
		if err := validate(&p); err != nil {
			t.Errorf("gecerli port %d reddedildi: %v", ok, err)
		}
	}
}

// TestNetRuleWithoutPortRejected closes a silent no-op.
//
// A net.* rule with no port produced an empty path key, while the
// eBPF side looks up "p:PORT". The rule loaded, the daemon reported
// it as loaded, and it could never fire. Python rejected this
// already, but policy can arrive straight over RPC with the CLI out
// of the loop, so the last gate before the map has to reject it too.
func TestNetRuleWithoutPortRejected(t *testing.T) {
	for _, action := range []string{"net.connect", "net.bind", "net.accept"} {
		p := validPolicy()
		p.Rules[0].Action = action
		p.Rules[0].Object = ""
		p.Rules[0].Port = 0
		err := validate(&p)
		if err == nil {
			t.Errorf("%s: portsuz kural kabul edildi, sessizce etkisiz", action)
			continue
		}
		if !strings.Contains(err.Error(), "port") {
			t.Errorf("%s: hata portu gerekce gostermiyor: %v", action, err)
		}
	}
}

// TestStructuralValidation covers the pre-existing checks, kept here
// so the package has a floor of coverage.
func TestStructuralValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Policy)
		wantSub string
	}{
		{"versiyon", func(p *Policy) { p.Version = 2 }, "versiyon"},
		// "kural yok" durumu artik hata DEGILDIR ve burada
		// yer almaz. Once validate() bos kural listesini
		// reddediyordu; bu iki yolu birden kirip gecersiz
		// kiliyordu:
		//   - "axctl reload --force-empty" (acil kurtarma yolu)
		//     hata veriyordu
		//   - "axctl init" + "axctl reload" (ilk kurulum)
		//     hata veriyordu
		// Bos kural listesinin GECERLI sayilmasi artik
		// TestLoadAcceptsEmptyRuleSet ile, "rules" anahtari
		// olmadiginda yazim hatasinin reddi ise
		// TestLoadRejectsMissingRulesKey ile korunuyor.
		{"id yok", func(p *Policy) { p.Rules[0].ID = "" }, "id"},
		{"action yok", func(p *Policy) { p.Rules[0].Action = "" }, "action"},
		{"effect gecersiz", func(p *Policy) { p.Rules[0].Effect = "maybe" }, "effect"},
		{"subject yok", func(p *Policy) { p.Rules[0].Subject = nil }, "subject"},
	}
	for _, c := range cases {
		p := validPolicy()
		c.mutate(&p)
		err := validate(&p)
		if err == nil {
			t.Errorf("%s: reddedilmedi", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("%s: hata %q icermiyor: %v", c.name, c.wantSub, err)
		}
	}
}

// TestFailedLoadKeepsPreviousPolicy is the property that makes
// two-phase reload safe: a rejected policy must not wipe the one
// currently in force.
func TestFailedLoadKeepsPreviousPolicy(t *testing.T) {
	m := NewManager()
	if _, err := m.Load([]byte(`{
		"version":1,"mode":"enforcing",
		"rules":[{"id":"rule_001","name":"x","subject":["curl"],
		          "action":"net.connect","port":443,"effect":"deny"}]
	}`)); err != nil {
		t.Fatalf("ilk yukleme basarisiz: %v", err)
	}
	if m.RuleCount() != 1 {
		t.Fatalf("ilk yukleme sayimi yanlis: %d", m.RuleCount())
	}

	// Same JSON but with an invalid mode: must be rejected outright.
	if _, err := m.Load([]byte(`{
		"version":1,"mode":"engelle",
		"rules":[{"id":"rule_002","name":"y","subject":["curl"],
		          "action":"net.connect","port":80,"effect":"deny"}]
	}`)); err == nil {
		t.Error("gecersiz modlu politika kabul edildi")
	}
	if m.RuleCount() != 1 {
		t.Errorf("basarisiz yukleme eski politikayi bozdu: %d", m.RuleCount())
	}
}

// TestConcurrentLoadGet runs the -race scenario: the RPC server reads
// the policy on every status call while reloads write it.
func TestConcurrentLoadGet(t *testing.T) {
	m := NewManager()
	doc := []byte(`{
		"version":1,"mode":"enforcing",
		"rules":[{"id":"rule_001","name":"x","subject":["curl"],
		          "action":"net.connect","port":443,"effect":"deny"}]
	}`)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = m.Load(doc)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = m.Get()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = m.RuleCount()
		}
	}()
	wg.Wait()

	if m.RuleCount() != 1 {
		t.Errorf("esh zamanli erisim sonrasi sayim %d, 1 bekleniyor",
			m.RuleCount())
	}
}

// TestLoadAcceptsEmptyRuleSet protects the EMERGENCY ESCAPE HATCH.
//
// "axctl reload --force-empty" is how an operator stops enforcement
// after a bad policy locks them out. It was broken: the daemon
// rejected any policy with zero rules, so the rescue command itself
// failed with "policy en az bir kural icermeli".
//
// It also broke first-time setup: "axctl init" writes "rules: []"
// and tells the user to run "axctl reload", which then errored.
func TestLoadAcceptsEmptyRuleSet(t *testing.T) {
	m := NewManager()
	snap, err := m.Load([]byte(`{"version":1,"mode":"disabled","rules":[]}`))
	if err != nil {
		t.Fatalf("bos politika reddedildi, acil kurtarma yolu calismiyor: %v", err)
	}
	if snap.Policy.Mode != "disabled" {
		t.Errorf("mod kayboldu: %q", snap.Policy.Mode)
	}
}

// TestLoadRejectsMissingRulesKey guards against the SILENT failure
// that removing the rule-count check would otherwise introduce.
//
// If the user typos the key ("rule:", "ruleset:"), the policy would
// decode to zero rules and the system would silently become
// unrestricted. That is the most dangerous outcome for a security
// tool: the operator believes enforcement is active when nothing
// is being enforced. A missing key must be an explicit error.
func TestLoadRejectsMissingRulesKey(t *testing.T) {
	m := NewManager()
	for _, body := range []string{
		`{"version":1,"mode":"enforcing"}`,
		`{"version":1,"mode":"enforcing","rule":[]}`,
		`{"version":1,"mode":"enforcing","ruleset":[]}`,
	} {
		if _, err := m.Load([]byte(body)); err == nil {
			t.Errorf("'rules' anahtari olmayan politika kabul edildi: %s", body)
		}
	}
}
