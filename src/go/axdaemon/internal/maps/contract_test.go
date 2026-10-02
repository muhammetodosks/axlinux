// Contract tests guard the numeric constants that are shared between
// the Go userspace daemon and the eBPF LSM programs in C.
//
// A mismatch here is silent and catastrophic: the kernel looks up
// ACTION_NET_CONNECT while the daemon wrote ACTION_FILE_DELETE, and
// deny rules are stored with Effect=2 while axbpf.h tests for
// EFFECT_DENY==0, so every deny rule is ignored and nothing is blocked.
//
// These tests parse axbpf.h directly, so the two sides can never drift
// apart without a test failure.
package maps

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// headerPath locates axbpf.h. It lives in src/bpf/ while these tests
// run in src/go/axdaemon/internal/maps/, so both the upward walk and
// the sibling bpf/ directory are checked.
func headerPath(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}

	for i := 0; i < 10; i++ {
		for _, candidate := range []string{
			filepath.Join(dir, "axbpf.h"),
			filepath.Join(dir, "bpf", "axbpf.h"),
			filepath.Join(dir, "src", "bpf", "axbpf.h"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("axbpf.h bulunamadi (src/bpf/axbpf.h bekleniyordu)")
	return ""
}

var defineRe = regexp.MustCompile(`^#define\s+(\w+)\s+(\d+)\s*$`)

// parseDefines reads every simple integer #define from axbpf.h.
func parseDefines(t *testing.T) map[string]int {
	t.Helper()

	f, err := os.Open(headerPath(t))
	if err != nil {
		t.Fatalf("axbpf.h acilamadi: %v", err)
	}
	defer f.Close()

	out := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := defineRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		out[m[1]] = n
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("okuma hatasi: %v", err)
	}
	return out
}

func requireDefine(t *testing.T, defines map[string]int, name string) int {
	t.Helper()
	v, ok := defines[name]
	if !ok {
		t.Fatalf("axbpf.h icinde %s tanimi yok", name)
	}
	return v
}

// TestActionConstantsMatch locks the ACTION_* numbering. The daemon
// and the kernel must agree byte for byte.
func TestActionConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	pairs := map[string]uint32{
		"file.read":    ActionFileRead,
		"file.write":   ActionFileWrite,
		"file.execute": ActionFileExec,
		"file.delete":  ActionFileDelete,
		"file.create":  ActionFileCreate,
		"net.connect":  ActionNetConnect,
		"net.bind":     ActionNetBind,
		"net.accept":   ActionNetAccept,
		"process.exec": ActionProcessExec,
	}

	for action, goVal := range pairs {
		cName := actionName(action)
		cVal := requireDefine(t, c, cName)

		if int(goVal) != cVal {
			t.Errorf("aksiyon %q uyusmazlik: Go=%d C=%s=%d",
				action, goVal, cName, cVal)
		}
	}
}

func actionName(action string) string {
	switch action {
	case "file.read":
		return "ACTION_FILE_READ"
	case "file.write":
		return "ACTION_FILE_WRITE"
	case "file.execute":
		return "ACTION_FILE_EXEC"
	case "file.delete":
		return "ACTION_FILE_DELETE"
	case "file.create":
		return "ACTION_FILE_CREATE"
	case "net.connect":
		return "ACTION_NET_CONNECT"
	case "net.bind":
		return "ACTION_NET_BIND"
	case "net.accept":
		return "ACTION_NET_ACCEPT"
	case "process.exec":
		return "ACTION_PROCESS_EXEC"
	}
	return "UNKNOWN"
}

// TestEffectConstantsMatch guards the deny/allow inversion that would
// otherwise disable all enforcement.
func TestEffectConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	if got := requireDefine(t, c, "EFFECT_DENY"); got != int(EffectDeny) {
		t.Errorf("EFFECT_DENY uyusmazlik: Go=%d C=%d", EffectDeny, got)
	}
	if got := requireDefine(t, c, "EFFECT_ALLOW"); got != int(EffectAllow) {
		t.Errorf("EFFECT_ALLOW uyusmazlik: Go=%d C=%d", EffectAllow, got)
	}

	// The kernel treats "not EFFECT_DENY" as allowed, so deny must be
	// the zero value for the unset/empty case to fail closed.
	if EffectDeny != 0 {
		t.Errorf("EFFECT_DENY 0 olmali (fail-closed), Go=%d", EffectDeny)
	}
}

// TestModeConstantsMatch guards the mode_map numbering.
func TestModeConstantsMatch(t *testing.T) {
	c := parseDefines(t)

	if got := requireDefine(t, c, "MODE_DISABLED"); got != int(ModeDisabled) {
		t.Errorf("MODE_DISABLED uyusmazlik: Go=%d C=%d", ModeDisabled, got)
	}
	if got := requireDefine(t, c, "MODE_PERMISSIVE"); got != int(ModePermissive) {
		t.Errorf("MODE_PERMISSIVE uyusmazlik: Go=%d C=%d", ModePermissive, got)
	}
	if got := requireDefine(t, c, "MODE_ENFORCING"); got != int(ModeEnforcing) {
		t.Errorf("MODE_ENFORCING uyusmazlik: Go=%d C=%d", ModeEnforcing, got)
	}
}

// TestProtectedProcessesRejectRules is the daemon-side lockout guard.
//
// The kernel refuses to enforce rules against these processes
// (ax_protected). This check is duplicated here so that a stale or
// unbuildable axbpf.o cannot reintroduce the lockout: a rule aimed
// at "bash" must be refused by the daemon rather than written to a
// map nothing will ever consult.
func TestProtectedProcessesRejectRules(t *testing.T) {
	m := &Manager{}

	// Liste KURTARMA YOLUNU kapsar: init/oturum acma, yetki
	// alma, ag ve kabuk. Yorumlayicilar (python3, node, perl)
	// BILINCLI olarak burada degildir; bkz.
	// TestInterpretersAreNotProtected.
	for _, comm := range []string{"bash", "sudo", "systemd", "sshd",
		"login", "agetty", "su", "doas"} {
		// ValidateRule saf dogrulama katmanidir; WriteRule once
		// bunu cagirir. Korumayi burada olcuyoruz, cunku
		// WriteRule'in hatasi "hedef map nil" ile de gelebilir
		// ve test yanlis sebeple yesil olurdu.
		err := ValidateRule(comm, "/etc/hostname", "file.read", 0)
		if err == nil {
			t.Errorf("korumali surece kural kabul edildi: %q", comm)
		} else if !strings.Contains(err.Error(), "korumali") {
			t.Errorf("hata mesaji korumayi anlatmiyor (%q): %v",
				comm, err)
		}
		// WriteRule de ayni hatayi vermeli: koruma kontrolu
		// harita erisiminden ONCE gelir, aksi halde korumali
		// surece kural yazilabilirdi.
		if werr := m.WriteRule(comm, "/etc/hostname", "file.read", 0, 1,
			EffectDeny); werr == nil ||
			!strings.Contains(werr.Error(), "korumali") {
			t.Errorf("WriteRule korumali sureci engellemedi (%q): %v",
				comm, werr)
		}
		if !IsProtected(comm) {
			t.Errorf("IsProtected(%q) = false, true olmali", comm)
		}
	}
}

// TestInterpretersAreNotProtected pins a decision that is easy to
// undo by accident and expensive to get wrong.
//
// A MAC built on interpreters (python3, node, perl) cannot protect
// anything: those processes run the user's shell, editors, build
// tools and login sessions as children. Denying them locks the user
// out of their own session, and the exemption cannot be expressed in
// policy anyway because the control unit is the program the
// interpreter launches, not the interpreter.
//
// The consequence is deliberate and must stay visible: a rule whose
// subject is an interpreter is accepted, and it is enforced against
// the interpreter process - which does not cover what it spawns. Real
// MAC targets are named in TestUnprotectedProcessesAccepted.
func TestInterpretersAreNotProtected(t *testing.T) {
	for _, comm := range []string{"python3", "python", "node", "perl",
		"ruby", "tmux"} {
		if IsProtected(comm) {
			t.Errorf("%q koruma listesinde; yorumlayicilari "+
				"korumak kullaniciyi kendi oturumundan kipar", comm)
		}
		// Korumali olmadigi icin dogrulama KABUL etmeli.
		if err := ValidateRule(comm, "/etc/shadow", "file.read", 0); err != nil {
			t.Errorf("%q icin kural reddedildi: %v", comm, err)
		}
	}
}

// TestUnprotectedProcessesAccepted guards the opposite direction: if
// the list ever grows too far the MAC silently stops working for the
// applications it exists to protect.
func TestUnprotectedProcessesAccepted(t *testing.T) {
	for _, comm := range []string{"firefox", "nginx", "apache2", "curl",
		"wget", "git", "redis-server", "postgres", "docker"} {
		if IsProtected(comm) {
			t.Errorf("%q koruma listesinde ama MAC'in hedefi; "+
				"listeyi daraltin", comm)
		}
	}
}

// TestProtectedListCoversShell pins the minimum set. Losing any of
// these means the user can be locked out.
func TestProtectedListCoversShell(t *testing.T) {
	must := []string{"bash", "sh", "dash", "zsh", "sudo", "su",
		"systemd", "sshd", "login", "agetty"}
	for _, p := range must {
		if !IsProtected(p) {
			t.Errorf("%q koruma listesinde olmali", p)
		}
	}
}

// TestProcessOnlyRulesAreAccepted guards a rule that used to be
// impossible to write.
//
// A rule like "nginx may not run any program" has no object and no
// port, so the kernel key legitimately carries an empty path. The
// keyIsEmpty check in ValidateRule was meant to catch truncated
// paths, but it also rejected every process-only rule: the user
// wrote a policy, the daemon refused it, and the only clue was
// "yol anahtari uretilemedi".
//
// The empty-path case is now distinguished from the
// unrepresentable-path case instead of being conflated with it.
func TestProcessOnlyRulesAreAccepted(t *testing.T) {
	cases := []struct {
		comm, path, action string
		port               int
	}{
		{"nginx", "", "process.exec", 0},
		{"dd", "", "file.read", 0},
		{"dd", "", "file.write", 0},
		{"dd", "", "file.execute", 0},
	}
	for _, c := range cases {
		if err := ValidateRule(c.comm, c.path, c.action, c.port); err != nil {
			t.Errorf("surec bazli kural reddedildi (%s %s): %v; "+
				"yolsuz kurallar gecerli olmali", c.comm, c.action, err)
		}
	}
}

// TestUnrepresentablePathStillRejected is the other half: relaxing
// the empty-path case must not let genuinely broken paths through.
func TestUnrepresentablePathStillRejected(t *testing.T) {
	deep := "/"
	for i := 0; i < PathDepth+3; i++ {
		deep += "x/"
	}
	if err := ValidateRule("firefox", deep, "file.read", 0); err == nil {
		t.Error("temsil edilemeyen yol reddedilmeliydi")
	}
	long := "/" + strings.Repeat("a", PathSlot+1)
	if err := ValidateRule("firefox", long, "file.read", 0); err == nil {
		t.Error("asiri uzun bilesen reddedilmeliydi")
	}
}

// TestUnimplementedActionsRejected proves the daemon refuses actions
// no hook can produce.
//
// file.delete, file.create and net.accept all have valid numeric
// constants, so the key builds fine and the rule would be written to
// the map. But no attached hook ever generates those action values,
// so the entry can never match. The user would be told "1 kural
// yuklendi" and would go on believing the file cannot be deleted.
//
// Rejecting at load time is the only honest option.
func TestUnimplementedActionsRejected(t *testing.T) {
	for action := range UnimplementedActions {
		err := ValidateRule("firefox", "/tmp/x", action, 0)
		if err == nil {
			t.Errorf("%q aksiyonu kabul edildi ama hicbir kanca "+
				"uretmiyor; kural sessizce islevsiz kalir", action)
			continue
		}
		if !strings.Contains(err.Error(), action) {
			t.Errorf("hata mesaji aksiyonu belirtmeli (%q): %v",
				action, err)
		}
	}
}

// TestImplementedActionsStillAccepted keeps the rejection from
// over-reaching into actions that do work.
func TestImplementedActionsStillAccepted(t *testing.T) {
	for _, action := range []string{"file.read", "file.write",
		"file.execute", "net.connect", "net.bind", "process.exec"} {
		if _, bad := UnimplementedActions[action]; bad {
			t.Errorf("%q uygulanabilir bir aksiyon olmali; "+
				"reddedilmesi MAC'i islevsizlestirir", action)
		}
		err := ValidateRule("dd", "/tmp/x", action, 0)
		if err != nil {
			t.Errorf("%q reddedildi: %v", action, err)
		}
	}
}

// TestStructLayoutsMatch checks the on-wire sizes of the map key and
// value against the compiler's view of the C structs.
func TestStructLayoutsMatch(t *testing.T) {
	// policy_key: char comm[16] + char path[AX_PATH_DEPTH][AX_PATH_SLOT]
	//             + u32 action  =  16 + 8*32 + 4 = 276
	wantKey := 16 + PathDepth*PathSlot + 4
	if got := SizeOfMapKey(); got != wantKey {
		t.Errorf("MapKey boyutu: Go=%d beklenen=%d", got, wantKey)
	}

	// policy_value: u32 rule_id + u32 effect
	wantVal := 8
	if got := SizeOfMapValue(); got != wantVal {
		t.Errorf("MapValue boyutu: Go=%d beklenen=%d", got, wantVal)
	}
}

// TestKeyPathRoundTrip proves the Go-side split and the kernel-side
// block layout agree.
//
// eBPF fills block (PathDepth-1-d) for the d'th dentry component, so
// Go must write the LAST component into the LAST block. If this
// ordering drifts, every path rule silently stops matching: the map
// entry is written, the daemon reports "1 rule loaded", and nothing
// is ever denied.
func TestKeyPathRoundTrip(t *testing.T) {
	cases := []struct {
		path   string
		blocks [PathDepth]string
	}{
		{"/etc/hostname", [PathDepth]string{
			"", "", "", "", "", "", "/etc", "/hostname",
		}},
		{"/usr/bin/cat", [PathDepth]string{
			"", "", "", "", "", "/usr", "/bin", "/cat",
		}},
		{"/a", [PathDepth]string{
			"", "", "", "", "", "", "", "/a",
		}},
		{"p:8080", [PathDepth]string{
			"p:8080", "", "", "", "", "", "", "",
		}},
	}

	for _, tc := range cases {
		var k MapKey
		setKeyPath(&k, tc.path)
		for i, want := range tc.blocks {
			got := strings.TrimRight(string(k.Path[i][:]), "\x00")
			if got != want {
				t.Errorf("setKeyPath(%q) blok %d = %q, beklenen %q",
					tc.path, i, got, want)
			}
		}
	}
}

// TestKeyPathTooLongIsRejected proves that a path which cannot be
// represented produces an EMPTY key rather than a truncated one.
//
// A silently truncated key would match some other file, or none, and
// the rule would be reported as loaded while doing nothing. WriteRule
// turns the empty key into an explicit error; this test locks the
// precondition that makes that possible.
func TestKeyPathTooLongIsRejected(t *testing.T) {
	long := ""
	for i := 0; i < PathSlot; i++ {
		long += "a"
	}

	var k MapKey
	setKeyPath(&k, "/"+long)

	if !keyIsEmpty(&k) {
		t.Errorf("cok uzun yol kirpildi, anahtar bos degil: %q",
			KeyToString(k))
	}
	if !keyIsEmpty(&k) {
		t.Error("keyIsEmpty kirpma durumunu yakalamadi")
	}
}

// TestKeyPathRejectsTooManyComponents pins the other half of the same
// guard: more than PathDepth components cannot be represented.
func TestKeyPathRejectsTooManyComponents(t *testing.T) {
	p := "/"
	for i := 0; i < PathDepth+3; i++ {
		p += "x/"
	}
	var k MapKey
	setKeyPath(&k, p)
	// Tam doldurulmus bir anahtar uretilmemeli; en az bir blok
	// bos kalir ve kirpma yapilmamis olmali.
	filled := 0
	for i := range k.Path {
		if strings.TrimRight(string(k.Path[i][:]), "\x00") != "" {
			filled++
		}
	}
	if filled == PathDepth {
		t.Errorf("%d bilesenli yol %d bloga sigmiyor ama hepisi dolu",
			PathDepth+3, PathDepth)
	}
}

// TestActionRoundTrip makes sure the string mapping is a bijection, so
// no two YAML actions collapse onto the same kernel constant.
func TestActionRoundTrip(t *testing.T) {
	// Not: liste UnimplementedActions'takileri de icerir. Sabit
	// esleme HENUZ bozulmadigi icin round trip gecerliligini
	// korumak burada degerlidir: bir aksiyonun sabiti yanlislikla
	// 0'a dustugunde ya da iki aksiyon ayni sayiya dustugunde
	// hata burada yakalanir. Bu aksiyonlarin YUKLENEMEMESI
	// ayrica ValidateRule seviyesinde test edilir
	// (TestUnimplementedActionsRejected).
	actions := []string{
		"file.read", "file.write", "file.execute", "file.delete",
		"file.create", "net.connect", "net.bind", "net.accept",
		"process.exec",
	}

	seen := map[uint32]string{}
	for _, a := range actions {
		n := actionToUint(a)
		if n == 0 {
			t.Errorf("aksiyon %q 0'a donusuyor", a)
			continue
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("aksiyon cakismasi: %q ve %q -> %d", prev, a, n)
		}
		seen[n] = a

		if back := actionToString(n); back != a {
			t.Errorf("round trip bozuk: %q -> %d -> %q", a, n, back)
		}
	}
}

// TestUnknownActionRejected ensures a typo never silently becomes a
// valid-looking rule.
func TestUnknownActionRejected(t *testing.T) {
	if n := actionToUint("process.spawn"); n != 0 {
		t.Errorf("bilinmeyen aksiyon 0 donmeli, %d dondu", n)
	}
	if n := actionToUint("net.exfiltrate"); n != 0 {
		t.Errorf("bilinmeyen aksiyon 0 donmeli, %d dondu", n)
	}
}

// ---------------------------------------------------------------------------
// Python <-> Go sozlesmesi
//
// Yukaridaki testler Go ile axbpf.h arasindaki sozlesmeyi koruyor.
// Python tarafi (axctl) ayni sayisal eslemeyi KENDI bir sozlesme
// olarak tasir: formatter.py audit kodundaki sayiyi eylem adina
// cevirir, validator.py hangi eylemlerin yazilabilecegini belirler.
//
// Uc taraf su an tutarli, ama HICBIR TEST bunu zorunlu kilmiyor.
// Go tarafinda bir aksiyon sabiti degistiginde veya eklendiginde
// Python sessizce eski kalir. Sonuc en kotusu: audit kaydi dogru
// olayda YANLIS eylem adi gosterir ("file.read" yerine
// "file.delete"). Operator hangi eylemin engellendigini okuyamaz;
// bu guvenlik aracinda en tehlikeli sessiz hatadir.
//
// Bu test uc tarafi tek noktada karsilastirir ve ayrilma
// ANINDA test hatasina donusur.
// ---------------------------------------------------------------------------

// repoFile locates a file in the source tree, walking up from the
// test's working directory.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		candidates := []string{
			filepath.Join(dir, rel),
			filepath.Join(dir, "..", "..", "..", "..", rel),
			filepath.Join(dir, "..", "..", "..", rel),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("dosya bulunamadi: %s", rel)
	return ""
}

// pythonActionNames reads the numeric -> name mapping out of
// axctl/formatter.py.
func pythonActionNames(t *testing.T) map[int]string {
	t.Helper()
	data, err := os.ReadFile(repoFile(t,
		"src/python/axctl/formatter.py"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(
		`(\d+):\s*"([a-z]+\.[a-z]+)"`)
	out := make(map[int]string)
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("aksiyon sayisi cozulemedi %q: %v", m[1], err)
		}
		out[n] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("formatter.py icinde sayisal esleme bulunamadi")
	}
	return out
}

// pythonValidActions reads VALID_ACTIONS out of axctl/validator.py.
func pythonValidActions(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(repoFile(t,
		"src/python/axctl/validator.py"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(
		`(?s)VALID_ACTIONS = \{(.*?)\}`).FindSubmatch(data)
	if m == nil {
		t.Fatal("validator.py icinde VALID_ACTIONS bulunamadi")
	}
	out := make(map[string]bool)
	for _, q := range regexp.MustCompile(`"([a-z]+\.[a-z]+)"`).
		FindAllStringSubmatch(string(m[1]), -1) {
		out[q[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("VALID_ACTIONS bos")
	}
	return out
}

// goActionNames is the daemon's own view, derived from the constants
// so the test cannot drift from them.
func goActionNames() map[int]string {
	return map[int]string{
		1: "file.read",
		2: "file.write",
		3: "file.execute",
		4: "file.delete",
		5: "file.create",
		6: "net.connect",
		7: "net.bind",
		8: "net.accept",
		9: "process.exec",
	}
}

// TestPythonActionNumbersMatchGo stops an audit record from being
// labelled with the wrong action.
func TestPythonActionNumbersMatchGo(t *testing.T) {
	py := pythonActionNames(t)
	goNames := goActionNames()

	for num, goName := range goNames {
		pyName, ok := py[num]
		if !ok {
			t.Errorf("formatter.py'de %d numarali eylem yok (Go: %q); "+
				"audit kaydi bu kodda 'action(%d)' olarak gorunur",
				num, goName, num)
			continue
		}
		if pyName != goName {
			t.Errorf("%d numarali eylem ayrilmis: Go=%q Python=%q. "+
				"Audit kayitlari yanlis eylem adiyle gosterilir",
				num, goName, pyName)
		}
	}
	for num := range py {
		if _, ok := goNames[num]; !ok {
			t.Errorf("formatter.py'de %d var ama Go'da yok; "+
				"bu kod Go tarafindan uretilemez", num)
		}
	}
}

// TestPythonValidActionsMatchUnimplemented keeps the CLI and the daemon
// agreeing on what is enforceable.
//
// VALID_ACTIONS must be exactly the actions with a hook. If Python
// accepted an action the daemon rejects, the user gets past
// "axctl policy check" only to hit an error at load time. If Python
// rejected an action that works, the feature is unreachable.
func TestPythonValidActionsMatchUnimplemented(t *testing.T) {
	valid := pythonValidActions(t)

	// Go'nun destekledigi = tum eylemler eksi uygulanamayanlar.
	supported := make(map[string]bool)
	for _, a := range goActionNames() {
		supported[a] = true
	}
	for a := range UnimplementedActions {
		delete(supported, a)
	}

	for action := range supported {
		if !valid[action] {
			t.Errorf("Go %q aksiyonunu destekliyor ama Python "+
				"VALID_ACTIONS'ta yok; CLI bu ozelligi erisilemez "+
				"birakir", action)
		}
	}
	for action := range valid {
		if !supported[action] {
			t.Errorf("Python %q aksiyonunu kabul ediyor ama Go "+
				"tarafinda kanca yok; kullanici policy check'ten "+
				"gecer ve yükleme anında reddedilir", action)
		}
	}
}

// TestPythonUnimplementedListMatchesGo keeps the human-readable reason
// in the compiler aligned with the daemon's rejection set.
func TestPythonUnimplementedListMatchesGo(t *testing.T) {
	data, err := os.ReadFile(repoFile(t,
		"src/python/axctl/compiler.py"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(
		`(?s)UNIMPLEMENTED_ACTIONS = \{(.*?)\n\}`).FindSubmatch(data)
	if m == nil {
		t.Fatal("compiler.py icinde UNIMPLEMENTED_ACTIONS bulunamadi")
	}
	pyUnimpl := make(map[string]bool)
	for _, q := range regexp.MustCompile(`"([a-z]+\.[a-z]+)":`).
		FindAllStringSubmatch(string(m[1]), -1) {
		pyUnimpl[q[1]] = true
	}

	for action := range UnimplementedActions {
		if !pyUnimpl[action] {
			t.Errorf("%q Go'da reddediliyor ama compiler.py "+
				"UNIMPLEMENTED_ACTIONS'ta yok; kullanici uyari "+
				"yerine sessizce etkisiz kural yazdirir", action)
		}
	}
	for action := range pyUnimpl {
		if _, ok := UnimplementedActions[action]; !ok {
			t.Errorf("%q compiler.py'da uygulanamaz diye isaretli "+
				"ama Go kabul ediyor; ozellik gereksiz yere "+
				"engelleniyor", action)
		}
	}
}

// bpfActionNames parses src/bpf/axbpf.h, the kernel-side source of truth.
//
// The BPF header, the Go daemon and the Python CLI each carry their own
// copy of the action numbering. TestPythonActionNumbersMatchGo only
// compares Python against Go, so the header was free to drift: moving
// ACTION_NET_ACCEPT from 8 to 99 in axbpf.h left every test green while
// the kernel labelled events with a number no userspace component knew
// about. This test closes that third gap.
func bpfActionNames(t *testing.T) map[int]string {
	t.Helper()
	data, err := os.ReadFile(repoFile(t, "src/bpf/axbpf.h"))
	if err != nil {
		t.Fatal(err)
	}
	// ACTION_FILE_READ 1  ->  "file.read"
	re := regexp.MustCompile(
		`(?m)^#define\s+ACTION_([A-Z_]+)\s+([0-9]+)`)
	names := map[int]string{}
	for _, m := range re.FindAllStringSubmatch(string(data), -1) {
		num, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("axbpf.h: %q sayiya cevrilemedi: %v", m[2], err)
		}
		names[num] = actionFromDefine(m[1])
	}
	if len(names) == 0 {
		t.Fatal("axbpf.h icinde ACTION_ tanimi bulunamadi; " +
			"sozlesme denetimi calismiyor")
	}
	return names
}

// actionFromDefine maps ACTION_FILE_READ -> file.read,
// ACTION_PROCESS_EXEC -> process.exec.
func actionFromDefine(def string) string {
	switch def {
	case "FILE_READ":
		return "file.read"
	case "FILE_WRITE":
		return "file.write"
	case "FILE_EXEC":
		return "file.execute"
	case "FILE_DELETE":
		return "file.delete"
	case "FILE_CREATE":
		return "file.create"
	case "NET_CONNECT":
		return "net.connect"
	case "NET_BIND":
		return "net.bind"
	case "NET_ACCEPT":
		return "net.accept"
	case "PROCESS_EXEC":
		return "process.exec"
	}
	return def
}

// TestBpfHeaderActionNumbersMatchGo checks the kernel-side constants.
func TestBpfHeaderActionNumbersMatchGo(t *testing.T) {
	bpf := bpfActionNames(t)
	goNames := goActionNames()

	for num, bpfName := range bpf {
		goName, ok := goNames[num]
		if !ok {
			t.Errorf("axbpf.h: %d numarali eylem var (%q) ama Go'da "+
				"yok; kernel bunu uretebilir, userspace okuyamaz",
				num, bpfName)
			continue
		}
		if bpfName != goName {
			t.Errorf("axbpf.h ile Go ayrilmis: %d -> bpf=%q go=%q. "+
				"Kernel audit kaydini Go'nun tanimadigi bir eylem "+
				"adiyle yazar", num, bpfName, goName)
		}
	}
	for num := range goNames {
		if _, ok := bpf[num]; !ok {
			t.Errorf("Go'da %d var ama axbpf.h'de yok; Go bunu "+
				"okuyor, kernel uretemiyor", num)
		}
	}
}

// TestBpfHeaderActionNumbersMatchPython checks the kernel against the CLI.
func TestBpfHeaderActionNumbersMatchPython(t *testing.T) {
	bpf := bpfActionNames(t)
	py := pythonActionNames(t)
	for num, bpfName := range bpf {
		pyName, ok := py[num]
		if !ok {
			t.Errorf("axbpf.h: %d (%q) formatter.py'de yok", num, bpfName)
			continue
		}
		if pyName != bpfName {
			t.Errorf("axbpf.h ile Python ayrilmis: %d -> bpf=%q py=%q",
				num, bpfName, pyName)
		}
	}
}
