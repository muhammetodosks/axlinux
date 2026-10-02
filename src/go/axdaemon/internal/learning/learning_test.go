package learning

import (
	"strings"
	"testing"
	"time"
)

// TestStartStopLifecycle covers the basic state machine. This package
// had no test file at all, despite generating the YAML a user is most
// likely to hand straight to axctl.
func TestStartStopLifecycle(t *testing.T) {
	m := NewManager()

	if m.IsActive() {
		t.Error("yeni manager aktif olmamali")
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start hata verdi: %v", err)
	}
	if !m.IsActive() {
		t.Error("Start sonrasi aktif olmali")
	}
	// Starting twice must be refused, or a second Start would reset
	// observations mid-session without telling the caller.
	if err := m.Start(); err == nil {
		t.Error("cift Start reddedilmeliydi")
	}
	m.Stop()
	if m.IsActive() {
		t.Error("Stop sonrasi pasif olmali")
	}
}

// TestRecordOnlyWhenActive ensures observation does not leak into a
// session that was never started: an inactive manager reporting
// patterns would suggest policy rules for activity AXlinux never saw.
func TestRecordOnlyWhenActive(t *testing.T) {
	m := NewManager()
	m.Record("firefox", "/etc/shadow", "file.read")
	if m.ObservationCount() != 0 {
		t.Error("pasifken kayit tutulmamali")
	}

	m.Start()
	m.Record("firefox", "/etc/shadow", "file.read")
	m.Record("firefox", "/etc/shadow", "file.read")
	if m.ObservationCount() != 1 {
		t.Errorf("ayni ucuzel 1 kalem olmali, %d", m.ObservationCount())
	}

	m.Stop()
	m.Record("nginx", "/var/www", "file.read")
	if m.ObservationCount() != 1 {
		t.Error("Stop sonrasi kayit tutulmamali")
	}
}

// TestElapsedZeroWhenNotStarted covers the zero-time bug.
//
// startedAt defaults to the zero time.Time, and time.Since(zero) is
// the age of the universe. The report used to say "17565 days" when
// learning had never been started.
func TestElapsedZeroWhenNotStarted(t *testing.T) {
	m := NewManager()
	if got := m.Elapsed(); got != 0 {
		t.Errorf("baslatilmamisken Elapsed 0 olmali, %v", got)
	}
	// A report generated before Start must not claim a duration.
	rep := m.GenerateReport()
	if rep.Duration != "" {
		t.Errorf("baslatilmamisken sure bildirilmemeli, %q", rep.Duration)
	}
}

// TestRestartResetsDurationAndObservations pins the Stop behaviour.
func TestRestartResetsDurationAndObservations(t *testing.T) {
	m := NewManager()
	m.Start()
	m.Record("curl", "/etc/passwd", "file.read")
	m.Stop()

	m.Start()
	defer m.Stop()

	if m.ObservationCount() != 0 {
		t.Error("yeniden baslatmada gozlemler sifirlanmali")
	}
	// A stale startedAt would make Elapsed span both sessions.
	//
	// Eski hali "got > 1" diyordu; Go'da turetilmemis 1 sabiti
	// 1 NANOSANIYE'dir, 1 saniye degil. Test surelerce mikrosaniye
	// mertebesinde tamamlandigi icin her gecerli calisma "basarisiz"
	// gorunuyordu - yani bu kontrol aslinda hicbir sey olcmuyordu.
	// Eski bir startedAt kalsaydi sure iki oturumu katlardi ve
	// saniyeyi gecerdi.
	if got := m.Elapsed(); got > time.Second {
		t.Errorf("yeniden baslatmada sure sifirdan sayilmali, %v", got)
	}
}

// TestYAMLQuoteEscapes is the test for a real breakage.
//
// Observed values come from the kernel: paths and process names. They
// can contain quotes, backslashes and colons. Interpolated raw into
// "..." they produced YAML that would not parse, so the report the
// user runs axctl on fails to load and there is no clue why.
func TestYAMLQuoteEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", `"plain"`},
		{`has"quote`, `"has\"quote"`},
		{`back\slash`, `"back\\slash"`},
		{"tab\there", `"tab\there"`},
		{"new\nline", `"new\nline"`},
		{"/tmp/a: b", `"/tmp/a: b"`},
		{"", `""`},
		{"\x01", `"\x01"`},
	}
	for _, c := range cases {
		if got := yamlQuote(c.in); got != c.want {
			t.Errorf("yamlQuote(%q) = %s, beklenen %s",
				c.in, got, c.want)
		}
	}
}

// TestGeneratedYAMLIsWellFormed checks the properties that actually
// matter: quoting is consistent and no raw newline escapes a scalar.
func TestGeneratedYAMLIsWellFormed(t *testing.T) {
	patterns := []Pattern{
		{Subject: "firefox", Object: "/etc/shadow", Action: "file.read", Count: 3},
		// A subject with a quote in it. This is what used to produce
		// unparseable output.
		{Subject: `weird"name`, Object: "/tmp/a: b", Action: "file.write", Count: 1},
	}
	y := generateYAML(patterns)

	for _, want := range []string{
		`subject: ["firefox"]`,
		`object: "/etc/shadow"`,
		`subject: ["weird\"name"]`,
		`object: "/tmp/a: b"`,
		"mode: permissive",
		"effect: allow",
	} {
		if !strings.Contains(y, want) {
			t.Errorf("uretilen YAML'de %q yok:\n%s", want, y)
		}
	}
	// Every scalar must be quoted; a bare value with a colon would
	// break the mapping.
	if strings.Contains(y, `subject: [firefox]`) {
		t.Errorf("subject degeri tirnaksiz:\n%s", y)
	}
}

// TestEmptyReport is a small guard on the degenerate case.
func TestEmptyReport(t *testing.T) {
	m := NewManager()
	m.Start()
	defer m.Stop()

	rep := m.GenerateReport()
	if len(rep.Patterns) != 0 {
		t.Errorf("bos oturumda desen olmamali, %d", len(rep.Patterns))
	}
	if !strings.Contains(rep.YAML, "yok") {
		t.Errorf("bos rapor belirtici olmali:\n%s", rep.YAML)
	}
}
