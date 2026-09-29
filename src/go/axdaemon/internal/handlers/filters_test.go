package handlers

import (
	"testing"

	"axlinux/axdaemon/pkg/protocol"
)

// TestParseSince covers the window parser. A wrong parse here does
// not error visibly: the user asks for "1h" and gets a different
// window, then reads the wrong audit trail believing it is right.
func TestParseSince(t *testing.T) {
	ok := []struct {
		in   string
		want string
	}{
		{"30m", "30m0s"},
		{"2h", "2h0m0s"},
		{"1d", "24h0m0s"},
		{"1w", "168h0m0s"},
		{"45", "45s"},
		{" 1h ", "1h0m0s"},
		{"1H", "1h0m0s"},
		{"3D", "72h0m0s"},
	}
	for _, c := range ok {
		got, err := parseSince(c.in)
		if err != nil {
			t.Errorf("parseSince(%q) hata verdi: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("parseSince(%q) = %s, %s bekleniyor",
				c.in, got, c.want)
		}
	}

	bad := []string{
		"", "abc", "-1h", "0", "0d", "h", "1y", "1.5h", "tomorrow",
	}
	for _, in := range bad {
		if _, err := parseSince(in); err == nil {
			t.Errorf("parseSince(%q) kabul edildi, reddedilmeliydi", in)
		}
	}
}

// row builds a log row the way handleGetLogs does.
func row(comm, path string, action, effect, decision, ruleID uint32) map[string]interface{} {
	return map[string]interface{}{
		"timestamp": uint64(1000),
		"pid":       uint32(42),
		"comm":      comm,
		"path":      path,
		"action":    action,
		"effect":    effect,
		"decision":  decision,
		"rule_id":   ruleID,
	}
}

// TestMatchesFiltersEffect covers the filter that users reach for
// first. Before Filters was read at all, "effect=deny" returned every
// event and looked like it had worked.
func TestMatchesFiltersEffect(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 5) // effect 0 = deny

	if !matchesFilters(r, map[string]any{"effect": "deny"}) {
		t.Error("effect=deny eslesmeli")
	}
	if matchesFilters(r, map[string]any{"effect": "allow"}) {
		t.Error("effect=allow eslesmemeli")
	}
	// Numeric form: the CLI sends strings, but a JSON client may send
	// 0 for deny. Both must land on the same value.
	if !matchesFilters(r, map[string]any{"effect": float64(0)}) {
		t.Error("effect=0 (deny) eslesmeli")
	}
}

// TestMatchesFiltersSubject covers comm/subject aliases.
func TestMatchesFiltersSubject(t *testing.T) {
	r := row("nginx", "/var/www", 1, 0, 1, 2)

	if !matchesFilters(r, map[string]any{"comm": "nginx"}) {
		t.Error("comm=nginx eslesmeli")
	}
	// "subject" is the alias axctl users type.
	if !matchesFilters(r, map[string]any{"subject": "nginx"}) {
		t.Error("subject=nginx (takma ad) eslesmeli")
	}
	if matchesFilters(r, map[string]any{"comm": "apache2"}) {
		t.Error("comm=apache2 eslesmemeli")
	}
}

// TestMatchesFiltersCaseInsensitive: a user typing "Deny" should not
// silently get zero results and conclude there was no activity.
func TestMatchesFiltersCaseInsensitive(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 5)
	if !matchesFilters(r, map[string]any{"effect": "DENY"}) {
		t.Error("buyuk harfli deger eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"comm": " DD "}) {
		t.Error("bosluk kirpilmali ve buyuk/kucuk duyarsiz olmali")
	}
}

// TestMatchesFiltersPathSubstring: filtering a prefix is the common
// case; requiring the exact full path would be unusable.
func TestMatchesFiltersPathSubstring(t *testing.T) {
	r := row("dd", "/etc/shadow", 1, 0, 1, 1)
	if !matchesFilters(r, map[string]any{"path": "/etc/sha"}) {
		t.Error("yol oneki eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"path": "shadow"}) {
		t.Error("yol parcasi eslesmeli")
	}
	if matchesFilters(r, map[string]any{"path": "/var/www"}) {
		t.Error("ilgisiz yol eslesmemeli")
	}
}

// TestMatchesFiltersRuleIDNumeric: JSON numbers arrive as float64, so
// a naive comparison against uint32 never matches.
func TestMatchesFiltersRuleIDNumeric(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 7)
	if !matchesFilters(r, map[string]any{"rule_id": "7"}) {
		t.Error("rule_id=7 (string) eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"rule_id": float64(7)}) {
		t.Error("rule_id=7 (float) eslesmeli")
	}
	if matchesFilters(r, map[string]any{"rule_id": "8"}) {
		t.Error("rule_id=8 eslesmemeli")
	}
}

// TestMatchesFiltersANDCombines: multiple filters are ANDed, not ORed.
// OR would return every event and look like a wide search.
func TestMatchesFiltersANDCombines(t *testing.T) {
	r := row("nginx", "/var/www", 1, 0, 1, 3)
	if !matchesFilters(r, map[string]any{
		"effect": "deny", "comm": "nginx", "action": "file.read",
	}) {
		t.Error("tum eslesen filtreler birlikte eslesmeli")
	}
	if matchesFilters(r, map[string]any{
		"effect": "deny", "comm": "apache2",
	}) {
		t.Error("biri eslesmeyen filtre tum sonucu elemesi")
	}
}

// TestMatchesFiltersEmptyMatchesEverything: no filter means no
// restriction, which is what a bare "axctl logs" asks for.
func TestMatchesFiltersEmptyMatchesEverything(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 1)
	if !matchesFilters(r, nil) {
		t.Error("filtre yoksa her kayit eslesmeli")
	}
	if !matchesFilters(r, map[string]any{}) {
		t.Error("bos filtre her kaydi gecmeli")
	}
}

// TestKnownFilterKey pins the advertised set. The handler reports
// filters_applied from this list, so the two must not drift or a
// user is told a filter was applied when it was not.
func TestKnownFilterKey(t *testing.T) {
	for _, k := range []string{
		"action", "effect", "decision", "comm", "subject",
		"path", "rule_id", "hook",
	} {
		if !knownFilterKey(k) {
			t.Errorf("%q bilinen filtre olmali", k)
		}
	}
	// Typo'da filtre sessizce yok sayilmamali; the handler lists
	// it under filters_ignored.
	for _, k := range []string{"subjct", "effekt", "since", "pid_x", ""} {
		if knownFilterKey(k) {
			t.Errorf("%q bilinen filtre OLMAMALI", k)
		}
	}
}

// TestNormalizeValueRendersWholeNumbers guards the float64 rendering.
// A row value of 7 must normalise to "7", not "7.000000", or a filter
// written as rule_id=7 would not match its own field.
func TestNormalizeValueRendersWholeNumbers(t *testing.T) {
	if got := normalizeValue(float64(7)); got != "7" {
		t.Errorf("normalizeValue(7.0) = %q, \"7\" bekleniyor", got)
	}
	if got := normalizeValue(uint32(7)); got != "7" {
		t.Errorf("normalizeValue(uint32(7)) = %q, \"7\" bekleniyor", got)
	}
	if got := normalizeValue(1.5); got != "1.5" {
		t.Errorf("normalizeValue(1.5) = %q", got)
	}
	if got := normalizeValue(" DENY "); got != "deny" {
		t.Errorf("normalizeValue(\" DENY \") = %q", got)
	}
}

// TestDispatchRejectsUnknownMethod is the boundary check that keeps a
// typo from looking like a successful no-op.
func TestDispatchRejectsUnknownMethod(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)
	resp := h.Dispatch(nil, protocol.Request{
		Method: "definitely_not_a_method",
		ID:     3,
	})
	if resp.Error == nil {
		t.Fatal("bilinmeyen metod hata vermeli")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("kod -32601 olmali, %d", resp.Error.Code)
	}
	if resp.ID != 3 {
		t.Errorf("hata yanitinda ID korunmali, %d", resp.ID)
	}
}

// TestSubstringMatchingIsPathOnly guards a false-positive class.
//
// valueMatches used to fall back to strings.Contains for every field,
// so rule_id=1 matched rule 21 and comm=ngin matched nginx. A filter
// that returns extra rows is worse than one that returns none: the
// extra rows look like real activity and the operator draws the wrong
// conclusion.
func TestSubstringMatchingIsPathOnly(t *testing.T) {
	r := row("nginx", "/etc/shadow", 1, 0, 1, 21)

	if matchesFilters(r, map[string]any{"rule_id": float64(1)}) {
		t.Error("rule_id=1, kural 21'i eslestirmemeli")
	}
	if matchesFilters(r, map[string]any{"comm": "ngin"}) {
		t.Error("comm=ngin, 'nginx'i eslestirmemeli")
	}
	// Exact matches still work on both.
	if !matchesFilters(r, map[string]any{"rule_id": float64(21)}) {
		t.Error("rule_id=21 eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"comm": "nginx"}) {
		t.Error("comm=nginx eslesmeli")
	}
	// Path keeps the prefix behaviour it is documented to have.
	if !matchesFilters(r, map[string]any{"path": "/etc/sha"}) {
		t.Error("path oneki eslesmeli")
	}
}

// TestEmptyFilterValueIsNotAWildcard: a stray "effect=" must not return
// the entire log and read as a match.
func TestEmptyFilterValueIsNotAWildcard(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 5)
	if matchesFilters(r, map[string]any{"effect": ""}) {
		t.Error("bos filtre degerinin tum kayitlari dondurmesi yanlis")
	}
	if matchesFilters(r, map[string]any{"effect": "   "}) {
		t.Error("yalnizca bosluk iceren deger de eslesmemeli")
	}
}

// TestHookFilter: "hook" is an accepted filter key, so the row has to
// carry the field. When it did not, hook=file_open matched nothing and
// read as "no events came from that hook".
func TestHookFilter(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 5)
	r["hook"] = "file_open"

	if !matchesFilters(r, map[string]any{"hook": "file_open"}) {
		t.Error("hook=file_open eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"hook": "FILE_OPEN"}) {
		t.Error("hook filtresi buyuk/kucuk duyarsiz olmali")
	}
	if matchesFilters(r, map[string]any{"hook": "socket_bind"}) {
		t.Error("hook=socket_bind eslesmemeli")
	}
	// A numeric hook id from a JSON client resolves to the same name.
	if !matchesFilters(r, map[string]any{"hook": float64(1)}) {
		t.Error("hook=1 (file_open) eslesmeli")
	}
}

// TestEffectAndDecisionEnumsAreNotMirrors pins the mapping that caused
// "effect=deny" to match nothing. The two enums run in opposite
// directions: effect 0 is deny, decision 0 is allowed. Treating them
// as the same numbering silently swaps allow and deny.
func TestEffectAndDecisionEnumsAreNotMirrors(t *testing.T) {
	denied := row("dd", "/etc/hostname", 1, 0, 1, 5) // effect 0, decision 1
	allowed := row("dd", "/etc/hostname", 1, 1, 0, 5)

	if !matchesFilters(denied, map[string]any{"effect": "deny"}) ||
		!matchesFilters(denied, map[string]any{"decision": "denied"}) {
		t.Error("reddedilen kayit effect=deny ve decision=denied ile eslesmeli")
	}
	if !matchesFilters(allowed, map[string]any{"effect": "allow"}) ||
		!matchesFilters(allowed, map[string]any{"decision": "allowed"}) {
		t.Error("izin verilen kayit effect=allow ve decision=allowed ile eslesmeli")
	}
	// The crossed cases must NOT match.
	if matchesFilters(denied, map[string]any{"effect": "allow"}) ||
		matchesFilters(denied, map[string]any{"decision": "allowed"}) {
		t.Error("reddedilen kayit allow/allowed ile eslesmemeli")
	}
}

// TestActionFilterResolvesNumericAndName covers the action field, which
// has the same numeric-row / name-filter split as the enums.
func TestActionFilterResolvesNumericAndName(t *testing.T) {
	r := row("dd", "/etc/hostname", 1, 0, 1, 5) // action 1 = file.read

	if !matchesFilters(r, map[string]any{"action": "file.read"}) {
		t.Error("action=file.read eslesmeli")
	}
	if !matchesFilters(r, map[string]any{"action": float64(1)}) {
		t.Error("action=1 (file.read) eslesmeli")
	}
	if matchesFilters(r, map[string]any{"action": "file.write"}) {
		t.Error("action=file.write eslesmemeli")
	}
}
