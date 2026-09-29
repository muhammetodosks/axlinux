package models

import (
	"testing"
	"time"
)

// TestFilterMatch is the core predicate behind every log query. A
// filter that returns true too easily looks like a working filter
// that happens to return extra rows; one that returns true too
// rarely looks like there was no activity. Both are silent.
func TestFilterMatch(t *testing.T) {
	base := AuditEvent{
		Timestamp: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		Action:    "file.read",
		Effect:    "deny",
		Decision:  "denied",
		Subject:   Subject{PID: 100, Comm: "firefox"},
	}

	cases := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"bos filtre her seyi gecirir", Filter{}, true},
		{"eslesen action", Filter{Action: "file.read"}, true},
		{"farkli action", Filter{Action: "net.bind"}, false},
		{"eslesen effect", Filter{Effect: "deny"}, true},
		{"farkli effect", Filter{Effect: "allow"}, false},
		{"eslesen subject", Filter{Subject: "firefox"}, true},
		{"farkli subject", Filter{Subject: "nginx"}, false},
		{"eslesen decision", Filter{Decision: "denied"}, true},
		{"farkli decision", Filter{Decision: "allowed"}, false},

		// Since: only events at or after the cut are kept. This is
		// the boundary that decides whether a query is "the last
		// hour" or "everything after the last hour".
		{"since esinde", Filter{Since: base.Timestamp}, true},
		{"since sonrasi", Filter{Since: base.Timestamp.Add(time.Hour)}, false},
		{"since oncesi", Filter{Since: base.Timestamp.Add(-time.Hour)}, true},
		{"bos since her seyi gecirir", Filter{Since: time.Time{}}, true},
	}

	for _, c := range cases {
		if got := c.filter.Match(base); got != c.want {
			t.Errorf("%s: Match = %v, %v bekleniyor",
				c.name, got, c.want)
		}
	}
}

// TestFilterCombinesWithAND: every set field must constrain. If one
// were ignored, "effect=deny,subject=nginx" would return every
// denial, which reads as a correct but broader search.
func TestFilterCombinesWithAND(t *testing.T) {
	e := AuditEvent{
		Action:  "file.read",
		Effect:  "deny",
		Subject: Subject{Comm: "firefox"},
	}
	if !(Filter{Action: "file.read", Effect: "deny"}).Match(e) {
		t.Error("iki eslesen alan birlikte eslesmeli")
	}
	if (Filter{Action: "file.read", Effect: "allow"}).Match(e) {
		t.Error("biri eslesmeyen alan sonucu elemesi")
	}
	// Filter.Subject bir string alan; Subject YAPISI event'in alanidir.
	if (Filter{Action: "file.read", Subject: "nginx"}).Match(e) {
		t.Error("eslesmeyen subject sonucu elemesi")
	}
}

// TestFilterIsCaseInsensitive guards a false all-clear.
//
// Stored effects are lowercase. A user typing "DENY" against stored
// "deny" used to get zero rows and conclude there had been no
// activity, which is the worst outcome an audit query can produce.
func TestFilterIsCaseInsensitive(t *testing.T) {
	e := AuditEvent{
		Action:   "file.read",
		Effect:   "deny",
		Decision: "denied",
		Subject:  Subject{Comm: "firefox"},
	}
	for _, c := range []struct {
		name   string
		filter Filter
	}{
		{"buyuk harf effect", Filter{Effect: "DENY"}},
		{"karisik harf effect", Filter{Effect: "Deny"}},
		{"buyuk harf action", Filter{Action: "FILE.READ"}},
		{"buyuk harf subject", Filter{Subject: "FIREFOX"}},
		{"buyuk harf decision", Filter{Decision: "DENIED"}},
	} {
		if !c.filter.Match(e) {
			t.Errorf("%s: eslesmeli", c.name)
		}
	}
	// And the other direction: a wrong value must still not match.
	if (Filter{Effect: "allow"}).Match(e) {
		t.Error("yanlis deger eslesmemeli")
	}
	// Different lengths never match, which is where a naive
	// byte-prefix implementation would be wrong.
	if (Filter{Effect: "den"}).Match(e) {
		t.Error("kisaltilmis deger eslesmemeli")
	}
}

// TestEmptyEventDoesNotMatchEverything: a zero-valued event still
// has to satisfy an empty filter. That is what makes a corrupt line
// show up as a row rather than vanishing.
func TestEmptyEventDoesNotMatchEverything(t *testing.T) {
	var e AuditEvent
	if !(Filter{}).Match(e) {
		t.Error("bos filtreye bos olay eslesmeli")
	}
	if (Filter{Action: "file.read"}).Match(e) {
		t.Error("bos olay herhangi bir filtreyle eslesmemeli")
	}
}
