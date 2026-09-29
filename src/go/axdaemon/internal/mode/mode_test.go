package mode

import (
	"sync"
	"testing"
)

// TestSetGetRoundTrip covers the three valid modes. This package has
// no test file at all, which is a gap in its own right: it is the
// value the emergency-exit path depends on.
func TestSetGetRoundTrip(t *testing.T) {
	m := NewManager()

	for _, want := range []Mode{ModeEnforcing, ModePermissive, ModeDisabled} {
		if err := m.Set(want); err != nil {
			t.Fatalf("Set(%q) hata verdi: %v", want, err)
		}
		if got := m.Get(); got != want {
			t.Errorf("Set(%q) sonrasi Get() = %q", want, got)
		}
	}
}

// TestDefaultIsPermissive pins the startup value.
//
// Permissive is the safe default: rules are evaluated and audited but
// not enforced, so an operator can see what a policy WOULD block
// before turning it on. Defaulting to enforcing would risk lockout
// from the first policy; defaulting to disabled would look like
// enforcement is off for no visible reason.
func TestDefaultIsPermissive(t *testing.T) {
	m := NewManager()
	if got := m.Get(); got != ModePermissive {
		t.Errorf("varsayilan mod permissive olmali, %q", got)
	}
	if m.IsEnforcing() {
		t.Error("varsayilan mod enforcing olmamali")
	}
	if m.IsDisabled() {
		t.Error("varsayilan mod disabled olmamali")
	}
}

// TestInvalidModeRejected ensures a typo cannot become a mode the
// kernel has no constant for. axbpf.h defines MODE_DISABLED=0,
// MODE_PERMISSIVE=1, MODE_ENFORCING=2; an unmapped string reaching
// mode_map would read as 0 and silently disable enforcement.
func TestInvalidModeRejected(t *testing.T) {
	m := NewManager()
	m.Set(ModeEnforcing)

	for _, bad := range []Mode{"", "ENFORCING", "block", "true", "1"} {
		if err := m.Set(bad); err == nil {
			t.Errorf("gecersiz mod %q kabul edildi", bad)
		}
	}
	// Rejection must leave the previous mode untouched: callers rely
	// on Set failing without side effects.
	if got := m.Get(); got != ModeEnforcing {
		t.Errorf("gecersiz mod denemesi durumu bozdu: %q", got)
	}
}

// TestHelperPredicates covers IsEnforcing/IsDisabled for every mode.
func TestHelperPredicates(t *testing.T) {
	cases := []struct {
		mode                  Mode
		enforcing, isDisabled bool
	}{
		{ModeEnforcing, true, false},
		{ModePermissive, false, false},
		{ModeDisabled, false, true},
	}
	for _, c := range cases {
		m := NewManager()
		m.Set(c.mode)
		if got := m.IsEnforcing(); got != c.enforcing {
			t.Errorf("%q: IsEnforcing = %v, %v bekleniyor",
				c.mode, got, c.enforcing)
		}
		if got := m.IsDisabled(); got != c.isDisabled {
			t.Errorf("%q: IsDisabled = %v, %v bekleniyor",
				c.mode, got, c.isDisabled)
		}
	}
}

// TestConcurrentAccess runs the race detector's scenario: the RPC
// server reads the mode from every request while set_mode changes it
// from another goroutine. The Manager dropped its unused mutex in
// favour of atomic.Value, so this is the test that justifies that
// choice — run with -race it is the only proof the field needs no
// lock.
func TestConcurrentAccess(t *testing.T) {
	m := NewManager()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Set(ModeEnforcing)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Set(ModeDisabled)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = m.Get()
			_ = m.IsEnforcing()
			_ = m.IsDisabled()
		}
	}()

	wg.Wait()

	// Whatever the interleaving, the final value must be one of the
	// three legal modes, not a torn or zero value.
	switch m.Get() {
	case ModeEnforcing, ModePermissive, ModeDisabled:
	default:
		t.Errorf("esh zamanli erisim sonrasi gecersiz mod: %q", m.Get())
	}
}
