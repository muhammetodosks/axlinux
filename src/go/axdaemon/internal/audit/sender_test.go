package audit

import (
	"os"
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startFakeAxlog creates a Unix socket that collects the lines it
// receives, standing in for the axlog service.
func startFakeAxlog(t *testing.T) (path string, lines <-chan string) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "axlog.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("sahte axlog dinlenemedi: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	out := make(chan string, 64)
	go func() {
		defer close(out)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					out <- strings.TrimRight(string(line), "\n")
				}
			}(conn)
		}
	}()

	return sock, out
}

func event() Event {
	var e Event
	e.PID = 4242
	copy(e.Comm[:], "dd")
	e.Action = 1 // file.read
	e.Effect = 0 // deny
	e.Decision = 1
	e.RuleID = 7
	e.HookType = 1 // file_open
	copy(e.Path[0][:], "/etc/hostname")
	return e
}

// TestUnixSenderDeliversAndPersists is the coverage for the missing
// piece this sender fills: nothing was ever written to disk, because
// main.go passed nil. An audit trail that exists only in the daemon's
// memory is lost exactly when it is needed.
func TestUnixSenderDeliversAndPersists(t *testing.T) {
	sock, lines := startFakeAxlog(t)
	s := NewUnixSender(sock)
	defer s.Close()

	if err := s.Send(event()); err != nil {
		t.Fatalf("Send hata verdi: %v", err)
	}

	select {
	case line := <-lines:
		var got map[string]interface{}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("gonderilen satir JSON degil: %v\n%s", err, line)
		}
		subject, ok := got["subject"].(map[string]interface{})
		if !ok {
			t.Fatalf("subject alani eksik: %s", line)
		}
		if subject["comm"] != "dd" {
			t.Errorf("comm = %v, dd bekleniyor", subject["comm"])
		}
		if subject["pid"] != float64(4242) {
			t.Errorf("pid = %v, 4242 bekleniyor", subject["pid"])
		}
		obj, ok := got["object"].(map[string]interface{})
		if !ok || obj["path"] != "/etc/hostname" {
			t.Errorf("object.path = %v, /etc/hostname bekleniyor", got["object"])
		}
		if got["action"] != "file.read" {
			t.Errorf("action = %v, file.read bekleniyor", got["action"])
		}
		if got["decision"] != "denied" {
			t.Errorf("decision = %v, denied bekleniyor", got["decision"])
		}
		if got["hook"] != "file_open" {
			t.Errorf("hook = %v, file_open bekleniyor", got["hook"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("axlog'a kayit ulasmadi")
	}
}

// TestUnixSenderReconnectsAfterAxlogRestart is why the connection is
// lazy. axlog is a separate service; it may start after the daemon or
// restart. A sender that latched onto a dead connection would drop
// every subsequent record.
func TestUnixSenderReconnectsAfterAxlogRestart(t *testing.T) {
	sock, lines := startFakeAxlog(t)
	s := NewUnixSender(sock)

	if err := s.Send(event()); err != nil {
		t.Fatalf("ilk gonderim basarisiz: %v", err)
	}
	select {
	case <-lines:
	case <-time.After(2 * time.Second):
		t.Fatal("ilk kayit ulasmadi")
	}

	// Simulate axlog going away and coming back on the same path.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	sock2, lines2 := startFakeAxlogAt(t, sock)
	if sock2 != sock {
		t.Fatalf("socket yolu degisti: %s != %s", sock2, sock)
	}

	if err := s.Send(event()); err != nil {
		t.Fatalf("yeniden baglanma basarisiz: %v", err)
	}
	select {
	case <-lines2:
	case <-time.After(2 * time.Second):
		t.Fatal("yeniden baglanildiktan sonra kayit ulasmadi")
	}
}

// startFakeAxlogAt restarts the fake on an explicit path.
func startFakeAxlogAt(t *testing.T, path string) (string, <-chan string) {
	t.Helper()
	// Onceki dinleyici kapandi ama Unix domain soket DOSYASI
	// silinmez; bu yuzden ayni yola yeniden dinlenmeden once
	// bayat dosya kaldirilmalidir. Gercek axlog sunucusu da
	// Start icinde ayni seyi yapar; test de sunucunun davranisini
	// taklit etmelidir, yoksa yeniden baslatma yolu test edilemez.
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("yeniden dinlenemedi: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	out := make(chan string, 64)
	go func() {
		defer close(out)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					out <- strings.TrimRight(string(line), "\n")
				}
			}(conn)
		}
	}()
	return path, out
}

// TestUnixSenderReportsMissingSocket covers the state a fresh boot
// hits: the daemon can start before axlog, and every Send must fail
// loudly rather than silently buffering into nothing.
func TestUnixSenderReportsMissingSocket(t *testing.T) {
	s := NewUnixSender(filepath.Join(t.TempDir(), "yok.sock"))
	defer s.Close()

	err := s.Send(event())
	if err == nil {
		t.Fatal("olmayan socket'a gonderim sessizce basarili olmamali")
	}
	if !strings.Contains(err.Error(), "axlog") {
		t.Errorf("hata mesaji axlog'u belirtmeli: %v", err)
	}
	_, failed := s.Stats()
	if failed != 1 {
		t.Errorf("basarisiz sayaci = %d, 1 bekleniyor", failed)
	}
	if s.Health() == "" {
		t.Error("Health() son hatayi bildirmeli")
	}
}

// TestTimestampIsWallClock guards a subtle corruption.
//
// The kernel timestamp is bpf_ktime_get_ns, monotonic since boot. It
// is NOT a Unix epoch. Writing it into a "timestamp" field produces
// records dated 1970, which makes the log useless for incident
// response even though every line parses.
func TestTimestampIsWallClock(t *testing.T) {
	s := NewUnixSender("")
	e := event()
	// A raw ktime value: ~6.5 years in nanoseconds for a typical
	// uptime. As a Unix timestamp this is 1970.
	e.Timestamp = uint64(205 * 24 * 3600 * 1000000000)

	out := s.toAxlogEvent(e)
	ts, err := time.Parse(time.RFC3339Nano, out.Timestamp)
	if err != nil {
		t.Fatalf("zaman damgasi ayristirilamadi: %v", err)
	}
	if ts.Year() < 2020 {
		t.Errorf("zaman damgasi duvar saati olmali, %s", ts)
	}
}

// TestNameMappingsMatchKernelConstants keeps the human-readable names
// in sync with axbpf.h. A mismatch writes wrong action names into the
// permanent record, where nothing would ever notice.
func TestNameMappingsMatchKernelConstants(t *testing.T) {
	actionCases := map[uint32]string{
		1: "file.read", 2: "file.write", 3: "file.execute",
		4: "file.delete", 5: "file.create", 6: "net.connect",
		7: "net.bind", 8: "net.accept", 9: "process.exec",
	}
	for num, want := range actionCases {
		if got := ActionName(num); got != want {
			t.Errorf("ActionName(%d) = %q, %q bekleniyor", num, got, want)
		}
	}
	hookCases := map[uint32]string{
		1: "file_open", 2: "inode_permission",
		3: "bprm_check_security", 4: "socket_connect", 5: "socket_bind",
	}
	for num, want := range hookCases {
		if got := hookNames[num]; got != want {
			t.Errorf("hookNames[%d] = %q, %q bekleniyor", num, got, want)
		}
	}
	// EFFECT_DENY is 0 and EFFECT_ALLOW is 1 in axbpf.h. Getting
	// these backwards writes "allow" for every denial.
	if EffectName(0) != "deny" || EffectName(1) != "allow" {
		t.Errorf("effect adlari ters: 0=%q 1=%q", EffectName(0), EffectName(1))
	}
	// DECISION_DENIED is 1, DECISION_ALLOWED is 0.
	if DecisionName(1) != "denied" || DecisionName(0) != "allowed" {
		t.Errorf("decision adlari ters: 0=%q 1=%q",
			DecisionName(0), DecisionName(1))
	}
}
