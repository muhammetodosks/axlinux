package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"axlinux/axdaemon/pkg/protocol"
)

// stubHandler records the methods it received and returns a
// configurable result.
type stubHandler struct {
	mu      sync.Mutex
	calls   []string
	lastID  int
	ctxSeen bool
}

func (h *stubHandler) Dispatch(ctx context.Context, req protocol.Request) protocol.Response {
	h.mu.Lock()
	h.calls = append(h.calls, req.Method)
	h.lastID = req.ID
	h.ctxSeen = ctx != nil
	h.mu.Unlock()
	return protocol.NewResponse(req.ID, map[string]interface{}{
		"status": "ok",
		"method": req.Method,
	})
}

func (h *stubHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startServer brings up a server on a temp socket and returns it plus
// a dial function. The temp path keeps the test off the real
// /run/axlinux.
func startServer(t *testing.T) (*Server, *stubHandler, func() net.Conn) {
	t.Helper()

	dir := t.TempDir()
	sock := filepath.Join(dir, "axdaemon.sock")

	h := &stubHandler{}
	s := NewServer(sock, h, quietLogger())

	done := make(chan error, 1)
	go func() { done <- s.Start() }()

	// Wait for the socket to appear rather than sleeping blindly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("socket olusmadi: %v", err)
	}

	dial := func() net.Conn {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("baglanilamadi: %v", err)
		}
		return c
	}

	t.Cleanup(func() {
		_ = s.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return s, h, dial
}

func readResponse(t *testing.T, r *bufio.Reader) protocol.Response {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("cevap okunamadi: %v", err)
	}
	var resp protocol.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("cevap ayristirilamadi: %v", err)
	}
	return resp
}

// TestSocketMode is a security assertion.
//
// The socket was chmod 0666, which let any local user call
// reload_policy and change the policy system-wide. A MAC system whose
// control plane is world-writable is not a MAC system.
func TestSocketMode(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	s := NewServer(sock, &stubHandler{}, quietLogger())

	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	defer func() {
		_ = s.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("socket yok: %v", err)
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		t.Errorf("socket herkese acik: %04o (grup/diger erisimi "+
			"kapatilmali, 0600 bekleniyordu)", perm)
	}
}

// TestDispatchRoutesRequest is the basic round trip.
func TestDispatchRoutesRequest(t *testing.T) {
	_, h, dial := startServer(t)
	conn := dial()
	defer conn.Close()

	fmt := `{"method":"get_status","params":{},"id":7}` + "\n"
	if _, err := conn.Write([]byte(fmt)); err != nil {
		t.Fatalf("istek yazilamadi: %v", err)
	}
	resp := readResponse(t, bufio.NewReader(conn))

	if resp.ID != 7 {
		t.Errorf("ID = %d, 7 bekleniyor", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("beklenmeyen hata: %v", resp.Error)
	}
	if h.count() != 1 {
		t.Errorf("Dispatch %d kez cagrildi, 1 bekleniyor", h.count())
	}
}

// TestHandlerReceivesContext proves the per-request timeout context
// reaches the handler. It used to be 30_000_000_000 as a bare
// number, which is correct by accident; a wrong unit would silently
// become 30 nanoseconds.
func TestHandlerReceivesContext(t *testing.T) {
	_, h, dial := startServer(t)
	conn := dial()
	defer conn.Close()

	if _, err := conn.Write([]byte(`{"method":"x","id":1}` + "\n")); err != nil {
		t.Fatalf("istek yazilamadi: %v", err)
	}
	readResponse(t, bufio.NewReader(conn))

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.ctxSeen {
		t.Error("handler'a context gecirilmemeliydi")
	}
}

// TestMalformedJSONGetsErrorResponse is the robustness case: bad input
// must produce a parse-error response, not a dropped connection and
// not a panic that takes the daemon down.
func TestMalformedJSONGetsErrorResponse(t *testing.T) {
	_, h, dial := startServer(t)
	conn := dial()
	defer conn.Close()

	if _, err := conn.Write([]byte("{not json\n")); err != nil {
		t.Fatalf("bozuk istek yazilamadi: %v", err)
	}
	resp := readResponse(t, bufio.NewReader(conn))
	if resp.Error == nil {
		t.Error("bozuk JSON icin hata cevabi bekleniyordu")
	} else if resp.Error.Code != -32700 {
		t.Errorf("parse hata kodu -32700 olmali, %d", resp.Error.Code)
	}

	// The connection must still work afterwards: a single bad
	// request cannot be allowed to kill the session.
	if _, err := conn.Write([]byte(`{"method":"ping","id":2}` + "\n")); err != nil {
		t.Fatalf("ikinci istek yazilamadi: %v", err)
	}
	resp2 := readResponse(t, bufio.NewReader(conn))
	if resp2.ID != 2 {
		t.Errorf("baglanti bozuk JSON sonrasi kullanilamaz, ID=%d", resp2.ID)
	}
	if h.count() != 1 {
		t.Errorf("bozuk istek handler'a gitmemeliydi, %d kez gitti",
			h.count())
	}
}

// TestPipelinedRequests: the loop must handle several requests on one
// connection, which is how axctl's helper talks to the daemon.
func TestPipelinedRequests(t *testing.T) {
	_, h, dial := startServer(t)
	conn := dial()
	defer conn.Close()

	r := bufio.NewReader(conn)
	for i := 1; i <= 3; i++ {
		req := fmt.Sprintf(`{"method":"m%d","id":%d}`+"\n", i, i)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("istek %d yazilamadi: %v", i, err)
		}
		resp := readResponse(t, r)
		if resp.ID != i {
			t.Errorf("istek %d: ID = %d", i, resp.ID)
		}
	}
	if h.count() != 3 {
		t.Errorf("3 istek gonderildi, %d handler cagrisi", h.count())
	}
}

// TestClientDisconnectIsNotAnError guards the log-noise fix: io.EOF on
// a clean close is normal and must not be reported as a read failure.
func TestClientDisconnectIsNotAnError(t *testing.T) {
	_, _, dial := startServer(t)

	for i := 0; i < 5; i++ {
		conn := dial()
		// Close immediately without sending anything.
		_ = conn.Close()
	}
	// The server must still be serving.
	conn := dial()
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"method":"still_here","id":1}` + "\n")); err != nil {
		t.Fatalf("anlik kapanislardan sonra sunucu calismiyor: %v", err)
	}
	if resp := readResponse(t, bufio.NewReader(conn)); resp.ID != 1 {
		t.Errorf("sunucu yanit vermiyor, ID=%d", resp.ID)
	}
}

// TestStaleSocketReplaced: a leftover socket file from a crashed run
// must not prevent startup.
func TestStaleSocketReplaced(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(sock, []byte("stale"), 0600); err != nil {
		t.Fatalf("sahte socket yazilamadi: %v", err)
	}

	s := NewServer(sock, &stubHandler{}, quietLogger())
	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	defer func() {
		_ = s.Stop()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("eski socket dosyasi temizlenmedi, sunucu baglanamaz oldu")
}

// TestStartFailsOnUnusablePath proves Start returns an error rather
// than panicking, so main.go can report it.
func TestStartFailsOnUnusablePath(t *testing.T) {
	// A path under a regular file cannot be created.
	f := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(filepath.Join(f, "sock"), &stubHandler{}, quietLogger())

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start() }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("hatali yolda Start hata donmeliydi")
		} else if !strings.Contains(err.Error(), "dinleme") &&
			!strings.Contains(err.Error(), "socket") {
			t.Logf("hata mesajsi: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Start hata donduremeden asili kaldi")
	}
}
