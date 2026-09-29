package reader

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axlinux/axlog/internal/models"
)

// newGzip is a small indirection so the gzip import is used by the
// test rather than by the production path, which opens files itself.
func newGzip(w *os.File) *gzip.Writer { return gzip.NewWriter(w) }

func writeJSONL(t *testing.T, path string, events ...models.AuditEvent) {
	t.Helper()
	var b strings.Builder
	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0640); err != nil {
		t.Fatalf("yazilamadi %s: %v", path, err)
	}
}

func ev(comm, action, effect string) models.AuditEvent {
	return models.AuditEvent{
		Timestamp: time.Now().UTC(),
		Type:      "lsm",
		Hook:      "file_open",
		Subject:   models.Subject{PID: 100, Comm: comm},
		Object:    models.Object{Path: "/etc/shadow"},
		Action:    action,
		Effect:    effect,
		Decision:  "denied",
	}
}

// TestQueryReadsAllDays is the baseline: a query over two days must
// see both. Results are appended per file, so a missed file is a
// silent gap.
func TestQueryReadsAllDays(t *testing.T) {
	dir := t.TempDir()
	writeJSONL(t, filepath.Join(dir, "audit-2026-01-01.jsonl"),
		ev("firefox", "file.read", "deny"))
	writeJSONL(t, filepath.Join(dir, "audit-2026-01-02.jsonl"),
		ev("nginx", "file.read", "deny"))

	r := NewReader(dir)
	got, err := r.Query(models.Filter{})
	if err != nil {
		t.Fatalf("Query hata verdi: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("2 kayit bekleniyor, %d geldi", len(got))
	}
}

// TestUnreadableFileIsReported is the test for the silent gap.
//
// readFromFile's error used to be discarded with `continue`. A corrupt
// .gz or a file that vanished between listing and opening meant that
// whole day disappeared, and the caller saw "no events" — which reads
// as "nothing happened" rather than "we cannot see what happened".
func TestUnreadableFileIsReported(t *testing.T) {
	dir := t.TempDir()
	// One readable day, one corrupt archive.
	writeJSONL(t, filepath.Join(dir, "audit-2026-01-01.jsonl"),
		ev("firefox", "file.read", "deny"))
	bad := filepath.Join(dir, "audit-2026-01-02.jsonl.gz")
	if err := os.WriteFile(bad, []byte("bu gzip degil"), 0640); err != nil {
		t.Fatal(err)
	}

	r := NewReader(dir)
	got, err := r.Query(models.Filter{})

	// Results for the readable day are still returned: a partial
	// answer beats no answer, provided the caller is told.
	if len(got) != 1 {
		t.Errorf("okunabilen gunden 1 kayit bekleniyor, %d", len(got))
	}
	if err == nil {
		t.Fatal("bozuk dosya sessizce yutulmamali")
	}
	pe, ok := err.(*PartialError)
	if !ok {
		t.Fatalf("*PartialError bekleniyordu, %T: %v", err, err)
	}
	if len(pe.Files) != 1 {
		t.Errorf("1 sorunlu dosya bekleniyor, %d: %v", len(pe.Files), pe.Files)
	}
	if !strings.Contains(pe.Error(), "2026-01-02") {
		t.Errorf("hata hangi tarihin eksik oldugunu belirtmeli: %s", pe.Error())
	}
}

// TestTempFilesIgnored: writer.go creates .tmp files during rotation.
// Reading one would surface half-written lines.
func TestTempFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	writeJSONL(t, filepath.Join(dir, "audit-2026-01-01.jsonl"),
		ev("firefox", "file.read", "deny"))
	if err := os.WriteFile(
		filepath.Join(dir, "audit-2026-01-02.jsonl.tmp"),
		[]byte("{\"yarim\""), 0640); err != nil {
		t.Fatal(err)
	}

	r := NewReader(dir)
	got, err := r.Query(models.Filter{})
	if err != nil {
		t.Fatalf("Query hata verdi: %v", err)
	}
	if len(got) != 1 {
		t.Errorf(".tmp dosyasi okunmamali, %d kayit geldi", len(got))
	}
}

// TestListFilesIsSorted pins the ordering dependency. Tail opens the
// last element as "the newest file"; relying on os.ReadDir to happen
// to sort is not a contract.
func TestListFilesIsSorted(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"2026-03-01", "2026-01-15", "2026-02-20"} {
		writeJSONL(t, filepath.Join(dir, "audit-"+d+".jsonl"),
			ev("firefox", "file.read", "deny"))
	}
	r := NewReader(dir)
	files, err := r.listFiles()
	if err != nil {
		t.Fatalf("listFiles: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("3 dosya bekleniyor, %d", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i-1] > files[i] {
			t.Errorf("sirali degil: %s > %s", files[i-1], files[i])
		}
	}
	// Newest last: that is what Tail opens.
	newest := filepath.Base(files[len(files)-1])
	if newest != "audit-2026-03-01.jsonl" {
		t.Errorf("en yeni dosya bekleniyordu, %s", newest)
	}
}

// TestGzippedDaysAreRead closes a real gap: writer.go compresses old
// days to .jsonl.gz and removes the plain file. The reader only
// matched ".jsonl", so compressed history was invisible.
func TestGzippedDaysAreRead(t *testing.T) {
	dir := t.TempDir()
	// Build a real gzip file using the same shape writer.go produces.
	gzPath := filepath.Join(dir, "audit-2025-12-31.jsonl.gz")
	raw, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := newGzip(raw)
	data, _ := json.Marshal(ev("firefox", "file.read", "deny"))
	gz.Write(data)
	// *gzip.Writer WriteByte sunmaz; Write kullanilir.
	if _, err := gz.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	r := NewReader(dir)
	got, err := r.Query(models.Filter{})
	if err != nil {
		t.Fatalf("Query hata verdi: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("sikistirilmis gunden 1 kayit bekleniyor, %d", len(got))
	}
	if got[0].Subject.Comm != "firefox" {
		t.Errorf("kayit yanlis: %+v", got[0])
	}
}

// TestFilterNarrows is the other direction: filters must still work
// after the partial-error plumbing.
func TestFilterNarrows(t *testing.T) {
	dir := t.TempDir()
	writeJSONL(t, filepath.Join(dir, "audit-2026-01-01.jsonl"),
		ev("firefox", "file.read", "deny"),
		ev("nginx", "net.bind", "deny"),
		ev("firefox", "net.connect", "deny"))

	r := NewReader(dir)
	got, err := r.Query(models.Filter{Subject: "firefox"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("subject filtresi 2 kayit bekleniyor, %d", len(got))
	}
	for _, e := range got {
		if e.Subject.Comm != "firefox" {
			t.Errorf("filtre sizmis: %+v", e)
		}
	}
}
