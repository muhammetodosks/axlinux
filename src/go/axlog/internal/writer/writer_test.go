package writer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"axlinux/axlog/internal/models"
)

func ev(n int) models.AuditEvent {
	return models.AuditEvent{
		Timestamp: time.Now().UTC(),
		Type:      "lsm",
		Mode:      "enforcing",
		Hook:      "file_open",
		Subject:   models.Subject{PID: uint32(1000 + n), Comm: "cat"},
		Object:    models.Object{Path: "/home/axdesktop/gizli-dosya"},
		Action:    "file.read",
		Effect:    "deny",
		Decision:  "denied",
	}
}

// TestRotateOnSize, 10 MB siniri asildiginda GERCEKTEN yeni bir
// dosya acildigini kanitlar.
//
// Bu test olmadan rotasyon sessizce calismiyordu: openCurrent() her
// zaman bugunun tarihiyle dosya adi uretiyordu, boyut siniri
// tetiklendiginde ayni dosya O_APPEND ile yeniden aciliyordu.
// Dosya 10 MB'yi gectigi halde buyumeye devam ediyordu; VM'de
// 10.798.351 bayta ulasmis bir dosya olustu.
func TestRotateOnSize(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(dir, false)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	first := w.CurrentFile()

	// Siniri asmaya zorla. Tek bir kayit sinirdan kucuk; yeterli
	// kayit biriktirilir.
	written := 0
	for i := 0; i < 200000; i++ {
		if err := w.Write(ev(i)); err != nil {
			t.Fatalf("Write #%d: %v", i, err)
		}
		written++

		// Ilk dosya siniri asinca yeniden ad degistirmeli.
		if written > 100 && w.CurrentFile() != first {
			break
		}
	}

	if w.CurrentFile() == first {
		t.Fatalf("10 MB siniri asildi ama dosya degismedi: %s", first)
	}

	info, err := os.Stat(first)
	if err != nil {
		t.Fatalf("ilk dosya bulunamadi: %v", err)
	}
	if info.Size() > maxFileSize+1024 {
		t.Errorf("ilk dosya sinirin cok ustunde: %d bayt (sinir %d)",
			info.Size(), int64(maxFileSize))
	}

	// Yeni dosya gercekten ayri ve yazilabilir olmali.
	newInfo, err := os.Stat(w.CurrentFile())
	if err != nil {
		t.Fatalf("yeni dosya bulunamadi: %v", err)
	}
	if newInfo.Size() == 0 {
		t.Errorf("yeni segment bos kaldi")
	}
}

// TestRestartResumesLatestSegment, yeniden baslatma sonrasi en
// son segmentin sonuna eklemeye devam etmelidir. Aksi halde her
// yeniden baslatmada 0. segment acilir ve kanit ezilir.
func TestRestartResumesLatestSegment(t *testing.T) {
	dir := t.TempDir()

	w, err := NewWriter(dir, false)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Yapay olarak yuksek boyutlu bir dosya birak: yeniden
	// baslatmada 0. segment yerine 1. segment bulunmali.
	today := time.Now().UTC().Format(timeFormat)
	seg1 := filepath.Join(dir, "audit-"+today+".1.jsonl")
	f, err := os.Create(seg1)
	if err != nil {
		t.Fatalf("seg1 olusturulamadi: %v", err)
	}
	f.Close()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w2, err := NewWriter(dir, false)
	if err != nil {
		t.Fatalf("NewWriter #2: %v", err)
	}
	defer w2.Close()

	if got, want := filepath.Base(w2.CurrentFile()), "audit-"+today+".1.jsonl"; got != want {
		t.Errorf("restart sonrasi dosya = %q, beklenen %q", got, want)
	}

	if err := w2.Write(ev(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Yazilan kayit 1. segmentte olmali, 0. segmentte degil.
	data, err := os.ReadFile(seg1)
	if err != nil {
		t.Fatalf("seg1 okunamadi: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("restart sonrasi kayit 1. segmente yazilmadi")
	}

	var got models.AuditEvent
	if err := json.Unmarshal(data[:len(data)-1], &got); err != nil {
		t.Fatalf("kayit cozulemedi: %v", err)
	}
	if got.Object.Path != "/home/axdesktop/gizli-dosya" {
		t.Errorf("kayit yolu = %q", got.Object.Path)
	}
}

// TestPruneOldDays, retention esiginin otesindeki gunlerin
// silindigini ve AKTIF gunun korundugunu dogrular.
func TestPruneOldDays(t *testing.T) {
	dir := t.TempDir()

	old := time.Now().UTC().AddDate(0, 0, -retentionDays-1).Format(timeFormat)
	recent := time.Now().UTC().AddDate(0, 0, -1).Format(timeFormat)
	today := time.Now().UTC().Format(timeFormat)

	for _, name := range []string{
		"audit-" + old + ".jsonl",
		"audit-" + old + ".jsonl.gz",
		"audit-" + recent + ".jsonl.gz",
		"audit-" + today + ".jsonl",
		"audit-" + today + ".1.jsonl",
		"deep_verify.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0640); err != nil {
			t.Fatalf("%s yazilamadi: %v", name, err)
		}
	}

	w, err := NewWriter(dir, false)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	w.prune()

	if _, err := os.Stat(filepath.Join(dir, "audit-"+old+".jsonl")); err == nil {
		t.Errorf("eski gun silinmedi: audit-%s.jsonl", old)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-"+old+".jsonl.gz")); err == nil {
		t.Errorf("eski gunun gz'i silinmedi: audit-%s.jsonl.gz", old)
	}

	// Aktif gun ve esik ici gun KORUNMALI: audit logu kanittir.
	for _, name := range []string{
		"audit-" + recent + ".jsonl.gz",
		"audit-" + today + ".jsonl",
		"audit-" + today + ".1.jsonl",
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("korunmasi gereken dosya silindi: %s", name)
		}
	}

	// Ilgisiz dosyalara dokunulmamali.
	if _, err := os.Stat(filepath.Join(dir, "deep_verify.log")); err != nil {
		t.Errorf("ilgisiz dosya silindi: deep_verify.log")
	}
}

// TestCompressDayAllSegments, gun degisiminde numarali segmentlerin
// de sikistirildigini dogrular. compressFile yalnizca numarasiz adi
// biliyordu; segmentler eklendiginden sonra gun degisimi 1..N
// segmentleri ham birakirdi.
func TestCompressDayAllSegments(t *testing.T) {
	dir := t.TempDir()

	old := time.Now().UTC().AddDate(0, 0, -1).Format(timeFormat)

	names := []string{
		"audit-" + old + ".jsonl",
		"audit-" + old + ".1.jsonl",
		"audit-" + old + ".2.jsonl",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"a":1}`+"\n"), 0640); err != nil {
			t.Fatalf("%s yazilamadi: %v", name, err)
		}
	}

	w, err := NewWriter(dir, true)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	w.compressDay(old)

	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name+".gz")); err != nil {
			t.Errorf("segment sikistirilmedi: %s.gz", name)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("kaynak silinmedi: %s", name)
		}
	}
}
