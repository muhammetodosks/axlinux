package writer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// TestPruneBySizeCapsTotal, toplam boyut maxTotalBytes'i asarsa
// en eski dosyalar silinir ve AKTIF gun korunur.
//
// NEDEN Gerekli: retentionDays gun sayisini sinirliyor ama bir gun
// icindeki ihlal sayisini DEGIL. Masaustunde hatali bir betik
// dakikada binlerce ihlal uretip 14 gun x 10 MB uretebilir; bu
// 140 MB'dir. Daha kotu senaryoda sinir asilir. Toplam boyut
// siniri her zaman gecerli.
func TestPruneBySizeCapsTotal(t *testing.T) {
	dir := t.TempDir()

	// Gercek 200 MB yazmak testi hem yavas hem de gecici dosya
	// sisteminde basarisiz kilardi (720 MB yazma denendi, WriteFile
	// sessizce kismi basarisiz oldu). Bu yuzden esik kucultulur.
	orig := maxTotalBytes
	maxTotalBytes = 4 * 1024 * 1024
	defer func() { maxTotalBytes = orig }()

	// 14 gunluk esik icinde 30 gunluk veri uret: gun siniri SILMEZ,
	// toplam boyut siniri SILMELI.
	now := time.Now().UTC()
	var written int64
	for d := 29; d >= 0; d-- {
		day := now.AddDate(0, 0, -d).Format(timeFormat)
		// Her gun 3 x 1 MB segment = 3 MB/gun -> ~90 MB toplam
		for seg := 0; seg < 3; seg++ {
			name := "audit-" + day + ".jsonl"
			if seg > 0 {
				name = "audit-" + day + "." + strconv.Itoa(seg) + ".jsonl"
			}
			data := make([]byte, 1024*1024)
			for i := range data {
				data[i] = 'x'
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0640); err != nil {
				t.Fatal(err)
			}
			written += int64(len(data))
		}
	}
	if written <= maxTotalBytes {
		t.Fatalf("test verisi yetersiz: %d <= %d", written, maxTotalBytes)
	}

	w, err := NewWriter(dir, false)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	w.pruneBySize()

	var total int64
	for _, f := range w.auditFiles() {
		total += f.size
	}

	if total > maxTotalBytes {
		t.Errorf("toplam boyut sinirini asiyor: %d > %d", total, int64(maxTotalBytes))
	}

	// Aktif gun SILINMEMELI: bugunun tum segmentleri durmali.
	// (Onceki yazimda mantik TERSI'ydi: dosya VARSA hata veriyordu.)
	today := now.Format(timeFormat)
	todayFound := 0
	for _, f := range w.auditFiles() {
		if f.day.Format(timeFormat) == today {
			todayFound++
		}
	}
	if todayFound == 0 {
		t.Fatalf("aktif gunun tum dosyalari silindi (toplam %d bayt kaldi, "+
			"sinir %d)", total, int64(maxTotalBytes))
	}

	// Yeni dosyalar (en eski) silinmis, yeni dosyalar kalmis olmali
	oldest := now.AddDate(0, 0, -29).Format(timeFormat)
	if _, err := os.Stat(filepath.Join(dir, "audit-"+oldest+".jsonl")); err == nil {
		t.Errorf("en eski dosya silinmedi: audit-%s.jsonl", oldest)
	}
}

// TestAuditFilesParsesGzipNames, .gz ve numarali segment adlari
// dogru cozulur. Isim cozumlemesi yanlis olursa prune HICBIR seyi
// silmez (gulerekce sinir asilir).
func TestAuditFilesParsesGzipNames(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"audit-2026-10-01.jsonl",
		"audit-2026-10-02.jsonl.gz",
		"audit-2026-10-03.1.jsonl",
		"audit-2026-10-03.12.jsonl",
		"audit-2026-10-04.2.jsonl.gz",
		"derisk.log",
		"okunmayan.txt",
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0640); err != nil {
			t.Fatal(err)
		}
	}

	w, err := NewWriter(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// NewWriter bugunun dosyasini kendisi acar; 5 test dosyasi +
	// 1 yeni = 6.
	files := w.auditFiles()
	if len(files) != 6 {
		t.Fatalf("cozulen dosya = %d, 6 bekleniyordu", len(files))
	}
	files = files[:5] // yalnizca test icin yazilanlari dogrula

	want := map[string]string{
		"audit-2026-10-01.jsonl":      "2026-10-01",
		"audit-2026-10-02.jsonl.gz":   "2026-10-02",
		"audit-2026-10-03.1.jsonl":    "2026-10-03",
		"audit-2026-10-03.12.jsonl":   "2026-10-03",
		"audit-2026-10-04.2.jsonl.gz": "2026-10-04",
	}
	for _, f := range files {
		got := f.day.Format(timeFormat)
		base := filepath.Base(f.path)
		if w2, ok := want[base]; !ok || w2 != got {
			t.Errorf("%s -> gun %q", base, got)
		}
	}

	// Segment siralamasi: 1'den 12'ye dogru
	var seqs []int
	for _, f := range files {
		if f.day.Format(timeFormat) == "2026-10-03" {
			seqs = append(seqs, f.seq)
		}
	}
	sort.Ints(seqs)
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 12 {
		t.Errorf("segment numaralari = %v, [1 12] bekleniyordu", seqs)
	}
}
