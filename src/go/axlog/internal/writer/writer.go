// Package writer handles persistent storage of audit events with
// rotation and compression.
package writer

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"axlinux/axlog/internal/models"
)

const (
	maxFileSize = 10 * 1024 * 1024
	timeFormat  = "2006-01-02"

	// retentionDays, sikistirilmis gunlerin kac gun saklanacagini
	// belirler. Onceki surumde bir ust sinir YOKTU: her gun yeni bir
	// dosya birikiyor, masaustu aylarca acik kaldiginda /var/log
	// sessizce doluyordu. 14 gun, haftalik inceleme icin yeterli
	// kanit biriktirirken diski sinirli tutar.
	retentionDays = 14
)

// Writer appends audit events to JSONL files with rotation.
type Writer struct {
	mu       sync.Mutex
	dir      string
	file     *os.File
	fileSize int64
	fileDate string
	segment  int
	compress bool
}

// NewWriter creates a writer that stores logs in the given directory.
func NewWriter(dir string, compressOld bool) (*Writer, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("log dizini olusturulamadi: %w", err)
	}

	w := &Writer{
		dir:      dir,
		compress: compressOld,
	}

	if err := w.openCurrent(); err != nil {
		return nil, err
	}

	return w, nil
}

// Write appends a single event to the log file.
func (w *Writer) Write(event models.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeeded(); err != nil {
		return err
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("event serialize hatasi: %w", err)
	}
	line := append(data, '\n')

	n, err := w.file.Write(line)
	if err != nil {
		return fmt.Errorf("log yazma hatasi: %w", err)
	}

	w.fileSize += int64(n)
	return nil
}

// Close flushes and closes the current log file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

func (w *Writer) openCurrent() error {
	date := time.Now().UTC().Format(timeFormat)

	// Yeniden baslatmada mevcut segmentin sonuna eklemeye devam et.
	// Digeri durumda her yeniden baslatmada 0. segment acilir ve
	// dosya numaralandirmasi geriye dogru gider.
	w.segment = w.latestSegment(date)
	return w.openSegment(date, w.segment)
}

func (w *Writer) openSegment(date string, segment int) error {
	filename := segmentFileName(w.dir, date, segment)

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("log dosyasi acilamadi: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("log dosya bilgisi alinamadi: %w", err)
	}

	w.file = f
	w.fileSize = info.Size()
	w.fileDate = date
	w.segment = segment
	return nil
}

func (w *Writer) rotateIfNeeded() error {
	today := time.Now().UTC().Format(timeFormat)

	// Gun degismisse eski gunu sikistir ve yeni gunun 0. segmentini ac.
	if w.fileDate != today {
		if w.file != nil {
			w.file.Close()
			w.file = nil
		}
		if w.compress && w.fileDate != "" {
			w.compressDay(w.fileDate)
		}
		w.prune()
		w.segment = 0
		return w.openSegment(today, 0)
	}

	// Ayni gun icinde boyut siniri asildiysa NUMARALI SEGMENT ac.
	//
	// Once openCurrent() her zaman "bugun"un adini uretiyordu; boyut
	// siniri tetiklendiginde ayni dosya O_APPEND ile yeniden
	// aciliyordu. Dosya hicbir zaman gercekten donmuyor, yalnizca
	// buyuyordu: 10 MB siniri gun icinde sessizce gecersiz kaliyor
	// ve masaustunde /var/log doluyordu. Numarali segment (".1",
	// ".2", ...) ayni gun icinde de yeni dosya acar.
	if w.fileSize >= maxFileSize {
		if w.file != nil {
			w.file.Close()
			w.file = nil
		}
		// Ayni gunun segmenti sikistirilMEZ: aktif gunun kaniti
		// yarim kalmis gz olarak gorunmemeli.
		w.segment++
		return w.openSegment(today, w.segment)
	}

	return nil
}

// segmentFileName, verilen gun ve segment icin dosya adini uretir.
func segmentFileName(dir, date string, segment int) string {
	if segment <= 0 {
		return filepath.Join(dir, "audit-"+date+".jsonl")
	}
	return filepath.Join(dir, "audit-"+date+"."+strconv.Itoa(segment)+".jsonl")
}

// latestSegment, verilen gun icin diskteki en yuksek segment
// numarasini bulur. Ayakta olan writer, mevcut dosyanin sonuna
// eklemeye devam etmelidir; yoksa yeniden baslatma kayitlari
// sifirlar veya ustune yazar.
func (w *Writer) latestSegment(date string) int {
	highest := 0

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0
	}

	prefix := "audit-" + date
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		rest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".jsonl")
		if rest == "" {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(rest, ".")); err == nil && n > highest {
			highest = n
		}
	}
	return highest
}

// compressFile gzips the given day's log and removes the original.
//
// SIRALAMA ONEMLI. Once gzipwriter, SONRA dosya taniticisi, EN
// SONDA kaynak silinmesi gerekir. Burada daha once defer
// kullaniliyordu ve bu sirayi bozuyordu: os.Remove(src) defer'lar
// calismadan ONCE execute ediliyordu, yani sikistirilmis dosya
// HENUZ TAMAMLANMAMISTI kaynak siliniyordu. Bir disk dolulugu ya da
// SIGKILL ile gzip yarim kalsaydi ve o gunun audit kaydi tamamen
// kaybolurdu.
//
// Audit logu kanit niteligindedir; yarim kalmis bir arsiv, hic
// kayit olmamasindan kotudur.
// compressDay, verilen gunun TUM segmentlerini sikistirir.
//
// compressFile yalnizca numarasiz "audit-<gun>.jsonl" adini
// biliyordu. Numarali segmentler eklendiginden sonra gun degisimi
// /var/log'da yalnizca 0. segmenti sikistirir, 1..N segmentleri
// ham olarak kalirdi.
func (w *Writer) compressDay(date string) {
	matches, err := filepath.Glob(filepath.Join(w.dir, "audit-"+date+"*.jsonl"))
	if err != nil {
		return
	}

	// Numarali segmentler once sikistirilir: 0. segment en eski
	// kaydi iceriyor, en yeniden basa dogru gitmek kanit
	// suresini korur.
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, src := range matches {
		w.compressFile(src)
	}
}

// prune, diski tuketmemek icin eski gunleri siler.
//
// Audit logu kanittir; bu yuzden yalnizca belirtilen gun esiginin
// OTESINDEKI dosyalar silinir. Aktif gunun segmentlerine dokunulmaz.
func (w *Writer) prune() {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	today := time.Now().UTC().Format(timeFormat)

	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "audit-") {
			continue
		}

		rest := strings.TrimSuffix(strings.TrimPrefix(name, "audit-"), ".jsonl.gz")
		rest = strings.TrimSuffix(strings.TrimPrefix(rest, "audit-"), ".jsonl")
		if len(rest) < len(timeFormat) {
			continue
		}

		day, err := time.Parse(timeFormat, rest[:len(timeFormat)])
		if err != nil {
			continue
		}

		if day.Format(timeFormat) == today {
			continue
		}
		if day.After(cutoff) {
			continue
		}

		_ = os.Remove(filepath.Join(w.dir, name))
	}
}

func (w *Writer) compressFile(src string) {
	dst := src + ".gz"

	if _, err := os.Stat(dst); err == nil {
		// Zaten sikistirilmis; kaynak varsa yarim kalmis olabilir.
		_ = os.Remove(src)
		return
	}

	f, err := os.Open(src)
	if err != nil {
		return
	}
	defer f.Close()

	// Once gecici ad: yarim kalan sikistirma .gz gorunmez.
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		f.Close()
		return
	}

	gz := gzip.NewWriter(out)
	_, copyErr := io.Copy(gz, f)

	// Kapatma sirasi onemli: once gzipwriter (veriyi diske yazar),
	// sonra dosya taniticisi.
	gzCloseErr := gz.Close()
	outCloseErr := out.Close()
	f.Close()

	if copyErr != nil || gzCloseErr != nil || outCloseErr != nil {
		// Sikistirma basarisiz: gecici dosyayi birak ve KAYNAGI
		// SILME. Yarim gz yerine bozuk gz olmamasi tercih
		// edilir.
		_ = os.Remove(tmp)
		return
	}

	// Atomik: gecici adi nihai adiye tasir.
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return
	}
	// Yalnizca gecici basariyla yerine oturduysa kaynak silinir.
	_ = os.Remove(src)
}

// CurrentFile returns the path of the active log file.
func (w *Writer) CurrentFile() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Name()
	}
	return ""
}
