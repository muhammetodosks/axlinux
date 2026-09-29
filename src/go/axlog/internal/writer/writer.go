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
	"sync"
	"time"

	"axlinux/axlog/internal/models"
)

const (
	maxFileSize = 10 * 1024 * 1024
	timeFormat  = "2006-01-02"
)

// Writer appends audit events to JSONL files with rotation.
type Writer struct {
	mu         sync.Mutex
	dir        string
	file       *os.File
	fileSize   int64
	fileDate   string
	compress   bool
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
	filename := filepath.Join(w.dir, "audit-"+date+".jsonl")

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
	return nil
}

func (w *Writer) rotateIfNeeded() error {
	needsRotation := false

	today := time.Now().UTC().Format(timeFormat)
	if w.fileDate != today {
		needsRotation = true
	} else if w.fileSize >= maxFileSize {
		needsRotation = true
	}

	if !needsRotation {
		return nil
	}

	if w.file != nil {
		w.file.Close()
	}

	if w.compress && w.fileDate != "" {
		w.compressFile(w.fileDate)
	}

	return w.openCurrent()
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
func (w *Writer) compressFile(date string) {
	src := filepath.Join(w.dir, "audit-"+date+".jsonl")
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
