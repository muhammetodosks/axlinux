// Package reader provides filtered and tailed access to audit logs.
package reader

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"axlinux/axlog/internal/models"
)

// Reader reads audit events from JSONL files.
type Reader struct {
	dir string
}

// NewReader creates a reader for the given log directory.
func NewReader(dir string) *Reader {
	return &Reader{dir: dir}
}

// Query returns events matching the filter.
func (r *Reader) Query(filter models.Filter) ([]models.AuditEvent, error) {
	files, err := r.listFiles()
	if err != nil {
		return nil, err
	}

	var results []models.AuditEvent

	// Okunamayan dosya SESSIZCE ATLANMAZ. Bozuk bir .gz ya da
	// silinmis bir dosya o tarihin tum kayitlarini gizler ve
	// kullaniciya "kayit yok" gorunur; veri KAYBIDIR ama
	// ayirt edilemez. Sorgu yine de devam eder, sonuclar
	// cift taraflidir: ne bulundu ne de neden eksik oldugu.
	var unreadable []string

	for _, f := range files {
		events, err := r.readFromFile(f, filter)
		if err != nil {
			unreadable = append(unreadable,
				fmt.Sprintf("%s: %v", filepath.Base(f), err))
			continue
		}
		results = append(results, events...)
	}

	if len(unreadable) > 0 {
		return results, &PartialError{
			Files: unreadable,
			Found: len(results),
		}
	}

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[len(results)-filter.Limit:]
	}

	return results, nil
}

// PartialError reports that a query could not read every candidate
// file. The results returned alongside it are complete for the files
// that did open, but a caller that ignores the error would believe
// the trail is whole when it has holes.
//
// This is the difference between "no events match" and "we cannot
// see those events", which for an audit log are opposites.
type PartialError struct {
	Files []string
	Found int
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("BOS KUSMELI SONU: %d dosya okunamadi "+
		"(%d kayit bulundu). Eksik tarihler: %s",
		len(e.Files), e.Found, strings.Join(e.Files, ", "))
}

// Tail streams events matching the filter and keeps following the log
// as new lines arrive. It does not return until the context is done,
// so a caller must be prepared for a long-lived call.
//
// The previous version read the latest file to EOF and returned. For
// a live audit stream that is the same as returning nothing: an
// operator watching for denials would have to re-run the command
// every time, and the log is exactly the place you do not poll.
func (r *Reader) Tail(ctx context.Context, filter models.Filter, ch chan<- models.AuditEvent) error {
	defer close(ch)

	var f *os.File
	var scanner *bufio.Scanner
	var path string

	// closeCurrent releases the open file, if any.
	closeCurrent := func() {
		if f != nil {
			_ = f.Close()
			f = nil
			scanner = nil
		}
	}
	defer closeCurrent()

	// openLatest attaches to the newest log file, emitting anything
	// that already exists in it.
	openLatest := func() error {
		files, err := r.listFiles()
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return nil
		}
		latest := files[len(files)-1]
		nf, err := os.Open(latest)
		if err != nil {
			return fmt.Errorf("tail dosyasi acilamadi: %w", err)
		}
		f = nf
		path = latest
		scanner = bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		return nil
	}

	if err := openLatest(); err != nil {
		return err
	}
	if f == nil {
		// No logs yet: wait for the writer to create one rather than
		// returning and looking like "no activity".
		f = nil
	}

	// Rotation switches the current file to a new one (or moves it to
	// .gz). The open handle then points at an unlinked or moved file
	// and would look frozen forever, so rotation is detected by
	// watching for a newer file appearing.
	const poll = 500 * time.Millisecond
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	emit := func(line []byte) {
		if len(line) == 0 {
			return
		}
		var event models.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return
		}
		if filter.Match(event) {
			select {
			case ch <- event:
			case <-ctx.Done():
			}
		}
	}

	for {
		// Drain whatever is readable right now.
		if scanner != nil {
			for scanner.Scan() {
				emit(scanner.Bytes())
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}

		// Check for rotation: a file newer than the one we hold.
		files, err := r.listFiles()
		if err == nil && len(files) > 0 {
			if newest := files[len(files)-1]; newest != path {
				closeCurrent()
				if err := openLatest(); err != nil {
					return err
				}
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ReadSince returns all events after the given time.
func (r *Reader) ReadSince(since time.Time, limit int) ([]models.AuditEvent, error) {
	return r.Query(models.Filter{Since: since, Limit: limit})
}

// ReadByAction returns events for a specific action.
func (r *Reader) ReadByAction(action string, limit int) ([]models.AuditEvent, error) {
	return r.Query(models.Filter{Action: action, Limit: limit})
}

// ReadBySubject returns events for a specific subject.
func (r *Reader) ReadBySubject(subject string, limit int) ([]models.AuditEvent, error) {
	return r.Query(models.Filter{Subject: subject, Limit: limit})
}

func (r *Reader) listFiles() ([]string, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("log dizini okunamadi: %w", err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Hem duz hem sikistirilmis gunler taranir. Gz'li
		// gunler readFromFile'da sayfan acilir; .tmp dosyalari
		// yazma sirasinda olusur ve HICBIR ZAMAN okunmamalidir
		// (yarim kayit icerirler).
		if strings.HasPrefix(name, "audit-") &&
			(strings.HasSuffix(name, ".jsonl") ||
				strings.HasSuffix(name, ".jsonl.gz")) &&
			!strings.HasSuffix(name, ".tmp") {
			files = append(files, filepath.Join(r.dir, name))
		}
	}

	// SIRALAMA ACIKCA YAPILIR. os.ReadDir bugun alfabetik donuyor
	// ama bu bir sozlesme degil; Tail ve Query en yeniden en
	// eskiye dogru siraya bagimlidir. Tarih adi YYYY-MM-DD oldugu
	// icin alfabetik siralama kronolojik siralamayla aynidir.
	sort.Strings(files)
	return files, nil
}

func (r *Reader) readFromFile(path string, filter models.Filter) ([]models.AuditEvent, error) {
	var f io.ReadCloser

	if strings.HasSuffix(path, ".gz") {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		f = gz
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		f = file
	}

	var events []models.AuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event models.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}

		if filter.Match(event) {
			events = append(events, event)
		}
	}

	return events, scanner.Err()
}
