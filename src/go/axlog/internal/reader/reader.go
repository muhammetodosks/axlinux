// Package reader provides filtered and tailed access to audit logs.
package reader

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	for _, f := range files {
		events, err := r.readFromFile(f, filter)
		if err != nil {
			continue
		}
		results = append(results, events...)
	}

	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[len(results)-filter.Limit:]
	}

	return results, nil
}

// Tail streams new events matching the filter.
func (r *Reader) Tail(filter models.Filter, ch chan<- models.AuditEvent) error {
	defer close(ch)

	files, err := r.listFiles()
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return nil
	}

	latest := files[len(files)-1]
	f, err := os.Open(latest)
	if err != nil {
		return fmt.Errorf("tail dosyasi acilamadi: %w", err)
	}
	defer f.Close()

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
			ch <- event
		}
	}

	return scanner.Err()
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
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".jsonl") {
			files = append(files, filepath.Join(r.dir, name))
		}
	}

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
