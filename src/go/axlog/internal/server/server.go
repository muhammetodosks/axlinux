// Package server implements the Unix socket server that receives
// audit events from axdaemon and persists them.
package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"axlinux/axlog/internal/models"
	"axlinux/axlog/internal/writer"
)

// Server listens on a Unix socket for incoming audit events.
type Server struct {
	socketPath string
	writer     *writer.Writer
	logger     *slog.Logger
	mu         sync.Mutex
	running    bool
	listener   net.Listener
}

// NewServer creates a new audit log server.
func NewServer(socketPath string, w *writer.Writer, logger *slog.Logger) *Server {
	return &Server{
		socketPath: socketPath,
		writer:     w,
		logger:     logger,
	}
}

// Start begins listening and accepting connections.
func (s *Server) Start() error {
	// Dizin socket yolundan turer, SABIT "/run/axlinux" degil.
	// axdaemon tarafinda ayni hata vardi: baska bir yola dinlenen
	// her sunucu, izin vermedigi icin start olmadan hata veriyordu
	// ve normal kullanicida sessizce hic baslamiyordu.
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("socket dizini olusturulamadi (%s): %w", dir, err)
	}

	// Bayat soket dosyasi: bir Unix domain dinleyicisi kapandiginda
	// dosya SİLİNMEZ. Temizlenmezse yeniden baslatma EADDRINUSE ile
	// basarisiz olur ve servis yeniden calisamaz.
	if _, err := os.Stat(s.socketPath); err == nil {
		_ = os.Remove(s.socketPath)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("socket dinleme hatasi: %w", err)
	}

	// Socket izni 0666 idi. Iki ayri sorun:
	//
	//   1) Herkes bağlanip SAHTE audit kaydi yazabiliyordu. Kanit
	//      zincirinde uretilmemis bir kayit, toplanan kayitlarin
	//      tamaminin degerini dusurur: "kimse erismedi" diyen bir
	//      sistemde uydurma bir kayit arayan kimse koyabilirdi.
	//   2) Yazma tarafi 0600 idi ama okuma tarafi degil; yalnizca
	//      root'un baglanmasi yeterlidir.
	//
	// 0600: yalnizca root (yani axdaemon) baglanabilir.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		return fmt.Errorf("socket izinleri ayarlanamadi: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	s.logger.Info("axlog socket dinleniyor", "path", s.socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return nil
			}
			s.logger.Warn("baglanti kabul hatasi", "error", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Stop shuts down the server.
func (s *Server) Stop() error {
	s.mu.Lock()
	s.running = false
	listener := s.listener
	s.mu.Unlock()

	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}

		if len(line) == 0 {
			continue
		}

		var event models.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			s.logger.Warn("event parse hatasi", "error", err)
			continue
		}

		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}

		if err := s.writer.Write(event); err != nil {
			s.logger.Error("event yazilamadi", "error", err)
		}
	}
}


