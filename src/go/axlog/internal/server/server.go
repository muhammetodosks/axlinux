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
	if err := os.MkdirAll("/run/axlinux", 0755); err != nil {
		return fmt.Errorf("run dizini olusturulamadi: %w", err)
	}

	if _, err := os.Stat(s.socketPath); err == nil {
		_ = os.Remove(s.socketPath)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("socket dinleme hatasi: %w", err)
	}

	if err := os.Chmod(s.socketPath, 0666); err != nil {
		s.logger.Warn("socket izinleri ayarlanamadi", "error", err)
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


