// Package server implements the Unix socket JSON-RPC server for axdaemon.
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"axlinux/axdaemon/pkg/protocol"
)

// Handler is the interface for dispatching RPC requests.
type Handler interface {
	Dispatch(ctx context.Context, req protocol.Request) protocol.Response
}

// Server listens on a Unix socket and serves JSON-RPC requests.
type Server struct {
	socketPath string
	listener   net.Listener
	handler    Handler
	logger     *slog.Logger
	mu         sync.Mutex
	running    bool
}

// NewServer creates a new Unix socket server.
func NewServer(socketPath string, handler Handler, logger *slog.Logger) *Server {
	return &Server{
		socketPath: socketPath,
		handler:    handler,
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

	s.logger.Info("axdaemon socket dinleniyor", "path", s.socketPath)

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

		var req protocol.Request
		if err := json.Unmarshal(line, &req); err != nil {
			resp := protocol.NewErrorResponse(0, -32700, "parse hatasi: "+err.Error())
			s.writeResponse(conn, resp)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30_000_000_000)
		resp := s.handler.Dispatch(ctx, req)
		cancel()

		if err := s.writeResponse(conn, resp); err != nil {
			s.logger.Warn("cevap yazilamadi", "error", err)
			return
		}
	}
}

func (s *Server) writeResponse(conn net.Conn, resp protocol.Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("cevap serialize hatasi: %w", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("cevap yazma hatasi: %w", err)
	}
	return nil
}


