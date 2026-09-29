// Package server implements the Unix socket JSON-RPC server for axdaemon.
package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	// Dizin socket yolundan turer, SABIT "/run/axlinux" degil.
	//
	// Sabit yol iki ayri sekilde yanlisiydi. Birincisi: socket
	// yolu yapilandirilabilir olmasina ragmen dizin onaylamak
	// imkansizdi; baska bir yola dinlenen her server, izin
	// vermedigi icin start olmadan hata veriyordu (testlerin
	// tamami bu yuzden kirmiziydi). Ikincisi: normal kullanici
	// /run'a yazamadigi icin Start() sessizce basarisiz oluyor,
	// hatayi gormeyen cagiran taraf "sunucu ayakta" saniyordu.
	//
	// Dizin, socket'un bulunmasi gereken yeri belirler; yani
	// socket yolunun dizini dogru ve tek dogruluk kaynagidir.
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("socket dizini olusturulamadi (%s): %w", dir, err)
	}

	if _, err := os.Stat(s.socketPath); err == nil {
		_ = os.Remove(s.socketPath)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("socket dinleme hatasi: %w", err)
	}

	// Socket izni 0666 idi: herhangi bir yerel kullanici
	// reload_policy gonderip sistem genelinde politika
	// degistirebiliyordu. Bu bir yetki yukseltme yuzeyi;
	// MAC sistemini yonetecek olan root olmali.
	//
	// 0600 root'a kisitlar. sudo kullanan normal kullanicilar
	// socket'e erisemez; bu bilincli bir tradeoff: guvenlik
	// araci, kullaniciya degil yoneticeye ait olur.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		return fmt.Errorf("socket izinleri ayarlanamadi: %w", err)
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
	// Istemci normal sekilde kapattiginda ReadBytes io.EOF doner.
	// Bu bir hata degil; ayirt edilmezse her komut sonrasi
	// "baglanti koptu" uyarisi logu kirletir ve gercek hatalari
	// gormeyi zorlastirir.
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				s.logger.Warn("okuma hatasi", "error", err)
			}
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

		// 30 saniyelik islem siniri. Sabit sayi yerine
		// time.Duration yazilmasi, birim karistirilmasini
		// (30 saniye mi 30 nanosaniye mi) imkansiz kilar.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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


