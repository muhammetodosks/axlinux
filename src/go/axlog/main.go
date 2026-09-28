// axlinux/axlog — JSON audit log service for AXlinux.
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"axlinux/axlog/internal/server"
	"axlinux/axlog/internal/writer"
)

func main() {
	var (
		socketPath = flag.String("socket", "/run/axlinux/axlog.sock", "Unix socket yolu")
		logDir     = flag.String("log-dir", "/var/log/axlinux", "Log dizini")
		logLevel   = flag.String("log-level", "info", "Log seviyesi (debug, info, warn, error)")
		compress   = flag.Bool("compress", true, "Eski loglari sikistir")
	)
	flag.Parse()

	logger := setupLogger(*logLevel)
	logger.Info("axlog baslatiliyor", "version", "1.0.0")

	w, err := writer.NewWriter(*logDir, *compress)
	if err != nil {
		logger.Error("log writer olusturulamadi", "error", err)
		os.Exit(1)
	}
	defer w.Close()

	srv := server.NewServer(*socketPath, w, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("sunucu hatasi", "error", err)
			os.Exit(1)
		}
	}()

	<-sigCh
	logger.Info("kinyali alindi, kapaniyor...")

	_ = srv.Stop()

	logger.Info("axlog kapandi")
}

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}


