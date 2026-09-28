// axlinux/axdaemon — MAC daemon: eBPF LSM enforcement, policy management,
// JSON-RPC server over a Unix socket.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"axlinux/axdaemon/internal/audit"
	"axlinux/axdaemon/internal/handlers"
	"axlinux/axdaemon/internal/learning"
	"axlinux/axdaemon/internal/lsm"
	"axlinux/axdaemon/internal/lsmenv"
	"axlinux/axdaemon/internal/maps"
	"axlinux/axdaemon/internal/mode"
	"axlinux/axdaemon/internal/policy"
	"axlinux/axdaemon/internal/server"
)

// Version is the daemon version. Keep in sync with axctl's __version__.
const Version = "0.1.0"

func main() {
	var (
		socketPath = flag.String("socket", "/run/axlinux/axdaemon.sock",
			"Unix socket yolu")
		logLevel = flag.String("log-level", "info",
			"Log seviyesi (debug, info, warn, error)")
		bpfObj = flag.String("bpf-obj", "/usr/lib/axlinux/axbpf.o",
			"eBPF nesne dosyasi yolu")
		pinDir = flag.String("pin-dir", "/sys/fs/bpf/axlinux",
			"Map pin dizini (bos: pinleme)")
		noEnforce = flag.Bool("no-enforce", false,
			"LSM kancalarini baglama, yalnizca RPC calistir")
	)
	flag.Parse()

	logger := setupLogger(*logLevel)

	// Enforcement mumkun mu? Bu soru kancalari baglamadan ONCE
	// sorulmalidir: bpf LSM zincirde yoksa AttachLSM yine de basarili
	// doner ve kullaniciya "5/5 bagli" denirken hicbir politika
	// uygulanmiyor olur.
	if !lsmenv.Available() {
		logger.Warn("UYARI: politika UYGULANAMAZ", "detay", lsmenv.Summary())
	} else {
		logger.Info("bpf LSM aktif", "zincir", strings.Join(lsmenv.Active(), ","))
	}

	logger.Info("axdaemon baslatiliyor",
		"version", Version, "bpf_obj", *bpfObj)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	policyMgr := policy.NewManager()
	modeMgr := mode.NewManager()
	learningMgr := learning.NewManager()

	// Enforcement parcalari. eBPF yuklenemezse daemon yine calisir:
	// RPC sunucusu, politika dogrulama ve simulasyon kullanilabilir kalir.
	lsmMgr := lsm.NewManager(*bpfObj)
	var mapsMgr *maps.Manager
	var auditMgr *audit.Manager

	if err := lsmMgr.Load(); err != nil {
		logger.Warn("ebpf yuklenemedi, yalnizca RPC calisiyor", "error", err)
	} else {
		logger.Info("ebpf collection yuklendi")

		m, err := maps.NewFromCollection(lsmMgr.Collection())
		if err != nil {
			logger.Error("map'ler alinamadi, enforcement devre disi",
				"error", err)
		} else {
			mapsMgr = m
			defer mapsMgr.Close()

			pinMaps(mapsMgr, *pinDir, logger)

			// Baslangicta permissive: kernel bos karar vermesin.
			if err := mapsMgr.SetMode(maps.ModePermissive); err != nil {
				logger.Warn("mod yazilamadi", "error", err)
			}

			if *noEnforce {
				logger.Warn("--no-enforce verildi, LSM kancalari baglanmiyor")
			} else if err := lsmMgr.Attach(); err != nil {
				logger.Warn("bazi LSM kancalari baglanamadi",
					"error", err)
			}

			// Baglanti basarili olsa bile bpf LSM zincirde yoksa
			// enforcement gerceklesmez. Sayilari oldugundan gibi
			// gostermek yaniltici olur.
			if lsmMgr.EnforcementPossible() {
				logger.Info("LSM kancalari baglandi",
					"aktif", lsmMgr.AttachedCount(),
					"toplam", lsmMgr.HookCount())
			} else {
				logger.Warn("LSM kancalari yuklendi ama CALISMIYOR " +
					"(bpf LSM zincirde yok) - politika uygulanmiyor",
					"aktif", lsmMgr.AttachedCount(),
					"toplam", lsmMgr.HookCount(),
					"detay", lsmenv.Summary())
			}

			// Audit perf buffer'i da collection'dan al.
			a := audit.NewManager(nil)
			if am := mapsMgr.Map(maps.AuditMapName); am != nil {
				if err := a.OpenPerfBuffer(am); err != nil {
					logger.Warn("perf buffer acilamadi, audit log kapali",
						"error", err)
				} else {
					auditMgr = a
					logger.Info("audit perf buffer acildi")
					go func() {
						if err := a.Run(ctx); err != nil &&
							err != context.Canceled {
							logger.Error("audit dongusu hatasi", "error", err)
						}
					}()
					defer a.Close()
				}
			} else {
				logger.Warn("audit_buffer map'i collection'da yok")
			}
		}

		defer lsmMgr.Close()
	}

	handler := handlers.NewHandler(policyMgr, mapsMgr, modeMgr, learningMgr)
	if mapsMgr != nil {
		handler.Attach(lsmMgr, auditMgr)
	}
	srv := server.NewServer(*socketPath, handler, logger)

	go func() {
		if err := srv.Start(); err != nil {
			logger.Error("sunucu hatasi", "error", err)
			cancel()
		}
	}()

	<-sigCh
	logger.Info("sinyali alindi, kapaniyor...")

	_ = srv.Stop()
	logger.Info("axdaemon kapandi")
}

// pinMaps pins the maps so a restarted daemon finds the same objects
// and so bpftool can inspect live policy.
func pinMaps(m *maps.Manager, dir string, logger *slog.Logger) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Warn("pin dizini olusturulamadi", "dir", dir, "error", err)
		return
	}
	for _, name := range []string{
		maps.AllowMapName, maps.DenyMapName, maps.ModeMapName,
	} {
		mm := m.Map(name)
		if mm == nil {
			continue
		}
		path := dir + "/" + name
		if err := mm.Pin(path); err != nil && !os.IsExist(err) {
			logger.Warn("map pinlenemedi", "map", name, "error", err)
		}
	}
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

	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
