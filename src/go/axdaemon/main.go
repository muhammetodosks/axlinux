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
const Version = "1.1.0"

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
		axlogSocket = flag.String("axlog-socket", "/run/axlinux/axlog.sock",
			"axlog Unix socket yolu (audit kayitlari buraya yazilir)")
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
	lsmMgr.SetPinDir(*pinDir)
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
			// Ogrenme bayragi kalici bir map'te tutulur. Ogrenme
			// acikken daemon yeniden baslatilirsa deger 1 kalir
			// ve kancalar surekli audit uretirken operator ogrenme
			// modunun kapandigini sanir. Her acilista sifirlanir:
			// ogrenme durumu surec yasamindadir, dosya degil.
			// Gorunmez mount kozlarini (btrfs alt birim koku)
			// mountinfo'dan okuyup BPF'ye ver.
			//
			// Bunu yapmazsak Fedora'da kok dosya sistemindeki
			// HER yol kurali sessizce calismaz: BPF yolu
			// "/root/etc/secret" gorur, politika "/etc/secret"
			// yazar.
			if names, err := mapsMgr.PopulateMountArtifacts(); err != nil {
				logger.Warn("mount kozlari okunamadi; kok dosya "+
					"sistemindeki yol kurallari btrfs'te "+
					"uygulanmayabilir", "error", err)
			} else if len(names) > 0 {
				logger.Info("gorunmez mount kozlari",
					"names", names)
			}

			// Mount NOKTASI oneki. /tmp gibi ayri mount'lar
			// icinde dentry yurusu mount adini GORMEZ:
			// "tmp" bir dizin girdisi degil, bir mount
			// baglantisidir. Bu harita olmadan /tmp kurallari
			// sessizce tutmaz (reload yine "basarili" der).
			if mps, err := mapsMgr.PopulateMountPoints(); err != nil {
				logger.Warn("mount noktalari okunamadi; /tmp gibi "+
					"ayri mount'larin yol kurallari uygulanmayabilir",
					"error", err)
			} else if len(mps) > 0 {
				logger.Info("mount noktasi onekleri", "count", len(mps))
			}

			if err := mapsMgr.SetLearning(false); err != nil {
				logger.Warn("ogrenme bayragi sifirlanamadi",
					"error", err)
			}

			if err := mapsMgr.SetMode(maps.ModePermissive); err != nil {
				logger.Warn("mod yazilamadi", "error", err)
			}

			enforceRequested := !*noEnforce
			if !enforceRequested {
				// Manager'a da bildir: aksi halde get_status
				// 0/5 kanca bildirip bunu bir build/kernel
				// hatas gibi gosterirdi.
				lsmMgr.SetNoEnforce()
				logger.Warn("--no-enforce verildi, LSM kancalari " +
					"BILINCLI OLARAK baglanmadi; politika " +
					"UYGULANMIYOR (RPC ve dogrulama calisir)")
			} else if err := lsmMgr.Attach(); err != nil {
				logger.Warn("bazi LSM kancalari baglanamadi",
					"error", err)
			}

			// EnforcementPossible iki kosulu da ister: bpf LSM
			// zincirde OLMALI ve TUM kancalar baglanmis OLMALI.
			// Ikinci kosul atlanirsa mesaj yaniltici olur: 3/5 kanca
			// bagliyken "bpf LSM zincirde yok" demek, sorunun
			// yerine gondermez. Kismi baglanmanin ayri bir tanisi
			// vardir.
			//
			// --no-enforce BILINCLI bir durumdur: hicbir kanca
			// baglanmamasi beklenir, sorun degil. Bu yuzden o
			// durumda "KISMI" tanisi yaniltici olurdu.
			switch {
			case !enforceRequested:
				// yukarida zaten uyarildi

			case lsmMgr.AllHooksAttached():
				logger.Info("LSM kancalari baglandi",
					"aktif", lsmMgr.AttachedCount(),
					"toplam", lsmMgr.HookCount())

			case lsmMgr.AttachedCount() == 0:
				// Hicbiri baglanmadi: buyuk ihtimalle zincir
				// sorunu ya da kernel destegi yok.
				logger.Warn("LSM kancalari baglanmadi - "+
					"bpf LSM zincirde olmali - politika UYGULANMIYOR",
					"toplam", lsmMgr.HookCount(),
					"detay", lsmenv.Summary())

			default:
				// Kismi: hangi kancalar eksik, operator ne
				// test etmeli bilmeli.
				logger.Warn("LSM KISMI BAGLANDI - enforcement TAM DEGIL",
					"aktif", lsmMgr.AttachedCount(),
					"toplam", lsmMgr.HookCount(),
					"eksik", strings.Join(lsmMgr.MissingHooks(), ","),
					"not", "eksik kancalara yazilan kurallar ETKISIZ kalir",
					"detay", lsmMgr.EnforcementNotice())
			}

			// Audit perf buffer'i da collection'dan al.
			//
			// --no-enforce durumunda hicbir kanca bagli
			// degildir; perf buffer acilsa bile uretilen olay
			// olmaz. Manager'i yine de baglamazsak
			// get_status "audit_healthy=false" der ve
			// operator bunun --no-enforce'dan kaynaklandigini
			// anlamaz. Bu yuzden acikca isaretlenir.
			//
			// Sender: once burada nil veriliyordu, yani HICBIR
			// audit kaydi kalici olarak yazilmazdi. get_status dolu
			// bir tampon ve "saglikli" gosteriyordu ama
			// /var/log/axlinux bos kaliyordu. Denetim izinin
			// surec olusturunce degil, diskte kaldiginda
			// anlami vardir.
			if !enforceRequested {
				logger.Info("--no-enforce: audit akisi " +
					"baslatilmiyor (kanca yok, kayit gelmez)")
			} else if am := mapsMgr.Map(maps.AuditMapName); am != nil {
				sender := audit.NewUnixSender(*axlogSocket)
				a := audit.NewManager(sender)
				if err := a.OpenPerfBuffer(am); err != nil {
					logger.Warn("perf buffer acilamadi, audit log kapali",
						"error", err)
				} else {
					auditMgr = a
					// Ogrenme gozlemleri olay akisindan
					// beslenir. Onceki tasarimda kayitlar
					// "axctl logs" sorgusundan aliniyordu;
					// boylece hicbir sey gozlenmiyor ya da
					// her sorguda ayni kayitlar tekrar
					// sayiliyordu.
					a.SetObserver(learningMgr)
					logger.Info("audit perf buffer acildi")
					go func() {
						if err := a.Run(ctx); err != nil &&
							err != context.Canceled {
							// Yalnizca loglamak yetmez: daemon
							// calismaya devam eder ve operator
							// enforcement aktif sanarken audit
							// toplamiyor olabilir. Manager'a
							// isaretlendi; get_status
							// audit_healthy=false doner ve
							// axctl bunu gosterir.
							logger.Error("audit dongusu DURDU - "+
								"kayitlar toplanmiyor, enforcement "+
								"calisiyor ama audit KAPALI",
								"error", err)
						}
					}()
					defer a.Close()
					// Sender'in socket baglantisi da kapatilmali;
					// manager Close yalnizca perf reader'i
					// serbest birakir.
					defer sender.Close()
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
		// Haritalari y yukleyici PinByName ile pinliyor ve
		// var olan pini YENIDEN KULLANIYOR. Burada yalniz
		// dogruluyoruz; elle Pin() çağrısı aynı yola ikinci
		// kez yazmaya çalışıp hata verirdi.
		if _, err := os.Stat(path); err == nil {
			logger.Debug("map zaten pinli, yeniden kullanildi",
				"map", name, "path", path)
			continue
		}
		if err := mm.Pin(path); err != nil {
			logger.Warn("map pinlenemedi", "map", name, "error", err)
			continue
		}
		logger.Debug("map pinlendi", "map", name, "path", path)
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
