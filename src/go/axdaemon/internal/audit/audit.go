// Package audit receives audit events from the eBPF perf buffer
// and forwards them to the axlog service.
package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// Yol alani policy_key ile ayni sekilde blokludur. Duz kopyalansaydi
// bloklar arka arkaya gelir ve kayit okunamazdi; birlestirme
// JoinPath ile yapilir.
const (
	PathDepth = 8
	PathSlot  = 32
)

// Event is the audit event received from the kernel perf buffer.
//
// The field order and types MUST match struct audit_event in
// axbpf.h byte for byte. Any divergence decodes garbage silently,
// so the layout is locked by TestEventLayoutMatchesC.
//
// C layout:
//
//	__u64 timestamp; __u32 pid; char comm[16];
//	char path[8][32];
//	__u32 action, effect, decision, rule_id, hook_type;
type Event struct {
	Timestamp uint64
	PID       uint32
	Comm      [16]byte
	Path      [PathDepth][PathSlot]byte
	Action    uint32
	Effect    uint32
	Decision  uint32
	RuleID    uint32
	HookType  uint32

	// Kimlik: path cozulemedigi durumlar icin (inode_permission).
	Ino uint64
	Dev uint32

	// APath, policy anahtarindan genis okunabilir audit yolu.
	//
	// Anahtar 8x31 ile sinirli oldugu icin 31 karakterden uzun
	// dosya adi veya 8'den derin dizin anahtara SIIGMIYOR ve
	// kayit `object: {}` olarak yaziliyordu. APath 16x63 tutar;
	// sigmiyorsa APFlags & PathFlagTruncated isareti birakilir.
	APath   [AuditDepth][AuditSlot]byte
	APFlags uint32
	APCount uint32
}

const (
	// PathFlagTruncated: yolun tamami sigmadi.
	PathFlagTruncated uint32 = 1 << 0
)

// Audit yolu tamponu sabitleri. BPF tarafiyla BIREBIR ayni
// olmak ZORUNDA: Event, perf buffer'dan okunan ham baytlardir
// (bkz. sender.go) ve Go derleyicisinin ekledigi bir hizalama
// veya alan siralamasi tum kayitlari kaydırır.

// JoinAPath returns the readable audit path, or "" if empty.
//
// Anahtar yolu (JoinPath) temsil edilemediginde bos doner; bu
// yontem her zaman doludur. Kirpma isareti Truncated ile birlikte
// doner.
func (e Event) JoinAPath() (s string, truncated bool) {
	var sb strings.Builder
	truncated = e.APFlags&PathFlagTruncated != 0

	// SIRALAMA KONUSU - burada dikkatli olmak gerekiyor:
	//
	// ax_fill_audit_path, dentry yurusunde dosyanin KENDI adindan
	// baslayip yukari dogru ilerler ve her bileseni sirayla
	// apath[0], apath[1], ... yazar. Yani:
	//
	//   apath[0] = "/aaaa.txt"   (en derin)
	//   apath[1] = "/olcum"
	//   apath[2] = "/tmp"        (en sig)
	//
	// Bu TERS siradir. Duz (0 -> N) iterate edilirse yol
	// "/aaaa.txt/olcum/tmp" olur - dosyanin hangi dizinde
	// oldugu kaybolur ve operator okudugu yolu tanimaz.
	//
	// Ayni sey JoinPath() icin de gecerli: politika anahtari
	// bilesenleri Path[7]'den Path[0]'a YAZAR, yani ilk yazilan
	// en derin bilesendir.
	//
	// Bu yuzden GERIYE dogru iterasyon zorunludur. Yanlis
	// yonun ilk denemesi tam olarak bu hatayi uretti:
	//   "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.txt/olcum/tmp"
	//
	// APCount, gercekten yazilan bilesen sayisidir; kirpma
	// durumunda da guvenilir.
	n := int(e.APCount)
	if n > AuditDepth {
		n = AuditDepth
	}
	if n == 0 {
		// APCount 0 ise ya hic bilesen yazilmadi ya da eski kayit.
		// Yine de dolu blogu tara: sessizce bos donmek, yol
		// cozulebilen durumda gecersiz bos kayit uretir.
		n = AuditDepth
	}
	for i := n - 1; i >= 0; i-- {
		blk := strings.TrimRight(string(e.APath[i][:]), "\x00")
		if blk == "" {
			continue
		}
		sb.WriteString(blk)
	}
	return sb.String(), truncated
}

// JoinPath stitches the path blocks back into a single string.
func (e Event) JoinPath() string {
	var sb strings.Builder
	for _, blk := range e.Path {
		s := strings.TrimRight(string(blk[:]), "\x00")
		if s == "" {
			continue
		}
		sb.WriteString(s)
	}
	if sb.Len() == 0 {
		return ""
	}
	return sb.String()
}

// EventSize is the wire size of struct audit_event as the kernel
// writes it: 8 (timestamp) + 4 (pid) + 16 (comm) + 256 (path) plus
// five u32 tail fields (action, effect, decision, rule_id, hook_type).
//
// It must equal the C sizeof exactly: parseEvent rejects records
// shorter than this, so an overestimate would silently drop every
// audit record. TestEventLayoutMatchesC computes the C value
// independently and compares.
// C yapisi: 8 + 4 + 16 + (8*32) + 5*4 + 8 + 4 + (16*64) + 4 + 4
//
// Ayri bir "tahmini toplam" DEGERI degil; TestEventLayoutMatchesC
// bunu C basligindan OLEN bolumun toplamiyla karsilastirir. Elle
// yazilan bir toplam sessizce kayar ve her kayit bozulur.
const EventSize = 8 + 4 + 16 + 8*32 + 5*4 + 8 + 4 + 16*64 + 4 + 4

// Audit tampon sabitleri C ile ayni olmak ZORUNDA.
const (
	AuditDepth = 16
	AuditSlot  = 64
)

// EventSender is the interface for forwarding events to axlog.
type EventSender interface {
	Send(event Event) error
}

// Manager reads from the eBPF perf buffer and dispatches events.
// Observer is notified once for every event the daemon parses, at the
// moment the event is produced.
//
// It exists because the learning subsystem must observe decisions as
// they happen. Driving learning from a log query is wrong in two ways
// at once: nothing is observed unless somebody happens to run
// "axctl logs", and every one of those queries re-counts the same
// recent events, so the report inflates each time it is read.
type Observer interface {
	Observe(subject, object, action string)
}

type Manager struct {
	mu     sync.Mutex
	reader *perf.Reader

	// lostSamples: kernel tarafindan dusurulen kayit sayisi.
	lostSamples uint64
	// undersized: EventSize'dan kucuk gelen kayit (yapi kaymasi).
	undersized uint64
	sender     EventSender
	events     []Event

	// obsMu is deliberately NOT m.mu. The observer is called from the
	// read loop, and an observer is free to call back into the audit
	// manager (to label an event, for example). Reusing m.mu here
	// would be a self-deadlock waiting for the first caller.
	obsMu    sync.RWMutex
	observer Observer

	// healthy is false once the read loop has hit its consecutive
	// error threshold and stopped. It is what separates "no events
	// have happened yet" from "the audit loop is dead": both show
	// Count() == 0, and only this field tells them apart.
	healthy   bool
	fatalErr  string
	closeOnce bool

	// sendFailed counts events the downstream writer rejected. A
	// silently discarded audit record is worse than a missing one:
	// the operator believes the trail is complete when it is not.
	// Disk full and a crashed axlog both land here.
	sendFailed int
}

// Healthy reports whether the read loop is running. A false value
// means audit records are no longer being collected, even though
// enforcement itself may still be working.
func (m *Manager) Healthy() (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthy, m.fatalErr
}

// LostSamples returns how many audit records the kernel dropped
// because the per-CPU perf buffer was full.
//
// SIFIR OLMAYAN BIR DEGER, DENETIM IZINDE BOSLUK DEMEKTIR:
// enforcement karar verdi ama kanit KAYDEDILMEDI. Bu sayac
// operatorun "kayitlar yaziliyor" varsayimini denetlenebilir
// kilar.
func (m *Manager) LostSamples() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lostSamples
}

// Undersized returns records that arrived shorter than EventSize.
// Sifir olmamalidir; sifirdan buyukse C/Go yapi kaymasi vardir.
func (m *Manager) Undersized() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.undersized
}

// SendFailures returns how many events the downstream writer rejected.
// This is the count of audit records that exist in memory but were
// never persisted, so the trail has gaps.
func (m *Manager) SendFailures() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendFailed
}

// NewManager creates an audit manager.
func NewManager(sender EventSender) *Manager {
	return &Manager{
		sender:  sender,
		events:  make([]Event, 0, 1024),
		healthy: true,
	}
}

// SetObserver installs (or with nil, removes) the per-event observer.
func (m *Manager) SetObserver(o Observer) {
	m.obsMu.Lock()
	m.observer = o
	m.obsMu.Unlock()
}

func (m *Manager) currentObserver() Observer {
	m.obsMu.RLock()
	o := m.observer
	m.obsMu.RUnlock()
	return o
}

// OpenPerfBuffer attaches to the given eBPF map's perf buffer.
func (m *Manager) OpenPerfBuffer(em *ebpf.Map) error {
	if em == nil {
		return fmt.Errorf("perf map nil")
	}

	// Per-CPU tampon 4096 -> 16384 bayt.
	//
	// OLAY BOYUTU 304 -> 1352 bayta cikti (genis okunabilir audit
	// yolu: 16 bilesen x 63 karakter). 4096 baytlik tampona artik
	// YALNIZCA 2 olay sigiyor; 3. olaydan itibaren kernel
	// PERF_RECORD_LOST uretiyor ve kayit SESSIZCE duser.
	//
	// 16384 bayt = 12 olay/olay basina, 4 sayfa. Burst (ornegin
	// 2000 islem) sirasinda tampon dolmadan bosalir.
	const perfBufPerCPU = 16384

	reader, err := perf.NewReader(em, perfBufPerCPU)
	if err != nil {
		return fmt.Errorf("perf reader acilamadi: %w", err)
	}

	m.mu.Lock()
	m.reader = reader
	m.mu.Unlock()

	return nil
}

// Run starts the event processing loop until context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	reader := m.reader
	m.mu.Unlock()

	if reader == nil {
		return fmt.Errorf("perf reader acik degil")
	}

	// Kalici okuma hatasinda sonsuz meşgul dongu olusurdu: Read
	// hemen hata doner, continue ile basa donulur ve ctx.Done()
	// kontrolu hicbir zaman calismaz. Audit sessizce OLMEYE devam
	// eder, daemon "5/5 kanca bagli" gosterir ama hicbir kayit
	// gelmez. Bu, MAC'te en kotu hata modudur: kullanici korundugunu
	// sanar.
	//
	// Burada surekli ayni hatayi sayip esik asilir; asilirsa hata
	// DONER, ust katman (main.go) bunu loglar. Ara sira gelen
	// gecici hatalar (perCpu tampon dolulugu gibi) sayacı sifirlamaz.
	var consecutive int
	const maxConsecutive = 100

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rec, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			consecutive++
			if consecutive >= maxConsecutive {
				m.markUnhealthy(fmt.Sprintf(
					"perf reader %d kez ust ust hata verdi (son: %v); "+
						"audit dongusu durdu, kayitlar toplanmiyor",
					consecutive, err))
				return fmt.Errorf("perf reader %d kez ust ust hata verdi "+
					"(son hata: %w); audit dongusu durduruluyor, "+
					"kayitlar toplanmiyor", consecutive, err)
			}
			// Hata sonrasi kisa bir soluklanma: meşgul donguye
			// donusmeden once CPU'yu birak ve ctx kontrolune
			// izin ver.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		consecutive = 0

		// Boyut kontrolu EventSize'a BIREBIR olmalidir. Elle
		// yazilmis bir toplam (316) EventSize'dan (304) buyuk
		// kalirsa her kayit sessizce dusurulur ve audit hicbir
		// zaman bos gorunmez.
		// KERNEL KAYBI: per-CPU tampon dolarsa kernel kaydi dusurur
		// ve LostSamples artar. Bu sayac OLMADAN, tampon yetersiz
		// oldugunda kayitlar sessizce yok olur ve operator "kural
		// uygulaniyor, kayit da yaziliyor" sanar.
		//
		// 304 -> 1352 bayt olay buyutmesiyle tampon 4096'da 2 olaya
		// sigiyordu; buyume sessizce %100 kayba donustu.
		if lost := rec.LostSamples; lost > 0 {
			m.mu.Lock()
			m.lostSamples += lost
			m.mu.Unlock()
			// Kalici degil: tek bir kayip normaldir (buffer anlik
			// dolar). Ama surekli kayip gostergeyi kirar.
			m.markUnhealthy(fmt.Sprintf(
				"kernel %d audit kaybini raporladi (per-CPU tampon dolu); "+
					"kayitlar dusuruluyor", lost))
			continue
		}

		if len(rec.RawSample) < EventSize {
			m.mu.Lock()
			m.undersized++
			m.mu.Unlock()
			continue
		}

		event, err := parseEvent(rec.RawSample)
		if err != nil {
			continue
		}

		m.mu.Lock()
		m.events = append(m.events, event)
		if len(m.events) > 10000 {
			m.events = m.events[len(m.events)-5000:]
		}
		m.mu.Unlock()

		// Gozlemci olay URETILIRKEN beslenir, sorgu aninda
		// degil. Boylece "kim neyi denedi" sorusu, kimse log
		// sorgulamasa bile birikir.
		if ob := m.currentObserver(); ob != nil {
			ob.Observe(
				strings.TrimRight(string(event.Comm[:]), "\x00"),
				event.JoinPath(),
				ActionName(event.Action),
			)
		}

		if m.sender != nil {
			// Yazma hatasi SESSIZCE YUTULMAZ. Disk doldugu ya da
			// axlog coktugunde burada hata olusur ve kayit
			// kaybolur. Sayac artar ve get_status bunu bildirir:
			// operator "kayit tutuluyor" sanarken gercekte
			// delikler olmamali.
			if err := m.sender.Send(event); err != nil {
				m.mu.Lock()
				m.sendFailed++
				m.mu.Unlock()
				// Ilk hatada saglik false yapiyoruz: yazma
				// tarafi calismiyorsa akis saglam sayilamaz.
				m.markUnhealthy("audit kaydi kalici olarak yazilamadi: " +
					err.Error())
			}
		}
	}
}

// Recent returns a copy of the most recent events.
func (m *Manager) Recent(limit int) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}

	start := len(m.events) - limit
	if start < 0 {
		start = 0
	}

	result := make([]Event, limit)
	copy(result, m.events[start:])
	return result
}

// Count returns the total number of buffered events.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// Stats reports how many events were denied versus allowed. These
// counters are cumulative across the whole daemon lifetime, not just
// the currently buffered window.
func (m *Manager) Stats() (denied, allowed int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.events {
		if m.events[i].Decision == 1 {
			denied++
		} else {
			allowed++
		}
	}
	return
}

// DeniedCount returns how many buffered events were denied.
func (m *Manager) DeniedCount() int {
	denied, _ := m.Stats()
	return denied
}

// AllowedCount returns how many buffered events were allowed.
func (m *Manager) AllowedCount() int {
	_, allowed := m.Stats()
	return allowed
}

// Close shuts down the perf reader.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closeOnce {
		return nil
	}
	m.closeOnce = true

	if m.reader != nil {
		err := m.reader.Close()
		m.reader = nil
		return err
	}
	return nil
}

// markUnhealthy records a fatal read-loop failure so get_status can
// report it. Without this the operator sees audit_log_count == 0 and
// has no way to tell an idle system from a dead audit loop.
func (m *Manager) markUnhealthy(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthy = false
	m.fatalErr = msg
}

// parseEvent decodes one perf buffer record. The offsets below mirror
// struct audit_event in axbpf.h; keep them in lockstep with Event.
func parseEvent(data []byte) (Event, error) {
	var e Event

	if len(data) < EventSize {
		return e, fmt.Errorf("audit kaydi kisa: %d bayt (beklenen %d)",
			len(data), EventSize)
	}

	offset := 0

	e.Timestamp = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	e.PID = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	copy(e.Comm[:], data[offset:offset+16])
	offset += 16

	for i := 0; i < PathDepth; i++ {
		copy(e.Path[i][:], data[offset:offset+PathSlot])
		offset += PathSlot
	}

	e.Action = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.Effect = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.Decision = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.RuleID = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.HookType = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Kimlik: inode_permission yol cozulemedigi icin.
	e.Ino = binary.LittleEndian.Uint64(data[offset:])
	offset += 8

	e.Dev = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Okunabilir audit yolu (anahtardan genis).
	for i := 0; i < AuditDepth; i++ {
		copy(e.APath[i][:], data[offset:offset+AuditSlot])
		offset += AuditSlot
	}

	e.APFlags = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	e.APCount = binary.LittleEndian.Uint32(data[offset:])

	return e, nil
}

// FormatEvent renders an event as a human-readable string.
func FormatEvent(e Event) string {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
	path := e.JoinPath()
	ts := time.Unix(0, int64(e.Timestamp)).UTC().Format(time.RFC3339)
	return fmt.Sprintf("[%s] pid=%d comm=%s path=%s action=%d effect=%d decision=%d rule=%d",
		ts, e.PID, comm, path, e.Action, e.Effect, e.Decision, e.RuleID)
}
