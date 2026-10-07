package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// DefaultAxlogSocket is where axlog listens by default.
const DefaultAxlogSocket = "/run/axlinux/axlog.sock"

// UnixSender forwards audit events to the axlog service over a Unix
// socket, one JSON object per line.
//
// Before this existed, main.go passed nil as the sender, so no audit
// record was ever persisted: `get_status` showed a full in-memory
// buffer and "audit saglikli" while /var/log/axlinux stayed empty.
// The whole point of an audit trail is what survives the process.
//
// The connection is lazy and reconnects on failure. axlog is a
// separate service and may start later or restart; dropping events
// for that reason would recreate the same silent gap.
type UnixSender struct {
	path string

	mu   sync.Mutex
	conn net.Conn
	w    *bufio.Writer
	// lastErr is surfaced by Health so the daemon can report that
	// events are being lost even when the read loop is fine.
	lastErr error
	sent    int
	failed  int
}

// NewUnixSender returns a sender writing to the given socket path.
// An empty path falls back to DefaultAxlogSocket.
func NewUnixSender(path string) *UnixSender {
	if path == "" {
		path = DefaultAxlogSocket
	}
	return &UnixSender{path: path}
}

// Send writes one event. It returns an error when the event could not
// be delivered so the caller can count the loss.
func (s *UnixSender) Send(e Event) error {
	payload, err := json.Marshal(s.toAxlogEvent(e))
	if err != nil {
		s.recordErr(fmt.Errorf("serialize: %w", err))
		return err
	}
	payload = append(payload, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureConnLocked(); err != nil {
		s.failed++
		s.lastErr = err
		return err
	}

	if _, err := s.w.Write(payload); err != nil {
		// The connection is probably dead. Drop it so the next
		// event reconnects instead of failing forever.
		s.closeLocked()
		s.failed++
		s.lastErr = err
		return err
	}
	// Buffer flush: without it the event sits in userspace and is
	// lost on a crash, which is the exact failure this whole
	// component exists to prevent.
	if err := s.w.Flush(); err != nil {
		s.closeLocked()
		s.failed++
		s.lastErr = err
		return err
	}
	s.sent++
	// Basarili gonderimden sonra saglik durumu TEMIZLENIR.
	//
	// lastErr onceki hatanin kalici hatasi olarak tutuluyordu:
	// axlog yeniden baslatildiginda bir kez "broken pipe" olusuyor,
	// bir sonraki denemede baglanti kendiliginden kuruluyor ve
	// kayitlar tekrar akmaya basliyordu - ama lastErr HAFIZADA
	// kalirdi. Sistem saglikliyken audit_healthy=false bildirirdi,
	// yani operatora surekli yanlis alarm giderdi. Gonderim dogrusu
	// gosteriyorsa hata yoktur.
	s.lastErr = nil
	return nil
}

func (s *UnixSender) recordErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed++
	s.lastErr = err
}

func (s *UnixSender) ensureConnLocked() error {
	if s.conn != nil {
		return nil
	}
	if _, err := os.Stat(s.path); err != nil {
		return fmt.Errorf("axlog socket bulunamadi (%s): %w", s.path, err)
	}
	conn, err := net.DialTimeout("unix", s.path, 3*time.Second)
	if err != nil {
		return fmt.Errorf("axlog'a baglanilamadi (%s): %w", s.path, err)
	}
	s.conn = conn
	s.w = bufio.NewWriter(conn)
	return nil
}

func (s *UnixSender) closeLocked() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
		s.w = nil
	}
}

// Close releases the socket.
func (s *UnixSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	return nil
}

// Health reports the last delivery error, if any. A sender that has
// never failed returns an empty string.
func (s *UnixSender) Health() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr == nil {
		return ""
	}
	return s.lastErr.Error()
}

// Stats returns delivered and failed counts.
func (s *UnixSender) Stats() (sent, failed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.failed
}

// axlogEvent mirrors models.AuditEvent in the axlog module. The two
// structures are separate types on purpose: axlog is a standalone
// service with its own on-disk schema, and coupling the daemon to it
// would make the wire format an import-time dependency.
//
// The mapping is explicit so a field added to one side and forgotten
// on the other shows up here rather than as an empty column in the
// log.
type axlogEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Mode      string `json:"mode"`
	Hook      string `json:"hook"`
	Subject   struct {
		PID  uint32 `json:"pid"`
		Comm string `json:"comm"`
	} `json:"subject"`
	Object struct {
		Path string `json:"path,omitempty"`
		// inode_permission yol cozulemez; kayit yine de kimlik
		// tasir: find / -xdev -inum <inode>.
		Inode uint64 `json:"inode,omitempty"`
		Dev   uint32 `json:"dev,omitempty"`
		// Truncated: yolun tamami sigmadi.
		Truncated bool `json:"truncated,omitempty"`
	} `json:"object"`
	Action   string `json:"action"`
	Effect   string `json:"effect"`
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id,omitempty"`
}

// Hook type names, matching the HOOK_* constants in axbpf.h.
var hookNames = map[uint32]string{
	1: "file_open",
	2: "inode_permission",
	3: "bprm_check_security",
	4: "socket_connect",
	5: "socket_bind",
}

// toAxlogEvent converts the daemon's kernel-side event into the
// on-disk shape.
func (s *UnixSender) toAxlogEvent(e Event) axlogEvent {
	var out axlogEvent

	// The kernel timestamp is bpf_ktime_get_ns: monotonic since
	// boot, NOT a wall clock. Converting it as if it were Unix time
	// yields 1970 dates, so it is recorded as-is and axlog stamps
	// the receipt time. Mixing the two silently would put every
	// record a decade and a half in the past.
	out.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	out.Type = "lsm"
	out.Hook = HookName(e.HookType)
	out.Subject.PID = e.PID
	out.Subject.Comm = trimNUL(e.Comm[:])
	// ONCE anahtar yolu (kisa ve kesin), yol cozulemediyse genis
	// audit yolu. JoinAPath her zaman doludur; kirpma isaretiyle
	// gelir.
	// DENETIM YOLU: once apath (genis, 16x63, mount onekli ve
	// her zaman TAM).
	//
	// Once burada JoinPath() (policy anahtari) tercih ediliyordu
	// ve bu YANLIS cikti. Anahtar 8x31 ile sinirlidir ve 8'den
	// derin yollarda TAMAMLANMADAN yazilir. Go tarafi bos olmayan
	// bir anahtar gorup "yol cozuldu" saniyor, operatora KIRIK
	// yol gosteriyordu:
	//
	//   /tmp/dp2/l1/l2/l3/l4/l5/l6/f.txt      dogru
	//     -> "/l1/l2/l3/l4/l5/l6/f.txt"       URETIMDE GORULDU
	//
	// Anahtar ESLESME icindir (hash lookup), GOSTERIM icin degil.
	// Bu yuzden once apath, bos kalirsa anahtar.
	apath, apathTrunc := e.JoinAPath()
	if apath != "" {
		out.Object.Path = apath
		out.Object.Truncated = apathTrunc
	} else if p := e.JoinPath(); p != "" {
		// apath dolu degilse anahtar tek sans. inode_permission
		// buraya duser (yol cozulemez); o zaman kayit ino/dev
		// kimligiyle anlamli kalir.
		out.Object.Path = p
		out.Object.Truncated = false
	}
	// inode_permission yol cozulemez; kayit yine de kimlik tasir.
	// Once `object: {}` yaziliyordu: operator hangi dosyaya
	// denialdigini hicbir sekilde ogrenemiyordu.
	out.Object.Inode = e.Ino
	out.Object.Dev = e.Dev
	out.Action = ActionName(e.Action)
	out.Effect = EffectName(e.Effect)
	out.Decision = DecisionName(e.Decision)
	out.RuleID = fmt.Sprintf("rule_%03d", e.RuleID)
	return out
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ActionName maps a numeric action id to its policy name. This is the
// single canonical mapping in the daemon: handlers, the JSONL writer
// and the learning observer all resolve names through here, so a new
// action cannot be spelled two different ways in two packages.
func ActionName(a uint32) string {
	switch a {
	case 1:
		return "file.read"
	case 2:
		return "file.write"
	case 3:
		return "file.execute"
	case 4:
		return "file.delete"
	case 5:
		return "file.create"
	case 6:
		return "net.connect"
	case 7:
		return "net.bind"
	case 8:
		return "net.accept"
	case 9:
		return "process.exec"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

// EffectName maps an EFFECT_* value to its policy name.
//
// The numeric encoding is a trap: EFFECT_DENY is 0 and EFFECT_ALLOW
// is 1, while DECISION_ALLOWED is 0 and DECISION_DENIED is 1. The two
// enums run in opposite directions, so anything that prints or filters
// on them has to go through these functions rather than formatting the
// number itself.
func EffectName(e uint32) string {
	// EFFECT_DENY = 0, EFFECT_ALLOW = 1 in axbpf.h.
	if e == 0 {
		return "deny"
	}
	return "allow"
}

// DecisionName maps a DECISION_* value to its name.
func DecisionName(d uint32) string {
	// DECISION_DENIED = 1, DECISION_ALLOWED = 0.
	if d == 1 {
		return "denied"
	}
	return "allowed"
}

// HookName maps a HOOK_* value to the kernel hook name.
func HookName(h uint32) string {
	if n, ok := hookNames[h]; ok {
		return n
	}
	return fmt.Sprintf("hook(%d)", h)
}
