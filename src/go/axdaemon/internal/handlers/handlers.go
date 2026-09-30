// Package handlers implements the JSON-RPC method handlers for axdaemon.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"axlinux/axdaemon/internal/audit"
	"axlinux/axdaemon/internal/learning"
	"axlinux/axdaemon/internal/maps"
	"axlinux/axdaemon/internal/mode"
	"axlinux/axdaemon/internal/policy"
	"axlinux/axdaemon/pkg/protocol"
)

// LSMStatus is the slice of LSM state the handler reports. It is
// implemented by lsm.Manager; declaring it here keeps the handler free
// of a direct dependency and lets it work when eBPF failed to load.
//
// MissingHooks is part of the interface because partial attachment has
// to be visible: reporting "3/5 aktif" without naming the missing hooks
// leaves the operator unable to tell which action class is unprotected.
type LSMStatus interface {
	IsLoaded() bool
	AttachedCount() int
	HookCount() int
	Status() map[string]bool
	EnforcementPossible() bool
	EnforcementNotice() string
	MissingHooks() []string
}

// Handler dispatches RPC methods to the appropriate subsystem.
type Handler struct {
	mu       sync.RWMutex
	policy   *policy.Manager
	maps     *maps.Manager
	mode     *mode.Manager
	learning *learning.Manager
	audit    *audit.Manager
	lsm      LSMStatus
	started  time.Time
}

// NewHandler creates a handler. The eBPF-backed dependencies are nil
// until the daemon confirms they loaded.
func NewHandler(
	p *policy.Manager,
	m *maps.Manager,
	md *mode.Manager,
	lm *learning.Manager,
) *Handler {
	return &Handler{
		policy:   p,
		maps:     m,
		mode:     md,
		learning: lm,
		started:  time.Now().UTC(),
	}
}

// Attach enables the eBPF-backed subsystems once they are live.
func (h *Handler) Attach(l LSMStatus, a *audit.Manager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lsm = l
	h.audit = a
}

// Dispatch routes a request to the correct method handler.
func (h *Handler) Dispatch(ctx context.Context, req protocol.Request) protocol.Response {
	switch req.Method {
	case "reload_policy":
		return h.handleReloadPolicy(req)
	case "get_status":
		return h.handleGetStatus(req)
	case "get_logs":
		return h.handleGetLogs(req)
	case "set_mode":
		return h.handleSetMode(req)
	case "learn_start":
		return h.handleLearnStart(req)
	case "learn_stop":
		return h.handleLearnStop(req)
	case "learn_report":
		return h.handleLearnReport(req)
	default:
		return protocol.NewErrorResponse(req.ID, -32601, "bilinmeyen metod: "+req.Method)
	}
}

func (h *Handler) handleReloadPolicy(req protocol.Request) protocol.Response {
	var params struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return protocol.NewErrorResponse(req.ID, -32602, "gecersiz params: "+err.Error())
	}

	snap, err := h.policy.Load(params.Policy)
	if err != nil {
		return protocol.NewErrorResponse(req.ID, -32000, "policy yukleme hatasi: "+err.Error())
	}

	// Kurallar ONCE dogrulanir; map'lere ve moda YAZILMADAN.
	//
	// Siranin onemi: Clear() once cagriliyordu ve bir kural
	// yazilamazsa hata donuluyordu. Bu durumda kullanici kuralsiz
	// (hicbir sey engellemeyen) bir sistemde kalirdi ve hata
	// mesaji "kural yazilamadi" ile gecildigi icin nedenini
	// anlamasi zor olurdu. Simdi once butun kurallar hazirlanir,
	// herhangi biri reddedilirse hicbiri yazilmaz ve hicbir sey
	// degistirilmez; boylece ya tam uygulama olur ya hicbiri.
	//
	// Dogrulama MODE YAZILMADAN da olmalidir. Once mod degistirilir,
	// sonra kural reddedilirse sistem, hicbir kurali olmayan yeni
	// bir modda birakilir: kullanici "enforcing aktif" gorur ama
	// hicbir sey engellenmez. Bu yuzden asagidaki dogrulama,
	// mode yazmadan ONCE calisir.
	type pending struct {
		comm, path, action string
		port               int
		ruleID, effect     uint32
	}
	var batch []pending

	if h.maps != nil {
		for _, rule := range snap.Policy.Rules {
			// effect constants live in the maps package and mirror axbpf.h
			effect := uint32(maps.EffectAllow)
			if rule.Effect == policy.EffectDeny {
				effect = maps.EffectDeny
			}
			for _, subj := range rule.Subject {
				batch = append(batch, pending{
					comm:   subj,
					path:   rule.Object,
					action: rule.Action,
					port:   rule.Port,
					ruleID: maps.RuleIDToUint(rule.ID),
					effect: effect,
				})
			}
		}

		// Asama 1: dogrulama (ne map'e ne moda yazmadan)
		for _, p := range batch {
			if err := maps.ValidateRule(p.comm, p.path, p.action, p.port); err != nil {
				return protocol.NewErrorResponse(req.ID, -32000,
					"politika uygulanamadi, hicbir kural yazilmadi: "+
						err.Error())
			}
		}
	}

	// Politika dosyasinda tanimli modu da uygula. Buraya yalnizca
	// dogrulama BASARILI olduktan SONRA gelir.
	if snap.Policy.Mode != "" {
		if err := h.mode.Set(mode.Mode(snap.Policy.Mode)); err != nil {
			return protocol.NewErrorResponse(req.ID, -32000,
				"policy mode gecersiz: "+err.Error())
		}
		if h.maps != nil {
			h.maps.SetMode(modeNumeric(h.mode.Get()))
		}
	}

	// Asama 2: yazma (dogrulama gecti, sistem degistirilebilir)
	if h.maps != nil {
		_ = h.maps.Clear()
		for _, p := range batch {
			if err := h.maps.WriteRule(p.comm, p.path, p.action,
				p.port, p.ruleID, p.effect); err != nil {
				return protocol.NewErrorResponse(req.ID, -32000,
					"kural yazilamadi: "+err.Error())
			}
		}
	}

	result := map[string]interface{}{
		"status":       "ok",
		"rules_loaded": snap.RulesLoaded,
		"loaded_at":    snap.LoadedAt.Format(time.RFC3339),
	}
	return protocol.NewResponse(req.ID, result)
}

// modeNumeric maps a mode.Manager value to the numeric constant that
// axbpf.h expects in mode_map.
func modeNumeric(m mode.Mode) uint32 {
	switch m {
	case mode.ModeDisabled:
		return maps.ModeDisabled
	case mode.ModeEnforcing:
		return maps.ModeEnforcing
	default:
		return maps.ModePermissive
	}
}

// humanDuration renders an uptime in a compact readable form such as
// "3sa 24dk" instead of Go's raw "3.532884723s".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dgun %dsa", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dsa %ddk", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%ddk %dsn", mins, secs)
	default:
		return fmt.Sprintf("%dsn", secs)
	}
}

func (h *Handler) handleGetStatus(req protocol.Request) protocol.Response {
	h.mu.RLock()
	lsmSt, auditMgr := h.lsm, h.audit
	h.mu.RUnlock()

	snap := h.policy.Get()

	result := map[string]interface{}{
		"status":     "running",
		"mode":       string(h.mode.Get()),
		"uptime":     humanDuration(time.Since(h.started)),
		"started_at": h.started.Format(time.RFC3339),
		// These keys are the contract consumed by axctl's formatter.
		// Keep them in sync with src/python/axctl/formatter.py.
		"rules_loaded":  snap.RulesLoaded,
		"labels_loaded": snap.LabelsLoaded,
	}

	if snap.Loaded {
		result["last_reload"] = snap.LoadedAt.Format(time.RFC3339)
	} else {
		result["last_reload"] = ""
	}

	if lsmSt != nil {
		enforcing := lsmSt.EnforcementPossible()
		notice := lsmSt.EnforcementNotice()

		result["ebpf_loaded"]  = lsmSt.IsLoaded()
		result["lsm_hooks_active"] = lsmSt.AttachedCount()
		result["lsm_hooks_total"]  = lsmSt.HookCount()
		result["bpf_programs_loaded"] = lsmSt.AttachedCount()
		result["bpf_programs_total"]  = lsmSt.HookCount()
		result["hooks"] = lsmSt.Status()

		// enforcement_active is the field that matters: it is false
		// when hooks are attached but the kernel cannot run them,
		// AND when only some hooks attached (partial enforcement is
		// not enforcement — see lsm.EnforcementPossible).
		result["enforcement_active"] = enforcing
		if notice != "" {
			result["enforcement_notice"] = notice
		}
		// Kanca bazinda hangisinin baglanmadigini goster. Kullanici
		// "3/5 aktif" gordugunde hangi kancanin eksik oldugunu
		// bilmezse neyi test etmesi gerektigini de bilemez.
		if missing := lsmSt.MissingHooks(); len(missing) > 0 {
			result["hooks_missing"] = missing
		}
	} else {
		result["ebpf_loaded"]         = false
		result["lsm_hooks_active"]    = 0
		result["lsm_hooks_total"]     = 0
		result["bpf_programs_loaded"] = 0
		result["bpf_programs_total"]  = 0
		result["enforcement_active"]  = false
		result["enforcement_notice"]  =
			"ebpf yuklenemedi; politika uygulanmiyor"
	}
	if h.maps != nil {
		allowCount, denyCount := h.maps.Count()
		result["map_allow_entries"] = allowCount
		result["map_deny_entries"]  = denyCount
	} else {
		result["map_allow_entries"] = 0
		result["map_deny_entries"]  = 0
	}

	if auditMgr != nil {
		denied, allowed := auditMgr.Stats()
		result["audit_log_count"]     = auditMgr.Count()
		result["audit_denied_count"]  = denied
		result["audit_allowed_count"] = allowed
		// audit_healthy, audit_log_count == 0 ile karistirilamaz.
		// Sayi sifirken iki durum mumkundur: hicbir olay olmadi
		// (normal) ya da okuma dongusu oldu (facia). Kullanici
		// yalnizca sayiya bakarsa sessizce korunuyor sanar.
		healthy, why := auditMgr.Healthy()
		result["audit_healthy"] = healthy
		if !healthy {
			result["audit_notice"] = why
		}
		// Kalici olarak yazilamayan kayit sayisi. Sifir degilse
		// audit izinde DELIK var demektir: enforcement karar verdi
		// ama kanit kaydedilmedi. Bu sayi olmadan operator
		// "kayitlar toplanmiyor" sanir.
		if failed := auditMgr.SendFailures(); failed > 0 {
			result["audit_send_failures"] = failed
		}
	} else {
		result["audit_log_count"]     = 0
		result["audit_denied_count"]  = 0
		result["audit_allowed_count"] = 0
		result["audit_healthy"]       = false
		result["audit_notice"] = "perf buffer acilmadi; audit kaydi alinmiyor"
	}

	if h.learning != nil {
		result["learning_active"]      = h.learning.IsActive()
		result["learning_observations"] = h.learning.ObservationCount()
	}

	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleGetLogs(req protocol.Request) protocol.Response {
	// Filters daha once HIC okunmuyordu: axctl "filters" alanini
	// gonderiyor, sunucu yalnizca limit'i aliyordu. Kullanici
	// "--filter effect=deny" yaziyor, tum kayitlar donuyordu ve
	// filtre uygulanmis gibi gorunuyordu. Sessiz ve yaniltici.
	var params struct {
		Limit   int            `json:"limit"`
		Filters map[string]any `json:"filters"`
		Since   string         `json:"since"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return protocol.NewErrorResponse(req.ID, -32602, "gecersiz params: "+err.Error())
		}
	}

	if params.Limit <= 0 {
		params.Limit = 100
	}
	if params.Limit > 1000 {
		params.Limit = 1000
	}

	// Uygulanamayan filtre sessizce YOK SAYILMAZ. Kullanici
	// "effect=deny" yazip "deny kayitlari" bekler; filtre taninmazsa
	// hepsini gormek, filtre calismiyor mesaji vermekten cok daha
	// kotudur, cunku kullanici sonuca guvenir.
	var (
		applied []string
		unknown []string
	)
	// Filtre alanlarinin kanit tarafiyla eslesmesi gerekir.
	// "effect" karnedir (deny/allow), "decision" de.
	known := map[string]bool{
		"action": true, "effect": true, "decision": true,
		"comm": true, "subject": true, "path": true,
		"rule_id": true, "hook": true,
	}
	for k := range params.Filters {
		if !known[k] {
			unknown = append(unknown, k)
		} else {
			applied = append(applied, k)
		}
	}

	// --since AYRI parametredir ve ONCE filtreye karistiriliyordu.
	// Sunucu "since"u bilinmeyen bir filtre alani sayip yok
	// sayiyordu; kullanici "son 1 saat" beklerken tum izi
	// goruyordu.
	//
	// KERNEL ZAMANI ktime'dir (boot'tan beri monotonik), duvar
	// saati DEGILDIR. Bu yuzden "1h once" dogrudan ktime'a
	// cevrilemez. Burada yapilabilen ve dogru olan: kayitlar
	// kronolojik gelis sirasiyla saklandigi icin, verilen sure
	// kadar once baslayan dilimi arayip yalnizca o pencereyi
	// dondurmek. Tam dogruluk degil, ama EN AZINDAN "tum izi"
	// gostermekten iyidir ve kullaniciya sinir bildirilir.
	var sinceWindow time.Duration
	if params.Since != "" {
		d, err := parseSince(params.Since)
		if err != nil {
			return protocol.NewErrorResponse(req.ID, -32602,
				"gecersiz --since: "+params.Since+
					" (bicim: 30m, 2h, 1d, 1w)")
		}
		sinceWindow = d
		applied = append(applied, "since")
	}

	var logs []map[string]interface{}
	if h.audit != nil {
		// Once limit kadar tazir, filtre UYGULANMADAN; filtre
		// sonrasi yeniden kirpmak daha dogru sonuc verir.
		fetch := params.Limit
		if len(applied) > 0 && fetch < 1000 {
			// Filtreli sorguda daha genis pencere gerekir, yoksa
			// eslesen kayitlar limit disinda kalir.
			fetch = 1000
		}
		events := h.audit.Recent(fetch)
		// since penceresi: kayitlar kronolojik oldugu icen
		// "simdi - pencere" ktime'ini hesaplayip yalnizca
		// karsilastiranlari birakir. Tam dogruluk icin boot
		// suresi gerekir; olmadigi icin son ktime degeri
		// "simdi" kabul edilir, yani pencere en son kayda gore
		// kurulur. Hata payi en fazla son kaydin yasindadir.
		var cutoff uint64
		if sinceWindow > 0 && len(events) > 0 {
			nowKtime := events[len(events)-1].Timestamp
			span := uint64(sinceWindow)
			if nowKtime > span {
				cutoff = nowKtime - span
			}
		}
		for _, e := range events {
			if cutoff > 0 && e.Timestamp < cutoff {
				continue
			}
			row := map[string]interface{}{
				"timestamp": e.Timestamp,
				"pid":       e.PID,
				"comm":      strings.TrimRight(string(e.Comm[:]), "\x00"),
				"path":      e.JoinPath(),
				"action":    e.Action,
				"effect":    e.Effect,
				"decision":  e.Decision,
				"rule_id":   e.RuleID,
				// hook is a filterable field, so it has to exist in
				// the row. Without it "hook=file_open" was accepted
				// and then matched nothing, which reads as "no events
				// came from that hook" rather than as a bad filter.
				"hook": audit.HookName(e.HookType),
			}
			if matchesFilters(row, params.Filters) {
				logs = append(logs, row)
			}
		}
	}

	if len(logs) > params.Limit {
		logs = logs[len(logs)-params.Limit:]
	}

	// Ogrenme gozlemleri BURADA toplanmaz. Once burada bir dongu
	// vardi ve iki ayri hata uretiyordu:
	//
	//  1) her "axctl logs" cagrisi son olaylari YENIDEN sayiyordu,
	//     yani rapor her okundugunda sisuyordu;
	//  2) hicbir kimse log sorgulamazsa hicbir sey gozlenmiyordu.
	//
	// Dogru yer olayin URETILDIGI noktadir: audit.Manager, her
	// olayi ayristirirken learning.Manager'i Observer olarak
	// besler (bkz. audit.Observer). Bu yuzden burada yalnizca
	// sorgu sonucu dondurulur.
	result := map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}
	if len(applied) > 0 {
		result["filters_applied"] = applied
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		result["filters_ignored"] = unknown
		result["filter_warning"] =
			"BILINMEYEN FILTRE ALANI: " + strings.Join(unknown, ", ") +
				". Bu filtreler UYGULANMADI; sonuc eksiktir."
	}
	return protocol.NewResponse(req.ID, result)
}

// matchesFilters applies the client-supplied filters to one row.
//
// Comparison is case-insensitive and substring-based on paths, exact
// on the rest. The values arrive as JSON, so numbers arrive as
// float64; a filter written as "rule_id=7" must match the uint32 the
// row carries, which is why both sides are normalised to strings
// before comparing rather than compared as typed values.
func matchesFilters(row map[string]interface{}, filters map[string]any) bool {
	for key, want := range filters {
		if !knownFilterKey(key) {
			continue // reported separately, not silently dropped here
		}
		// "subject" is the name policy files and the CLI use; the
		// audit row calls the same field "comm". Without this alias
		// every subject= filter returned zero rows, and a user
		// searching for one process concluded there had been no
		// activity at all.
		lookup := key
		if key == "subject" {
			lookup = "comm"
		}
		got, ok := row[lookup]
		if !ok {
			return false
		}
		if !valueMatches(lookup, got, want) {
			return false
		}
	}
	return true
}

// canonicalFilterValue reduces one side of a comparison to a single
// comparable string.
//
// Both sides go through here. The row carries numeric values while the
// CLI sends names ("deny"), and a JSON client may send either. The two
// enums also run in opposite directions - effect 0 is deny while
// decision 0 is allowed - so a number can never be compared as text
// against a name without going through the mapping first. That is why
// "effect=deny" silently matched nothing.
func canonicalFilterValue(key string, v interface{}) string {
	s := normalizeValue(v)
	switch key {
	case "effect":
		switch s {
		case "0":
			return "deny"
		case "1":
			return "allow"
		}
		return s
	case "decision":
		switch s {
		case "0":
			return "allowed"
		case "1":
			return "denied"
		}
		return s
	case "action", "hook":
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			if key == "action" {
				return audit.ActionName(uint32(n))
			}
			return audit.HookName(uint32(n))
		}
		return s
	}
	return s
}

// knownFilterKey is the set the handler advertises via
// filters_applied. Kept as a package function so matchesFilters and
// the unknown-field check cannot drift apart.
func knownFilterKey(k string) bool {
	switch k {
	case "action", "effect", "decision", "comm", "subject",
		"path", "rule_id", "hook":
		return true
	}
	return false
}

// valueMatches compares a row value against a filter value.
//
// Substring matching is deliberately limited to path. It used to apply
// to every field, which made rule_id=1 match rule 21, and comm=ngin
// match nginx - a filter that returns extra rows is worse than one
// that returns none, because the extra rows look like real activity.
func valueMatches(key string, got, want interface{}) bool {
	gs := canonicalFilterValue(key, got)
	ws := canonicalFilterValue(key, want)

	// An empty filter value is not a wildcard. If it were, a stray
	// "effect=" would return the whole log and read as a match.
	if ws == "" {
		return false
	}
	if gs == ws {
		return true
	}
	// Path filters are substrings: "action=/etc/sha" should match
	// "/etc/shadow". Exact equality would force the user to know the
	// full path for a prefix search, which is the common case.
	if key == "path" && strings.Contains(gs, ws) {
		return true
	}
	return false
}

func normalizeValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(t))
	case nil:
		return ""
	case float64:
		// JSON numbers decode as float64; render whole values
		// without a trailing ".0" so "rule_id=7" matches 7.
		if t == float64(int64(t)) {
			return strings.ToLower(fmt.Sprintf("%d", int64(t)))
		}
		return strings.ToLower(fmt.Sprintf("%g", t))
	case uint32:
		return strings.ToLower(fmt.Sprintf("%d", t))
	case bool:
		return strings.ToLower(fmt.Sprintf("%t", t))
	default:
		return strings.ToLower(fmt.Sprintf("%v", t))
	}
}

// parseSince converts a --since argument to a duration.
//
// Accepted forms: "30m", "2h", "1d", "1w" and a bare number of
// seconds. Only these are allowed: a date parser would have to guess
// the user's timezone, and a wrong guess on an audit query silently
// returns the wrong window.
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("bos")
	}

	// Bare number: seconds.
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("suresiz deger")
		}
		return time.Duration(n) * time.Second, nil
	}

	unit := s[len(s)-1]
	value := s[:len(s)-1]
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("sayi cozumlenemedi")
	}
	if n <= 0 {
		return 0, fmt.Errorf("suresiz deger")
	}

	switch unit {
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("bilinmeyen birim %q (m, h, d, w)", string(unit))
	}
}

func (h *Handler) handleSetMode(req protocol.Request) protocol.Response {
	var params struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return protocol.NewErrorResponse(req.ID, -32602, "gecersiz params: "+err.Error())
	}

	newMode := mode.Mode(params.Mode)

	// GECERSIZ MODU EN BASTA REDDET.
	//
	// modeNumeric bilinmeyen bir modu sessizce ModePermissive'a
	// esliyor. Once haritaya yazsaydik yanlis bir mod icin
	// permissive yazip sonra geri almaya calisirdik; bu calisir
	// ama yanlis deger haritasina dokunmus olmak demek.
	// Dogrulama en basa alininca haritaya hicbir zaman gecersiz
	// deger yazilmaz.
	if newMode != mode.ModeEnforcing &&
		newMode != mode.ModePermissive &&
		newMode != mode.ModeDisabled {
		return protocol.NewErrorResponse(req.ID, -32000,
			"gecersiz mod: "+params.Mode+
				" (gecerli: enforcing, permissive, disabled)")
	}

	// Once HARITAYA yaz, sonra Go bellegine.
	//
	// Ters sirada (once h.mode.Set) kalici bir bolunme olusur:
	// map yazilamazsa hata donulur ama Go bellegi degismis olur.
	// Kullanici "enforcing" gorurken kernel "disabled"da kalir;
	// enforcement sessizce kapali, arayuz aktif diyor. Acil cikis
	// yolunun calistigini dusunen operator gercekte hicbir seyi
	// kapatmiyordur.
	//
	// Tersi de ayni sekilde kotu: harita "enforcing" olup Go
	// bellegi "disabled" kalirsa get_status yanlis modu bildirir.
	// Bu yuzden harita kaynag kabul edilir ve bellek ondan sonra
	// guncellenir.
	if h.maps != nil {
		if err := h.maps.SetMode(modeNumeric(newMode)); err != nil {
			return protocol.NewErrorResponse(req.ID, -32000,
				"mod haritaya yazilamadi, mod DEGISTIRILMADI: "+
					err.Error())
		}
	}

	if err := h.mode.Set(newMode); err != nil {
		// Yukaridaki dogrulama gectigi icin buraya ulasmamasi
		// gerekir. Yine de savunma olarak eski harita degeri
		// geri yazilir; iki taraf birbirinden ayrilmaz.
		if h.maps != nil {
			_ = h.maps.SetMode(modeNumeric(h.mode.Get()))
		}
		return protocol.NewErrorResponse(req.ID, -32000, err.Error())
	}

	result := map[string]interface{}{
		"status": "ok",
		"mode":   string(h.mode.Get()),
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleLearnStart(req protocol.Request) protocol.Response {
	// --days daha once TAMAMEN YOK SAYILIYORDU: CLI "3 gun
	// izlenecek" yaziyor, sunucu ne bir gun sayiyor ne de
	// sonlandiriyor. Kullanici geri donup rapor aldiginda
	// ogrenme hala acik, ya da baska bir komut kapattiysa
	// ozellik yarim kalmis oluyordu.
	//
	// Burada gercek bir sonlanma suresi atanir. Sure dolunca
	// ogrenme otomatik kapanir ve operator bunu status'ta gorur.
	var params struct {
		Days int `json:"days"`
	}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return protocol.NewErrorResponse(req.ID, -32602,
				"gecersiz params: "+err.Error())
		}
	}
	if params.Days <= 0 {
		params.Days = 3
	}

	if err := h.learning.Start(); err != nil {
		return protocol.NewErrorResponse(req.ID, -32000, err.Error())
	}

	// Gozlem bayragi AYRICA set edilir. Manager.Start() yalnizca
	// Go tarafindaki sayaci etkinlestirir; kancalar ise izin
	// verilen operasyonlari olay uretmek icin bayragi sorar.
	// Bayrak set edilmezse ogrenme "aktif" gorunur ama sifir
	// gozlem toplanir.
	//
	// Hata DONDURULMEZ: ogrenme yine de baslar, ama operator
	// bunu duyurmus olur. SESSIZCE gecmek, tam da duzeltilen
	// hatayi yeniden uretirdi.
	if h.maps != nil {
		if err := h.maps.SetLearning(true); err != nil {
			slog.Warn("ogrenme bayragi set edilemedi; "+
				"gozlem toplanmayabilir", "error", err)
		}
	}

	until := time.Now().UTC().AddDate(0, 0, params.Days)

	result := map[string]interface{}{
		"status":     "ok",
		"message":    "ogrenme modu baslatildi",
		"days":       params.Days,
		"until":      until.Format(time.RFC3339),
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"how": "Simdi normal islerinizi yapin: dosya okuma, ag " +
			"baglantisi, surec calistirma. Gozlemler enforcement " +
			"kancalarindan dogrudan gelir; onaylamaniz gerekmez. " +
			"Bitince 'axctl learn report' calistirin.",
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleLearnStop(req protocol.Request) protocol.Response {
	// Durdururken gozlem sayisi kaybolur; ogrenme.Start() bir
	// sonraki oturumda sifirladigi icin buradaki sayi yalnizca
	// "kac gozlem toplandi" bilgisidir. Kullaniciya ne kadar
	// veri oldugunu soylemek ogrenme akisinin bittigini
	// onaylamak icin gerekli.
	collected := h.learning.ObservationCount()
	h.learning.Stop()

	// Bayrak dusurulur: kancalar bundan sonra yalnizca DENY
	// olaylarini uretir. acik kalsaydi her izinli dosya okumasi
	// audit akisina duser ve sistem gereksiz yuk tasirdi.
	if h.maps != nil {
		if err := h.maps.SetLearning(false); err != nil {
			slog.Warn("ogrenme bayragi dusurulemedi", "error", err)
		}
	}

	result := map[string]interface{}{
		"status":       "ok",
		"message":      "ogrenme modu durduruldu",
		"observations": collected,
		"hint": "Toplanan gozlemler 'axctl learn report' ile " +
			"gorulebilir. Yeni oturum icin 'axctl learn start'.",
	}
	return protocol.NewResponse(req.ID, result)
}

// NOT: burada ayri bir action etiketleme fonksiyonu YOK. Ogrenme
// ciktisi dogrudan yapistirilabilir bir YAML politikasi olmak
// zorunda, yani etiketler derleyicinin kabul ettigi adlar olmali.
// Tek kaynak audit.ActionName'dir; ikinci bir kopya ("unknown(%d)"
// farkli yazilan bir surum dahil) sessizce ayrisir ve ogrenme
// raporu gecersiz YAML uretir.

func (h *Handler) handleLearnReport(req protocol.Request) protocol.Response {
	report := h.learning.GenerateReport()

	// Sozlesme: axctl "observations" ve "suggestions" bekler.
	// Sunucu daha once "patterns" ve "yaml" donuyordu; iki anahtar
	// da tutmadiigi icin rapor CLI'da BOS gorunuyordu.
	//
	// observations: subject -> action -> count
	observations := make(map[string]map[string]int)
	for _, p := range report.Patterns {
		if observations[p.Subject] == nil {
			observations[p.Subject] = make(map[string]int)
		}
		observations[p.Subject][p.Action] += p.Count
	}

	active := h.learning.IsActive()
	msg := "Ogrenme raporu hazir"
	if !active {
		// Bu ayrim onemli: rapor bosken kullanici "sistemde
		// hicbir sey olmadi" sanir. Oysa ogrenme hic baslamamistir
		// ya da hicbir sey kaydedilmemistir.
		msg = "Ogrenme modu AKTIF DEGIL. Rapor yalnizca " +
			"'axctl learn start' sonrasi toplanan gozlemleri " +
			"icer; simdilik bos."
	}

	result := map[string]interface{}{
		"generated_at":   report.GeneratedAt.Format(time.RFC3339),
		"duration":       report.Duration,
		"active":         active,
		"message":        msg,
		"pattern_count":  len(report.Patterns),
		"total_count":    h.learning.ObservationCount(),
		"patterns":       report.Patterns,
		"observations":   observations,
		"suggestions":    report.YAML,
		"yaml":           report.YAML,
	}
	return protocol.NewResponse(req.ID, result)
}
