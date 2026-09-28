// Package handlers implements the JSON-RPC method handlers for axdaemon.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
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
type LSMStatus interface {
	IsLoaded() bool
	AttachedCount() int
	HookCount() int
	Status() map[string]bool
	EnforcementPossible() bool
	EnforcementNotice() string
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

	// Politika dosyasinda tanimli modu da uygula. Aksi halde reload
	// "enforcing" dese bile daemon eski modde kalir ve CLI ile
	// gercek durum uyusmaz.
	if snap.Policy.Mode != "" {
		if err := h.mode.Set(mode.Mode(snap.Policy.Mode)); err != nil {
			return protocol.NewErrorResponse(req.ID, -32000,
				"policy mode gecersiz: "+err.Error())
		}
		if h.maps != nil {
			h.maps.SetMode(modeNumeric(h.mode.Get()))
		}
	}

	if h.maps != nil {
		_ = h.maps.Clear()
		for _, rule := range snap.Policy.Rules {
			// effect constants live in the maps package and mirror axbpf.h
			effect := maps.EffectAllow
			if rule.Effect == policy.EffectDeny {
				effect = maps.EffectDeny
			}
			for _, subj := range rule.Subject {
				if err := h.maps.WriteRule(subj, rule.Object, rule.Action,
					maps.RuleIDToUint(rule.ID), effect); err != nil {
					return protocol.NewErrorResponse(req.ID, -32000,
						"kural yazilamadi: "+err.Error())
				}
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
		// when hooks are attached but the kernel cannot run them.
		result["enforcement_active"] = enforcing
		if notice != "" {
			result["enforcement_notice"] = notice
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
	} else {
		result["audit_log_count"]     = 0
		result["audit_denied_count"]  = 0
		result["audit_allowed_count"] = 0
	}

	if h.learning != nil {
		result["learning_active"]      = h.learning.IsActive()
		result["learning_observations"] = h.learning.ObservationCount()
	}

	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleGetLogs(req protocol.Request) protocol.Response {
	var params struct {
		Limit int `json:"limit"`
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

	var logs []map[string]interface{}
	if h.audit != nil {
		events := h.audit.Recent(params.Limit)
		for _, e := range events {
			logs = append(logs, map[string]interface{}{
				"timestamp": e.Timestamp,
				"pid":       e.PID,
				"comm":      string(e.Comm[:]),
				"path":      string(e.Path[:]),
				"action":    e.Action,
				"effect":    e.Effect,
				"decision":  e.Decision,
				"rule_id":   e.RuleID,
			})
		}
	}

	result := map[string]interface{}{
		"logs":  logs,
		"count": len(logs),
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleSetMode(req protocol.Request) protocol.Response {
	var params struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return protocol.NewErrorResponse(req.ID, -32602, "gecersiz params: "+err.Error())
	}

	newMode := mode.Mode(params.Mode)
	if err := h.mode.Set(newMode); err != nil {
		return protocol.NewErrorResponse(req.ID, -32000, err.Error())
	}

	result := map[string]interface{}{
		"status": "ok",
		"mode":   string(h.mode.Get()),
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleLearnStart(req protocol.Request) protocol.Response {
	if err := h.learning.Start(); err != nil {
		return protocol.NewErrorResponse(req.ID, -32000, err.Error())
	}

	result := map[string]interface{}{
		"status":  "ok",
		"message": "ogrenme modu baslatildi",
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleLearnStop(req protocol.Request) protocol.Response {
	h.learning.Stop()

	result := map[string]interface{}{
		"status":       "ok",
		"message":      "ogrenme modu durduruldu",
		"observations": h.learning.ObservationCount(),
	}
	return protocol.NewResponse(req.ID, result)
}

func (h *Handler) handleLearnReport(req protocol.Request) protocol.Response {
	report := h.learning.GenerateReport()

	result := map[string]interface{}{
		"generated_at":  report.GeneratedAt.Format(time.RFC3339),
		"duration":      report.Duration,
		"pattern_count": len(report.Patterns),
		"patterns":      report.Patterns,
		"yaml":          report.YAML,
	}
	return protocol.NewResponse(req.ID, result)
}
