package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/scanner"
)

// GlobalStats represents overall statistics
type GlobalStats struct {
	Chains            []scanner.ChainStats `json:"chains"`
	TotalRValues      int                  `json:"total_r_values"`
	TotalCollisions   int                  `json:"total_collisions"`
	RecoveredKeys     int                  `json:"recovered_keys"`
	RecoveredNonces   int                  `json:"recovered_nonces"`
	PendingComponents int                  `json:"pending_components"`
	AutoRecovery      bool                 `json:"auto_recovery"`
	DatabaseHealthy   bool                 `json:"database_healthy"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status   string          `json:"status"`
	Database db.HealthStatus `json:"database"`
	Chains   []ChainHealth   `json:"chains"`
}

// ChainHealth represents health for a chain
type ChainHealth struct {
	Name       string `json:"name"`
	ChainID    int    `json:"chain_id"`
	Running    bool   `json:"running"`
	ErrorCount int    `json:"error_count"`
}

// Handler holds HTTP handler dependencies
type Handler struct {
	scanner *scanner.Scanner
	db      db.Database
	logger  *logger.Logger
}

// NewHandler creates a new API handler
func NewHandler(s *scanner.Scanner, database db.Database, log *logger.Logger) *Handler {
	return &Handler{
		scanner: s,
		db:      database,
		logger:  log,
	}
}

// RegisterRoutes registers all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.serveIndex)
	mux.HandleFunc("/api/stats", h.handleStats)
	mux.HandleFunc("/api/health", h.handleHealth)
	mux.HandleFunc("/api/collisions", h.handleCollisions)
	mux.HandleFunc("/api/recovered-keys", h.handleRecoveredKeys)
	mux.HandleFunc("/api/recovered-nonces", h.handleRecoveredNonces)
	mux.HandleFunc("/api/pending-components", h.handlePendingComponents)
	mux.HandleFunc("/api/recovery/toggle", h.handleRecoveryToggle)
	mux.HandleFunc("/api/start", h.handleStart)
	mux.HandleFunc("/api/stop", h.handleStop)
	mux.HandleFunc("/api/logs", h.handleLogs)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	dbStats, err := h.db.GetStats(ctx)

	stats := GlobalStats{
		Chains:          h.scanner.GetChainStats(),
		AutoRecovery:    h.scanner.IsRecoveryEnabled(),
		DatabaseHealthy: true,
	}

	if err != nil {
		h.logger.Warn("Failed to get stats: %v", err)
		stats.DatabaseHealthy = false
	} else if dbStats != nil {
		stats.TotalRValues = dbStats.TotalRValues
		stats.TotalCollisions = dbStats.TotalCollisions
		stats.RecoveredKeys = dbStats.RecoveredKeys
		stats.RecoveredNonces = dbStats.RecoveredNonces
		stats.PendingComponents = dbStats.PendingComponents
		stats.DatabaseHealthy = dbStats.Healthy
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	dbHealth := h.db.Health(ctx)
	chainStats := h.scanner.GetChainStats()

	var chainHealths []ChainHealth
	for _, cs := range chainStats {
		chainHealths = append(chainHealths, ChainHealth{
			Name:       cs.Chain,
			ChainID:    cs.ChainID,
			Running:    cs.Running,
			ErrorCount: cs.ErrorCount,
		})
	}

	status := "healthy"
	if !dbHealth.Connected {
		status = "unhealthy"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{
		Status:   status,
		Database: dbHealth,
		Chains:   chainHealths,
	})
}

func (h *Handler) handleCollisions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	collisions, err := h.db.GetAllCollisions(ctx)
	if err != nil {
		h.logger.Error("Failed to get collisions: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich with chain names
	type EnrichedCollision struct {
		RValue  string `json:"r_value"`
		TxRefs  []struct {
			TxHash    string `json:"tx_hash"`
			ChainID   int    `json:"chain_id"`
			ChainName string `json:"chain_name"`
		} `json:"tx_refs"`
	}

	var enriched []EnrichedCollision
	for _, c := range collisions {
		ec := EnrichedCollision{RValue: c.RValue}
		for _, ref := range c.TxRefs {
			chainName := ""
			if cfg := config.ChainByID(ref.ChainID); cfg != nil {
				chainName = cfg.Name
			}
			ec.TxRefs = append(ec.TxRefs, struct {
				TxHash    string `json:"tx_hash"`
				ChainID   int    `json:"chain_id"`
				ChainName string `json:"chain_name"`
			}{
				TxHash:    ref.TxHash,
				ChainID:   ref.ChainID,
				ChainName: chainName,
			})
		}
		enriched = append(enriched, ec)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enriched)
}

func (h *Handler) handleRecoveredKeys(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	keys, err := h.db.GetRecoveredKeys(ctx)
	if err != nil {
		h.logger.Error("Failed to get keys: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add chain names
	for i := range keys {
		if cfg := config.ChainByID(keys[i].ChainID); cfg != nil {
			keys[i].ChainName = cfg.Name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (h *Handler) handleRecoveredNonces(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	nonces, err := h.db.GetRecoveredNonces(ctx)
	if err != nil {
		h.logger.Error("Failed to get nonces: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nonces)
}

func (h *Handler) handlePendingComponents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	comps, err := h.db.GetPendingComponents(ctx)
	if err != nil {
		h.logger.Error("Failed to get components: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comps)
}

func (h *Handler) handleRecoveryToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabled := r.URL.Query().Get("enabled")
	if enabled == "" {
		current := h.scanner.IsRecoveryEnabled()
		h.scanner.SetRecoveryEnabled(!current)
	} else if enabled == "true" || enabled == "1" {
		h.scanner.SetRecoveryEnabled(true)
	} else {
		h.scanner.SetRecoveryEnabled(false)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"auto_recovery": h.scanner.IsRecoveryEnabled(),
	})
}

func (h *Handler) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chain := r.URL.Query().Get("chain")
	if chain == "" {
		h.scanner.StartAll()
		h.logger.Info("Started all scanners")
	} else {
		h.scanner.StartChainByName(chain)
		h.logger.Info("Started scanner: %s", chain)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (h *Handler) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chain := r.URL.Query().Get("chain")
	if chain == "" {
		h.scanner.StopAll()
		h.logger.Info("Stopped all scanners")
	} else {
		h.scanner.StopChainByName(chain)
		h.logger.Info("Stopped scanner: %s", chain)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.logger.GetEntries())
}
