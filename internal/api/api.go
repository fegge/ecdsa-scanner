package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/recovery"
	"ecdsa-scanner/internal/scanner"
)

// GlobalStats represents the overall statistics
type GlobalStats struct {
	Chains              []scanner.ChainStats `json:"chains"`
	TotalTxScanned      uint64               `json:"total_tx_scanned"`
	TotalSignatures     int                  `json:"total_signatures"`
	DuplicateSameKey    int                  `json:"duplicate_same_key"`
	DuplicateCrossKey   int                  `json:"duplicate_cross_key"`
	DuplicateCrossChain int                  `json:"duplicate_cross_chain"`
	RecoveredKeys       int                  `json:"recovered_keys"`
	DatabaseHealthy     bool                 `json:"database_healthy"`
	WriteErrors         int                  `json:"write_errors"`
	AutoRecovery        bool                 `json:"auto_recovery"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status   string         `json:"status"`
	Database db.HealthStatus `json:"database"`
	Chains   []ChainHealth  `json:"chains"`
}

// ChainHealth represents health status for a chain
type ChainHealth struct {
	Name        string `json:"name"`
	Running     bool   `json:"running"`
	CircuitOpen bool   `json:"circuit_open"`
	ErrorCount  int    `json:"error_count"`
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	scanner    *scanner.Scanner
	db         db.Database
	logger     *logger.Logger
	ankrAPIKey string
}

// NewHandler creates a new API handler
func NewHandler(s *scanner.Scanner, database db.Database, log *logger.Logger, ankrAPIKey string) *Handler {
	return &Handler{
		scanner:    s,
		db:         database,
		logger:     log,
		ankrAPIKey: ankrAPIKey,
	}
}

// RegisterRoutes registers all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", h.serveIndex)
	mux.HandleFunc("/api/stats", h.handleStats)
	mux.HandleFunc("/api/health", h.handleHealth)
	mux.HandleFunc("/api/duplicates", h.handleDuplicates)
	mux.HandleFunc("/api/duplicates/same-key", h.handleDuplicatesSameKey)
	mux.HandleFunc("/api/duplicates/cross-key", h.handleDuplicatesCrossKey)
	mux.HandleFunc("/api/recovered-keys", h.handleRecoveredKeys)
	mux.HandleFunc("/api/recover", h.handleRecover)
	mux.HandleFunc("/api/recovery/toggle", h.handleRecoveryToggle)
	mux.HandleFunc("/api/start", h.handleStart)
	mux.HandleFunc("/api/stop", h.handleStop)
	mux.HandleFunc("/api/logs", h.handleLogs)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/index.html")
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	dbHealth := h.db.Health(ctx)

	chainStats := h.scanner.GetChainStats()
	chainHealths := make([]ChainHealth, 0, len(chainStats))
	for _, cs := range chainStats {
		chainHealths = append(chainHealths, ChainHealth{
			Name:        cs.Chain,
			Running:     cs.Running,
			CircuitOpen: cs.CircuitOpen,
			ErrorCount:  cs.ErrorCount,
		})
	}

	status := "healthy"
	if !dbHealth.Connected {
		status = "unhealthy"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	resp := HealthResponse{
		Status:   status,
		Database: dbHealth,
		Chains:   chainHealths,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	dbStats, err := h.db.GetStats(ctx)

	stats := GlobalStats{
		Chains:          h.scanner.GetChainStats(),
		TotalTxScanned:  h.scanner.GetTotalTxScanned(),
		WriteErrors:     h.scanner.GetWriteErrors(),
		DatabaseHealthy: true,
		AutoRecovery:    h.scanner.IsRecoveryEnabled(),
	}

	if err != nil {
		h.logger.Warn("Failed to get database stats: %v", err)
		stats.DatabaseHealthy = false
	}

	if dbStats != nil {
		stats.TotalSignatures = dbStats.TotalSignatures
		stats.DuplicateSameKey = dbStats.DuplicateSameKey
		stats.DuplicateCrossKey = dbStats.DuplicateCrossKey
		stats.DuplicateCrossChain = dbStats.DuplicateCrossChain
		stats.RecoveredKeys = dbStats.RecoveredKeys
		stats.DatabaseHealthy = dbStats.Healthy
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (h *Handler) handleDuplicates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	duplicates, err := h.db.FindDuplicates(ctx)
	if err != nil {
		h.logger.Error("Failed to find duplicates: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(duplicates)
}

func (h *Handler) handleDuplicatesSameKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	duplicates, err := h.db.FindDuplicates(ctx)
	if err != nil {
		h.logger.Error("Failed to find duplicates: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var sameKey []db.DuplicateR
	for _, d := range duplicates {
		if d.SameKey {
			sameKey = append(sameKey, d)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sameKey)
}

func (h *Handler) handleDuplicatesCrossKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	duplicates, err := h.db.FindDuplicates(ctx)
	if err != nil {
		h.logger.Error("Failed to find duplicates: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var crossKey []db.DuplicateR
	for _, d := range duplicates {
		if !d.SameKey {
			crossKey = append(crossKey, d)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(crossKey)
}

func (h *Handler) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	chain := r.URL.Query().Get("chain")
	if chain == "" {
		h.scanner.StartAll()
		h.logger.Info("Started all chain scanners")
	} else {
		h.scanner.StartChain(chain)
		h.logger.Info("Started chain scanner: %s", chain)
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
		h.logger.Info("Stopped all chain scanners")
	} else {
		h.scanner.StopChain(chain)
		h.logger.Info("Stopped chain scanner: %s", chain)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.logger.GetEntries())
}

func (h *Handler) handleRecoveredKeys(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	keys, err := h.db.GetRecoveredKeys(ctx)
	if err != nil {
		h.logger.Error("Failed to get recovered keys: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func (h *Handler) handleRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// Get same-key duplicates that haven't been recovered yet
	duplicates, err := h.db.GetSameKeyDuplicatesForRecovery(ctx)
	if err != nil {
		h.logger.Error("Failed to get duplicates for recovery: %v", err)
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(duplicates) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "no_duplicates",
			"message":   "No same-key duplicates found for recovery",
			"recovered": 0,
		})
		return
	}

	// Try to recover keys
	var recovered int
	var errors []string

	for _, dup := range duplicates {
		if len(dup.Entries) < 2 {
			continue
		}

		chain := dup.Entries[0].Chain
		rpcURL := h.getRPCURL(chain)
		if rpcURL == "" {
			errors = append(errors, "No RPC URL for chain: "+chain)
			continue
		}

		h.logger.Info("Attempting key recovery for address %s on %s", dup.Entries[0].Address, chain)

		recoveredKey, err := recovery.RecoverPrivateKey(ctx, rpcURL, dup.Entries[0].TxHash, dup.Entries[1].TxHash)
		if err != nil {
			errMsg := "Recovery failed for " + dup.Entries[0].Address + ": " + err.Error()
			h.logger.Warn("%s", errMsg)
			errors = append(errors, errMsg)
			continue
		}

		recoveredKey.Chain = chain

		// Save to database
		dbKey := &db.RecoveredKey{
			Address:    recoveredKey.Address,
			PrivateKey: recoveredKey.PrivateKey,
			Chain:      recoveredKey.Chain,
			RValue:     recoveredKey.RValue,
			TxHash1:    recoveredKey.TxHash1,
			TxHash2:    recoveredKey.TxHash2,
		}

		if err := h.db.SaveRecoveredKey(ctx, dbKey); err != nil {
			h.logger.Error("Failed to save recovered key: %v", err)
			errors = append(errors, "Failed to save key for "+recoveredKey.Address)
			continue
		}

		h.logger.Info("Successfully recovered private key for %s on %s", recoveredKey.Address, chain)
		recovered++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "completed",
		"recovered": recovered,
		"attempted": len(duplicates),
		"errors":    errors,
	})
}

func (h *Handler) handleRecoveryToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	enabled := r.URL.Query().Get("enabled")
	if enabled == "" {
		// Toggle current state
		current := h.scanner.IsRecoveryEnabled()
		h.scanner.SetRecoveryEnabled(!current)
		h.logger.Info("Auto-recovery toggled to %v", !current)
	} else if enabled == "true" || enabled == "1" {
		h.scanner.SetRecoveryEnabled(true)
		h.logger.Info("Auto-recovery enabled")
	} else {
		h.scanner.SetRecoveryEnabled(false)
		h.logger.Info("Auto-recovery disabled")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "ok",
		"auto_recovery": h.scanner.IsRecoveryEnabled(),
	})
}

func (h *Handler) getRPCURL(chainName string) string {
	// Get RPC URL from config
	for _, chain := range config.DefaultChains() {
		if chain.Name == chainName {
			rpcURL := chain.RPCURL
			if h.ankrAPIKey != "" && strings.Contains(rpcURL, "ankr.com") {
				rpcURL = rpcURL + "/" + h.ankrAPIKey
			}
			return rpcURL
		}
	}
	return ""
}
