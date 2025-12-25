package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
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
	DatabaseHealthy     bool                 `json:"database_healthy"`
	WriteErrors         int                  `json:"write_errors"`
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
	mux.HandleFunc("/api/duplicates", h.handleDuplicates)
	mux.HandleFunc("/api/duplicates/same-key", h.handleDuplicatesSameKey)
	mux.HandleFunc("/api/duplicates/cross-key", h.handleDuplicatesCrossKey)
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
