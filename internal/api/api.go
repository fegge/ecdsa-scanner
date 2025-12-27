package api

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/notify"
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
	scanner    *scanner.Scanner
	db         db.Database
	logger     *logger.Logger
	ankrAPIKey string
	notifier   *notify.Notifier
}

// NewHandler creates a new API handler
func NewHandler(s *scanner.Scanner, database db.Database, log *logger.Logger, ankrAPIKey string, notifier *notify.Notifier) *Handler {
	return &Handler{
		scanner:    s,
		db:         database,
		logger:     log,
		ankrAPIKey: ankrAPIKey,
		notifier:   notifier,
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
	mux.HandleFunc("/api/notifications/test", h.handleTestNotification)
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

	enriched := []EnrichedCollision{}
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

// RecoveredKeyWithBalance extends RecoveredKey with current balance
type RecoveredKeyWithBalance struct {
	db.RecoveredKey
	BalanceWei string `json:"balance_wei"`
	BalanceEth string `json:"balance_eth"`
}

func (h *Handler) handleRecoveredKeys(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	keys, err := h.db.GetRecoveredKeys(ctx)
	if err != nil {
		h.logger.Error("Failed to get keys: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Enrich with chain names and balances
	result := make([]RecoveredKeyWithBalance, len(keys))
	for i, key := range keys {
		if cfg := config.ChainByID(key.ChainID); cfg != nil {
			key.ChainName = cfg.Name
		}
		result[i] = RecoveredKeyWithBalance{
			RecoveredKey: key,
			BalanceWei:   "0",
			BalanceEth:   "0",
		}

		// Fetch balance from RPC
		balance, err := h.getBalance(ctx, key.Address, key.ChainID)
		if err == nil {
			result[i].BalanceWei = balance.String()
			result[i].BalanceEth = weiToEth(balance)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// getBalance fetches the current balance of an address
func (h *Handler) getBalance(ctx context.Context, address string, chainID int) (*big.Int, error) {
	cfg := config.ChainByID(chainID)
	if cfg == nil {
		return nil, nil
	}

	rpcURL := cfg.RPCURL
	if h.ankrAPIKey != "" && strings.Contains(rpcURL, "ankr.com") {
		rpcURL = rpcURL + "/" + h.ankrAPIKey
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return client.BalanceAt(ctx, common.HexToAddress(address), nil)
}

// weiToEth converts wei to ETH as a string with 6 decimal places
func weiToEth(wei *big.Int) string {
	if wei == nil {
		return "0"
	}
	// Convert to float: wei / 1e18
	fWei := new(big.Float).SetInt(wei)
	ethValue := new(big.Float).Quo(fWei, big.NewFloat(1e18))
	
	// Format with up to 6 decimal places, trim trailing zeros
	text := ethValue.Text('f', 6)
	// Trim trailing zeros after decimal point
	if strings.Contains(text, ".") {
		text = strings.TrimRight(text, "0")
		text = strings.TrimRight(text, ".")
	}
	if text == "" {
		return "0"
	}
	return text
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

func (h *Handler) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if h.notifier == nil || !h.notifier.IsEnabled() {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Pushover notifications not configured",
		})
		return
	}

	err := h.notifier.SendTest()
	if err != nil {
		h.logger.Error("Test notification failed: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	h.logger.Info("Test notification sent successfully")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}
