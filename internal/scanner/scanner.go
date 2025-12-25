package scanner

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/retry"
)

// RPCTransaction represents a transaction from the RPC
type RPCTransaction struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	V     string `json:"v"`
	R     string `json:"r"`
	S     string `json:"s"`
}

// RPCBlock represents a block from the RPC
type RPCBlock struct {
	Number       string           `json:"number"`
	Hash         string           `json:"hash"`
	Timestamp    string           `json:"timestamp"`
	Transactions []RPCTransaction `json:"transactions"`
}

// ChainStats holds statistics for a single chain
type ChainStats struct {
	Chain          string `json:"chain"`
	StartBlock     uint64 `json:"start_block"`
	CurrentBlock   uint64 `json:"current_block"`
	LatestBlock    uint64 `json:"latest_block"`
	TxScanned      uint64 `json:"tx_scanned"`
	Running        bool   `json:"running"`
	ErrorCount     int    `json:"error_count"`
	CircuitOpen    bool   `json:"circuit_open"`
	LastError      string `json:"last_error,omitempty"`
	LastErrorTime  string `json:"last_error_time,omitempty"`
}

// ChainScanner handles scanning for a single chain
type ChainScanner struct {
	config         config.ChainConfig
	client         *rpc.Client
	running        bool
	stopChan       chan struct{}
	mu             sync.Mutex
	stats          ChainStats
	circuitBreaker *retry.CircuitBreaker
	retryConfig    retry.Config
	errorCount     int
	lastError      string
	lastErrorTime  time.Time
}

// Scanner coordinates scanning across all chains
type Scanner struct {
	db            db.Database
	logger        *logger.Logger
	chainScanners map[string]*ChainScanner
	mu            sync.RWMutex
	writeQueue    chan db.Signature
	writeErrors   int
}

// New creates a new Scanner
func New(database db.Database, log *logger.Logger, ankrAPIKey string) (*Scanner, error) {
	s := &Scanner{
		db:            database,
		logger:        log,
		chainScanners: make(map[string]*ChainScanner),
		writeQueue:    make(chan db.Signature, 10000),
	}

	// Start batch writer
	go s.batchWriter()

	// Initialize chain scanners
	for _, cfg := range config.DefaultChains() {
		if !cfg.Enabled {
			continue
		}

		rpcURL := cfg.RPCURL
		if ankrAPIKey != "" && strings.Contains(rpcURL, "ankr.com") {
			rpcURL = rpcURL + "/" + ankrAPIKey
		}

		client, err := rpc.Dial(rpcURL)
		if err != nil {
			log.Warn("[%s] Failed to connect: %v (will retry later)", cfg.Name, err)
			// Still create scanner, it will retry connection
		}

		s.chainScanners[cfg.Name] = &ChainScanner{
			config:         cfg,
			client:         client,
			stopChan:       make(chan struct{}),
			stats:          ChainStats{Chain: cfg.Name},
			circuitBreaker: retry.NewCircuitBreaker(5, 60*time.Second),
			retryConfig: retry.Config{
				MaxAttempts: 3,
				BaseDelay:   time.Second,
				MaxDelay:    30 * time.Second,
			},
		}
		if client != nil {
			log.Info("[%s] Initialized scanner", cfg.Name)
		}
	}

	return s, nil
}

// StartAll starts all chain scanners
func (s *Scanner) StartAll() {
	for name := range s.chainScanners {
		s.StartChain(name)
		time.Sleep(500 * time.Millisecond)
	}
}

// StopAll stops all chain scanners
func (s *Scanner) StopAll() {
	for name := range s.chainScanners {
		s.StopChain(name)
	}
}

// StartChain starts a specific chain scanner
func (s *Scanner) StartChain(name string) {
	cs, ok := s.chainScanners[name]
	if !ok {
		return
	}

	cs.mu.Lock()
	if cs.running {
		cs.mu.Unlock()
		return
	}
	cs.running = true
	cs.stopChan = make(chan struct{})
	cs.mu.Unlock()

	go s.scanLoop(cs)
}

// StopChain stops a specific chain scanner
func (s *Scanner) StopChain(name string) {
	cs, ok := s.chainScanners[name]
	if !ok {
		return
	}

	cs.mu.Lock()
	if !cs.running {
		cs.mu.Unlock()
		return
	}
	cs.running = false
	close(cs.stopChan)
	cs.mu.Unlock()
}

// GetChainStats returns statistics for all chains
func (s *Scanner) GetChainStats() []ChainStats {
	var stats []ChainStats
	for _, cs := range s.chainScanners {
		cs.mu.Lock()
		chainStats := cs.stats
		chainStats.Running = cs.running
		chainStats.ErrorCount = cs.errorCount
		chainStats.CircuitOpen = cs.circuitBreaker.IsOpen()
		chainStats.LastError = cs.lastError
		if !cs.lastErrorTime.IsZero() {
			chainStats.LastErrorTime = cs.lastErrorTime.Format(time.RFC3339)
		}
		cs.mu.Unlock()
		stats = append(stats, chainStats)
	}
	return stats
}

// GetTotalTxScanned returns total transactions scanned across all chains
func (s *Scanner) GetTotalTxScanned() uint64 {
	var total uint64
	for _, cs := range s.chainScanners {
		cs.mu.Lock()
		total += cs.stats.TxScanned
		cs.mu.Unlock()
	}
	return total
}

func (s *Scanner) recordError(cs *ChainScanner, err error) {
	cs.mu.Lock()
	cs.errorCount++
	cs.lastError = err.Error()
	cs.lastErrorTime = time.Now()
	cs.circuitBreaker.RecordFailure()
	cs.mu.Unlock()
}

func (s *Scanner) recordSuccess(cs *ChainScanner) {
	cs.mu.Lock()
	cs.circuitBreaker.RecordSuccess()
	cs.mu.Unlock()
}

func (s *Scanner) scanLoop(cs *ChainScanner) {
	ctx := context.Background()
	chainName := cs.config.Name

	// Ensure we have a client connection
	if cs.client == nil {
		if err := s.reconnect(cs); err != nil {
			s.logger.Error("[%s] Failed to establish initial connection: %v", chainName, err)
			return
		}
	}

	// Get last scanned block
	lastBlock, err := s.db.GetLastBlock(ctx, chainName)
	if err != nil {
		s.logger.Warn("[%s] Failed to get last block from DB: %v", chainName, err)
	}

	// If no previous scan, start from recent blocks
	if lastBlock == 0 {
		latestBlock, err := s.getLatestBlockWithRetry(cs, ctx)
		if err != nil {
			s.logger.Error("[%s] Failed to get latest block: %v", chainName, err)
			return
		}
		lastBlock = latestBlock - 1000
	}

	// Load existing transaction count
	initialCount, _ := s.db.GetChainTxCount(ctx, chainName)

	cs.mu.Lock()
	cs.stats.StartBlock = lastBlock + 1
	cs.stats.TxScanned = initialCount
	cs.mu.Unlock()

	s.logger.Info("[%s] Starting scan from block %d", chainName, lastBlock+1)

	consecutiveErrors := 0
	maxConsecutiveErrors := 10

	for {
		select {
		case <-cs.stopChan:
			s.logger.Info("[%s] Scanner stopped", chainName)
			return
		default:
		}

		// Check circuit breaker
		if !cs.circuitBreaker.Allow() {
			s.logger.Warn("[%s] Circuit breaker open, waiting...", chainName)
			time.Sleep(10 * time.Second)
			continue
		}

		latestBlock, err := s.getLatestBlockWithRetry(cs, ctx)
		if err != nil {
			s.recordError(cs, err)
			consecutiveErrors++
			s.logger.Error("[%s] Failed to get latest block: %v (consecutive: %d)",
				chainName, err, consecutiveErrors)

			if consecutiveErrors >= maxConsecutiveErrors {
				s.logger.Error("[%s] Too many consecutive errors, attempting reconnect", chainName)
				if err := s.reconnect(cs); err != nil {
					s.logger.Error("[%s] Reconnect failed: %v", chainName, err)
				}
				consecutiveErrors = 0
			}

			time.Sleep(5 * time.Second)
			continue
		}

		cs.mu.Lock()
		cs.stats.LatestBlock = latestBlock
		cs.stats.Running = true
		cs.mu.Unlock()

		if lastBlock >= latestBlock {
			time.Sleep(3 * time.Second)
			continue
		}

		nextBlock := lastBlock + 1
		count, err := s.scanBlockWithRetry(cs, ctx, nextBlock)
		if err != nil {
			s.recordError(cs, err)
			consecutiveErrors++
			s.logger.Error("[%s] Failed to scan block %d: %v", chainName, nextBlock, err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Success - reset error counter
		s.recordSuccess(cs)
		consecutiveErrors = 0

		cs.mu.Lock()
		cs.stats.CurrentBlock = nextBlock
		cs.stats.TxScanned += uint64(count)
		cs.mu.Unlock()

		lastBlock = nextBlock

		// Save state every 100 blocks
		if nextBlock%100 == 0 {
			if err := s.db.SaveLastBlock(ctx, chainName, nextBlock); err != nil {
				s.logger.Warn("[%s] Failed to save state: %v", chainName, err)
			}
		}

		if nextBlock%500 == 0 {
			s.logger.Info("[%s] Scanned block %d (%d txs), %d blocks behind",
				chainName, nextBlock, count, latestBlock-nextBlock)
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func (s *Scanner) reconnect(cs *ChainScanner) error {
	rpcURL := cs.config.RPCURL
	// Note: We don't have access to ankrAPIKey here, but the URL was already built with it

	client, err := rpc.Dial(rpcURL)
	if err != nil {
		return fmt.Errorf("failed to dial RPC: %w", err)
	}

	cs.mu.Lock()
	if cs.client != nil {
		cs.client.Close()
	}
	cs.client = client
	cs.mu.Unlock()

	s.logger.Info("[%s] Reconnected to RPC", cs.config.Name)
	return nil
}

func (s *Scanner) getLatestBlockWithRetry(cs *ChainScanner, ctx context.Context) (uint64, error) {
	return retry.DoWithResult(ctx, cs.retryConfig, func() (uint64, error) {
		return s.getLatestBlock(cs, ctx)
	})
}

func (s *Scanner) getLatestBlock(cs *ChainScanner, ctx context.Context) (uint64, error) {
	if cs.client == nil {
		return 0, fmt.Errorf("no RPC client connection")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var blockNum hexutil.Big
	if err := cs.client.CallContext(ctx, &blockNum, "eth_blockNumber"); err != nil {
		return 0, err
	}
	return (*big.Int)(&blockNum).Uint64(), nil
}

func (s *Scanner) scanBlockWithRetry(cs *ChainScanner, ctx context.Context, blockNum uint64) (int, error) {
	return retry.DoWithResult(ctx, cs.retryConfig, func() (int, error) {
		return s.scanBlock(cs, ctx, blockNum)
	})
}

func (s *Scanner) scanBlock(cs *ChainScanner, ctx context.Context, blockNum uint64) (int, error) {
	if cs.client == nil {
		return 0, fmt.Errorf("no RPC client connection")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var block RPCBlock
	blockNumHex := fmt.Sprintf("0x%x", blockNum)
	if err := cs.client.CallContext(ctx, &block, "eth_getBlockByNumber", blockNumHex, true); err != nil {
		return 0, err
	}

	count := 0
	for _, tx := range block.Transactions {
		if tx.R == "" || tx.S == "" || tx.From == "" {
			continue
		}

		select {
		case s.writeQueue <- db.Signature{
			Chain:       cs.config.Name,
			BlockNumber: blockNum,
			TxHash:      tx.Hash,
			FromAddress: tx.From,
			R:           tx.R,
			S:           tx.S,
			V:           tx.V,
		}:
			count++
		default:
			s.logger.Warn("[%s] Write queue full, dropping transaction", cs.config.Name)
		}
	}

	return count, nil
}

func (s *Scanner) batchWriter() {
	batch := make([]db.Signature, 0, 1000)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-s.writeQueue:
			batch = append(batch, sig)
			if len(batch) >= 1000 {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Scanner) flushBatch(batch []db.Signature) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.db.InsertSignatures(ctx, batch); err != nil {
		s.mu.Lock()
		s.writeErrors++
		s.mu.Unlock()
		s.logger.Error("Failed to insert batch of %d signatures: %v", len(batch), err)
	}
}

// GetWriteErrors returns the number of batch write errors
func (s *Scanner) GetWriteErrors() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeErrors
}
