package db

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// Common errors
var (
	ErrConnectionFailed = errors.New("database connection failed")
	ErrQueryTimeout     = errors.New("query timeout")
	ErrPoolExhausted    = errors.New("connection pool exhausted")
	ErrNotFound         = errors.New("not found")
)

// TxRef is a minimal reference to a transaction
type TxRef struct {
	TxHash  string
	ChainID int
}

// Collision represents a detected R-value collision
type Collision struct {
	RValue  string  // hex encoded
	TxRefs  []TxRef // all transactions sharing this R
}

// RecoveredKey represents a recovered private key
type RecoveredKey struct {
	ID         int64    `json:"id"`
	Address    string   `json:"address"`
	PrivateKey string   `json:"private_key"`
	ChainID    int      `json:"chain_id"`
	ChainName  string   `json:"chain_name"`
	RValues    []string `json:"r_values"`
	TxHashes   []string `json:"tx_hashes"`
	CreatedAt  string   `json:"created_at"`
}

// RecoveredNonce represents a nonce derived from a recovered key
type RecoveredNonce struct {
	RValue           string `json:"r_value"`
	KValue           string `json:"k_value"`
	DerivedFromKeyID int64  `json:"derived_from_key_id"`
}

// PendingComponent tracks cross-key collisions not yet solvable
type PendingComponent struct {
	ID        int64    `json:"id"`
	RValues   []string `json:"r_values"`
	TxHashes  []string `json:"tx_hashes"`
	Addresses []string `json:"addresses"`
	ChainIDs  []int    `json:"chain_ids"`
	Equations int      `json:"equations"`
	Unknowns  int      `json:"unknowns"`
}

// Stats holds statistics
type Stats struct {
	TotalRValues      int  `json:"total_r_values"`
	TotalCollisions   int  `json:"total_collisions"`
	PendingComponents int  `json:"pending_components"`
	RecoveredKeys     int  `json:"recovered_keys"`
	RecoveredNonces   int  `json:"recovered_nonces"`
	Healthy           bool `json:"healthy"`
}

// HealthStatus represents database health
type HealthStatus struct {
	Connected       bool   `json:"connected"`
	LatencyMs       int64  `json:"latency_ms"`
	OpenConnections int    `json:"open_connections"`
	Error           string `json:"error,omitempty"`
}

// DB wraps database operations
type DB struct {
	conn *sql.DB
}

// New creates a new database connection
func New(databaseURL string) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)
	conn.SetConnMaxIdleTime(1 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	db := &DB{conn: conn}

	if err := db.migrate(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

func (db *DB) migrate(ctx context.Context) error {
	_, err := db.conn.ExecContext(ctx, `
		-- Minimal R-value index for collision detection (~66 bytes per unique R)
		CREATE TABLE IF NOT EXISTS r_value_index (
			r_value BYTEA PRIMARY KEY,
			tx_hash BYTEA NOT NULL,
			chain_id SMALLINT NOT NULL
		);

		-- Track collisions (multiple txs with same R)
		CREATE TABLE IF NOT EXISTS collisions (
			id BIGSERIAL PRIMARY KEY,
			r_value BYTEA NOT NULL,
			tx_hash BYTEA NOT NULL,
			chain_id SMALLINT NOT NULL,
			address BYTEA,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(r_value, tx_hash)
		);
		CREATE INDEX IF NOT EXISTS idx_collisions_r_value ON collisions(r_value);

		-- Scan progress per chain
		CREATE TABLE IF NOT EXISTS scan_state (
			chain_id SMALLINT PRIMARY KEY,
			last_block BIGINT NOT NULL,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		-- Recovered private keys
		CREATE TABLE IF NOT EXISTS recovered_keys (
			id BIGSERIAL PRIMARY KEY,
			address BYTEA NOT NULL,
			private_key BYTEA NOT NULL,
			chain_id SMALLINT NOT NULL,
			r_values BYTEA[] NOT NULL,
			tx_hashes BYTEA[] NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(address, chain_id)
		);
		CREATE INDEX IF NOT EXISTS idx_recovered_keys_address ON recovered_keys(address);

		-- Recovered nonces (enables cross-key recovery)
		CREATE TABLE IF NOT EXISTS recovered_nonces (
			r_value BYTEA PRIMARY KEY,
			k_value BYTEA NOT NULL,
			derived_from_key_id BIGINT REFERENCES recovered_keys(id),
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		-- Pending cross-key components (not yet solvable)
		CREATE TABLE IF NOT EXISTS pending_components (
			id BIGSERIAL PRIMARY KEY,
			component_hash BYTEA UNIQUE NOT NULL,
			r_values BYTEA[] NOT NULL,
			tx_hashes BYTEA[] NOT NULL,
			addresses BYTEA[] NOT NULL,
			chain_ids SMALLINT[] NOT NULL,
			equations INT NOT NULL,
			unknowns INT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
	`)
	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// Health checks database connectivity
func (db *DB) Health(ctx context.Context) HealthStatus {
	status := HealthStatus{}
	start := time.Now()
	err := db.conn.PingContext(ctx)
	status.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		status.Error = err.Error()
		return status
	}

	status.Connected = true
	status.OpenConnections = db.conn.Stats().OpenConnections
	return status
}

func (db *DB) wrapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "53300":
			return fmt.Errorf("%w: %v", ErrPoolExhausted, err)
		case "57014":
			return fmt.Errorf("%w: %v", ErrQueryTimeout, err)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrQueryTimeout, err)
	}
	return err
}

// hexToBytes converts hex string (with or without 0x) to bytes
func hexToBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	b, _ := hex.DecodeString(s)
	return b
}

// bytesToHex converts bytes to 0x-prefixed hex string
func bytesToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// CheckAndInsertRValue checks if R value exists, inserts if not, returns collision info
// Returns (existingTxRef, isCollision, error)
func (db *DB) CheckAndInsertRValue(ctx context.Context, rValue string, txHash string, chainID int) (*TxRef, bool, error) {
	rBytes := hexToBytes(rValue)
	txBytes := hexToBytes(txHash)

	// Try to get existing
	var existingTx []byte
	var existingChain int
	err := db.conn.QueryRowContext(ctx,
		"SELECT tx_hash, chain_id FROM r_value_index WHERE r_value = $1",
		rBytes).Scan(&existingTx, &existingChain)

	if err == sql.ErrNoRows {
		// First time seeing this R value - insert it
		_, err = db.conn.ExecContext(ctx,
			"INSERT INTO r_value_index (r_value, tx_hash, chain_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
			rBytes, txBytes, chainID)
		return nil, false, db.wrapError(err)
	}

	if err != nil {
		return nil, false, db.wrapError(err)
	}

	// Collision detected!
	return &TxRef{
		TxHash:  bytesToHex(existingTx),
		ChainID: existingChain,
	}, true, nil
}

// RecordCollision records a collision in the collisions table
func (db *DB) RecordCollision(ctx context.Context, rValue string, txHash string, chainID int, address string) error {
	_, err := db.conn.ExecContext(ctx,
		`INSERT INTO collisions (r_value, tx_hash, chain_id, address) 
		 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		hexToBytes(rValue), hexToBytes(txHash), chainID, hexToBytes(address))
	return db.wrapError(err)
}

// GetCollisionTxRefs returns all transaction references for a given R value
func (db *DB) GetCollisionTxRefs(ctx context.Context, rValue string) ([]TxRef, error) {
	rBytes := hexToBytes(rValue)

	// First get the original from r_value_index
	var refs []TxRef
	var origTx []byte
	var origChain int
	err := db.conn.QueryRowContext(ctx,
		"SELECT tx_hash, chain_id FROM r_value_index WHERE r_value = $1",
		rBytes).Scan(&origTx, &origChain)
	if err == nil {
		refs = append(refs, TxRef{TxHash: bytesToHex(origTx), ChainID: origChain})
	}

	// Then get all from collisions table
	rows, err := db.conn.QueryContext(ctx,
		"SELECT tx_hash, chain_id FROM collisions WHERE r_value = $1",
		rBytes)
	if err != nil {
		return refs, db.wrapError(err)
	}
	defer rows.Close()

	for rows.Next() {
		var tx []byte
		var chain int
		if err := rows.Scan(&tx, &chain); err != nil {
			continue
		}
		refs = append(refs, TxRef{TxHash: bytesToHex(tx), ChainID: chain})
	}

	return refs, nil
}

// GetLastBlock returns the last scanned block for a chain
func (db *DB) GetLastBlock(ctx context.Context, chainID int) (uint64, error) {
	var lastBlock uint64
	err := db.conn.QueryRowContext(ctx,
		"SELECT last_block FROM scan_state WHERE chain_id = $1",
		chainID).Scan(&lastBlock)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return lastBlock, db.wrapError(err)
}

// SaveLastBlock saves the last scanned block for a chain
func (db *DB) SaveLastBlock(ctx context.Context, chainID int, block uint64) error {
	_, err := db.conn.ExecContext(ctx,
		`INSERT INTO scan_state (chain_id, last_block, updated_at) VALUES ($1, $2, NOW())
		 ON CONFLICT (chain_id) DO UPDATE SET last_block = $2, updated_at = NOW()`,
		chainID, block)
	return db.wrapError(err)
}

// SaveRecoveredKey saves a recovered private key
func (db *DB) SaveRecoveredKey(ctx context.Context, key *RecoveredKey) (int64, error) {
	var rValuesBytes [][]byte
	for _, r := range key.RValues {
		rValuesBytes = append(rValuesBytes, hexToBytes(r))
	}
	var txHashesBytes [][]byte
	for _, tx := range key.TxHashes {
		txHashesBytes = append(txHashesBytes, hexToBytes(tx))
	}

	var id int64
	err := db.conn.QueryRowContext(ctx,
		`INSERT INTO recovered_keys (address, private_key, chain_id, r_values, tx_hashes)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (address, chain_id) DO UPDATE SET
		   private_key = $2, r_values = $4, tx_hashes = $5
		 RETURNING id`,
		hexToBytes(key.Address), hexToBytes(key.PrivateKey), key.ChainID,
		pq.Array(rValuesBytes), pq.Array(txHashesBytes)).Scan(&id)
	return id, db.wrapError(err)
}

// GetRecoveredKeys returns all recovered private keys
func (db *DB) GetRecoveredKeys(ctx context.Context) ([]RecoveredKey, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT id, address, private_key, chain_id, r_values, tx_hashes, created_at
		 FROM recovered_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	keys := []RecoveredKey{}
	for rows.Next() {
		var key RecoveredKey
		var addr, privKey []byte
		var rValues, txHashes [][]byte
		var createdAt time.Time

		if err := rows.Scan(&key.ID, &addr, &privKey, &key.ChainID,
			pq.Array(&rValues), pq.Array(&txHashes), &createdAt); err != nil {
			continue
		}

		key.Address = bytesToHex(addr)
		key.PrivateKey = bytesToHex(privKey)
		for _, r := range rValues {
			key.RValues = append(key.RValues, bytesToHex(r))
		}
		for _, tx := range txHashes {
			key.TxHashes = append(key.TxHashes, bytesToHex(tx))
		}
		key.CreatedAt = createdAt.Format(time.RFC3339)
		keys = append(keys, key)
	}

	return keys, nil
}

// IsKeyRecovered checks if a key has been recovered for an address/chain
func (db *DB) IsKeyRecovered(ctx context.Context, address string, chainID int) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM recovered_keys WHERE address = $1 AND chain_id = $2",
		hexToBytes(address), chainID).Scan(&count)
	return count > 0, db.wrapError(err)
}

// SaveRecoveredNonce saves a recovered nonce
func (db *DB) SaveRecoveredNonce(ctx context.Context, nonce *RecoveredNonce) error {
	_, err := db.conn.ExecContext(ctx,
		`INSERT INTO recovered_nonces (r_value, k_value, derived_from_key_id)
		 VALUES ($1, $2, $3) ON CONFLICT (r_value) DO UPDATE SET k_value = $2`,
		hexToBytes(nonce.RValue), hexToBytes(nonce.KValue), nonce.DerivedFromKeyID)
	return db.wrapError(err)
}

// GetRecoveredNonce retrieves a recovered nonce by R value
func (db *DB) GetRecoveredNonce(ctx context.Context, rValue string) (*RecoveredNonce, error) {
	var kValue []byte
	var keyID int64
	err := db.conn.QueryRowContext(ctx,
		"SELECT k_value, derived_from_key_id FROM recovered_nonces WHERE r_value = $1",
		hexToBytes(rValue)).Scan(&kValue, &keyID)
	if err != nil {
		return nil, db.wrapError(err)
	}
	return &RecoveredNonce{
		RValue:           rValue,
		KValue:           bytesToHex(kValue),
		DerivedFromKeyID: keyID,
	}, nil
}

// GetRecoveredNonces returns all recovered nonces
func (db *DB) GetRecoveredNonces(ctx context.Context) ([]RecoveredNonce, error) {
	rows, err := db.conn.QueryContext(ctx,
		"SELECT r_value, k_value, derived_from_key_id FROM recovered_nonces")
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	nonces := []RecoveredNonce{}
	for rows.Next() {
		var rValue, kValue []byte
		var keyID int64
		if err := rows.Scan(&rValue, &kValue, &keyID); err != nil {
			continue
		}
		nonces = append(nonces, RecoveredNonce{
			RValue:           bytesToHex(rValue),
			KValue:           bytesToHex(kValue),
			DerivedFromKeyID: keyID,
		})
	}
	return nonces, nil
}

// SavePendingComponent saves a pending cross-key component
func (db *DB) SavePendingComponent(ctx context.Context, comp *PendingComponent) error {
	// Create a deterministic hash of the component for deduplication
	var rValuesBytes, txHashesBytes, addressesBytes [][]byte
	for _, r := range comp.RValues {
		rValuesBytes = append(rValuesBytes, hexToBytes(r))
	}
	for _, tx := range comp.TxHashes {
		txHashesBytes = append(txHashesBytes, hexToBytes(tx))
	}
	for _, addr := range comp.Addresses {
		addressesBytes = append(addressesBytes, hexToBytes(addr))
	}

	// Simple hash: concatenate sorted r_values
	compHash := hexToBytes(comp.RValues[0]) // simplified

	_, err := db.conn.ExecContext(ctx,
		`INSERT INTO pending_components 
		 (component_hash, r_values, tx_hashes, addresses, chain_ids, equations, unknowns)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (component_hash) DO UPDATE SET
		   tx_hashes = $3, addresses = $4, equations = $6, unknowns = $7, updated_at = NOW()`,
		compHash, pq.Array(rValuesBytes), pq.Array(txHashesBytes),
		pq.Array(addressesBytes), pq.Array(comp.ChainIDs), comp.Equations, comp.Unknowns)
	return db.wrapError(err)
}

// GetPendingComponents returns all pending components
func (db *DB) GetPendingComponents(ctx context.Context) ([]PendingComponent, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT id, r_values, tx_hashes, addresses, chain_ids, equations, unknowns
		 FROM pending_components ORDER BY equations - unknowns DESC`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	comps := []PendingComponent{}
	for rows.Next() {
		var comp PendingComponent
		var rValues, txHashes, addresses [][]byte

		if err := rows.Scan(&comp.ID, pq.Array(&rValues), pq.Array(&txHashes),
			pq.Array(&addresses), pq.Array(&comp.ChainIDs), &comp.Equations, &comp.Unknowns); err != nil {
			continue
		}

		for _, r := range rValues {
			comp.RValues = append(comp.RValues, bytesToHex(r))
		}
		for _, tx := range txHashes {
			comp.TxHashes = append(comp.TxHashes, bytesToHex(tx))
		}
		for _, addr := range addresses {
			comp.Addresses = append(comp.Addresses, bytesToHex(addr))
		}
		comps = append(comps, comp)
	}
	return comps, nil
}

// DeletePendingComponent removes a pending component (after solving)
func (db *DB) DeletePendingComponent(ctx context.Context, id int64) error {
	_, err := db.conn.ExecContext(ctx, "DELETE FROM pending_components WHERE id = $1", id)
	return db.wrapError(err)
}

// GetStats returns database statistics
func (db *DB) GetStats(ctx context.Context) (*Stats, error) {
	stats := &Stats{Healthy: true}

	health := db.Health(ctx)
	if !health.Connected {
		stats.Healthy = false
		return stats, nil
	}

	db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM r_value_index").Scan(&stats.TotalRValues)
	db.conn.QueryRowContext(ctx, "SELECT COUNT(DISTINCT r_value) FROM collisions").Scan(&stats.TotalCollisions)
	db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_components").Scan(&stats.PendingComponents)
	db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovered_keys").Scan(&stats.RecoveredKeys)
	db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovered_nonces").Scan(&stats.RecoveredNonces)

	return stats, nil
}

// HasCrossKeyPotential checks if an R-value has signatures from multiple addresses
func (db *DB) HasCrossKeyPotential(ctx context.Context, rValue string, excludeAddress string) (bool, error) {
	rBytes := hexToBytes(rValue)
	excludeBytes := hexToBytes(excludeAddress)

	var count int
	err := db.conn.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT address) FROM collisions 
		WHERE r_value = $1 AND address != $2 AND address IS NOT NULL
	`, rBytes, excludeBytes).Scan(&count)
	if err != nil {
		return false, db.wrapError(err)
	}
	return count > 0, nil
}

// GetAllCollisions returns all R values that have collisions
func (db *DB) GetAllCollisions(ctx context.Context) ([]Collision, error) {
	rows, err := db.conn.QueryContext(ctx,
		`SELECT DISTINCT r_value FROM collisions ORDER BY r_value`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	collisions := []Collision{}
	for rows.Next() {
		var rValue []byte
		if err := rows.Scan(&rValue); err != nil {
			continue
		}

		rHex := bytesToHex(rValue)
		refs, err := db.GetCollisionTxRefs(ctx, rHex)
		if err != nil {
			continue
		}

		collisions = append(collisions, Collision{
			RValue: rHex,
			TxRefs: refs,
		})
	}

	return collisions, nil
}
