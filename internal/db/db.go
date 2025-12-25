package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"ecdsa-scanner/internal/retry"
)

// Common errors
var (
	ErrConnectionFailed = errors.New("database connection failed")
	ErrQueryTimeout     = errors.New("query timeout")
	ErrPoolExhausted    = errors.New("connection pool exhausted")
)

// Signature represents an ECDSA signature from a transaction
type Signature struct {
	Chain       string
	BlockNumber uint64
	TxHash      string
	FromAddress string
	R           string
	S           string
	V           string
}

// DuplicateEntry represents a single entry in a duplicate group
type DuplicateEntry struct {
	Chain       string `json:"chain"`
	Address     string `json:"address"`
	TxHash      string `json:"tx_hash"`
	BlockNumber uint64 `json:"block_number"`
}

// DuplicateR represents a group of signatures sharing the same R value
type DuplicateR struct {
	RValue  string           `json:"r_value"`
	Count   int              `json:"count"`
	SameKey bool             `json:"same_key"`
	Entries []DuplicateEntry `json:"entries"`
}

// Stats holds duplicate statistics
type Stats struct {
	TotalSignatures     int  `json:"total_signatures"`
	DuplicateSameKey    int  `json:"duplicate_same_key"`
	DuplicateCrossKey   int  `json:"duplicate_cross_key"`
	DuplicateCrossChain int  `json:"duplicate_cross_chain"`
	RecoveredKeys       int  `json:"recovered_keys"`
	Healthy             bool `json:"healthy"`
}

// RecoveredKey represents a recovered private key
type RecoveredKey struct {
	ID         int64  `json:"id"`
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	Chain      string `json:"chain"`
	RValue     string `json:"r_value"`
	TxHash1    string `json:"tx_hash_1"`
	TxHash2    string `json:"tx_hash_2"`
	CreatedAt  string `json:"created_at"`
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
	conn            *sql.DB
	systemAddresses map[string]bool
	retryConfig     retry.Config
}

// New creates a new database connection
func New(databaseURL string, systemAddresses map[string]bool) (*DB, error) {
	conn, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)
	conn.SetConnMaxIdleTime(1 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	db := &DB{
		conn:            conn,
		systemAddresses: systemAddresses,
		retryConfig:     retry.DefaultConfig(),
	}

	if err := db.migrate(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

func (db *DB) migrate(ctx context.Context) error {
	_, err := db.conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS signatures (
			id BIGSERIAL PRIMARY KEY,
			chain TEXT NOT NULL,
			block_number BIGINT NOT NULL,
			tx_hash TEXT NOT NULL,
			from_address TEXT NOT NULL,
			r_value TEXT NOT NULL,
			s_value TEXT NOT NULL,
			v_value TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(chain, tx_hash)
		);

		CREATE INDEX IF NOT EXISTS idx_signatures_r_value ON signatures(r_value);
		CREATE INDEX IF NOT EXISTS idx_signatures_from_address ON signatures(from_address);
		CREATE INDEX IF NOT EXISTS idx_signatures_chain_block ON signatures(chain, block_number);

		CREATE TABLE IF NOT EXISTS scan_state (
			chain TEXT PRIMARY KEY,
			last_block BIGINT NOT NULL,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS recovered_keys (
			id BIGSERIAL PRIMARY KEY,
			address TEXT NOT NULL,
			private_key TEXT NOT NULL,
			chain TEXT NOT NULL,
			r_value TEXT NOT NULL,
			tx_hash_1 TEXT NOT NULL,
			tx_hash_2 TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(address, chain)
		);

		CREATE INDEX IF NOT EXISTS idx_recovered_keys_address ON recovered_keys(address);
	`)
	return err
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// Health checks database connectivity and returns status
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

	// Get connection pool stats
	poolStats := db.conn.Stats()
	status.OpenConnections = poolStats.OpenConnections

	return status
}

// wrapError converts database errors to application errors
func (db *DB) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific postgres errors
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "53300": // too_many_connections
			return fmt.Errorf("%w: %v", ErrPoolExhausted, err)
		case "57014": // query_canceled
			return fmt.Errorf("%w: %v", ErrQueryTimeout, err)
		}
	}

	// Check for context errors
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrQueryTimeout, err)
	}

	return err
}

// InsertSignatures batch inserts signatures with retry
func (db *DB) InsertSignatures(ctx context.Context, sigs []Signature) error {
	if len(sigs) == 0 {
		return nil
	}

	return retry.Do(ctx, db.retryConfig, func() error {
		return db.insertSignaturesBatch(ctx, sigs)
	})
}

func (db *DB) insertSignaturesBatch(ctx context.Context, sigs []Signature) error {
	// Build batch insert
	valueStrings := make([]string, 0, len(sigs))
	valueArgs := make([]interface{}, 0, len(sigs)*7)

	i := 0
	for _, sig := range sigs {
		// Skip invalid signatures
		if sig.R == "0x0" || sig.R == "0x00" || sig.R == "" {
			continue
		}
		if db.systemAddresses[strings.ToLower(sig.FromAddress)] {
			continue
		}

		valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*7+1, i*7+2, i*7+3, i*7+4, i*7+5, i*7+6, i*7+7))
		valueArgs = append(valueArgs,
			sig.Chain,
			sig.BlockNumber,
			sig.TxHash,
			strings.ToLower(sig.FromAddress),
			strings.ToLower(sig.R),
			strings.ToLower(sig.S),
			sig.V,
		)
		i++
	}

	if len(valueStrings) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		INSERT INTO signatures (chain, block_number, tx_hash, from_address, r_value, s_value, v_value)
		VALUES %s
		ON CONFLICT (chain, tx_hash) DO NOTHING
	`, strings.Join(valueStrings, ","))

	_, err := db.conn.ExecContext(ctx, query, valueArgs...)
	return db.wrapError(err)
}

// GetLastBlock returns the last scanned block for a chain
func (db *DB) GetLastBlock(ctx context.Context, chain string) (uint64, error) {
	var lastBlock uint64

	err := retry.Do(ctx, db.retryConfig, func() error {
		err := db.conn.QueryRowContext(ctx,
			"SELECT last_block FROM scan_state WHERE chain = $1", chain).Scan(&lastBlock)
		if err == sql.ErrNoRows {
			lastBlock = 0
			return nil
		}
		return db.wrapError(err)
	})

	return lastBlock, err
}

// SaveLastBlock saves the last scanned block for a chain
func (db *DB) SaveLastBlock(ctx context.Context, chain string, block uint64) error {
	return retry.Do(ctx, db.retryConfig, func() error {
		_, err := db.conn.ExecContext(ctx, `
			INSERT INTO scan_state (chain, last_block, updated_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (chain) DO UPDATE SET last_block = $2, updated_at = NOW()
		`, chain, block)
		return db.wrapError(err)
	})
}

// GetChainTxCount returns the number of signatures for a chain
func (db *DB) GetChainTxCount(ctx context.Context, chain string) (uint64, error) {
	var count uint64

	err := retry.Do(ctx, db.retryConfig, func() error {
		return db.wrapError(db.conn.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM signatures WHERE chain = $1", chain).Scan(&count))
	})

	return count, err
}

// GetStats returns duplicate statistics
func (db *DB) GetStats(ctx context.Context) (*Stats, error) {
	stats := &Stats{Healthy: true}

	// Check health first
	health := db.Health(ctx)
	if !health.Connected {
		stats.Healthy = false
		return stats, fmt.Errorf("database unhealthy: %s", health.Error)
	}

	// Build exclusion clause for system addresses
	excludeAddrs := db.buildAddressExclusion()

	// Total signatures (with timeout per query)
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	db.conn.QueryRowContext(queryCtx,
		"SELECT COUNT(*) FROM signatures WHERE r_value != '0x0'"+excludeAddrs).Scan(&stats.TotalSignatures)
	cancel()

	// Same key duplicates
	queryCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	db.conn.QueryRowContext(queryCtx, `
		SELECT COUNT(*) FROM (
			SELECT r_value FROM signatures
			WHERE r_value != '0x0'`+excludeAddrs+`
			GROUP BY r_value, from_address
			HAVING COUNT(*) > 1
		) sub
	`).Scan(&stats.DuplicateSameKey)
	cancel()

	// Cross-key duplicates
	queryCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	db.conn.QueryRowContext(queryCtx, `
		SELECT COUNT(*) FROM (
			SELECT r_value FROM signatures
			WHERE r_value != '0x0'`+excludeAddrs+`
			GROUP BY r_value, chain
			HAVING COUNT(DISTINCT from_address) > 1
		) sub
	`).Scan(&stats.DuplicateCrossKey)
	cancel()

	// Cross-chain duplicates
	queryCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	db.conn.QueryRowContext(queryCtx, `
		SELECT COUNT(*) FROM (
			SELECT r_value FROM signatures
			WHERE r_value != '0x0'`+excludeAddrs+`
			GROUP BY r_value
			HAVING COUNT(DISTINCT chain) > 1
		) sub
	`).Scan(&stats.DuplicateCrossChain)
	cancel()

	// Recovered keys count
	queryCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
	db.conn.QueryRowContext(queryCtx, "SELECT COUNT(*) FROM recovered_keys").Scan(&stats.RecoveredKeys)
	cancel()

	return stats, nil
}

// FindDuplicates returns duplicate R values
func (db *DB) FindDuplicates(ctx context.Context) ([]DuplicateR, error) {
	excludeAddrs := db.buildAddressExclusion()

	rows, err := db.conn.QueryContext(ctx, `
		SELECT r_value, COUNT(*) as cnt
		FROM signatures
		WHERE r_value != '0x0'`+excludeAddrs+`
		GROUP BY r_value
		HAVING COUNT(*) > 1
		ORDER BY cnt DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	var duplicates []DuplicateR
	for rows.Next() {
		var rValue string
		var count int
		if err := rows.Scan(&rValue, &count); err != nil {
			continue
		}

		entries, sameKey, err := db.getDuplicateEntries(ctx, rValue, excludeAddrs)
		if err != nil || len(entries) < 2 {
			continue
		}

		duplicates = append(duplicates, DuplicateR{
			RValue:  rValue,
			Count:   len(entries),
			SameKey: sameKey,
			Entries: entries,
		})
	}

	return duplicates, nil
}

func (db *DB) getDuplicateEntries(ctx context.Context, rValue, excludeAddrs string) ([]DuplicateEntry, bool, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT chain, from_address, tx_hash, block_number
		FROM signatures
		WHERE r_value = $1`+excludeAddrs+`
		ORDER BY chain, block_number
	`, rValue)
	if err != nil {
		return nil, false, db.wrapError(err)
	}
	defer rows.Close()

	var entries []DuplicateEntry
	uniqueAddrs := make(map[string]bool)

	for rows.Next() {
		var entry DuplicateEntry
		if err := rows.Scan(&entry.Chain, &entry.Address, &entry.TxHash, &entry.BlockNumber); err != nil {
			continue
		}
		entries = append(entries, entry)
		uniqueAddrs[entry.Address] = true
	}

	return entries, len(uniqueAddrs) == 1, nil
}

func (db *DB) buildAddressExclusion() string {
	if len(db.systemAddresses) == 0 {
		return ""
	}

	addrs := make([]string, 0, len(db.systemAddresses))
	for addr := range db.systemAddresses {
		addrs = append(addrs, "'"+addr+"'")
	}
	return " AND from_address NOT IN (" + strings.Join(addrs, ",") + ")"
}

// SaveRecoveredKey saves a recovered private key to the database
func (db *DB) SaveRecoveredKey(ctx context.Context, key *RecoveredKey) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO recovered_keys (address, private_key, chain, r_value, tx_hash_1, tx_hash_2)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (address, chain) DO UPDATE SET
			private_key = $2,
			r_value = $4,
			tx_hash_1 = $5,
			tx_hash_2 = $6
	`, strings.ToLower(key.Address), key.PrivateKey, key.Chain, key.RValue, key.TxHash1, key.TxHash2)
	return db.wrapError(err)
}

// GetRecoveredKeys returns all recovered private keys
func (db *DB) GetRecoveredKeys(ctx context.Context) ([]RecoveredKey, error) {
	rows, err := db.conn.QueryContext(ctx, `
		SELECT id, address, private_key, chain, r_value, tx_hash_1, tx_hash_2, created_at
		FROM recovered_keys
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	var keys []RecoveredKey
	for rows.Next() {
		var key RecoveredKey
		var createdAt time.Time
		if err := rows.Scan(&key.ID, &key.Address, &key.PrivateKey, &key.Chain, &key.RValue, &key.TxHash1, &key.TxHash2, &createdAt); err != nil {
			continue
		}
		key.CreatedAt = createdAt.Format(time.RFC3339)
		keys = append(keys, key)
	}

	return keys, nil
}

// GetRecoveredKeyCount returns the number of recovered keys
func (db *DB) GetRecoveredKeyCount(ctx context.Context) (int, error) {
	var count int
	err := db.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM recovered_keys").Scan(&count)
	return count, db.wrapError(err)
}

// IsKeyRecovered checks if a key has already been recovered for an address/chain
func (db *DB) IsKeyRecovered(ctx context.Context, address, chain string) (bool, error) {
	var count int
	err := db.conn.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM recovered_keys
		WHERE address = $1 AND chain = $2
	`, strings.ToLower(address), chain).Scan(&count)
	if err != nil {
		return false, db.wrapError(err)
	}
	return count > 0, nil
}

// InsertSignaturesAndFindDuplicates inserts signatures and returns any new same-key duplicates found
func (db *DB) InsertSignaturesAndFindDuplicates(ctx context.Context, sigs []Signature) ([]DuplicateR, error) {
	if len(sigs) == 0 {
		return nil, nil
	}

	// Collect R values and addresses from this batch for duplicate checking
	rValueSet := make(map[string]map[string]bool) // r_value -> addresses
	for _, sig := range sigs {
		if sig.R == "0x0" || sig.R == "0x00" || sig.R == "" {
			continue
		}
		if db.systemAddresses[strings.ToLower(sig.FromAddress)] {
			continue
		}
		rLower := strings.ToLower(sig.R)
		if rValueSet[rLower] == nil {
			rValueSet[rLower] = make(map[string]bool)
		}
		rValueSet[rLower][strings.ToLower(sig.FromAddress)] = true
	}

	// Insert the signatures
	if err := db.insertSignaturesBatch(ctx, sigs); err != nil {
		return nil, err
	}

	// Check for duplicates among the R values we just inserted
	var duplicates []DuplicateR
	excludeAddrs := db.buildAddressExclusion()

	for rValue := range rValueSet {
		// Find all same-key duplicates for this R value that aren't recovered yet
		rows, err := db.conn.QueryContext(ctx, `
			SELECT s.from_address, s.chain, COUNT(*) as cnt
			FROM signatures s
			LEFT JOIN recovered_keys rk ON s.from_address = rk.address AND s.chain = rk.chain
			WHERE s.r_value = $1
			  AND rk.id IS NULL`+excludeAddrs+`
			GROUP BY s.from_address, s.chain
			HAVING COUNT(*) > 1
		`, rValue)
		if err != nil {
			continue
		}

		for rows.Next() {
			var address, chain string
			var count int
			if err := rows.Scan(&address, &chain, &count); err != nil {
				continue
			}

			// Get the two transaction hashes for recovery
			txRows, err := db.conn.QueryContext(ctx, `
				SELECT tx_hash, block_number
				FROM signatures
				WHERE r_value = $1 AND from_address = $2 AND chain = $3
				ORDER BY block_number
				LIMIT 2
			`, rValue, address, chain)
			if err != nil {
				continue
			}

			var entries []DuplicateEntry
			for txRows.Next() {
				var entry DuplicateEntry
				if err := txRows.Scan(&entry.TxHash, &entry.BlockNumber); err != nil {
					continue
				}
				entry.Chain = chain
				entry.Address = address
				entries = append(entries, entry)
			}
			txRows.Close()

			if len(entries) >= 2 {
				duplicates = append(duplicates, DuplicateR{
					RValue:  rValue,
					Count:   count,
					SameKey: true,
					Entries: entries,
				})
			}
		}
		rows.Close()
	}

	return duplicates, nil
}

// GetSameKeyDuplicatesForRecovery returns same-key duplicates that haven't been recovered yet
func (db *DB) GetSameKeyDuplicatesForRecovery(ctx context.Context) ([]DuplicateR, error) {
	excludeAddrs := db.buildAddressExclusion()

	// Find R values that appear multiple times from the same address
	rows, err := db.conn.QueryContext(ctx, `
		SELECT s.r_value, s.from_address, s.chain, COUNT(*) as cnt
		FROM signatures s
		LEFT JOIN recovered_keys rk ON s.from_address = rk.address AND s.chain = rk.chain
		WHERE s.r_value != '0x0'
		  AND rk.id IS NULL`+excludeAddrs+`
		GROUP BY s.r_value, s.from_address, s.chain
		HAVING COUNT(*) > 1
		ORDER BY cnt DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, db.wrapError(err)
	}
	defer rows.Close()

	var duplicates []DuplicateR
	for rows.Next() {
		var rValue, address, chain string
		var count int
		if err := rows.Scan(&rValue, &address, &chain, &count); err != nil {
			continue
		}

		// Get the transaction hashes for this R value
		txRows, err := db.conn.QueryContext(ctx, `
			SELECT tx_hash, block_number
			FROM signatures
			WHERE r_value = $1 AND from_address = $2 AND chain = $3
			ORDER BY block_number
			LIMIT 2
		`, rValue, address, chain)
		if err != nil {
			continue
		}

		var entries []DuplicateEntry
		for txRows.Next() {
			var entry DuplicateEntry
			if err := txRows.Scan(&entry.TxHash, &entry.BlockNumber); err != nil {
				continue
			}
			entry.Chain = chain
			entry.Address = address
			entries = append(entries, entry)
		}
		txRows.Close()

		if len(entries) >= 2 {
			duplicates = append(duplicates, DuplicateR{
				RValue:  rValue,
				Count:   count,
				SameKey: true,
				Entries: entries,
			})
		}
	}

	return duplicates, nil
}
