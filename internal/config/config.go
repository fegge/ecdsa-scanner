package config

import (
	"os"
)

// Config holds all application configuration
type Config struct {
	DatabaseURL string
	AnkrAPIKey  string
	Port        string
	BindAddrs   string
}

// ChainConfig defines a blockchain to scan
type ChainConfig struct {
	Name        string
	ChainID     int64
	RPCURL      string
	ExplorerURL string
	Enabled     bool
}

// Load reads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		AnkrAPIKey:  os.Getenv("ANKR_API_KEY"),
		Port:        os.Getenv("PORT"),
		BindAddrs:   os.Getenv("BIND_ADDRS"),
	}

	if cfg.Port == "" {
		cfg.Port = "8000"
	}
	if cfg.BindAddrs == "" {
		cfg.BindAddrs = "0.0.0.0"
	}

	return cfg
}

// DefaultChains returns the list of chains to scan
func DefaultChains() []ChainConfig {
	return []ChainConfig{
		{Name: "Ethereum", ChainID: 1, RPCURL: "https://rpc.ankr.com/eth", ExplorerURL: "https://etherscan.io", Enabled: true},
		{Name: "BSC", ChainID: 56, RPCURL: "https://rpc.ankr.com/bsc", ExplorerURL: "https://bscscan.com", Enabled: true},
		{Name: "Polygon", ChainID: 137, RPCURL: "https://rpc.ankr.com/polygon", ExplorerURL: "https://polygonscan.com", Enabled: true},
		{Name: "Arbitrum", ChainID: 42161, RPCURL: "https://rpc.ankr.com/arbitrum", ExplorerURL: "https://arbiscan.io", Enabled: true},
		{Name: "Avalanche", ChainID: 43114, RPCURL: "https://rpc.ankr.com/avalanche", ExplorerURL: "https://snowtrace.io", Enabled: true},
		{Name: "Fantom", ChainID: 250, RPCURL: "https://rpc.ankr.com/fantom", ExplorerURL: "https://ftmscan.com", Enabled: true},
		{Name: "Optimism", ChainID: 10, RPCURL: "https://rpc.ankr.com/optimism", ExplorerURL: "https://optimistic.etherscan.io", Enabled: true},
		{Name: "Base", ChainID: 8453, RPCURL: "https://rpc.ankr.com/base", ExplorerURL: "https://basescan.org", Enabled: true},
		{Name: "zkSync", ChainID: 324, RPCURL: "https://rpc.ankr.com/zksync_era", ExplorerURL: "https://explorer.zksync.io", Enabled: true},
		{Name: "Gnosis", ChainID: 100, RPCURL: "https://rpc.ankr.com/gnosis", ExplorerURL: "https://gnosisscan.io", Enabled: true},
		{Name: "Celo", ChainID: 42220, RPCURL: "https://rpc.ankr.com/celo", ExplorerURL: "https://celoscan.io", Enabled: true},
	}
}

// SystemAddresses returns addresses to filter out (L2 system transactions)
func SystemAddresses() map[string]bool {
	return map[string]bool{
		"0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001": true, // Optimism/Base L1 deposits
		"0x00000000000000000000000000000000000a4b05": true, // Arbitrum system
		"0x977f82a600a1414e583f7f13623f1ac5d58b1c0b": true, // Celo system
	}
}
