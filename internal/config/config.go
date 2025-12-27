package config

import (
	"os"
	"time"
)

// Config holds all application configuration
type Config struct {
	DatabaseURL      string
	AnkrAPIKey       string
	Port             string
	BindAddrs        string
	PushoverAppToken string
	PushoverUserKey  string
}

// ChainConfig defines a blockchain to scan
type ChainConfig struct {
	Name        string
	ChainID     int
	RPCURL      string
	ExplorerURL string
	Enabled     bool
	BlockTime   time.Duration // Average block time for rate limiting
}

// ChainByID returns chain config by ID
func ChainByID(id int) *ChainConfig {
	for _, c := range DefaultChains() {
		if c.ChainID == id {
			return &c
		}
	}
	return nil
}

// ChainByName returns chain config by name
func ChainByName(name string) *ChainConfig {
	for _, c := range DefaultChains() {
		if c.Name == name {
			return &c
		}
	}
	return nil
}

// Load reads configuration from environment variables
func Load() *Config {
	cfg := &Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		AnkrAPIKey:       os.Getenv("ANKR_API_KEY"),
		Port:             os.Getenv("PORT"),
		BindAddrs:        os.Getenv("BIND_ADDRS"),
		PushoverAppToken: os.Getenv("PUSHOVER_APP_TOKEN"),
		PushoverUserKey:  os.Getenv("PUSHOVER_USER_KEY"),
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
		// Original chains
		{Name: "Ethereum", ChainID: 1, RPCURL: "https://rpc.ankr.com/eth", ExplorerURL: "https://etherscan.io", Enabled: true, BlockTime: 12 * time.Second},
		{Name: "BSC", ChainID: 56, RPCURL: "https://rpc.ankr.com/bsc", ExplorerURL: "https://bscscan.com", Enabled: true, BlockTime: 3 * time.Second},
		{Name: "Polygon", ChainID: 137, RPCURL: "https://rpc.ankr.com/polygon", ExplorerURL: "https://polygonscan.com", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Arbitrum", ChainID: 42161, RPCURL: "https://rpc.ankr.com/arbitrum", ExplorerURL: "https://arbiscan.io", Enabled: true, BlockTime: 250 * time.Millisecond},
		{Name: "Avalanche", ChainID: 43114, RPCURL: "https://rpc.ankr.com/avalanche", ExplorerURL: "https://snowtrace.io", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Fantom", ChainID: 250, RPCURL: "https://rpc.ankr.com/fantom", ExplorerURL: "https://ftmscan.com", Enabled: true, BlockTime: 1 * time.Second},
		{Name: "Optimism", ChainID: 10, RPCURL: "https://rpc.ankr.com/optimism", ExplorerURL: "https://optimistic.etherscan.io", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Base", ChainID: 8453, RPCURL: "https://rpc.ankr.com/base", ExplorerURL: "https://basescan.org", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "zkSync", ChainID: 324, RPCURL: "https://rpc.ankr.com/zksync_era", ExplorerURL: "https://explorer.zksync.io", Enabled: true, BlockTime: 1 * time.Second},
		{Name: "Gnosis", ChainID: 100, RPCURL: "https://rpc.ankr.com/gnosis", ExplorerURL: "https://gnosisscan.io", Enabled: true, BlockTime: 5 * time.Second},
		{Name: "Celo", ChainID: 42220, RPCURL: "https://rpc.ankr.com/celo", ExplorerURL: "https://celoscan.io", Enabled: true, BlockTime: 5 * time.Second},
		// High priority L2s
		{Name: "Linea", ChainID: 59144, RPCURL: "https://rpc.ankr.com/linea", ExplorerURL: "https://lineascan.build", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Scroll", ChainID: 534352, RPCURL: "https://rpc.ankr.com/scroll", ExplorerURL: "https://scrollscan.com", Enabled: true, BlockTime: 3 * time.Second},
		{Name: "Mantle", ChainID: 5000, RPCURL: "https://rpc.ankr.com/mantle", ExplorerURL: "https://mantlescan.xyz", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Blast", ChainID: 81457, RPCURL: "https://rpc.ankr.com/blast", ExplorerURL: "https://blastscan.io", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Arbitrum Nova", ChainID: 42170, RPCURL: "https://rpc.ankr.com/arbitrumnova", ExplorerURL: "https://nova.arbiscan.io", Enabled: true, BlockTime: 250 * time.Millisecond},
		// Medium priority chains
		{Name: "Moonbeam", ChainID: 1284, RPCURL: "https://rpc.ankr.com/moonbeam", ExplorerURL: "https://moonscan.io", Enabled: true, BlockTime: 12 * time.Second},
		{Name: "Metis", ChainID: 1088, RPCURL: "https://rpc.ankr.com/metis", ExplorerURL: "https://andromeda-explorer.metis.io", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "Kaia", ChainID: 8217, RPCURL: "https://rpc.ankr.com/kaia", ExplorerURL: "https://kaiascan.io", Enabled: true, BlockTime: 1 * time.Second},
		{Name: "Harmony", ChainID: 1666600000, RPCURL: "https://rpc.ankr.com/harmony", ExplorerURL: "https://explorer.harmony.one", Enabled: true, BlockTime: 2 * time.Second},
		{Name: "IoTeX", ChainID: 4689, RPCURL: "https://rpc.ankr.com/iotex", ExplorerURL: "https://iotexscan.io", Enabled: true, BlockTime: 5 * time.Second},
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
