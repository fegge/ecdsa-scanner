package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ecdsa-scanner/internal/api"
	"ecdsa-scanner/internal/config"
	"ecdsa-scanner/internal/db"
	"ecdsa-scanner/internal/logger"
	"ecdsa-scanner/internal/scanner"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Load configuration
	cfg := config.Load()

	// Initialize logger
	appLogger := logger.New(500)

	// Initialize database (or mock for demo mode)
	var database db.Database
	var err error

	if cfg.DatabaseURL == "" {
		appLogger.Warn("DATABASE_URL not set - running in demo mode")
		database = db.NewMock(config.SystemAddresses())
	} else {
		database, err = db.New(cfg.DatabaseURL, config.SystemAddresses())
		if err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}
		appLogger.Info("Connected to database")
	}
	defer database.Close()

	// Initialize scanner
	sc, err := scanner.New(database, appLogger, cfg.AnkrAPIKey)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}

	// Initialize API handler
	handler := api.NewHandler(sc, database, appLogger)

	// Register routes
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Auto-start all chains
	go func() {
		time.Sleep(2 * time.Second)
		appLogger.Log("Auto-starting all chain scanners...")
		sc.StartAll()
	}()

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		appLogger.Log("Shutting down...")
		sc.StopAll()
		os.Exit(0)
	}()

	// Start HTTP server(s)
	addrs := strings.Split(cfg.BindAddrs, ",")
	for i, addr := range addrs[:len(addrs)-1] {
		listenAddr := fmt.Sprintf("%s:%s", strings.TrimSpace(addr), cfg.Port)
		appLogger.Log("Starting server on %s", listenAddr)
		go func(la string, idx int) {
			if err := http.ListenAndServe(la, mux); err != nil {
				log.Printf("Listener %d (%s) error: %v", idx, la, err)
			}
		}(listenAddr, i)
	}

	// Last address blocks
	lastAddr := fmt.Sprintf("%s:%s", strings.TrimSpace(addrs[len(addrs)-1]), cfg.Port)
	appLogger.Log("Starting server on %s", lastAddr)
	log.Fatal(http.ListenAndServe(lastAddr, mux))
}
