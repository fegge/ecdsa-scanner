package notify

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const pushoverAPI = "https://api.pushover.net/1/messages.json"

// Priority levels for Pushover
const (
	PriorityLowest    = -2
	PriorityLow       = -1
	PriorityNormal    = 0
	PriorityHigh      = 1
	PriorityEmergency = 2
)

// Notifier sends push notifications
type Notifier struct {
	appToken  string
	userKey   string
	enabled   bool
	client    *http.Client
}

// New creates a new Pushover notifier
// If appToken or userKey is empty, notifications are disabled
func New(appToken, userKey string) *Notifier {
	return &Notifier{
		appToken: appToken,
		userKey:  userKey,
		enabled:  appToken != "" && userKey != "",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsEnabled returns whether notifications are enabled
func (n *Notifier) IsEnabled() bool {
	return n.enabled
}

// Send sends a notification with normal priority
func (n *Notifier) Send(title, message string) error {
	return n.SendWithPriority(title, message, PriorityNormal)
}

// SendWithPriority sends a notification with specified priority
func (n *Notifier) SendWithPriority(title, message string, priority int) error {
	if !n.enabled {
		return nil
	}

	data := url.Values{}
	data.Set("token", n.appToken)
	data.Set("user", n.userKey)
	data.Set("title", title)
	data.Set("message", message)
	data.Set("priority", fmt.Sprintf("%d", priority))

	// Emergency priority requires retry and expire parameters
	if priority == PriorityEmergency {
		data.Set("retry", "60")
		data.Set("expire", "3600")
	}

	resp, err := n.client.PostForm(pushoverAPI, data)
	if err != nil {
		return fmt.Errorf("pushover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}

	return nil
}

// NotifyKeyRecovered sends a high-priority notification for key recovery
func (n *Notifier) NotifyKeyRecovered(address, chainName string, txCount int) error {
	title := "🔑 Private Key Recovered!"
	message := fmt.Sprintf("Address: %s\nChain: %s\nTransactions: %d",
		shortenAddress(address), chainName, txCount)
	return n.SendWithPriority(title, message, PriorityHigh)
}

// NotifyCollision sends a normal-priority notification for R-value collision
func (n *Notifier) NotifyCollision(rValue, address string, chainID int, isSameKey bool) error {
	var title, message string
	if isSameKey {
		title = "⚠️ Same-Key Nonce Reuse Detected"
		message = fmt.Sprintf("Address: %s\nChain ID: %d\nR-value: %s",
			shortenAddress(address), chainID, shortenHash(rValue))
	} else {
		title = "🔄 Cross-Key R-Value Collision"
		message = fmt.Sprintf("Chain ID: %d\nR-value: %s",
			chainID, shortenHash(rValue))
	}
	return n.Send(title, message)
}

// shortenAddress returns a shortened address (0x1234...5678)
func shortenAddress(addr string) string {
	addr = strings.ToLower(addr)
	if len(addr) > 14 {
		return addr[:8] + "..." + addr[len(addr)-6:]
	}
	return addr
}

// shortenHash returns a shortened hash
func shortenHash(hash string) string {
	if len(hash) > 18 {
		return hash[:18] + "..."
	}
	return hash
}
