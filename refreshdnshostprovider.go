package zk

import (
	"log/slog"
	"sync"
)

// RefreshDNSHostProvider is a wrapper around DNSHostProvider
// that will re-resolve server addresses:
//   - everytime the list of server IPs has been fully tried
//   - everytime we ask for a server IP for a reconnection
type RefreshDNSHostProvider struct {
	DNSHostProvider

	mu              sync.Mutex
	connected       bool
	serverAddresses []string
}

func NewRefreshDNSHostProvider() HostProvider {
	return &RefreshDNSHostProvider{}
}

func (hp *RefreshDNSHostProvider) Init(servers []string) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.serverAddresses = servers
	return hp.DNSHostProvider.Init(hp.serverAddresses)
}

func (hp *RefreshDNSHostProvider) Next() (server string, retryStart bool) {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	// we were connected and we're not anymore, refresh the list of servers
	if hp.connected {
		hp.refresh()
	}

	server, retryStart = hp.DNSHostProvider.Next()
	if retryStart {
		hp.refresh()
	}
	return
}

// Connected notifies the HostProvider of a successful connection.
func (hp *RefreshDNSHostProvider) Connected() {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.connected = true
}

// backgroundRefresh is a refresh() but logs the error and does not return it.
func (hp *RefreshDNSHostProvider) refresh() {
	hp.connected = false
	if err := hp.DNSHostProvider.Init(hp.serverAddresses); err != nil {
		slog.Error("failed to refresh serverAddresses", "error", err)
	}
}
