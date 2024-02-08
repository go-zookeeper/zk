package zk

import (
	"fmt"
	"net"
	"sync"
)

// DNSHostProvider is a simple implementation of a HostProvider. It resolves the hosts once during
// Init, and iterates through the resolved addresses for every call to Next. Note that if the
// addresses that back the ZK hosts change, those changes will not be reflected.
//
// Deprecated: Because this HostProvider does not attempt to re-read from DNS, it can lead to issues
// if the addresses of the hosts change. It is preserved for backwards compatibility.
type DNSHostProvider struct {
	mu         sync.Mutex // Protects everything, so we can add asynchronous updates later.
	servers    []string
	curr       int
	last       int
	lookupHost func(string) ([]string, error) // Override of net.LookupHost, for testing.
}

// Init is called first, with the servers specified in the connection
// string. It uses DNS to look up addresses for each server, then
// shuffles them all together.
func (hp *DNSHostProvider) Init(servers []string) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	lookupHost := hp.lookupHost
	if lookupHost == nil {
		lookupHost = net.LookupHost
	}

	var found []string
	for _, server := range servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			return err
		}
		addrs, err := lookupHost(host)
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			found = append(found, net.JoinHostPort(addr, port))
		}
	}

	if len(found) == 0 {
		return fmt.Errorf("zk: no hosts found for addresses %q", servers)
	}

	// Randomize the order of the servers to avoid creating hotspots
	shuffleSlice(found)

	hp.servers = found
	hp.curr = 0
	hp.last = len(hp.servers) - 1

	return nil
}

// Next returns the next server to connect to. retryStart should be true if this call to Next
// exhausted the list of known servers without Connected being called. If connecting to this final
// host fails, the connect loop will back off before invoking Next again for a fresh server.
func (hp *DNSHostProvider) Next() (server string, retryStart bool) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	retryStart = hp.curr == hp.last
	server = hp.servers[hp.curr]
	hp.curr = (hp.curr + 1) % len(hp.servers)
	return server, retryStart
}

// Connected notifies the HostProvider of a successful connection.
func (hp *DNSHostProvider) Connected() {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.curr == 0 {
		hp.last = len(hp.servers) - 1
	} else {
		hp.last = hp.curr - 1
	}
}
