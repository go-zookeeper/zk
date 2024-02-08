package zk

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
)

type hostPort struct {
	host, port string
}

func (hp *hostPort) String() string {
	return hp.host + ":" + hp.port
}

// StaticHostProvider is the default HostProvider, and replaces the now deprecated DNSHostProvider.
// It will iterate through the ZK hosts on every call to Next, and return a random address selected
// from the resolved addresses of the ZK host (if the host is already an IP, it will return that
// directly). It is important to manually resolve and shuffle the addresses because the DNS record
// that backs a host may rarely (or never) change, so repeated calls to connect to this host may
// always connect to the same IP. This mode is the default mode, and matches the Java client's
// implementation. Note that if the host cannot be resolved, Next will return it directly, instead of
// an error. This will cause Dial to fail and the loop will move on to a new host. It is implemented
// as a pound-for-pound copy of the standard Java client's equivalent:
// https://github.com/linkedin/zookeeper/blob/629518b5ea2b26d88a9ec53d5a422afe9b12e452/zookeeper-server/src/main/java/org/apache/zookeeper/client/StaticHostProvider.java#L368
type StaticHostProvider struct {
	mu      sync.Mutex // Protects everything, so we can add asynchronous updates later.
	servers []hostPort
	// nextServer is the index (in servers) of the next server that will be returned by Next.
	nextServer int
	// lastConnectedServer is the index (in servers) of the last server to which a successful connection
	// was established. Used to track whether Next iterated through all available servers without
	// successfully connecting.
	lastConnectedServer int
	lookupHost          func(string) ([]string, error) // Override of net.LookupHost, for testing.
}

func (shp *StaticHostProvider) Init(servers []string) error {
	shp.mu.Lock()
	defer shp.mu.Unlock()

	if shp.lookupHost == nil {
		shp.lookupHost = net.LookupHost
	}

	var found []hostPort
	for _, server := range servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			return err
		}
		// Perform the lookup to validate the initial set of hosts, but discard the results as the addresses
		// will be resolved dynamically when Next is called.
		_, err = shp.lookupHost(host)
		if err != nil {
			return err
		}

		found = append(found, hostPort{host, port})
	}

	if len(found) == 0 {
		return fmt.Errorf("zk: no hosts found for addresses %q", servers)
	}

	// Randomize the order of the servers to avoid creating hotspots
	shuffleSlice(found)

	shp.servers = found
	shp.nextServer = 0
	shp.lastConnectedServer = len(shp.servers) - 1

	return nil
}

// Next returns the next server to connect to. retryStart should be true if this call to Next
// exhausted the list of known servers without Connected being called. If connecting to this final
// host fails, the connect loop will back off before invoking Next again for a fresh server.
func (shp *StaticHostProvider) Next() (server string, retryStart bool) {
	shp.mu.Lock()
	defer shp.mu.Unlock()
	retryStart = shp.nextServer == shp.lastConnectedServer

	next := shp.servers[shp.nextServer]
	addrs, err := shp.lookupHost(next.host)
	if len(addrs) == 0 {
		if err == nil {
			// If for whatever reason lookupHosts returned an empty list of addresses but a nil error, use a
			// default error
			err = fmt.Errorf("zk: no hosts resolved by lookup for %q", next.host)
		}
		slog.Warn("Could not resolve ZK host", "host", next.host, "err", err)
		server = next.String()
	} else {
		server = net.JoinHostPort(addrs[rand.Intn(len(addrs))], next.port)
	}

	shp.nextServer = (shp.nextServer + 1) % len(shp.servers)

	return server, retryStart
}

// Connected notifies the HostProvider of a successful connection.
func (shp *StaticHostProvider) Connected() {
	shp.mu.Lock()
	defer shp.mu.Unlock()
	if shp.nextServer == 0 {
		shp.lastConnectedServer = len(shp.servers) - 1
	} else {
		shp.lastConnectedServer = shp.nextServer - 1
	}
}
