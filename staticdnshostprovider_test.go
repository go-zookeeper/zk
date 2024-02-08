package zk

import "testing"

// The test in TestHostProvidersRetryStart checks that the semantics of StaticHostProvider's
// implementation of Next are correct, this test only checks that the provider correctly interacts
// with the resolver.
func TestStaticHostProvider(t *testing.T) {
	const fooPort, barPort = "2121", "6464"
	const fooHost, barHost = "foo.com", "bar.com"
	hostToPort := map[string]string{
		fooHost: fooPort,
		barHost: barPort,
	}
	hostToAddrs := map[string][]string{
		fooHost: {"0.0.0.1", "0.0.0.2", "0.0.0.3"},
		barHost: {"0.0.0.4", "0.0.0.5", "0.0.0.6"},
	}
	addrToHost := map[string]string{}
	for host, addrs := range hostToAddrs {
		for _, addr := range addrs {
			addrToHost[addr+":"+hostToPort[host]] = host
		}
	}

	hp := &StaticHostProvider{
		lookupHost: func(host string) ([]string, error) {
			addrs, ok := hostToAddrs[host]
			if !ok {
				t.Fatalf("Unexpected argument to lookupHost %q", host)
			}
			return addrs, nil
		},
	}

	err := hp.Init([]string{fooHost + ":" + fooPort, barHost + ":" + barPort})
	if err != nil {
		t.Fatalf("Unexpected err from Init %v", err)
	}

	addr1, retryStart := hp.Next()
	if retryStart {
		t.Fatalf("retryStart should be false")
	}
	addr2, retryStart := hp.Next()
	if !retryStart {
		t.Fatalf("retryStart should be true")
	}
	host1, host2 := addrToHost[addr1], addrToHost[addr2]
	if host1 == host2 {
		t.Fatalf("Next yielded addresses from same host (%q)", host1)
	}

	// Final sanity check that it is shuffling the addresses
	seenAddresses := map[string]map[string]bool{
		fooHost: {},
		barHost: {},
	}
	for i := 0; i < 10_000; i++ {
		addr, _ := hp.Next()
		seenAddresses[addrToHost[addr]][addr] = true
	}

	for host, addrs := range hostToAddrs {
		for _, addr := range addrs {
			if !seenAddresses[host][addr+":"+hostToPort[host]] {
				t.Fatalf("expected addr %q for host %q not seen (seen: %v)", addr, host, seenAddresses)
			}
		}
	}
}
