package zk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"time"
)

func CreateTLSConfig(rootCAFile, certFile, keyFile string) (*tls.Config, error) {
	rootCABytes, err := os.ReadFile(rootCAFile)
	if err != nil {
		return nil, err
	}

	rootCA := x509.NewCertPool()
	ok := rootCA.AppendCertsFromPEM(rootCABytes)
	if !ok {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCA,
	}, nil
}

func GetTLSDialer(servers []string, dialer *net.Dialer, tlsConfig *tls.Config) (Dialer, error) {
	if len(servers) == 0 {
		return nil, errors.New("zk: server list must not be empty")
	}
	srvs := FormatServers(servers)

	addrToHostname := map[string]string{}

	for _, server := range srvs {
		ips, err := addrsByHostname(server)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			addrToHostname[ip] = server
		}
	}

	return func(network, address string, _ time.Duration) (net.Conn, error) {
		server, ok := addrToHostname[address]
		if !ok {
			server = address
		}
		return tls.DialWithDialer(dialer, network, server, tlsConfig)
	}, nil
}
