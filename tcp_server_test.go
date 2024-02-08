package zk

import (
	"net"
	"testing"
	"time"
)

func WithListenServer(t *testing.T, test func(server string)) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to start listen server: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Logf("Failed to accept connection: %s", err.Error())
		}

		handleRequest(conn)
	}()

	test(l.Addr().String())
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	time.Sleep(5 * time.Second)
	conn.Close()
}
