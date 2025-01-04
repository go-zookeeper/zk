package zk

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

func WithListenServer(t *testing.T, test func(server string)) {
	startPort := int(rand.Int31n(6000) + 10000)
	server := fmt.Sprintf("localhost:%d", startPort)
	l, err := net.Listen("tcp", server)
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

	test(server)
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	time.Sleep(5 * time.Second)
	conn.Close()
}
