package zk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStateChanges(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		callbackChan := make(chan Event)
		f := func(event Event) {
			callbackChan <- event
		}

		zk, eventChan, err := tc.ConnectWithOptions(15*time.Second, WithEventCallback(f))
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}

		verifyEventOrder := func(c <-chan Event, expectedStates []State, source string) {
			for _, state := range expectedStates {
				for {
					event, ok := <-c
					if !ok {
						t.Fatalf("unexpected channel close for %s", source)
					}

					if event.Type != EventSession {
						continue
					}

					if event.State != state {
						t.Fatalf("mismatched state order from %s, expected %v, received %v", source, state, event.State)
					}
					break
				}
			}
		}

		states := []State{StateConnecting, StateConnected, StateHasSession}
		verifyEventOrder(callbackChan, states, "callback")
		verifyEventOrder(eventChan, states, "event channel")

		zk.Close()
		verifyEventOrder(callbackChan, []State{StateDisconnected}, "callback")
		verifyEventOrder(eventChan, []State{StateDisconnected}, "event channel")
	})
}

func TestCreate(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if p, err := c.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}
			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}
		})
	})
}

func TestCreateTTL(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if _, err := c.CreateTTL("", []byte{1, 2, 3, 4}, FlagTTL|FlagEphemeral, WorldACL(PermAll), 60*time.Second); err != ErrInvalidPath {
				t.Fatalf("Create path check failed")
			}
			if _, err := c.CreateTTL(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll), 60*time.Second); err != ErrInvalidFlags {
				t.Fatalf("Create flags check failed")
			}
			if p, err := c.CreateTTL(path, []byte{1, 2, 3, 4}, FlagTTL|FlagEphemeral, WorldACL(PermAll), 60*time.Second); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}
			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if p, err := c.CreateTTL(path, []byte{1, 2, 3, 4}, FlagTTL|FlagSequence, WorldACL(PermAll), 60*time.Second); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if !strings.HasPrefix(p, path) {
				t.Fatalf("Create returned invalid path '%s' are not '%s' with sequence", p, path)
			} else if data, stat, err := c.Get(p); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}
		})
	})
}

func TestCreateContainer(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if _, err := c.CreateContainer("", []byte{1, 2, 3, 4}, FlagTTL, WorldACL(PermAll)); err != ErrInvalidPath {
				t.Fatalf("Create path check failed")
			}
			if _, err := c.CreateContainer(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != ErrInvalidFlags {
				t.Fatalf("Create flags check failed")
			}
			if p, err := c.CreateContainer(path, []byte{1, 2, 3, 4}, FlagTTL, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}
			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}
		})
	})
}

func TestDelete(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if p, err := c.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}

			// First delete succeeds.
			if err := c.Delete(path, -1); err != nil {
				t.Fatalf("Expected no error, but got: %+v", err)
			}

			// Second delete fails with ErrNoNode.
			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Expected ErrNoNode, but got: %+v", err)
			}
		})
	})
}

func TestIncrementalReconfig(t *testing.T) {
	if zkVersion := zkVersionFromEnv(); zkVersion.IsValid() {
		if zkVersion.LessThan(Version{3, 5, 0}) {
			t.Skip("running with zookeeper that does not support this api")
		}
	} else {
		t.Skip("did not detect valid ZK_VERSION from env. skipping reconfig test")
	}

	t.Parallel()

	WithTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		// start and add a new server.
		tmpPath, err := os.MkdirTemp("", "gozk")
		requireNoError(t, err, "failed to create tmp dir for test server setup")
		defer func(path string) {
			_ = os.RemoveAll(path)
		}(tmpPath)

		startPort := int(mathrand.Int31n(6000) + 10000)

		srvPath := filepath.Join(tmpPath, "srv4")
		if err := os.Mkdir(srvPath, 0700); err != nil {
			requireNoError(t, err, "failed to make server path")
		}
		testSrvConfig := ServerConfigServer{
			ID:                 4,
			Host:               "127.0.0.1",
			PeerPort:           startPort + 1,
			LeaderElectionPort: startPort + 2,
		}
		cfg := ServerConfig{
			ClientPort: startPort,
			DataDir:    srvPath,
			Servers:    []ServerConfigServer{testSrvConfig},
		}

		// TODO: clean all this server creating up to a better helper method
		cfgPath := filepath.Join(srvPath, _testConfigName)
		fi, err := os.Create(cfgPath)
		requireNoError(t, err)

		requireNoError(t, cfg.Marshall(fi))
		_ = fi.Close()

		fi, err = os.Create(filepath.Join(srvPath, _testMyIDFileName))
		requireNoError(t, err)

		_, err = fmt.Fprintln(fi, "4")
		_ = fi.Close()
		requireNoError(t, err)

		testServer, err := NewIntegrationTestServer(t, cfgPath, nil, nil)
		requireNoError(t, err)
		requireNoError(t, testServer.Start())
		defer func() {
			_ = testServer.Stop()
		}()

		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			err = c.AddAuth("digest", []byte("super:test"))
			requireNoError(t, err, "failed to auth to cluster")

			waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = waitForSession(waitCtx, c, ech)
			requireNoError(t, err, "failed to wail for session")

			_, _, err = c.Get("/zookeeper/config")
			if err != nil {
				t.Fatalf("get config returned error: %+v", err)
			}

			// initially should be 1<<32, which is 0x100000000. This is the zxid
			// of the first NEWLEADER message, used as the inital version
			// reflect.DeepEqual(bytes.Split(data, []byte("\n")), []byte("version=100000000"))

			// remove node 3.
			_, err = c.IncrementalReconfig(nil, []string{"3"}, -1)
			if err != nil && err == ErrConnectionClosed {
				t.Log("conneciton closed is fine since the cluster re-elects and we dont reconnect")
			} else {
				requireNoError(t, err, "failed to remove node from cluster")
			}

			// add node a new 4th node
			server := fmt.Sprintf("server.%d=%s:%d:%d;%d", testSrvConfig.ID, testSrvConfig.Host, testSrvConfig.PeerPort, testSrvConfig.LeaderElectionPort, cfg.ClientPort)
			_, err = c.IncrementalReconfig([]string{server}, nil, -1)
			if err != nil && err == ErrConnectionClosed {
				t.Log("conneciton closed is fine since the cluster re-elects and we dont reconnect")
			} else {
				requireNoError(t, err, "failed to add new server to cluster")
			}
		})
	})
}

func TestReconfig(t *testing.T) {
	if zkVersion := zkVersionFromEnv(); zkVersion.IsValid() {
		if zkVersion.LessThan(Version{3, 5, 0}) {
			t.Skip("running with zookeeper that does not support this api")
		}
	} else {
		t.Skip("did not detect valid ZK_VERSION from env. skipping reconfig test")
	}

	t.Parallel()

	WithTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			err := c.AddAuth("digest", []byte("super:test"))
			requireNoError(t, err, "failed to auth to cluster")

			waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = waitForSession(waitCtx, c, ech)
			requireNoError(t, err, "failed to wail for session")

			_, _, err = c.Get("/zookeeper/config")
			if err != nil {
				t.Fatalf("get config returned error: %+v", err)
			}

			// essentially remove the first node
			var s []string
			for _, host := range tc.Config.Servers[1:] {
				s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, tc.Config.ClientPort))
			}

			_, err = c.Reconfig(s, -1)
			requireNoError(t, err, "failed to reconfig cluster")

			// reconfig to all the hosts again
			s = []string{}
			for _, host := range tc.Config.Servers {
				s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, tc.Config.ClientPort))
			}

			_, err = c.Reconfig(s, -1)
			requireNoError(t, err, "failed to reconfig cluster")
		})
	})
}

func TestOpsAfterCloseDontDeadlock(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			c.Close() // Close before creating.
			path := "/gozk-test"
			errs := make(chan error, 1)
			go func() {
				defer close(errs)
				for i := 0; i < 30; i++ {
					if _, err := c.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err == nil {
						errs <- fmt.Errorf("expected Create to return an error, got nil")
						return
					}
				}
			}()
			select {
			case e, ok := <-errs:
				if ok {
					t.Fatal(e)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ZK connection deadlocked when executing ops after a Close operation")
			}
		})
	})
}

func TestMulti(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			// Create and set data with check versions.
			ops := []any{
				&CreateRequest{Path: path, Data: []byte{1, 2, 3, 4}, Acl: WorldACL(PermAll)},
				&CheckVersionRequest{Path: path, Version: 0}, // Should be at version 0
				&SetDataRequest{Path: path, Data: []byte{1, 2, 3, 4}, Version: 0},
				&CheckVersionRequest{Path: path, Version: 1}, // Should be at version 1
			}
			if res, err := c.Multi(ops...); err != nil {
				t.Fatalf("Multi returned error: %+v", err)
			} else if len(res) != 4 {
				t.Fatalf("Expected 4 responses got %d", len(res))
			} else {
				t.Logf("%+v", res)
			}

			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}

			// Check version fails and prevents delete.
			ops = []any{
				&CheckVersionRequest{Path: path, Version: 10}, // Should be at version 1
				&DeleteRequest{Path: path, Version: 1},
			}
			if res, err := c.Multi(ops...); err == nil {
				t.Fatal("Multi returned no error, but error was expected")
			} else if !strings.Contains(err.Error(), "version conflict") {
				t.Fatalf("Multi returned unexpected error: %+v", err)
			} else if len(res) != 2 {
				t.Fatalf("Expected 2 responses got %d", len(res))
			} else if res[0].Error != ErrBadVersion {
				t.Fatalf("Expected ErrBadVersion got %+v", res[0].Error)
			} else {
				t.Logf("%+v", res)
			}

			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Get returned nil stat")
			} else if len(data) < 4 {
				t.Fatal("Get returned wrong size data")
			}

			// Successful delete and check version.
			ops = []any{
				&CheckVersionRequest{Path: path, Version: 1}, // Should be at version 1
				&DeleteRequest{Path: path, Version: 1},
			}
			if res, err := c.Multi(ops...); err != nil {
				t.Fatalf("Multi returned error: %+v", err)
			} else if len(res) != 2 {
				t.Fatalf("Expected 2 responses got %d", len(res))
			} else {
				t.Logf("%+v", res)
			}

			if ok, stat, err := c.Exists(path); err != nil {
				t.Fatalf("Get returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Exists returned nil stat")
			} else if ok {
				t.Fatal("Exists returned true; expected false")
			}
		})
	})
}

func TestMultiRead(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-multiread",
				"/gozk-test-multiread/a",
				"/gozk-test-multiread/a/b",
				"/gozk-test-multiread/a/c",
				"/gozk-test-multiread/a/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			ops := []any{
				&GetChildrenRequest{Path: paths[0]},
				&GetChildrenRequest{Path: paths[1]},
				&GetChildrenRequest{Path: paths[2]},
				&GetDataRequest{Path: paths[3]},
			}
			if res, err := c.MultiRead(ops...); err != nil {
				t.Fatalf("MultiRead returned error: %+v", err)
			} else if len(res) != 4 {
				t.Fatalf("Expected 4 responses got %d", len(res))
			} else if res[0].Error != nil {
				t.Fatalf("GetChildren returned error: %+v", res[0].Error)
			} else if !slicesEqual(res[0].Children, []string{"a"}) {
				t.Fatalf("GetChildren returned wrong children: %+v", res[0].Children)
			} else if res[1].Error != nil {
				t.Fatalf("GetChildren returned error: %+v", res[1].Error)
			} else if !slicesEqual(res[1].Children, []string{"b", "c"}) {
				t.Fatalf("GetChildren returned wrong children: %+v", res[1].Children)
			} else if res[2].Error != nil {
				t.Fatalf("GetChildren returned error: %+v", res[2].Error)
			} else if len(res[2].Children) != 0 {
				t.Fatalf("GetChildren returned wrong number of children: %d", len(res[2].Children))
			} else if res[3].Error != nil {
				t.Fatalf("GetData returned error: %+v", res[3].Error)
			} else if res[3].Stat == nil {
				t.Fatal("GetData returned nil stat")
			} else if !slicesEqual(res[3].Data, []byte{1, 2, 3, 4}) {
				t.Fatalf("GetData returned wrong data: %+v", res[3].Data)
			} else {
				t.Logf("%+v", res)
			}
		})
	})
}

func TestIfAuthdataSurvivesReconnect(t *testing.T) {
	t.Parallel()

	// This test case ensures authentication data is being resubmited after
	// reconnect.
	testNode := "/auth-testnode"

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			acl := DigestACL(PermAll, "userfoo", "passbar")

			_, err := c.Create(testNode, []byte("Some very secret content"), 0, acl)
			if err != nil && err != ErrNodeExists {
				t.Fatalf("Failed to create test node : %+v", err)
			}

			_, _, err = c.Get(testNode)
			if err == nil || err != ErrNoAuth {
				var msg string

				if err == nil {
					msg = "Fetching data without auth should have resulted in an error"
				} else {
					msg = fmt.Sprintf("Expecting ErrNoAuth, got `%+v` instead", err)
				}
				t.Fatalf(msg)
			}

			err = c.AddAuth("digest", []byte("userfoo:passbar"))
			if err != nil {
				t.Fatalf("Failed to add auth : %+v", err)
			}

			_, _, err = c.Get(testNode)
			if err != nil {
				t.Fatalf("Fetching data with auth failed: %+v", err)
			}

			_ = tc.StopAllServers()
			_ = tc.StartAllServers()

			_, _, err = c.Get(testNode)
			if err != nil {
				t.Fatalf("Fetching data after reconnect failed: %+v", err)
			}
		})
	})
}

func TestMultiFailures(t *testing.T) {
	t.Parallel()

	// This test case ensures that we return the errors associated with each
	// opeThis in the event a call to Multi() fails.
	const firstPath = "/gozk-test-first"
	const secondPath = "/gozk-test-second"

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			// Ensure firstPath doesn't exist and secondPath does. This will cause the
			// 2nd operation in the Multi() to fail.
			if err := c.Delete(firstPath, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if _, err := c.Create(secondPath, nil /* data */, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			}

			ops := []any{
				&CreateRequest{Path: firstPath, Data: []byte{1, 2}, Acl: WorldACL(PermAll)},
				&CreateRequest{Path: secondPath, Data: []byte{3, 4}, Acl: WorldACL(PermAll)},
			}
			res, err := c.Multi(ops...)
			if err != ErrNodeExists {
				t.Fatalf("Multi() didn't return correct error: %+v", err)
			}
			if len(res) != 2 {
				t.Fatalf("Expected 2 responses received %d", len(res))
			}
			if res[0].Error != nil {
				t.Fatalf("First operation returned an unexpected error %+v", res[0].Error)
			}
			if res[1].Error != ErrNodeExists {
				t.Fatalf("Second operation returned incorrect error %+v", res[1].Error)
			}
			if _, _, err := c.Get(firstPath); err != ErrNoNode {
				t.Fatalf("Node %s was incorrectly created: %+v", firstPath, err)
			}
		})
	})
}

func TestGetSetACL(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.AddAuth("digest", []byte("blah")); err != nil {
				t.Fatalf("AddAuth returned error %+v", err)
			}

			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if path, err := c.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			expected := WorldACL(PermAll)

			if acl, stat, err := c.GetACL(path); err != nil {
				t.Fatalf("GetACL returned error %+v", err)
			} else if stat == nil {
				t.Fatalf("GetACL returned nil Stat")
			} else if len(acl) != 1 || expected[0] != acl[0] {
				t.Fatalf("GetACL mismatch expected %+v instead of %+v", expected, acl)
			}

			expected = []ACL{{PermAll, "ip", "127.0.0.1"}}

			if stat, err := c.SetACL(path, expected, -1); err != nil {
				t.Fatalf("SetACL returned error %+v", err)
			} else if stat == nil {
				t.Fatalf("SetACL returned nil Stat")
			}

			if acl, stat, err := c.GetACL(path); err != nil {
				t.Fatalf("GetACL returned error %+v", err)
			} else if stat == nil {
				t.Fatalf("GetACL returned nil Stat")
			} else if len(acl) != 1 || expected[0] != acl[0] {
				t.Fatalf("GetACL mismatch expected %+v instead of %+v", expected, acl)
			}
		})
	})
}

func TestAuth(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-digest-test"
			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			acl := DigestACL(PermAll, "user", "password")

			if p, err := c.Create(path, []byte{1, 2, 3, 4}, 0, acl); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if p != path {
				t.Fatalf("Create returned different path '%s' != '%s'", p, path)
			}

			if _, _, err := c.Get(path); err != ErrNoAuth {
				t.Fatalf("Get returned error %+v instead of ErrNoAuth", err)
			}

			if err := c.AddAuth("digest", []byte("user:password")); err != nil {
				t.Fatalf("AddAuth returned error %+v", err)
			}

			if a, stat, err := c.GetACL(path); err != nil {
				t.Fatalf("GetACL returned error %+v", err)
			} else if stat == nil {
				t.Fatalf("GetACL returned nil Stat")
			} else if len(a) != 1 || acl[0] != a[0] {
				t.Fatalf("GetACL mismatch expected %+v instead of %+v", acl, a)
			}

			if data, stat, err := c.Get(path); err != nil {
				t.Fatalf("Get returned error %+v", err)
			} else if stat == nil {
				t.Fatalf("Get returned nil Stat")
			} else if len(data) != 4 {
				t.Fatalf("Get returned wrong data length")
			}
		})
	})
}

func TestChildren(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			deleteNode := func(node string) {
				if err := c.Delete(node, -1); err != nil && err != ErrNoNode {
					t.Fatalf("Delete returned error: %+v", err)
				}
			}

			deleteNode("/gozk-test-big")

			if path, err := c.Create("/gozk-test-big", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test-big" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test-big'", path)
			}

			rb := make([]byte, 1000)
			hb := make([]byte, 2000)
			prefix := []byte("/gozk-test-big/")
			for i := 0; i < 1000; i++ {
				_, err := rand.Read(rb)
				if err != nil {
					t.Fatal("Cannot create random znode name")
				}
				hex.Encode(hb, rb)

				expect := string(append(prefix, hb...))
				if path, err := c.Create(expect, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != expect {
					t.Fatalf("Create returned different path '%s' != '%s'", path, expect)
				}

				if (i+1)%100 == 0 {
					t.Log("created", i+1, "/ 1000 children")
				}

				defer deleteNode(expect)
			}

			t.Log("fetching children...")
			children, _, err := c.Children("/gozk-test-big")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if len(children) != 1000 {
				t.Fatal("Children returned wrong number of nodes")
			}
		})
	})
}

func TestChildWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			children, stat, childCh, err := c.ChildrenW("/")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Children returned nil stat")
			} else if len(children) < 1 {
				t.Fatal("Children should return at least 1 child")
			}

			// Creating a child should trigger EventNodeChildrenChanged.
			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			// Verify childCh yields EventNodeChildrenChanged
			select {
			case ev := <-childCh:
				if ev.Type != EventNodeChildrenChanged {
					t.Fatalf("Child watcher event wrong type %v instead of EventNodeChildrenChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Child watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Child watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}
			// Verify childCh is closed.
			select {
			case _, ok := <-childCh:
				if ok {
					t.Fatal("Child watcher channel should be closed")
				}
			default:
				t.Fatal("Child watcher channel should be closed")
			}

			children, stat, childCh, err = c.ChildrenW("/gozk-test")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Children returned nil stat")
			} else if len(children) != 0 {
				t.Fatal("Children should return 0 children")
			}

			// Delete of the watched node should trigger EventNodeDeleted
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			// Verify childCh yields EventNodeDeleted.
			select {
			case ev := <-childCh:
				if ev.Type != EventNodeDeleted {
					t.Fatalf("Child watcher event wrong type %v instead of EventNodeChildrenChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Child watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Child watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}
			// Verify childCh is closed.
			select {
			case _, ok := <-childCh:
				if ok {
					t.Fatal("Child watcher channel should be closed")
				}
			default:
				t.Fatal("Child watcher channel should be closed")
			}
		})
	})
}

func TestRemoveChildWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			children, stat, childCh, err := c.ChildrenW("/")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Children returned nil stat")
			} else if len(children) < 1 {
				t.Fatal("Children should return at least 1 child")
			}

			err = c.RemoveWatch(childCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

			// Verify childCh yields EventNotWatching
			select {
			case ev := <-childCh:
				if ev.Type != EventNotWatching {
					t.Fatalf("Child watcher event wrong type %v instead of EventNotWatching", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Child watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Child watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}
			// Verify childCh is closed.
			select {
			case _, ok := <-childCh:
				if ok {
					t.Fatal("Child watcher channel should be closed")
				}
			default:
				t.Fatal("Child watcher channel should be closed")
			}
		})
	})
}

func TestExistsWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			exists, stat, existsCh, err := c.ExistsW("/gozk-test")
			if err != nil {
				t.Fatalf("Exists returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Exists returned nil stat")
			} else if exists {
				t.Fatal("Exists returned true")
			}

			// Create of the watched node should trigger EventNodeCreated
			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			// Verify existsCh yields EventNodeCreated.
			select {
			case ev := <-existsCh:
				if ev.Type != EventNodeCreated {
					t.Fatalf("Exists watcher event wrong event type %v instead of %v", ev.Type, EventNodeCreated)
				}
				if ev.Err != nil {
					t.Fatalf("Exists watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Exists watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Exists watcher timed out")
			}
			// Verify existsCh is closed.
			select {
			case _, ok := <-existsCh:
				if ok {
					t.Fatal("Exists watcher channel should be closed")
				}
			default:
				t.Fatal("Exists watcher channel should be closed")
			}

			exists, stat, existsCh, err = c.ExistsW("/gozk-test")
			if err != nil {
				t.Fatalf("Exists returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Exists returned nil stat")
			} else if !exists {
				t.Fatal("Exists should return true")
			}

			// Delete of the watched node should trigger EventNodeDeleted.
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			// Verify existsCh yields EventNodeDeleted.
			select {
			case ev := <-existsCh:
				if ev.Type != EventNodeDeleted {
					t.Fatalf("Exists watcher event wrong event type %v instead of %v", ev.Type, EventNodeDeleted)
				}
				if ev.Err != nil {
					t.Fatalf("Exists watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Exists watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Exists watcher timed out")
			}
			// Verify existsCh is closed.
			select {
			case _, ok := <-existsCh:
				if ok {
					t.Fatal("Exists watcher channel should be closed")
				}
			default:
				t.Fatal("Exists watcher channel should be closed")
			}
		})
	})
}

func TestRemoveExistsWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			exists, _, existsCh, err := c.ExistsW("/gozk-test")
			if err != nil {
				t.Fatalf("Exists returned error: %+v", err)
			} else if exists {
				t.Fatal("Exists returned true")
			}

			err = c.RemoveWatch(existsCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

			// Verify existsCh yields EventNotWatching.
			select {
			case ev := <-existsCh:
				if ev.Type != EventNotWatching {
					t.Fatalf("Exists watcher event wrong type %v instead of %v", ev.Type, EventNotWatching)
				}
				if ev.Err != nil {
					t.Fatalf("Exists watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Exists watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Exists watcher timed out")
			}
			// Verify existsCh is closed.
			select {
			case _, ok := <-existsCh:
				if ok {
					t.Fatal("Exists watcher channel should be closed")
				}
			default:
				t.Fatal("Exists watcher channel should be closed")
			}
		})
	})
}

func TestAddPersistentWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", false)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			// Creating child node should trigger EventNodeChildrenChanged.
			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			// Verify watchCh yields EventNodeChildrenChanged.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeChildrenChanged {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeChildrenChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}

			// Delete of child node should trigger EventNodeChildrenChanged
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			// Verify watchCh yields EventNodeChildrenChanged.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeChildrenChanged {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeChildrenChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestRemovePersistentWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			watchCh, err := c.AddWatch("/", false)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			err = c.RemoveWatch(watchCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

			// Verify watchCh yields EventNotWatching.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNotWatching {
					t.Fatalf("Watcher event wrong type %v instead of EventNotWatching", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}
			// Verify watchCh is closed.
			select {
			case _, ok := <-watchCh:
				if ok {
					t.Fatal("Watcher channel should be closed")
				}
			default:
				t.Fatal("Watcher channel should be closed")
			}
		})
	})
}

func TestAddPersistentRecursiveWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			// Creating child node should trigger EventNodeCreated.
			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			// Verify watchCh yields EventNodeCreated.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeCreated {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeCreated", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}

			// Delete of the child node should trigger EventNodeDeleted.
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			// Verify watchCh yields EventNodeDeleted.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeDeleted {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeDeleted", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestRemovePersistentRecursiveWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			err = c.RemoveWatch(watchCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

			// Verify watchCh yields EventNotWatching.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNotWatching {
					t.Fatalf("Watcher event wrong type %v instead of EventNotWatching", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}
			// Verify watchCh is closed.
			select {
			case _, ok := <-watchCh:
				if ok {
					t.Fatal("Watcher channel should be closed")
				}
			default:
				t.Fatal("Watcher channel should be closed")
			}
		})
	})
}

func TestGetWatchResumedAfterReconnect(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			c.reconnectLatch = make(chan struct{})

			if _, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			}

			_, _, watchCh, err := c.GetW("/gozk-test")
			if err != nil {
				t.Fatalf("GetW returned error: %+v", err)
			}

			// Brutally close the connection.
			_ = c.conn.Close()

			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				// Updating node should trigger EventNodeDataChanged.
				if _, err := c2.Set("/gozk-test", []byte{1, 2, 3, 4}, -1); err != nil {
					t.Fatalf("Set returned error: %+v", err)
				}
			})

			close(c.reconnectLatch)

			// Verify watchCh yields EventNodeDataChanged.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeDataChanged {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeDataChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestExistsWatchResumedAfterReconnect(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			c.reconnectLatch = make(chan struct{})

			ok, _, watchCh, err := c.ExistsW("/gozk-test")
			if ok {
				t.Fatalf("ExistsW returned ok")
			}
			if err != nil {
				t.Fatalf("ExistsW returned error: %+v", err)
			}

			// Brutally close the connection.
			_ = c.conn.Close()

			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				// Creating node should trigger EventNodeCreated.
				if _, err := c2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				}
			})

			close(c.reconnectLatch)

			// Verify watchCh yields EventNodeCreated.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeCreated {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeCreated", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestChildrenWatchResumedAfterReconnect(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			c.reconnectLatch = make(chan struct{})

			_, _, watchCh, err := c.ChildrenW("/")
			if err != nil {
				t.Fatalf("ChildrenW returned error: %+v", err)
			}

			// Brutally close the connection.
			_ = c.conn.Close()

			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				// Creating node should trigger EventNodeChildrenChanged.
				if _, err := c2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				}
			})

			close(c.reconnectLatch)

			// Verify watchCh yields EventNodeChildrenChanged.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeChildrenChanged {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeChildrenChanged", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestPersistentWatchResumedAfterReconnect(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			c.reconnectLatch = make(chan struct{})

			setWatchLatch := make(chan struct{})
			c.setWatchCallback = func(_ []*setWatches2Request) {
				close(setWatchLatch)
			}

			watchCh, err := c.AddWatch("/gozk-test", false)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			// Brutally close the connection.
			_ = c.conn.Close()
			close(c.reconnectLatch)

			// Wait for watches to be restored.
			select {
			case <-setWatchLatch:
			case <-time.After(time.Second * 2):
			}

			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				// Creating child node should trigger EventNodeCreated.
				if path, err := c2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != "/gozk-test" {
					t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
				}
			})

			// Verify watchCh yields EventNodeCreated.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeCreated {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeCreated", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

func TestPersistentRecursiveWatchResumedAfterReconnect(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			c.reconnectLatch = make(chan struct{})

			setWatchLatch := make(chan struct{})
			c.setWatchCallback = func(_ []*setWatches2Request) {
				close(setWatchLatch)
			}

			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			// Brutally close the connection.
			_ = c.conn.Close()
			close(c.reconnectLatch)

			// Wait for watches to be restored.
			select {
			case <-setWatchLatch:
			case <-time.After(time.Second * 2):
			}

			WithConnectAll(t, tc, func(t *testing.T, c2 *Conn, _ <-chan Event) {
				// Creating child node should trigger EventNodeCreated.
				if path, err := c2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != "/gozk-test" {
					t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
				}
			})

			// Verify watchCh yields EventNodeCreated.
			select {
			case ev := <-watchCh:
				if ev.Type != EventNodeCreated {
					t.Fatalf("Watcher event wrong type %v instead of EventNodeCreated", ev.Type)
				}
				if ev.Err != nil {
					t.Fatalf("Watcher event error %+v", ev.Err)
				}
				if ev.Path != "/gozk-test" {
					t.Fatalf("Watcher event wrong path %s instead of %s", ev.Path, "/gozk-test")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}
		})
	})
}

// This test works hard to abuse a watcher into stalling.
// It does this by generating lots of events but never consuming them.
// The client does its best to discard the watch.
func TestPersistentWatchStall(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			stallLatch := make(chan struct{})

			go func() {
				for e := range c.eventChan {
					if e.Type == EventWatcherStalled {
						t.Log("Watcher stalled")
						close(stallLatch)
						break
					}
				}
			}()

			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			// Create lots of paths to generate events, but with no consumer of watch events.
			// This should cause the watcher to stall.
		nodeLoop:
			for i := 0; i < 3000; i++ {
				path, err := c.Create(fmt.Sprintf("/gozk-test-%d", i), []byte{}, 0, WorldACL(PermAll))
				if err != nil {
					t.Fatalf("Create returned: %+v", err)
				}
				err = c.Delete(path, -1)
				if err != nil {
					t.Fatalf("Delete returned: %+v", err)
				}

				select {
				case <-stallLatch:
					break nodeLoop // We can break early if we get the stall event.
				default:
				}
			}

			// Verify we saw the stall event.
			select {
			case <-stallLatch:
			case <-time.After(time.Second * 5):
				t.Fatal("Watcher did not stall")
			}

			// Verify that the watch channel gets closed.
			for {
				select {
				case _, ok := <-watchCh:
					if !ok {
						return // Saw the channel close.
					}
				case <-time.After(time.Second * 5):
					t.Fatal("Expected to see the event channel close")
				}
			}
		})
	})
}

func TestSetWatchers(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		c1, _, err := tc.ConnectAll()
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c1.Close()

		c1.reconnectLatch = make(chan struct{})
		c1.setWatchLimit = 512 // break up set-watch step into 512-byte requests

		// Capture setWatches2Request.
		var setWatchReqs atomic.Value
		c1.setWatchCallback = func(reqs []*setWatches2Request) {
			if prev := setWatchReqs.Load(); prev != nil {
				setWatchReqs.Store(append(prev.([]*setWatches2Request), reqs...))
			} else {
				setWatchReqs.Store(reqs)
			}
		}

		c2, _, err := tc.ConnectAll()
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c2.Close()

		if err := c1.Delete("/gozk-test-x", -1); err != nil && err != ErrNoNode {
			t.Fatalf("Delete returned error: %+v", err)
		}
		testPaths := map[string]<-chan Event{}
		defer func() {
			// clean up all of the test paths we create
			for p := range testPaths {
				_ = c2.Delete(p, -1)
			}
		}()

		expectedTotalWatches := 0

		// Create lots of paths for data expected that we expect to be restored on reconnect.
		// There are too many expected for a single "setWatches2" request, so they will be spread across multiple packets.
		for i := 0; i < 100; i++ {
			testPath, err := c1.Create(fmt.Sprintf("/gozk-test-%d", i), []byte{}, 0, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("Create returned: %+v", err)
			}
			testPaths[testPath] = nil
			_, _, testEvCh, err := c1.GetW(testPath)
			if err != nil {
				t.Fatalf("GetW returned: %+v", err)
			}
			testPaths[testPath] = testEvCh
			expectedTotalWatches++
		}

		// Create a child watch at root, which we expect to be restored on reconnect.
		children, stat, childCh, err := c1.ChildrenW("/")
		if err != nil {
			t.Fatalf("Children returned error: %+v", err)
		} else if stat == nil {
			t.Fatal("Children returned nil stat")
		} else if len(children) < 1 {
			t.Fatal("Children should return at least 1 child")
		}
		expectedTotalWatches++

		// Create an exists watch on `/gozk-test-x`, which we expect to be restored on reconnect.
		found, _, existsCh, err := c1.ExistsW("/gozk-test-x") // Path doesn't exist, yet, but that's ok.
		if err != nil {
			t.Fatalf("ExistsW returned error: %+v", err)
		} else if found {
			t.Fatal("ExistsW returned true")
		}
		expectedTotalWatches++

		// Create a persistent watch on `/gozk-test-x`, which we expect to be restored on reconnect.
		persistentCh, err := c1.AddWatch("/gozk-test-x", false)
		if err != nil {
			t.Fatalf("AddWatch returned error: %+v", err)
		}
		expectedTotalWatches++

		// Create persistent-recursive watch on `/`, which we expect to be restored on reconnect.
		persistentRecCh, err := c1.AddWatch("/", true)
		if err != nil {
			t.Fatalf("AddWatch (recursive) returned error: %+v", err)
		}
		expectedTotalWatches++

		// Simulate network error by brutally closing the network connection.
		_ = c1.conn.Close()

		// On c2 connection, delete all the test paths.
		// This would normally fire events on data and persistent watches, but the connection c1 is gone.
		// We expect these events to arrive after reconnect of c1.
		for p := range testPaths {
			if err := c2.Delete(p, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		}

		// Create new node `/gozk-test-x` to trigger the exists watch and the persistent watch.
		// Again, we expect these events to be queued up and delivered after reconnect of c1.
		if path, err := c2.Create("/gozk-test-x", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
			t.Fatalf("Create returned error: %+v", err)
		} else if path != "/gozk-test-x" {
			t.Fatalf("Create returned different path '%s' != '/gozk-test-x'", path)
		}

		time.Sleep(100 * time.Millisecond) // Give some time for things to happen.

		// c1 should still be waiting to reconnect (blocked by reconnect latch),
		// so none of the expected should have been triggered.
		for p, ch := range testPaths {
			select {
			case _, ok := <-ch:
				if !ok {
					t.Fatalf("GetW watcher for %s was closed", p)
				}
				t.Fatalf("GetW watcher for %q should not have triggered yet", p)
			default:
			}
		}
		select {
		case _, ok := <-childCh:
			if !ok {
				t.Fatalf("ChildrenW watcher was closed")
			}
			t.Fatalf("ChildrenW watcher should not have triggered yet")
		default:
		}
		select {
		case _, ok := <-existsCh:
			if !ok {
				t.Fatalf("ExistsW watcher was closed")
			}
			t.Fatalf("ExistsW watcher should not have triggered yet")
		default:
		}
		select {
		case _, ok := <-persistentCh:
			if !ok {
				t.Fatalf("Persistent watcher was closed")
			}
			t.Fatalf("Persistent watcher should not have triggered yet")
		default:
		}
		select {
		case _, ok := <-persistentRecCh:
			if !ok {
				t.Fatalf("Persistent-recursive watcher was closed")
			}
			t.Fatalf("Persistent-recursive watcher should not have triggered yet")
		default:
		}

		// Now we let the reconnect occur and make sure it restores expected.
		close(c1.reconnectLatch)

		// Verify that we see the EventNodeDeleted events.
		for p, ch := range testPaths {
			select {
			case ev, ok := <-ch:
				if !ok {
					t.Fatalf("GetW watcher for %s was closed", p)
				}
				if ev.Err != nil {
					t.Fatalf("GetW watcher error %+v", ev.Err)
				}
				if ev.Path != p {
					t.Fatalf("GetW watcher wrong path %s instead of %s", ev.Path, p)
				}
				if ev.Type != EventNodeDeleted {
					t.Fatalf("GetW watcher wrong event type %d instead of %d", ev.Type, EventNodeDeleted)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("GetW watcher timed out")
			}
		}

		// Verify that we see the EventNodeChildrenChanged event at "/".
		select {
		case ev, ok := <-childCh:
			if !ok {
				t.Fatalf("ChildrenW watcher was closed")
			}
			if ev.Err != nil {
				t.Fatalf("ChildrenW watcher error %+v", ev.Err)
			}
			if ev.Path != "/" {
				t.Fatalf("ChildrenW watcher wrong path %s instead of %s", ev.Path, "/")
			}
			if ev.Type != EventNodeChildrenChanged {
				t.Fatalf("ChildrenW watcher wrong event type %d instead of %d", ev.Type, EventNodeChildrenChanged)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ChildrenW watcher timed out")
		}

		// Verify that we see the EventNodeCreated event at "/gozk-test-x" from exists watch.
		select {
		case ev, ok := <-existsCh:
			if !ok {
				t.Fatalf("ExistsW watcher was closed")
			}
			if ev.Err != nil {
				t.Fatalf("ExistsW watcher error %+v", ev.Err)
			}
			if ev.Path != "/gozk-test-x" {
				t.Fatalf("ExistsW watcher wrong path %s instead of %s", ev.Path, "/gozk-test-x")
			}
			if ev.Type != EventNodeCreated {
				t.Fatalf("ExistsW watcher wrong event type %d instead of %d", ev.Type, EventNodeCreated)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ExistsW watcher timed out")
		}

		// Verify that we see the EventNodeCreated event at "/gozk-test-x" from persistent watch.
		select {
		case ev, ok := <-persistentCh:
			if !ok {
				t.Fatalf("Persistent watcher was closed")
			}
			if ev.Err != nil {
				t.Fatalf("Persistent watcher error %+v", ev.Err)
			}
			if ev.Path != "/gozk-test-x" {
				t.Fatalf("Persistent watcher wrong path %s instead of %s", ev.Path, "/gozk-test-x")
			}
			if ev.Type != EventNodeCreated {
				t.Fatalf("Persistent watcher wrong event type %d instead of %d", ev.Type, EventNodeCreated)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Persistent watcher timed out")
		}

		// The persistent-recursive watcher should have observed all test-paths deleted and `/gozk-test-x` created.
		var observedPathsDeleted []string
		var observedPathsCreated []string
		for {
			if len(observedPathsDeleted) >= len(testPaths) && len(observedPathsCreated) >= 1 {
				// We saw enough events.
				break
			}

			select {
			case ev, ok := <-persistentRecCh:
				if !ok {
					t.Fatalf("Persistent-recursive watcher was closed")
				}
				if ev.Err != nil {
					t.Fatalf("Persistent-recursive watcher error %+v", ev.Err)
				}
				if ev.Type == EventNodeDeleted {
					observedPathsDeleted = append(observedPathsDeleted, ev.Path)
				} else if ev.Type == EventNodeCreated {
					observedPathsCreated = append(observedPathsCreated, ev.Path)
				} else if ev.Type == EventNodeChildrenChanged {
					// Ignore this event.
				} else {
					t.Fatalf("Persistent-recursive watcher wrong event type %d", ev.Type)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Persistent-recursive watcher timed out")
			}
		}

		if len(observedPathsDeleted) != len(testPaths) {
			t.Fatalf("Persistent-recursive watcher should have observed %d paths deleted, but observed %d", len(testPaths), len(observedPathsDeleted))
		}
		for _, p := range observedPathsDeleted {
			if _, ok := testPaths[p]; !ok {
				t.Fatalf("Persistent-recursive watcher observed unexpected path deleted: %s", p)
			}
		}

		if len(observedPathsCreated) != 1 {
			t.Fatalf("Persistent-recursive watcher should have observed 1 created path, got %d", len(observedPathsCreated))
		}
		if observedPathsCreated[0] != "/gozk-test-x" {
			t.Fatalf("Persistent-recursive watcher should have observed /gozk-test-x created, got %s", observedPathsCreated[0])
		}

		// Yay! All expected fired correctly. Now we also inspect the actual set-watch request objects
		// to ensure they didn't exceed the expected packet set.
		buf := make([]byte, bufferSize)
		actualTotalWatches := 0
		actualReqs := setWatchReqs.Load().([]*setWatches2Request)
		if len(actualReqs) < 4 {
			// sanity check: we should have generated *at least* 4 requests to reset expected
			t.Fatalf("too few setWatches2Request messages: %d", len(actualReqs))
		}
		for _, r := range actualReqs {
			actualTotalWatches += len(r.ChildWatches) + len(r.DataWatches) + len(r.ExistWatches) +
				len(r.PersistentWatches) + len(r.PersistentRecursiveWatches)
			n, err := encodePacket(buf, r)
			if err != nil {
				t.Fatalf("encodePacket failed: %v! request:\n%+v", err, r)
			} else if n > 512 {
				t.Fatalf("setWatches2Request exceeded allowed size (%d > 512)! request:\n%+v", n, r)
			}
		}

		if actualTotalWatches != expectedTotalWatches {
			t.Fatalf("setWatches2Requests did not include all expected expected; expecting %d, got %d",
				expectedTotalWatches, actualTotalWatches)
		}
	})
}

func TestExpiringWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			children, stat, childCh, err := c.ChildrenW("/")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Children returned nil stat")
			} else if len(children) < 1 {
				t.Fatal("Children should return at least 1 child")
			}

			c.sessionID = 99999
			_ = c.conn.Close()

			select {
			case ev := <-childCh:
				if ev.Err != ErrSessionExpired {
					t.Fatalf("Child watcher error %+v instead of expected ErrSessionExpired", ev.Err)
				}
				if ev.Path != "/" {
					t.Fatalf("Child watcher wrong path %s instead of %s", ev.Path, "/")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Child watcher timed out")
			}
		})
	})
}

func TestRequestFail(t *testing.T) {
	// If connecting fails to all servers in the list then pending requests
	// should be errored out so they don't hang forever.
	c, _, err := Connect([]string{"127.0.0.1:32444"}, time.Second*15)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ch := make(chan error)
	go func() {
		_, _, err := c.Get("/blah")
		ch <- err
	}()
	select {
	case err := <-ch:
		if err == nil {
			t.Fatal("Expected non-nil error on failed request due to connection failure")
		}
	case <-time.After(time.Second * 2):
		t.Fatal("Get hung when connection could not be made")
	}
}

func TestIdempotentClose(t *testing.T) {
	c, _, err := Connect([]string{"127.0.0.1:32444"}, time.Second*15)
	if err != nil {
		t.Fatal(err)
	}
	// multiple calls to Close() should not panic
	c.Close()
	c.Close()
}

func TestSlowServer(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		realAddr := fmt.Sprintf("127.0.0.1:%d", tc.Servers[0].Port)
		proxyAddr, stopCh, err := startSlowProxy(t,
			Rate{}, Rate{},
			realAddr, func(ln *Listener) {
				if ln.Up.Latency == 0 {
					ln.Up.Latency = time.Millisecond * 2000
					ln.Down.Latency = time.Millisecond * 2000
				} else {
					ln.Up.Latency = 0
					ln.Down.Latency = 0
				}
			})
		if err != nil {
			t.Fatal(err)
		}
		defer close(stopCh)

		c, _, err := Connect([]string{proxyAddr}, time.Millisecond*500)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		_, _, wch, err := c.ChildrenW("/")
		if err != nil {
			t.Fatal(err)
		}

		// Force a reconnect to get a throttled connection
		_ = c.conn.Close()

		time.Sleep(time.Millisecond * 100)

		if err := c.Delete("/gozk-test", -1); err == nil {
			t.Fatal("Delete should have failed")
		}

		// The previous request should have timed out causing the server to be disconnected and reconnected

		if _, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
			t.Fatal(err)
		}

		// Make sure event is still returned because the session should not have been affected
		select {
		case ev := <-wch:
			t.Logf("Received event: %+v", ev)
		case <-time.After(time.Second):
			t.Fatal("Expected to receive a watch event")
		}
	})
}

func TestMaxBufferSize(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		// no buffer size
		c, _, err := tc.ConnectWithOptions(15 * time.Second)
		var l testLogger
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c.Close()
		// 1k buffer size, logs to custom test logger
		cLimited, _, err := tc.ConnectWithOptions(15*time.Second, WithMaxBufferSize(1024), func(conn *Conn) {
			conn.SetLogger(&l)
		})
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer cLimited.Close()

		// With small node with small number of children
		data := []byte{101, 102, 103, 103}
		_, err = c.Create("/foo", data, 0, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned error: %+v", err)
		}
		var children []string
		for i := 0; i < 4; i++ {
			childName, err := c.Create("/foo/child", nil, FlagEphemeral|FlagSequence, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("Create returned error: %+v", err)
			}
			children = append(children, childName[len("/foo/"):]) // strip parent prefix from name
		}
		sort.Strings(children)

		// Limited client works fine
		resultData, _, err := cLimited.Get("/foo")
		if err != nil {
			t.Fatalf("Get returned error: %+v", err)
		}
		if !reflect.DeepEqual(resultData, data) {
			t.Fatalf("Get returned unexpected data; expecting %+v, got %+v", data, resultData)
		}
		resultChildren, _, err := cLimited.Children("/foo")
		if err != nil {
			t.Fatalf("Children returned error: %+v", err)
		}
		sort.Strings(resultChildren)
		if !reflect.DeepEqual(resultChildren, children) {
			t.Fatalf("Children returned unexpected names; expecting %+v, got %+v", children, resultChildren)
		}

		// With large node though...
		data = make([]byte, 1024)
		for i := 0; i < 1024; i++ {
			data[i] = byte(i)
		}
		_, err = c.Create("/bar", data, 0, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned error: %+v", err)
		}
		_, _, err = cLimited.Get("/bar")
		// NB: Sadly, without actually de-serializing the too-large response packet, we can't send the
		// right error to the corresponding outstanding request. So the request just sees ErrConnectionClosed
		// while the log will see the actual reason the connection was closed.
		expectErr(t, err, ErrConnectionClosed)
		expectLogMessage(t, &l, "received packet from server with length .*, which exceeds max buffer size 1024")

		// Or with large number of children...
		totalLen := 0
		children = nil
		for totalLen < 1024 {
			childName, err := c.Create("/bar/child", nil, FlagEphemeral|FlagSequence, WorldACL(PermAll))
			if err != nil {
				t.Fatalf("Create returned error: %+v", err)
			}
			n := childName[len("/bar/"):] // strip parent prefix from name
			children = append(children, n)
			totalLen += len(n)
		}
		sort.Strings(children)
		_, _, err = cLimited.Children("/bar")
		expectErr(t, err, ErrConnectionClosed)
		expectLogMessage(t, &l, "received packet from server with length .*, which exceeds max buffer size 1024")

		// Other client (without buffer size limit) can successfully query the node and its children, of course
		resultData, _, err = c.Get("/bar")
		if err != nil {
			t.Fatalf("Get returned error: %+v", err)
		}
		if !reflect.DeepEqual(resultData, data) {
			t.Fatalf("Get returned unexpected data; expecting %+v, got %+v", data, resultData)
		}
		resultChildren, _, err = c.Children("/bar")
		if err != nil {
			t.Fatalf("Children returned error: %+v", err)
		}
		sort.Strings(resultChildren)
		if !reflect.DeepEqual(resultChildren, children) {
			t.Fatalf("Children returned unexpected names; expecting %+v, got %+v", children, resultChildren)
		}
	})
}

func TestBatchWalker(t *testing.T) {
	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, _ <-chan Event) {
			startTime := time.Now()
			paths := createTree(t, c, "/gozk-test-batchtreewalker", 3, 20)
			t.Logf("Tree created in %d ms", time.Since(startTime).Milliseconds())

			sort.Strings(paths) // Sort so we can compare the results later.

			runTest := func(t *testing.T, batchSize int) {
				walker := c.BatchWalker("/gozk-test-batchtreewalker", batchSize)

				startTime := time.Now()
				var visited []string
				var numBatches = 0
				err := walker.Walk(func(paths []string) error {
					visited = append(visited, paths...)
					numBatches++
					return nil
				})
				if err != nil {
					t.Fatalf("Walk returned error: %+v", err)
				}
				t.Logf("Tree walked %d nodes over %d batches in %d ms",
					len(paths), numBatches, time.Since(startTime).Milliseconds())

				// Verify that we got all the expected paths.
				sort.Strings(visited) // Order doesn't matter
				if !reflect.DeepEqual(visited, paths) {
					t.Fatalf("Walk returned the wrong patchs, exptected %+v, got %+v", paths, visited)
				}
			}

			t.Run("BatchSize=1", func(t *testing.T) {
				runTest(t, 1)
			})

			t.Run("BatchSize=2", func(t *testing.T) {
				runTest(t, 2)
			})

			t.Run("BatchSize=4", func(t *testing.T) {
				runTest(t, 4)
			})

			t.Run("BatchSize=8", func(t *testing.T) {
				runTest(t, 8)
			})

			t.Run("BatchSize=16", func(t *testing.T) {
				runTest(t, 16)
			})

			t.Run("BatchSize=32", func(t *testing.T) {
				runTest(t, 32)
			})

			t.Run("BatchSize=64", func(t *testing.T) {
				runTest(t, 64)
			})

			t.Run("BatchSize=128", func(t *testing.T) {
				runTest(t, 512)
			})

			t.Run("BatchSize=256", func(t *testing.T) {
				runTest(t, 2048)
			})
		})
	})
}

func createTree(t *testing.T, c *Conn, root string, depth int, breadth int) []string {
	var paths = []string{root}
	paths = append(paths, generateTreePaths(root, depth, breadth)...)

	createBatch := func(t *testing.T, c *Conn, paths []string) {
		var ops = make([]any, len(paths))
		for i, p := range paths {
			ops[i] = &CreateRequest{Path: p, Data: []byte(p), Acl: WorldACL(PermAll)}
		}
		if _, err := c.Multi(ops...); err != nil {
			t.Fatalf("Multi returned error: %+v", err)
		}
	}

	var batch []string

	for _, p := range paths {
		batch = append(batch, p)
		if len(batch) >= 1024 {
			createBatch(t, c, batch)
			batch = nil
		}
	}

	if len(batch) > 0 {
		createBatch(t, c, batch)
	}

	return paths
}

func generateTreePaths(prefix string, depth int, breadth int) []string {
	var paths []string
	for i := 0; i < breadth; i++ {
		paths = append(paths, fmt.Sprintf("%s/%d", prefix, i))
	}
	if depth > 1 {
		for _, p := range paths {
			paths = append(paths, generateTreePaths(p, depth-1, breadth)...)
		}
	}
	return paths
}

type testLogger struct {
	mu     sync.Mutex
	events []string
}

func (l *testLogger) Printf(msgFormat string, args ...any) {
	msg := fmt.Sprintf(msgFormat, args...)
	fmt.Println(msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, msg)
}

func (l *testLogger) Reset() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ret := l.events
	l.events = nil
	return ret
}

func startSlowProxy(t *testing.T, up, down Rate, upstream string, adj func(ln *Listener)) (string, chan bool, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	tln := &Listener{
		Listener: ln,
		Up:       up,
		Down:     down,
	}
	stopCh := make(chan bool)
	go func() {
		<-stopCh
		_ = tln.Close()
	}()

	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		for {
			cn, err := tln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("accept error: %v", err)
					t.Fail()
				}
				return
			}
			if adj != nil {
				adj(tln)
			}
			go func(cn net.Conn) {
				defer func() {
					_ = cn.Close()
				}()
				upcn, err := net.Dial("tcp", upstream)
				if err != nil {
					t.Log(err)
					return
				}
				// This will leave hanging goroutines util stopCh is closed
				// but it doesn't matter in the context of running tests.
				go func() {
					<-stopCh
					_ = upcn.Close()
				}()
				go func() {
					if _, err := io.Copy(upcn, cn); err != nil {
						if !strings.Contains(err.Error(), "use of closed network connection") {
							t.Logf("Upstream write failed: %s", err.Error())
						}
					}
				}()
				if _, err := io.Copy(cn, upcn); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						t.Logf("Upstream read failed: %s", err.Error())
					}
				}
			}(cn)
		}
	}()

	return ln.Addr().String(), stopCh, nil
}

func expectErr(t *testing.T, err error, expected error) {
	if err == nil {
		t.Fatalf("Get for node that is too large should have returned error!")
	}
	if err != expected {
		t.Fatalf("Get returned wrong error; expecting ErrClosing, got %+v", err)
	}
}

func expectLogMessage(t *testing.T, logger *testLogger, pattern string) {
	re := regexp.MustCompile(pattern)
	events := logger.Reset()
	if len(events) == 0 {
		t.Fatalf("Failed to log error; expecting message that matches pattern: %s", pattern)
	}
	var found []string
	for _, e := range events {
		if re.Match([]byte(e)) {
			found = append(found, e)
		}
	}
	if len(found) == 0 {
		t.Fatalf("Failed to log error; expecting message that matches pattern: %s", pattern)
	} else if len(found) > 1 {
		t.Fatalf("Logged error redundantly %d times:\n%+v", len(found), found)
	}
}

func zkVersionFromEnv() Version {
	vs, ok := os.LookupEnv("ZK_VERSION")
	if !ok {
		return Version{-1, -1, -1}
	}
	return ParseVersion(vs)
}
