package zk

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		callbackChan := make(chan Event)
		f := func(event Event) {
			callbackChan <- event
		}

		zk, eventChan, err := ts.ConnectWithOptions(15*time.Second, WithEventCallback(f))
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

func TestIncrementalReconfig(t *testing.T) {
	if val, ok := os.LookupEnv("zk_version"); ok {
		if !strings.HasPrefix(val, "3.5") {
			t.Skip("running with zookeeper that does not support this api")
		}
	} else {
		t.Skip("did not detect zk_version from env. skipping reconfig test")
	}

	t.Parallel()

	WithTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		// start and add a new server.
		tmpPath, err := ioutil.TempDir("", "gozk")
		requireNoError(t, err, "failed to create tmp dir for test server setup")
		defer os.RemoveAll(tmpPath)

		startPort := int(rand.Int31n(6000) + 10000)

		srvPath := filepath.Join(tmpPath, fmt.Sprintf("srv4"))
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
		fi.Close()

		fi, err = os.Create(filepath.Join(srvPath, _testMyIDFileName))
		requireNoError(t, err)

		_, err = fmt.Fprintln(fi, "4")
		fi.Close()
		requireNoError(t, err)

		testServer, err := NewIntegrationTestServer(t, cfgPath, nil, nil)
		requireNoError(t, err)
		requireNoError(t, testServer.Start())
		defer testServer.Stop()

		WithConnectAll(t, ts, func(t *testing.T, c *Conn, ech <-chan Event) {
			err = c.AddAuth("digest", []byte("super:test"))
			requireNoError(t, err, "failed to auth to cluster")

			waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = waitForSession(waitCtx, ech)
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
	if val, ok := os.LookupEnv("zk_version"); ok {
		if !strings.HasPrefix(val, "3.5") {
			t.Skip("running with zookeeper that does not support this api")
		}
	} else {
		t.Skip("did not detect zk_version from env. skipping reconfig test")
	}

	t.Parallel()

	WithTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, ech <-chan Event) {
			err := c.AddAuth("digest", []byte("super:test"))
			requireNoError(t, err, "failed to auth to cluster")

			waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			err = waitForSession(waitCtx, ech)
			requireNoError(t, err, "failed to wail for session")

			_, _, err = c.Get("/zookeeper/config")
			if err != nil {
				t.Fatalf("get config returned error: %+v", err)
			}

			// essentially remove the first node
			var s []string
			for _, host := range ts.Config.Servers[1:] {
				s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, ts.Config.ClientPort))
			}

			_, err = c.Reconfig(s, -1)
			requireNoError(t, err, "failed to reconfig cluster")

			// reconfig to all the hosts again
			s = []string{}
			for _, host := range ts.Config.Servers {
				s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, ts.Config.ClientPort))
			}

			_, err = c.Reconfig(s, -1)
			requireNoError(t, err, "failed to reconfig cluster")
		})
	})
}

func TestOpsAfterCloseDontDeadlock(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			c.Close() // Close before creating.

			path := "/gozk-test"

			ch := make(chan struct{})
			go func() {
				defer close(ch)
				for range make([]struct{}, 30) {
					if _, err := c.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err == nil {
						t.Fatal("Create did not return error")
					}
				}
			}()
			select {
			case <-ch:
				// expected
			case <-time.After(10 * time.Second):
				t.Fatal("ZK connection deadlocked when executing ops after a Close operation")
			}
		})
	})
}

func TestMulti(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			path := "/gozk-test"

			if err := c.Delete(path, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			ops := []interface{}{
				&CreateRequest{Path: path, Data: []byte{1, 2, 3, 4}, Acl: WorldACL(PermAll)},
				&SetDataRequest{Path: path, Data: []byte{1, 2, 3, 4}, Version: -1},
			}
			if res, err := c.Multi(ops...); err != nil {
				t.Fatalf("Multi returned error: %+v", err)
			} else if len(res) != 2 {
				t.Fatalf("Expected 2 responses got %d", len(res))
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
		})
	})
}

func TestIfAuthdataSurvivesReconnect(t *testing.T) {
	t.Parallel()

	// This test case ensures authentication data is being resubmited after
	// reconnect.
	testNode := "/auth-testnode"

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

			c.AddAuth("digest", []byte("userfoo:passbar"))

			_, _, err = c.Get(testNode)
			if err != nil {
				t.Fatalf("Fetching data with auth failed: %+v", err)
			}

			ts.StopAllServers()
			ts.StartAllServers()

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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			// Ensure firstPath doesn't exist and secondPath does. This will cause the
			// 2nd operation in the Multi() to fail.
			if err := c.Delete(firstPath, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
			if _, err := c.Create(secondPath, nil /* data */, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			}

			ops := []interface{}{
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

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

			// Delete of the watched node should trigger the watch

			children, stat, childCh, err = c.ChildrenW("/gozk-test")
			if err != nil {
				t.Fatalf("Children returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Children returned nil stat")
			} else if len(children) != 0 {
				t.Fatal("Children should return 0 children")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

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
		})
	})
}

func TestRemoveChildWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

			err = c.RemoveWatch(childCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			select {
			case _, ok := <-childCh:
				if ok {
					t.Fatalf("Child watcher should have been closed")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Child watcher timed out")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		})
	})
}

func TestExistsWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

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

			// Delete of the watched node should trigger the watch

			exists, stat, existsCh, err = c.ExistsW("/gozk-test")
			if err != nil {
				t.Fatalf("Exists returned error: %+v", err)
			} else if stat == nil {
				t.Fatal("Exists returned nil stat")
			} else if !exists {
				t.Fatal("Exists should return true")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

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
		})
	})
}

func TestRemoveExistsWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			select {
			case _, ok := <-existsCh:
				if ok {
					t.Fatalf("Exists watcher should have been closed")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Exists watcher timed out")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		})
	})
}

func TestAddPersistentWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", false)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

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

			// Delete of the watched node should trigger the watch

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", false)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			err = c.RemoveWatch(watchCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			select {
			case _, ok := <-watchCh:
				if ok {
					t.Fatalf("Watcher should have been closed")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		})
	})
}

func TestAddPersistentRecursiveWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

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

			// Delete of the watched node should trigger the watch

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}

			watchCh, err := c.AddWatch("/", true)
			if err != nil {
				t.Fatalf("AddWatch returned error: %+v", err)
			}

			err = c.RemoveWatch(watchCh)
			if err != nil {
				t.Fatalf("RemoveWatch returned error: %+v", err)
			}

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

			if path, err := c.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
				t.Fatalf("Create returned error: %+v", err)
			} else if path != "/gozk-test" {
				t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
			}

			select {
			case _, ok := <-watchCh:
				if ok {
					t.Fatalf("Watcher should have been closed")
				}
			case <-time.After(time.Second * 2):
				t.Fatal("Watcher timed out")
			}

			if err := c.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		})
	})
}

func TestSetWatchers(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		c1, _, err := ts.ConnectAll()
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c1.Close()

		c1.reconnectLatch = make(chan struct{})
		c1.setWatchLimit = 512 // break up set-watch step into 512-byte requests
		var setWatchReqs atomic.Value
		c1.setWatchCallback = func(reqs []*setWatches2Request) {
			setWatchReqs.Store(reqs)
		}

		c2, _, err := ts.ConnectAll()
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c2.Close()

		if err := c1.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
			t.Fatalf("Delete returned error: %+v", err)
		}

		testPaths := map[string]<-chan Event{}
		defer func() {
			// clean up all of the test paths we create
			for p := range testPaths {
				_ = c2.Delete(p, -1)
			}
		}()

		// we create lots of paths to watch, to make sure a "set watches" request
		// on re-create will be too big and be required to span multiple packets
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
		}

		children, stat, childCh, err := c1.ChildrenW("/")
		if err != nil {
			t.Fatalf("Children returned error: %+v", err)
		} else if stat == nil {
			t.Fatal("Children returned nil stat")
		} else if len(children) < 1 {
			t.Fatal("Children should return at least 1 child")
		}

		// Simulate network error by brutally closing the network connection.
		c1.conn.Close()
		for p := range testPaths {
			if err := c2.Delete(p, -1); err != nil && err != ErrNoNode {
				t.Fatalf("Delete returned error: %+v", err)
			}
		}
		if path, err := c2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
			t.Fatalf("Create returned error: %+v", err)
		} else if path != "/gozk-test" {
			t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
		}

		time.Sleep(100 * time.Millisecond)

		// c1 should still be waiting to reconnect, so none of the watches should have been triggered
		for p, ch := range testPaths {
			select {
			case <-ch:
				t.Fatalf("GetW watcher for %q should not have triggered yet", p)
			default:
			}
		}
		select {
		case <-childCh:
			t.Fatalf("ChildrenW watcher should not have triggered yet")
		default:
		}

		// now we let the reconnect occur and make sure it resets watches
		close(c1.reconnectLatch)

		for p, ch := range testPaths {
			select {
			case ev := <-ch:
				if ev.Err != nil {
					t.Fatalf("GetW watcher error %+v", ev.Err)
				}
				if ev.Path != p {
					t.Fatalf("GetW watcher wrong path %s instead of %s", ev.Path, p)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("GetW watcher timed out")
			}
		}

		select {
		case ev := <-childCh:
			if ev.Err != nil {
				t.Fatalf("Child watcher error %+v", ev.Err)
			}
			if ev.Path != "/" {
				t.Fatalf("Child watcher wrong path %s instead of %s", ev.Path, "/")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Child watcher timed out")
		}

		// Yay! All watches fired correctly. Now we also inspect the actual set-watch request objects
		// to ensure they didn't exceed the expected packet set.
		buf := make([]byte, bufferSize)
		totalWatches := 0
		actualReqs := setWatchReqs.Load().([]*setWatches2Request)
		if len(actualReqs) < 4 {
			// sanity check: we should have generated *at least* 4 requests to reset watches
			t.Fatalf("too few setWatches2Request messages: %d", len(actualReqs))
		}
		for _, r := range actualReqs {
			totalWatches += len(r.ChildWatches) + len(r.DataWatches) + len(r.ExistWatches)
			n, err := encodePacket(buf, r)
			if err != nil {
				t.Fatalf("encodePacket failed: %v! request:\n%+v", err, r)
			} else if n > 512 {
				t.Fatalf("setWatches2Request exceeded allowed size (%d > 512)! request:\n%+v", n, r)
			}
		}

		if totalWatches != len(testPaths)+1 {
			t.Fatalf("setWatches2Requests did not include all expected watches; expecting %d, got %d", len(testPaths)+1, totalWatches)
		}
	})
}

func TestExpiringWatch(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
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
			c.conn.Close()

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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		realAddr := fmt.Sprintf("127.0.0.1:%d", ts.Servers[0].Port)
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
		c.conn.Close()

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

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		// no buffer size
		c, _, err := ts.ConnectWithOptions(15 * time.Second)
		var l testLogger
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer c.Close()
		// 1k buffer size, logs to custom test logger
		cLimited, _, err := ts.ConnectWithOptions(15*time.Second, WithMaxBufferSize(1024), func(conn *Conn) {
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

func TestWalkDepthFirst(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-walkdepthfirst",
				"/gozk-test-walkdepthfirst/a",
				"/gozk-test-walkdepthfirst/a/b",
				"/gozk-test-walkdepthfirst/a/c",
				"/gozk-test-walkdepthfirst/a/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			t.Run("IncludeRoot", func(t *testing.T) {
				var visited []string

				err := c.WalkDepthFirst("/gozk-test-walkdepthfirst/a", true, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkDepthFirst returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkdepthfirst/a/b",
					"/gozk-test-walkdepthfirst/a/c/d",
					"/gozk-test-walkdepthfirst/a/c",
					"/gozk-test-walkdepthfirst/a",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkDepthFirst returned the wrong paths, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("ExcludeSelf", func(t *testing.T) {
				var visited []string

				err := c.WalkDepthFirst("/gozk-test-walkdepthfirst/a", false, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkDepthFirst returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkdepthfirst/a/b",
					"/gozk-test-walkdepthfirst/a/c/d",
					"/gozk-test-walkdepthfirst/a/c",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkDepthFirst returned the wrong paths, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("Not Found", func(t *testing.T) {
				var visited []string

				err := c.WalkDepthFirst("/gozk-test-walkdepthfirst/e", false, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkDepthFirst returned error: %+v", err)
				}

				if len(visited) != 0 {
					t.Fatalf("WalkDepthFirst returned the wrong paths, exptected [], got %+v", visited)
				}
			})
		})
	})
}

func TestWalkBreadthFirst(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-walkbreadthfirst",
				"/gozk-test-walkbreadthfirst/a",
				"/gozk-test-walkbreadthfirst/a/b",
				"/gozk-test-walkbreadthfirst/a/c",
				"/gozk-test-walkbreadthfirst/a/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			t.Run("IncludeRoot", func(t *testing.T) {
				var visited []string

				err := c.WalkBreadthFirst("/gozk-test-walkbreadthfirst/a", true, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkBreadthFirst returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkbreadthfirst/a",
					"/gozk-test-walkbreadthfirst/a/b",
					"/gozk-test-walkbreadthfirst/a/c",
					"/gozk-test-walkbreadthfirst/a/c/d",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkBreadthFirst returned the wrong paths, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("ExcludeSelf", func(t *testing.T) {
				var visited []string

				err := c.WalkBreadthFirst("/gozk-test-walkbreadthfirst/a", false, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkBreadthFirst returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkbreadthfirst/a/b",
					"/gozk-test-walkbreadthfirst/a/c",
					"/gozk-test-walkbreadthfirst/a/c/d",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkBreadthFirst returned the wrong paths, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("Not Found", func(t *testing.T) {
				var visited []string

				err := c.WalkBreadthFirst("/gozk-test-walkbreadthfirst/e", false, func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkBreadthFirst returned error: %+v", err)
				}

				if len(visited) != 0 {
					t.Fatalf("WalkBreadthFirst returned the wrong paths, exptected [], got %+v", visited)
				}
			})
		})
	})
}

func TestWalkLeaves(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-walkleaves",
				"/gozk-test-walkleaves/a",
				"/gozk-test-walkleaves/a/b",
				"/gozk-test-walkleaves/a/c",
				"/gozk-test-walkleaves/a/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			t.Run("Found", func(t *testing.T) {
				var visited []string

				err := c.WalkLeaves("/gozk-test-walkleaves/a", func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkLeaves returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkleaves/a/b",
					"/gozk-test-walkleaves/a/c/d",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkLeaves returned the wrong leaves, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("Not Found", func(t *testing.T) {
				var visited []string

				err := c.WalkLeaves("/gozk-test-walkleaves/e", func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkLeaves returned error: %+v", err)
				}

				if len(visited) != 0 {
					t.Fatalf("WalkLeaves returned the wrong leaves, exptected [], got %+v", visited)
				}
			})
		})
	})
}

func TestWalkLeavesParallel(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-walkleavesparallel",
				"/gozk-test-walkleavesparallel/a",
				"/gozk-test-walkleavesparallel/a/b",
				"/gozk-test-walkleavesparallel/a/c",
				"/gozk-test-walkleavesparallel/a/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			t.Run("Found", func(t *testing.T) {
				var visited []string

				err := c.WalkLeaves("/gozk-test-walkleavesparallel/a", func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkLeaves returned error: %+v", err)
				}

				expected := []string{
					"/gozk-test-walkleavesparallel/a/b",
					"/gozk-test-walkleavesparallel/a/c/d",
				}
				if !reflect.DeepEqual(visited, expected) {
					t.Fatalf("WalkLeaves returned the wrong leaves, exptected %+v, got %+v", expected, visited)
				}
			})

			t.Run("Not Found", func(t *testing.T) {
				var visited []string

				err := c.WalkLeaves("/gozk-test-walkleavesparallel/e", func(p string, stat *Stat) error {
					visited = append(visited, p)
					return nil
				})
				if err != nil {
					t.Fatalf("WalkLeaves returned error: %+v", err)
				}

				if len(visited) != 0 {
					t.Fatalf("WalkLeaves returned the wrong leaves, exptected [], got %+v", visited)
				}
			})
		})
	})
}

func TestCachedLeavesWalker(t *testing.T) {
	t.Parallel()

	WithTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "}, func(t *testing.T, ts *TestCluster) {
		WithConnectAll(t, ts, func(t *testing.T, c *Conn, _ <-chan Event) {
			paths := []string{
				"/gozk-test-cachedleaveswalker",
				"/gozk-test-cachedleaveswalker/a",
				"/gozk-test-cachedleaveswalker/a/b",
				"/gozk-test-cachedleaveswalker/a/c",
				"/gozk-test-cachedleaveswalker/a/c/d",
				"/gozk-test-ignoreme",
				"/gozk-test-ignoreme/a",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			walker, err := NewCachedLeavesWalker(c, "/gozk-test-cachedleaveswalker")
			if err != nil {
				t.Fatalf("AddCachedLeavesWalker returned error: %+v", err)
			}

			var visited []string
			err = walker.WalkLeaves(func(p string) error {
				visited = append(visited, p)
				return nil
			})
			if err != nil {
				t.Fatalf("WalkLeaves returned error: %+v", err)
			}
			expected := []string{
				"/gozk-test-cachedleaveswalker/a/b",
				"/gozk-test-cachedleaveswalker/a/c/d",
			}
			sort.Strings(expected)
			sort.Strings(visited) // Order doesn't matter
			if !reflect.DeepEqual(visited, expected) {
				t.Fatalf("WalkLeaves returned the wrong leaves, exptected %+v, got %+v", expected, visited)
			}

			paths = []string{
				"/gozk-test-cachedleaveswalker/b",
				"/gozk-test-cachedleaveswalker/b/b",
				"/gozk-test-cachedleaveswalker/b/c",
				"/gozk-test-cachedleaveswalker/b/c/d",
			}
			for _, p := range paths {
				if path, err := c.Create(p, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
					t.Fatalf("Create returned error: %+v", err)
				} else if path != p {
					t.Fatalf("Create returned different path '%s' != '%s'", path, p)
				}
			}

			if err := c.Delete("/gozk-test-cachedleaveswalker/a/b", -1); err != nil {
				t.Fatalf("Delete returned error: %+v", err)
			}

			time.Sleep(time.Millisecond * 100)

			visited = []string{}
			err = walker.WalkLeaves(func(p string) error {
				visited = append(visited, p)
				return nil
			})
			if err != nil {
				t.Fatalf("WalkLeaves returned error: %+v", err)
			}
			expected = []string{
				"/gozk-test-cachedleaveswalker/a/c/d",
				"/gozk-test-cachedleaveswalker/b/b",
				"/gozk-test-cachedleaveswalker/b/c/d",
			}
			sort.Strings(expected)
			sort.Strings(visited) // Order doesn't matter
			if !reflect.DeepEqual(visited, expected) {
				t.Fatalf("WalkLeaves returned the wrong leaves, exptected %+v, got %+v", expected, visited)
			}
		})
	})
}

type testLogger struct {
	mu     sync.Mutex
	events []string
}

func (l *testLogger) Printf(msgFormat string, args ...interface{}) {
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
		tln.Close()
	}()
	go func() {
		for {
			cn, err := tln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					t.Fatalf("Accept failed: %s", err.Error())
				}
				return
			}
			if adj != nil {
				adj(tln)
			}
			go func(cn net.Conn) {
				defer cn.Close()
				upcn, err := net.Dial("tcp", upstream)
				if err != nil {
					t.Log(err)
					return
				}
				// This will leave hanging goroutines util stopCh is closed
				// but it doesn't matter in the context of running tests.
				go func() {
					<-stopCh
					upcn.Close()
				}()
				go func() {
					if _, err := io.Copy(upcn, cn); err != nil {
						if !strings.Contains(err.Error(), "use of closed network connection") {
							// log.Printf("Upstream write failed: %s", err.Error())
						}
					}
				}()
				if _, err := io.Copy(cn, upcn); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						// log.Printf("Upstream read failed: %s", err.Error())
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
