package zk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegration_StateChanges(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()

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
}

func TestIntegration_Create(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if p, err := zk.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if p != path {
		t.Fatalf("Create returned different path '%s' != '%s'", p, path)
	}
	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}
}

func TestIntegration_CreateTTL(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if _, err := zk.CreateTTL("", []byte{1, 2, 3, 4}, FlagTTL|FlagEphemeral, WorldACL(PermAll), 60*time.Second); err != ErrInvalidPath {
		t.Fatalf("Create path check failed")
	}
	if _, err := zk.CreateTTL(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll), 60*time.Second); err != ErrInvalidFlags {
		t.Fatalf("Create flags check failed")
	}
	if p, err := zk.CreateTTL(path, []byte{1, 2, 3, 4}, FlagTTL|FlagEphemeral, WorldACL(PermAll), 60*time.Second); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if p != path {
		t.Fatalf("Create returned different path '%s' != '%s'", p, path)
	}
	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if p, err := zk.CreateTTL(path, []byte{1, 2, 3, 4}, FlagTTL|FlagSequence, WorldACL(PermAll), 60*time.Second); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if !strings.HasPrefix(p, path) {
		t.Fatalf("Create returned invalid path '%s' are not '%s' with sequence", p, path)
	} else if data, stat, err := zk.Get(p); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}
}

func TestIntegration_CreateContainer(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if _, err := zk.CreateContainer("", []byte{1, 2, 3, 4}, FlagTTL, WorldACL(PermAll)); err != ErrInvalidPath {
		t.Fatalf("Create path check failed")
	}
	if _, err := zk.CreateContainer(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != ErrInvalidFlags {
		t.Fatalf("Create flags check failed")
	}
	if p, err := zk.CreateContainer(path, []byte{1, 2, 3, 4}, FlagTTL, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if p != path {
		t.Fatalf("Create returned different path '%s' != '%s'", p, path)
	}
	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}
}

func TestIntegration_IncrementalReconfig(t *testing.T) {
	RequireMinimumZkVersion(t, "3.5")

	ts, err := StartTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "})
	requireNoErrorf(t, err, "failed to setup test cluster")
	defer ts.Stop()

	// start and add a new server.
	tmpPath, err := ioutil.TempDir("", "gozk")
	requireNoErrorf(t, err, "failed to create tmp dir for test server setup")
	defer os.RemoveAll(tmpPath)

	startPort := int(rand.Int31n(6000) + 10000)

	srvPath := filepath.Join(tmpPath, fmt.Sprintf("srv4"))
	if err := os.Mkdir(srvPath, 0700); err != nil {
		requireNoErrorf(t, err, "failed to make server path")
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
	requireNoErrorf(t, err)

	requireNoErrorf(t, cfg.Marshall(fi))
	fi.Close()

	fi, err = os.Create(filepath.Join(srvPath, _testMyIDFileName))
	requireNoErrorf(t, err)

	_, err = fmt.Fprintln(fi, "4")
	fi.Close()
	requireNoErrorf(t, err)

	testServer, err := NewIntegrationTestServer(t, cfgPath, nil, nil)
	requireNoErrorf(t, err)
	requireNoErrorf(t, testServer.Start())
	defer testServer.Stop()

	zk, events, err := ts.ConnectAll()
	requireNoErrorf(t, err, "failed to connect to cluster")
	defer zk.Close()

	err = zk.AddAuth("digest", []byte("super:test"))
	requireNoErrorf(t, err, "failed to auth to cluster")

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = waitForSession(waitCtx, events)
	requireNoErrorf(t, err, "failed to wail for session")

	_, _, err = zk.Get("/zookeeper/config")
	if err != nil {
		t.Fatalf("get config returned error: %+v", err)
	}

	// initially should be 1<<32, which is 0x100000000. This is the zxid
	// of the first NEWLEADER message, used as the inital version
	// reflect.DeepEqual(bytes.Split(data, []byte("\n")), []byte("version=100000000"))

	// remove node 3.
	_, err = zk.IncrementalReconfig(nil, []string{"3"}, -1)
	if err != nil && errors.Is(err, ErrConnectionClosed) {
		t.Log("conneciton closed is fine since the cluster re-elects and we dont reconnect")
	} else {
		requireNoErrorf(t, err, "failed to remove node from cluster")
	}

	// add node a new 4th node
	server := fmt.Sprintf("server.%d=%s:%d:%d;%d", testSrvConfig.ID, testSrvConfig.Host, testSrvConfig.PeerPort, testSrvConfig.LeaderElectionPort, cfg.ClientPort)
	_, err = zk.IncrementalReconfig([]string{server}, nil, -1)
	if err != nil && errors.Is(err, ErrConnectionClosed) {
		t.Log("conneciton closed is fine since the cluster re-elects and we dont reconnect")
	} else {
		requireNoErrorf(t, err, "failed to add new server to cluster")
	}
}

func TestIntegration_Reconfig(t *testing.T) {
	RequireMinimumZkVersion(t, "3.5")

	// This test enures we can do an non-incremental reconfig
	ts, err := StartTestCluster(t, 3, nil, logWriter{t: t, p: "[ZKERR] "})
	requireNoErrorf(t, err, "failed to setup test cluster")
	defer ts.Stop()

	zk, events, err := ts.ConnectAll()
	requireNoErrorf(t, err, "failed to connect to cluster")
	defer zk.Close()

	err = zk.AddAuth("digest", []byte("super:test"))
	requireNoErrorf(t, err, "failed to auth to cluster")

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = waitForSession(waitCtx, events)
	requireNoErrorf(t, err, "failed to wail for session")

	_, _, err = zk.Get("/zookeeper/config")
	if err != nil {
		t.Fatalf("get config returned error: %+v", err)
	}

	// essentially remove the first node
	var s []string
	for _, host := range ts.Config.Servers[1:] {
		s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, ts.Config.ClientPort))
	}

	_, err = zk.Reconfig(s, -1)
	requireNoErrorf(t, err, "failed to reconfig cluster")

	// reconfig to all the hosts again
	s = []string{}
	for _, host := range ts.Config.Servers {
		s = append(s, fmt.Sprintf("server.%d=%s:%d:%d;%d\n", host.ID, host.Host, host.PeerPort, host.LeaderElectionPort, ts.Config.ClientPort))
	}

	_, err = zk.Reconfig(s, -1)
	requireNoErrorf(t, err, "failed to reconfig cluster")
}

func TestIntegration_OpsAfterCloseDontDeadlock(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	zk.Close()

	path := "/gozk-test"

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for range make([]struct{}, 30) {
			if _, err := zk.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err == nil {
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
}

func TestIntegration_Multi(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	ops := []interface{}{
		&CreateRequest{Path: path, Data: []byte{1, 2, 3, 4}, Acl: WorldACL(PermAll)},
		&SetDataRequest{Path: path, Data: []byte{1, 2, 3, 4}, Version: -1},
	}
	if res, err := zk.Multi(ops...); err != nil {
		t.Fatalf("Multi returned error: %+v", err)
	} else if len(res) != 2 {
		t.Fatalf("Expected 2 responses got %d", len(res))
	} else {
		t.Logf("%+v", res)
	}
	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Get returned nil stat")
	} else if len(data) < 4 {
		t.Fatal("Get returned wrong size data")
	}
}

func TestIntegration_MultiRead(t *testing.T) {
	RequireMinimumZkVersion(t, "3.6")

	WithTestCluster(t, 10*time.Second, func(ts *TestCluster, zk *Conn) {
		nodeChildren := map[string][]string{}
		nodeData := map[string][]byte{}
		var ops []ReadOp

		create := func(path string, data []byte) {
			if _, err := zk.Create(path, data, 0, nil); err != nil {
				requireNoErrorf(t, err, "create returned an error")
			} else {
				dir, name := SplitPath(path)
				nodeChildren[dir] = append(nodeChildren[dir], name)
				nodeData[path] = data
				ops = append(ops, GetDataOp(path), GetChildrenOp(path))
			}
		}

		root := "/gozk-test"
		create(root, nil)

		for i := byte(0); i < 10; i++ {
			child := JoinPath(root, fmt.Sprint(i))
			create(child, []byte{i})
		}

		const foo = "foo"
		create(JoinPath(JoinPath(root, "0"), foo), []byte(foo))

		opResults, err := zk.MultiRead(ops...)
		if err != nil {
			t.Fatalf("MultiRead returned error: %+v", err)
		} else if len(opResults) != len(ops) {
			t.Fatalf("Expected %d responses got %d", len(ops), len(opResults))
		}

		nodeStats := map[string]*Stat{}
		for k := range nodeData {
			_, nodeStats[k], err = zk.Exists(k)
			requireNoErrorf(t, err, "exists returned an error")
		}

		for i, res := range opResults {
			opPath := ops[i].GetPath()
			switch op := ops[i].(type) {
			case GetDataOp:
				if res.Err != nil {
					t.Fatalf("GetDataOp(%q) returned an error: %+v", op, res.Err)
				}
				if !bytes.Equal(res.Data, nodeData[opPath]) {
					t.Fatalf("GetDataOp(%q).Data did not return %+v, got %+v", op, nodeData[opPath], res.Data)
				}
				if !reflect.DeepEqual(res.Stat, nodeStats[opPath]) {
					t.Fatalf("GetDataOp(%q).Stat did not return %+v, got %+v", op, nodeStats[opPath], res.Stat)
				}
			case GetChildrenOp:
				if res.Err != nil {
					t.Fatalf("GetChildrenOp(%q) returned an error: %+v", opPath, res.Err)
				}
				// Cannot use DeepEqual here because it fails for []string{} == nil, even though in practice they are
				// the same.
				actual, expected := res.Children, nodeChildren[opPath]
				if len(actual) != len(expected) {
					t.Fatalf("GetChildrenOp(%q) did not return %+v, got %+v", opPath, expected, actual)
				}
				sort.Strings(actual)
				sort.Strings(expected)
				for i, c := range expected {
					if actual[i] != c {
						t.Fatalf("GetChildrenOp(%q) did not return %+v, got %+v", opPath, expected, actual)
					}
				}
			}
		}

		opResults, err = zk.MultiRead(GetDataOp("/invalid"), GetDataOp(root))
		requireNoErrorf(t, err, "MultiRead returned error")

		if opResults[0].Err != ErrNoNode {
			t.Fatalf("MultiRead on invalid node did not return error")
		}
		if opResults[1].Err != nil {
			t.Fatalf("MultiRead on valid node did not return error")
		}
		if !reflect.DeepEqual(opResults[1].Data, nodeData[root]) {
			t.Fatalf("MultiRead on valid node did not return correct data")
		}
	})
}

func TestIntegration_GetDataAndChildren(t *testing.T) {
	RequireMinimumZkVersion(t, "3.6")

	WithTestCluster(t, 10*time.Second, func(ts *TestCluster, zk *Conn) {

		const path = "/test"
		_, _, _, err := zk.GetDataAndChildren(path)
		if err != ErrNoNode {
			t.Fatalf("GetDataAndChildren(%q) did not return an error", path)
		}

		create := func(path string, data []byte) {
			if _, err := zk.Create(path, data, 0, nil); err != nil {
				requireNoErrorf(t, err, "create returned an error")
			}
		}
		expectedData := []byte{1, 2, 3, 4}
		create(path, expectedData)
		var expectedChildren []string
		for i := 0; i < 10; i++ {
			child := fmt.Sprint(i)
			create(JoinPath(path, child), nil)
			expectedChildren = append(expectedChildren, child)
		}

		data, _, children, err := zk.GetDataAndChildren(path)
		requireNoErrorf(t, err, "GetDataAndChildren return an error")

		if !bytes.Equal(data, expectedData) {
			t.Fatalf("GetDataAndChildren(%q) did not return expected data (expected %v): %v", path, expectedData, data)
		}
		sort.Strings(children)
		if !reflect.DeepEqual(children, expectedChildren) {
			t.Fatalf("GetDataAndChildren(%q) did not return expected children (expected %v): %v",
				path, expectedChildren, children)
		}
	})
}

func TestIntegration_IfAuthdataSurvivesReconnect(t *testing.T) {
	// This test case ensures authentication data is being resubmited after
	// reconnect.
	testNode := "/auth-testnode"

	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()

	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	acl := DigestACL(PermAll, "userfoo", "passbar")

	_, err = zk.Create(testNode, []byte("Some very secret content"), 0, acl)
	if err != nil && err != ErrNodeExists {
		t.Fatalf("Failed to create test node : %+v", err)
	}

	_, _, err = zk.Get(testNode)
	if err == nil || err != ErrNoAuth {
		var msg string

		if err == nil {
			msg = "Fetching data without auth should have resulted in an error"
		} else {
			msg = fmt.Sprintf("Expecting ErrNoAuth, got `%+v` instead", err)
		}
		t.Fatalf(msg)
	}

	zk.AddAuth("digest", []byte("userfoo:passbar"))

	_, _, err = zk.Get(testNode)
	if err != nil {
		t.Fatalf("Fetching data with auth failed: %+v", err)
	}

	ts.StopAllServers()
	ts.StartAllServers()

	_, _, err = zk.Get(testNode)
	if err != nil {
		t.Fatalf("Fetching data after reconnect failed: %+v", err)
	}
}

func TestIntegration_PersistentWatchOnReconnect(t *testing.T) {
	RequireMinimumZkVersion(t, "3.6")

	WithTestCluster(t, 10*time.Second, func(ts *TestCluster, zk *Conn) {
		zk.reconnectLatch = make(chan struct{})

		zk2, _, err := ts.ConnectAll()
		if err != nil {
			t.Fatalf("Connect returned error: %+v", err)
		}
		defer zk2.Close()

		const testNode = "/gozk-test"

		if err := zk.Delete(testNode, -1); err != nil && err != ErrNoNode {
			t.Fatalf("Delete returned error: %+v", err)
		}

		watchEventsQueue, err := zk.AddPersistentWatch(testNode, AddWatchModePersistent)
		if err != nil {
			t.Fatalf("AddPersistentWatch returned error: %+v", err)
		}

		// wait for the initial EventWatching
		waitForEvent(t, time.Second, watchEventsQueue, EventWatching)

		_, err = zk2.Create(testNode, []byte{1}, 0, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned an error: %+v", err)
		}

		e := waitForEvent(t, time.Second, watchEventsQueue, EventNodeCreated)
		if e.Path != testNode {
			t.Fatalf("Event on persistent watch did not fire for expected node %q, got %q", testNode, e.Path)
		}

		// Simulate network error by brutally closing the network connection.
		zk.conn.Close()

		_, err = zk2.Set(testNode, []byte{2}, -1)
		if err != nil {
			t.Fatalf("Set returned error: %+v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		t.Cleanup(cancel)
		// zk should still be waiting to reconnect, so none of the watches should have been triggered
		e, err = watchEventsQueue.Next(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Persistent watcher for %q should not have triggered yet (%+v)", testNode, e)
		}

		// now we let the reconnect occur and make sure it resets watches
		close(zk.reconnectLatch)

		// wait for reconnect event
		waitForEvent(t, 5*time.Second, watchEventsQueue, EventWatching)

		_, err = zk2.Set(testNode, []byte{3}, -1)
		if err != nil {
			t.Fatalf("Set returned error: %+v", err)
		}

		waitForEvent(t, 1*time.Second, watchEventsQueue, EventNodeDataChanged)
	})
}

func waitForEvent(t *testing.T, timeout time.Duration, ch EventQueue, expectedType EventType) Event {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	e, err := ch.Next(ctx)
	requireNoErrorf(t, err)

	if e.Type != expectedType {
		t.Fatalf("Did not receive event of type %s, got %s instead", expectedType, e.Type)
	}

	return e
}

func TestIntegration_PersistentWatchOnClose(t *testing.T) {
	RequireMinimumZkVersion(t, "3.6")

	WithTestCluster(t, 10*time.Second, func(_ *TestCluster, zk *Conn) {
		ch, err := zk.AddPersistentWatch("/", AddWatchModePersistent)
		requireNoErrorf(t, err, "could not add persistent watch")

		waitForEvent(t, 2*time.Second, ch, EventWatching)
		zk.Close()
		waitForEvent(t, 2*time.Second, ch, EventNotWatching)
	})
}

func TestIntegration_PersistentWatchGetsPinged(t *testing.T) {
	RequireMinimumZkVersion(t, "3.6")

	WithTestCluster(t, 60*time.Second, func(_ *TestCluster, zk *Conn) {
		ch, err := zk.AddPersistentWatch("/", AddWatchModePersistent)
		if err != nil {
			t.Fatalf("Could not add persistent watch: %+v", err)
		}

		waitForEvent(t, time.Minute, ch, EventWatching)
		waitForEvent(t, time.Minute, ch, EventPingReceived)
	})
}

func TestIntegration_MultiFailures(t *testing.T) {
	// This test case ensures that we return the errors associated with each
	// opeThis in the event a call to Multi() fails.
	const firstPath = "/gozk-test-first"
	const secondPath = "/gozk-test-second"

	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	// Ensure firstPath doesn't exist and secondPath does. This will cause the
	// 2nd operation in the Multi() to fail.
	if err := zk.Delete(firstPath, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if _, err := zk.Create(secondPath, nil /* data */, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	}

	ops := []interface{}{
		&CreateRequest{Path: firstPath, Data: []byte{1, 2}, Acl: WorldACL(PermAll)},
		&CreateRequest{Path: secondPath, Data: []byte{3, 4}, Acl: WorldACL(PermAll)},
	}
	res, err := zk.Multi(ops...)
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
	if _, _, err := zk.Get(firstPath); err != ErrNoNode {
		t.Fatalf("Node %s was incorrectly created: %+v", firstPath, err)
	}
}

func TestIntegration_GetSetACL(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	if err := zk.AddAuth("digest", []byte("blah")); err != nil {
		t.Fatalf("AddAuth returned error %+v", err)
	}

	path := "/gozk-test"

	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}
	if path, err := zk.Create(path, []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if path != "/gozk-test" {
		t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
	}

	expected := WorldACL(PermAll)

	if acl, stat, err := zk.GetACL(path); err != nil {
		t.Fatalf("GetACL returned error %+v", err)
	} else if stat == nil {
		t.Fatalf("GetACL returned nil Stat")
	} else if len(acl) != 1 || expected[0] != acl[0] {
		t.Fatalf("GetACL mismatch expected %+v instead of %+v", expected, acl)
	}

	expected = []ACL{{PermAll, "ip", "127.0.0.1"}}

	if stat, err := zk.SetACL(path, expected, -1); err != nil {
		t.Fatalf("SetACL returned error %+v", err)
	} else if stat == nil {
		t.Fatalf("SetACL returned nil Stat")
	}

	if acl, stat, err := zk.GetACL(path); err != nil {
		t.Fatalf("GetACL returned error %+v", err)
	} else if stat == nil {
		t.Fatalf("GetACL returned nil Stat")
	} else if len(acl) != 1 || expected[0] != acl[0] {
		t.Fatalf("GetACL mismatch expected %+v instead of %+v", expected, acl)
	}
}

func TestIntegration_Auth(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	path := "/gozk-digest-test"
	if err := zk.Delete(path, -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}

	acl := DigestACL(PermAll, "user", "password")

	if p, err := zk.Create(path, []byte{1, 2, 3, 4}, 0, acl); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if p != path {
		t.Fatalf("Create returned different path '%s' != '%s'", p, path)
	}

	if _, _, err := zk.Get(path); err != ErrNoAuth {
		t.Fatalf("Get returned error %+v instead of ErrNoAuth", err)
	}

	if err := zk.AddAuth("digest", []byte("user:password")); err != nil {
		t.Fatalf("AddAuth returned error %+v", err)
	}

	if a, stat, err := zk.GetACL(path); err != nil {
		t.Fatalf("GetACL returned error %+v", err)
	} else if stat == nil {
		t.Fatalf("GetACL returned nil Stat")
	} else if len(a) != 1 || acl[0] != a[0] {
		t.Fatalf("GetACL mismatch expected %+v instead of %+v", acl, a)
	}

	if data, stat, err := zk.Get(path); err != nil {
		t.Fatalf("Get returned error %+v", err)
	} else if stat == nil {
		t.Fatalf("Get returned nil Stat")
	} else if len(data) != 4 {
		t.Fatalf("Get returned wrong data length")
	}
}

// Tests that we correctly handle a response larger than the default buffer size
func TestIntegration_Children(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	deleteNode := func(node string) {
		if err := zk.Delete(node, -1); err != nil && err != ErrNoNode {
			t.Fatalf("Delete returned error: %+v", err)
		}
	}

	testNode := "/gozk-test-big"
	deleteNode(testNode)

	if _, err := zk.Create(testNode, nil, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	}

	const (
		nodesToCreate = 100
		// By creating many nodes with long names, the response from the Children call should be significantly longer
		// than the buffer size, forcing recvLoop to allocate a bigger buffer
		nameLength = 2 * bufferSize / nodesToCreate
	)

	format := fmt.Sprintf("%%0%dd", nameLength)
	if name := fmt.Sprintf(format, 0); len(name) != nameLength {
		// Sanity check that the generated format string creates strings of the right length
		t.Fatalf("Length of generated name was not %d, got %d", nameLength, len(name))
	}

	var createdNodes []string
	for i := 0; i < nodesToCreate; i++ {
		name := fmt.Sprintf(format, i)
		createdNodes = append(createdNodes, name)
		path := testNode + "/" + name
		if _, err := zk.Create(path, nil, 0, WorldACL(PermAll)); err != nil {
			t.Fatalf("Create returned error: %+v", err)
		}
		defer deleteNode(path)
	}

	children, _, err := zk.Children(testNode)
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	}
	sort.Strings(children)
	if !reflect.DeepEqual(children, createdNodes) {
		t.Fatal("Children did not return expected nodes")
	}
}

func TestIntegration_ChildWatch(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	if err := zk.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}

	children, stat, childCh, err := zk.ChildrenW("/")
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Children returned nil stat")
	} else if len(children) < 1 {
		t.Fatal("Children should return at least 1 child")
	}

	if path, err := zk.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if path != "/gozk-test" {
		t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
	}

	select {
	case ev := <-childCh:
		if ev.Err != nil {
			t.Fatalf("Child watcher error %+v", ev.Err)
		}
		if ev.Path != "/" {
			t.Fatalf("Child watcher wrong path %s instead of %s", ev.Path, "/")
		}
	case _ = <-time.After(time.Second * 2):
		t.Fatal("Child watcher timed out")
	}

	// Delete of the watched node should trigger the watch

	children, stat, childCh, err = zk.ChildrenW("/gozk-test")
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Children returned nil stat")
	} else if len(children) != 0 {
		t.Fatal("Children should return 0 children")
	}

	if err := zk.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}

	select {
	case ev := <-childCh:
		if ev.Err != nil {
			t.Fatalf("Child watcher error %+v", ev.Err)
		}
		if ev.Path != "/gozk-test" {
			t.Fatalf("Child watcher wrong path %s instead of %s", ev.Path, "/")
		}
	case _ = <-time.After(time.Second * 2):
		t.Fatal("Child watcher timed out")
	}
}

func TestIntegration_SetWatchers(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	zk.reconnectLatch = make(chan struct{})
	zk.setWatchLimit = 1024 // break up set-watch step into 1k requests
	var setWatchReqs atomic.Value
	zk.setWatchCallback = func(reqs []*setWatchesRequest) {
		setWatchReqs.Store(reqs)
	}

	zk2, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk2.Close()

	if err := zk.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}

	testPaths := map[string]<-chan Event{}
	defer func() {
		// clean up all of the test paths we create
		for p := range testPaths {
			zk2.Delete(p, -1)
		}
	}()

	// we create lots of long paths to watch, to make sure a "set watches" request on will be too big and be broken
	// into multiple packets. The size is chosen such that each packet can hold exactly 2 watches, meaning we should
	// see half as many packets as there are watches.
	const (
		watches               = 50
		watchedNodeNameFormat = "/gozk-test-%0450d"
	)

	for i := 0; i < watches; i++ {
		testPath, err := zk.Create(fmt.Sprintf(watchedNodeNameFormat, i), []byte{}, 0, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned: %+v", err)
		}
		testPaths[testPath] = nil
		_, _, testEvCh, err := zk.GetW(testPath)
		if err != nil {
			t.Fatalf("GetW returned: %+v", err)
		}
		testPaths[testPath] = testEvCh
	}

	children, stat, childCh, err := zk.ChildrenW("/")
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Children returned nil stat")
	} else if len(children) < 1 {
		t.Fatal("Children should return at least 1 child")
	}

	// Simulate network error by brutally closing the network connection.
	zk.conn.Close()
	for p := range testPaths {
		if err := zk2.Delete(p, -1); err != nil && err != ErrNoNode {
			t.Fatalf("Delete returned error: %+v", err)
		}
	}
	if path, err := zk2.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatalf("Create returned error: %+v", err)
	} else if path != "/gozk-test" {
		t.Fatalf("Create returned different path '%s' != '/gozk-test'", path)
	}

	time.Sleep(100 * time.Millisecond)

	// zk should still be waiting to reconnect, so none of the watches should have been triggered
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
	close(zk.reconnectLatch)

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
	actualReqs := setWatchReqs.Load().([]*setWatchesRequest)
	if len(actualReqs) != watches/2 {
		// sanity check: we should have generated exactly 25 requests to reset watches
		t.Fatalf("Did not send exactly %d setWatches requests, got %d instead", watches/2, len(actualReqs))
	}
	for _, r := range actualReqs {
		totalWatches += len(r.ChildWatches) + len(r.DataWatches) + len(r.ExistWatches)
		n, err := encodePacket(buf, r)
		if err != nil {
			t.Fatalf("encodePacket failed: %v! request:\n%+v", err, r)
		} else if n > 1024 {
			t.Fatalf("setWatchesRequest exceeded allowed size (%d > 1024)! request:\n%+v", n, r)
		}
	}

	if totalWatches != len(testPaths)+1 {
		t.Fatalf("setWatchesRequests did not include all expected watches; expecting %d, got %d", len(testPaths)+1, totalWatches)
	}
}

func TestIntegration_ExpiringWatch(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	zk, _, err := ts.ConnectAll()
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()

	if err := zk.Delete("/gozk-test", -1); err != nil && err != ErrNoNode {
		t.Fatalf("Delete returned error: %+v", err)
	}

	children, stat, childCh, err := zk.ChildrenW("/")
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	} else if stat == nil {
		t.Fatal("Children returned nil stat")
	} else if len(children) < 1 {
		t.Fatal("Children should return at least 1 child")
	}

	zk.sessionID = 99999
	zk.conn.Close()

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
}

func TestRequestFail(t *testing.T) {
	// If connecting fails to all servers in the list then pending requests
	// should be errored out so they don't hang forever.

	zk, _, err := Connect([]string{"127.0.0.1:32444"}, time.Second*15)
	if err != nil {
		t.Fatal(err)
	}
	defer zk.Close()

	ch := make(chan error)
	go func() {
		_, _, err := zk.Get("/blah")
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
	zk, _, err := Connect([]string{"127.0.0.1:32444"}, time.Second*15)
	if err != nil {
		t.Fatal(err)
	}
	// multiple calls to Close() should not panic
	zk.Close()
	zk.Close()
}

func TestIntegration_SlowServer(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()

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

	zk, _, err := Connect([]string{proxyAddr}, time.Millisecond*500)
	if err != nil {
		t.Fatal(err)
	}
	defer zk.Close()

	_, _, wch, err := zk.ChildrenW("/")
	if err != nil {
		t.Fatal(err)
	}

	// Force a reconnect to get a throttled connection
	zk.conn.Close()

	time.Sleep(time.Millisecond * 100)

	if err := zk.Delete("/gozk-test", -1); err == nil {
		t.Fatal("Delete should have failed")
	}

	// The previous request should have timed out causing the server to be disconnected and reconnected

	if _, err := zk.Create("/gozk-test", []byte{1, 2, 3, 4}, 0, WorldACL(PermAll)); err != nil {
		t.Fatal(err)
	}

	// Make sure event is still returned because the session should not have been affected
	select {
	case ev := <-wch:
		t.Logf("Received event: %+v", ev)
	case <-time.After(time.Second):
		t.Fatal("Expected to receive a watch event")
	}
}

func TestIntegration_MaxBufferSize(t *testing.T) {
	ts, err := StartTestCluster(t, 1, nil, logWriter{t: t, p: "[ZKERR] "})
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Stop()
	// no buffer size
	zk, _, err := ts.ConnectWithOptions(15 * time.Second)
	//var l testLogger
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zk.Close()
	// 1k buffer size, logs to custom test logger
	zkLimited, _, err := ts.ConnectWithOptions(15*time.Second, WithMaxBufferSize(1024))
	if err != nil {
		t.Fatalf("Connect returned error: %+v", err)
	}
	defer zkLimited.Close()

	// With small node with small number of children
	data := []byte{101, 102, 103, 103}
	_, err = zk.Create("/foo", data, 0, WorldACL(PermAll))
	if err != nil {
		t.Fatalf("Create returned error: %+v", err)
	}
	var children []string
	for i := 0; i < 4; i++ {
		childName, err := zk.Create("/foo/child", nil, FlagEphemeral|FlagSequence, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned error: %+v", err)
		}
		children = append(children, childName[len("/foo/"):]) // strip parent prefix from name
	}
	sort.Strings(children)

	// Limited client works fine
	resultData, _, err := zkLimited.Get("/foo")
	if err != nil {
		t.Fatalf("Get returned error: %+v", err)
	}
	if !reflect.DeepEqual(resultData, data) {
		t.Fatalf("Get returned unexpected data; expecting %+v, got %+v", data, resultData)
	}
	resultChildren, _, err := zkLimited.Children("/foo")
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
	_, err = zk.Create("/bar", data, 0, WorldACL(PermAll))
	if err != nil {
		t.Fatalf("Create returned error: %+v", err)
	}
	_, _, err = zkLimited.Get("/bar")
	expectErr(t, err, ErrConnectionClosed)
	expectErr(t, err, ErrResponseBufferSizeExceeded)

	// Or with large number of children...
	totalLen := 0
	children = nil
	for totalLen < 1024 {
		childName, err := zk.Create("/bar/child", nil, FlagEphemeral|FlagSequence, WorldACL(PermAll))
		if err != nil {
			t.Fatalf("Create returned error: %+v", err)
		}
		n := childName[len("/bar/"):] // strip parent prefix from name
		children = append(children, n)
		totalLen += len(n)
	}
	sort.Strings(children)
	_, _, err = zkLimited.Children("/bar")
	expectErr(t, err, ErrConnectionClosed)
	expectErr(t, err, ErrResponseBufferSizeExceeded)

	// Other client (without buffer size limit) can successfully query the node and its children, of course
	resultData, _, err = zk.Get("/bar")
	if err != nil {
		t.Fatalf("Get returned error: %+v", err)
	}
	if !reflect.DeepEqual(resultData, data) {
		t.Fatalf("Get returned unexpected data; expecting %+v, got %+v", data, resultData)
	}
	resultChildren, _, err = zk.Children("/bar")
	if err != nil {
		t.Fatalf("Children returned error: %+v", err)
	}
	sort.Strings(resultChildren)
	if !reflect.DeepEqual(resultChildren, children) {
		t.Fatalf("Children returned unexpected names; expecting %+v, got %+v", children, resultChildren)
	}
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
	if !errors.Is(err, expected) {
		t.Fatalf("Get returned wrong error; expecting ErrClosing, got %+v", err)
	}
}
