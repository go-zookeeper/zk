package zk

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecurringReAuthHang(t *testing.T) {
	WithTestCluster(t, 3, io.Discard, io.Discard, func(t *testing.T, tc *TestCluster) {
		WithConnectAll(t, tc, func(t *testing.T, c *Conn, ech <-chan Event) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			if err := waitForSession(ctx, ech); err != nil {
				t.Fatalf("failed to wait for session: %v", err)
			}

			// Add auth.
			if err := c.AddAuth("digest", []byte("test:test")); err != nil {
				t.Fatalf("Failed to add auth %s", err)
			}

			var reauthCloseOnce sync.Once
			reauthSig := make(chan struct{}, 1)
			c.resendZkAuthFn = func(ctx context.Context, c *Conn) error {
				// in current implimentation the reauth might be called more than once based on various conditions
				reauthCloseOnce.Do(func() { close(reauthSig) })
				return resendZkAuth(ctx, c)
			}

			c.debugCloseRecvLoop = true
			currentServer := c.Server()
			tc.StopServer(currentServer)
			// wait connect to new zookeeper.
			ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			if err := waitForSession(ctx, ech); err != nil {
				t.Fatalf("failed to wait for session: %v", err)
			}

			select {
			case _, ok := <-reauthSig:
				if !ok {
					return // we closed the channel as expected
				}
				t.Fatal("reauth testing channel should have been closed")
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	})
}

func TestConcurrentReadAndClose(t *testing.T) {
	WithListenServer(t, func(server string) {
		conn, _, err := Connect([]string{server}, 15*time.Second)
		if err != nil {
			t.Fatalf("Failed to create Connection %s", err)
		}

		okChan := make(chan struct{})
		var setErr error
		go func() {
			_, setErr = conn.Create("/test-path", []byte("test data"), 0, WorldACL(PermAll))
			close(okChan)
		}()

		go func() {
			time.Sleep(1 * time.Second)
			conn.Close()
		}()

		select {
		case <-okChan:
			if setErr != ErrConnectionClosed {
				t.Fatalf("unexpected error returned from Set %v", setErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("apparent deadlock!")
		}
	})
}

func TestDeadlockInClose(t *testing.T) {
	c := &Conn{
		shouldQuit:     make(chan struct{}),
		connectTimeout: 1 * time.Second,
		sendChan:       make(chan *request, sendChanSize),
		logger:         DefaultLogger,
	}

	for i := 0; i < sendChanSize; i++ {
		c.sendChan <- &request{}
	}

	okChan := make(chan struct{})
	go func() {
		c.Close()
		close(okChan)
	}()

	select {
	case <-okChan:
	case <-time.After(3 * time.Second):
		t.Fatal("apparent deadlock!")
	}
}

func TestNotifyWatches(t *testing.T) {
	cases := []struct {
		eType    EventType
		path     string
		expected map[watcherKey]bool
	}{
		{
			EventNodeCreated, "/",
			map[watcherKey]bool{
				{"/", watcherKindExist}:               true,
				{"/", watcherKindChildren}:            false,
				{"/", watcherKindData}:                false,
				{"/", watcherKindPersistent}:          true,
				{"/", watcherKindPersistentRecursive}: true,
			},
		},
		{
			EventNodeCreated, "/a",
			map[watcherKey]bool{
				{"/", watcherKindExist}:               false,
				{"/", watcherKindChildren}:            false,
				{"/", watcherKindData}:                false,
				{"/", watcherKindPersistent}:          false,
				{"/", watcherKindPersistentRecursive}: true,
			},
		},
		{
			EventNodeCreated, "/a",
			map[watcherKey]bool{
				{"/b", watcherKindExist}:               false,
				{"/b", watcherKindChildren}:            false,
				{"/b", watcherKindData}:                false,
				{"/b", watcherKindPersistent}:          false,
				{"/b", watcherKindPersistentRecursive}: false,
			},
		},
		{
			EventNodeDataChanged, "/",
			map[watcherKey]bool{
				{"/", watcherKindExist}:               true,
				{"/", watcherKindData}:                true,
				{"/", watcherKindChildren}:            false,
				{"/", watcherKindPersistent}:          true,
				{"/", watcherKindPersistentRecursive}: true,
			},
		},
		{
			EventNodeChildrenChanged, "/",
			map[watcherKey]bool{
				{"/", watcherKindExist}:               false,
				{"/", watcherKindData}:                false,
				{"/", watcherKindChildren}:            true,
				{"/", watcherKindPersistent}:          true,
				{"/", watcherKindPersistentRecursive}: true,
			},
		},
		{
			EventNodeDeleted, "/",
			map[watcherKey]bool{
				{"/", watcherKindExist}:               true,
				{"/", watcherKindData}:                true,
				{"/", watcherKindChildren}:            true,
				{"/", watcherKindPersistent}:          true,
				{"/", watcherKindPersistentRecursive}: true,
			},
		},
	}

	conn := &Conn{
		watchersByKey: make(map[watcherKey][]watcher),
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("#%d %s", i, c.eType), func(t *testing.T) {
			c := c

			notifications := make([]struct {
				path string
				kind watcherKind
				want bool
				ch   <-chan Event
			}, len(c.expected))

			var idx int
			for key, want := range c.expected {
				ch := conn.addWatcher(key.path, key.kind)
				notifications[idx].path = key.path
				notifications[idx].kind = key.kind
				notifications[idx].want = want
				notifications[idx].ch = ch
				idx++
			}
			ev := Event{Type: c.eType, Path: c.path}
			conn.notifyWatchers(ev)

			// Wait for all notifications to be received.
			time.Sleep(100 * time.Millisecond)

			for _, n := range notifications {
				select {
				case e := <-n.ch:
					if !n.want {
						// We did not expect an event, but got one.
						t.Fatal("unexpected notification received", e.Path, e.Type, n.kind)
					} else if n.kind.isRecursive() {
						// Special case for recursive watchers - paths match by prefix.
						if !strings.HasPrefix(e.Path, n.path) {
							// We expected an event, but the path has an unexpected prefix.
							t.Fatal("notification received with unexpected path", e.Path, e.Type, n.kind)
						}
					} else if e.Path != n.path {
						// We expected an event, but the path does not match the expected one.
						t.Fatal("notification received with unexpected path", e.Path, e.Type, n.kind)
					}
				default:
					if n.want {
						t.Fatal("expected notification not received", n.path, n.kind)
					}
				}
			}
		})
	}
}
